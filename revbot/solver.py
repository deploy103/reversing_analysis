from __future__ import annotations

import base64
import ast
import bz2
import codecs
import hashlib
import html
import io
import json
import lzma
import marshal
import os
import quopri
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import tempfile
import types
import urllib.parse
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from revbot.artifacts import normalize_artifacts
from revbot.collectors.tools import ExternalToolCollector
from revbot.models import ToolResult
from revbot.static_analysis import StaticAnalyzer, extract_strings


FLAG_PATTERNS = [
    re.compile(r"(?:DH|FLAG|flag|DreamHack|dreamhack)\{[^{}\r\n]{3,160}\}"),
    re.compile(r"[A-Za-z0-9_]{2,32}\{[ -~]{3,160}\}"),
]
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])")
BASE64URL_RE = re.compile(r"(?<![A-Za-z0-9_\-=])(?:[A-Za-z0-9_\-]{12,}={0,2})(?![A-Za-z0-9_\-=])")
BASE32_RE = re.compile(r"(?<![A-Z2-7=])(?:[A-Z2-7]{16,}={0,6})(?![A-Z2-7=])")
BASE58_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])(?:[1-9A-HJ-NP-Za-km-z]{10,})(?![1-9A-HJ-NP-Za-km-z])")
HEX_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{16,})(?![A-Fa-f0-9])")
BINARY_RE = re.compile(r"(?<![01])(?:[01]{8}){2,}(?![01])")
PERCENT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}){4,}")
MORSE_RE = re.compile(r"(?<![A-Za-z0-9])(?:[.\-]{1,6}(?:[ /|]+|$)){6,}")
BRAINFUCK_RUN_RE = re.compile(r"[+\-<>\[\].,\s]{20,}")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SOURCE_DECODE_CONTEXT_RE = re.compile(
    r"\b(?:secret|password|passwd|pass|key|serial|token|pin|code|answer|flag|input|atob|b64decode|fromhex|decode|buffer\.from)\b",
    re.IGNORECASE,
)
SUCCESS_RE = re.compile(
    r"correct|success|congrat|good|right|flag|well done|pass|\uc815\ub2f5|\uc131\uacf5|\ucd95\ud558|\ub9de\uc558",
    re.IGNORECASE,
)
FAIL_RE = re.compile(
    r"wrong|fail|incorrect|nope|invalid|try again|bad|\uc624\ub2f5|\uc2e4\ud328|\ud2c0\ub838|\ud2c0\ub9bc",
    re.IGNORECASE,
)
COMPARISON_NAMES = {
    "strcmp",
    "strncmp",
    "memcmp",
    "strcasecmp",
    "strncasecmp",
    "lstrcmpa",
    "lstrcmpw",
    "comparestringa",
    "comparestringw",
}
STRING_SEARCH_NAMES = {"strstr", "strcasestr"}
DEFAULT_ENV_NAMES = (
    "REV_INPUT",
    "INPUT",
    "PASSWORD",
    "PASS",
    "KEY",
    "FLAG",
    "TOKEN",
    "SERIAL",
    "SECRET",
    "CODE",
    "ANSWER",
    "LICENSE",
    "AUTH",
    "USER",
    "USERNAME",
)
DEFAULT_INPUT_FILES = (
    "input.txt",
    "key.txt",
    "flag.txt",
    "password.txt",
    "serial.txt",
    "secret.txt",
    "answer.txt",
    "code.txt",
    "license.txt",
    "license.key",
    "data.txt",
    "data/input.txt",
)
SCRIPT_AND_SOURCE_SUFFIXES = {
    ".js",
    ".mjs",
    ".ts",
    ".lua",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".cs",
    ".go",
    ".rs",
}
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
HASH_HEX_RE = re.compile(
    r"(?<![A-Fa-f0-9])([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128})(?![A-Fa-f0-9])"
)
NUMERIC_SEQUENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:\[\s*|array\s*\(\s*|bytes\s*\(\s*\[\s*)?"
    r"((?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*(?:,\s*(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*){3,})"
    r"(?:\]\s*\)?|\))?"
)
SPACE_NUMERIC_SEQUENCE_RE = re.compile(r"(?<![A-Za-z0-9_])((?:0x[0-9A-Fa-f]{1,2}|\d{2,3})(?:\s+(?:0x[0-9A-Fa-f]{1,2}|\d{2,3})){5,})(?![A-Za-z0-9_])")
FROM_CHAR_CODE_RE = re.compile(r"\b(?:String\.)?fromCharCode\s*\(\s*((?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*(?:,\s*(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*){3,})\)")
CHR_JOIN_RE = re.compile(r"\bchr\s*\(\s*(0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*\)")
HINT_VALUE_RE = re.compile(
    r"\b(?:password|passwd|pass|key|serial|token|pin|code|answer|flag)\b\s*(?:is|=|:|-|=>)\s*([A-Za-z0-9_{}!@#$%^&*+=:,.?/\\-]{3,80})",
    re.IGNORECASE,
)
MORSE_TABLE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    "-.-.--": "!",
    "-....-": "-",
    "-..-.": "/",
    "-.--.": "(",
    "-.--.-": ")",
}


@dataclass
class SolveCandidate:
    value: str
    source: str
    confidence: float
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
        }


class SolveEngine:
    def __init__(
        self,
        tool_timeout: int = 20,
        execute: bool = False,
        exec_timeout: float = 2.0,
        max_bytes: int = 128 * 1024 * 1024,
        custom_inputs: list[str] | None = None,
        bruteforce_pin: bool = False,
        max_probes: int = 80,
        validation_limit: int = 24,
    ) -> None:
        self.tool_timeout = tool_timeout
        self.execute = execute
        self.exec_timeout = exec_timeout
        self.custom_inputs = custom_inputs or []
        self.bruteforce_pin = bruteforce_pin
        self.max_probes = max(1, max_probes)
        self.validation_limit = max(1, validation_limit)
        self.static_analyzer = StaticAnalyzer(max_bytes=max_bytes)
        self.collector = ExternalToolCollector(timeout_seconds=tool_timeout)

    def solve(self, sample_path: Path | str, extra_artifacts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        path = Path(sample_path)
        data = path.read_bytes()
        static = self.static_analyzer.analyze(path)
        all_strings = extract_strings(data)
        all_strings.extend(static.get("zip", {}).get("embedded_strings", []))
        tools = self.collector.collect(path)
        artifact_summary = normalize_artifacts(extra_artifacts or [])
        artifact_strings = collect_artifact_strings(artifact_summary)
        all_strings.extend(artifact_strings)
        candidates: list[SolveCandidate] = []
        candidates.extend(find_flag_literals(static, data))
        candidates.extend(hint_value_candidates(static.get("strings", {}).get("top", []), "static:hint-value"))
        candidates.extend(find_flags_in_string_list(static.get("zip", {}).get("embedded_strings", []), "zip:embedded-string"))
        candidates.extend(zip_entry_candidates(path, self.custom_inputs))
        candidates.extend(tar_entry_candidates(path))
        candidates.extend(find_flags_in_string_list(artifact_strings, "artifact:string"))
        candidates.extend(hint_value_candidates(artifact_strings, "artifact:hint-value"))
        candidates.extend(decode_embedded_encodings(static))
        candidates.extend(decode_embedded_encodings({"strings": {"top": artifact_strings[:1000]}}))
        candidates.extend(literal_probe_candidates(artifact_strings, "artifact:literal"))
        candidates.extend(python_artifact_candidates(path))
        candidates.extend(script_artifact_candidates(path))
        candidates.extend(numeric_sequence_candidates_from_bytes(data, "static:numeric-sequence"))
        candidates.extend(brainfuck_candidates_from_text(data[:2_000_000].decode("latin1", errors="ignore"), "static:brainfuck"))
        candidates.extend(png_chunk_candidates(data))
        candidates.extend(compressed_stream_candidates(data))
        candidates.extend(xor_search(data))
        candidates.extend(byte_shift_search(data))
        candidates.extend(bit_rotate_search(data))
        crypto_keys = derive_crypto_keys(all_strings + self.custom_inputs)
        candidates.extend(repeating_xor_search(data, extra_keys=crypto_keys))
        candidates.extend(rc4_common_key_search(data, extra_keys=crypto_keys))
        candidates.extend(hash_crack_candidates(static, self.custom_inputs))
        candidates.extend(immediate_string_candidates(tools))
        candidates = dedupe_candidates(candidates)

        dynamic = {}
        if self.execute:
            dynamic = run_dynamic_probes(
                path,
                static,
                candidates,
                timeout=self.exec_timeout,
                extra_strings=all_strings,
                custom_inputs=self.custom_inputs,
                bruteforce_pin=self.bruteforce_pin,
                max_probes=self.max_probes,
            )
            candidates.extend(dynamic_candidates(dynamic))
            candidates = dedupe_candidates(candidates)
            validations = validate_candidates(path, candidates[: self.validation_limit], timeout=self.exec_timeout)
            dynamic["candidate_validation"] = validations
            candidates.extend(validation_candidates(validations))
            candidates = dedupe_candidates(candidates)

        ranked_functions = merge_ranked_functions(rank_objdump_functions(tools), artifact_summary.get("ranked_functions", []))
        strategy = build_strategy(path, static, tools, candidates, dynamic)
        return {
            "file": static["identity"],
            "solved": bool(candidates and candidates[0].confidence >= 0.82),
            "candidates": [item.to_dict() for item in candidates],
            "ranked_functions": ranked_functions,
            "static": summarize_static_for_solve(static),
            "tools": summarize_tools_for_solve(tools),
            "artifacts": artifact_summary,
            "dynamic": dynamic,
            "strategy": strategy,
        }


def collect_artifact_strings(artifact_summary: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in artifact_summary.get("strings", []):
        value = str(item.get("value", ""))
        if len(value) >= 4:
            values.append(value)
    for function in artifact_summary.get("functions", []):
        for value in function.get("strings", []):
            if len(str(value)) >= 4:
                values.append(str(value))
    return list(dict.fromkeys(values))


def merge_ranked_functions(primary: list[dict[str, Any]], artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = []
    for item in primary:
        clone = dict(item)
        clone.setdefault("source", "objdump")
        merged.append(clone)
    for item in artifacts:
        clone = dict(item)
        clone.setdefault("source", "artifact")
        merged.append(clone)
    return sorted(merged, key=lambda item: (item.get("score", 0), str(item.get("name", ""))), reverse=True)[:120]


def find_flag_literals(static: dict[str, Any], data: bytes) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    haystacks = static.get("strings", {}).get("top", []) + [data.decode("latin1", errors="ignore")]
    for text in haystacks:
        for flag, confidence in extract_flags_with_confidence(text):
            candidates.append(
                SolveCandidate(
                    value=flag,
                    source="literal",
                    confidence=confidence,
                    evidence=["flag-shaped literal found in strings"],
                )
            )
    return candidates


def find_flags_in_string_list(strings: list[str], source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for value in strings:
        for flag, confidence in extract_flags_with_confidence(value):
            candidates.append(SolveCandidate(flag, source, min(0.97, confidence), [short(value)]))
    return candidates


def decode_embedded_encodings(static: dict[str, Any]) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    strings = static.get("strings", {}).get("top", [])
    for value in strings:
        for decoded, method in recursive_decode_string_variants(value):
            decoded_flags = extract_flags(decoded)
            if not decoded_flags and likely_probe_input(decoded):
                candidates.append(
                    SolveCandidate(
                        value=decoded,
                        source=f"decoded-input:{method}",
                        confidence=0.79,
                        evidence=[short(value), short(decoded)],
                    )
                )
            for flag in extract_flags(decoded):
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"decoded:{method}",
                        confidence=0.9,
                        evidence=[short(value), short(decoded)],
                    )
                )
        rot13 = codecs.decode(value, "rot_13")
        for flag, confidence in extract_flags_with_confidence(rot13):
            candidates.append(SolveCandidate(flag, "decoded:rot13", 0.86 if confidence >= 0.9 else 0.78, [short(value), short(rot13)]))
        rot47 = rot47_text(value)
        for flag, confidence in extract_flags_with_confidence(rot47):
            candidates.append(SolveCandidate(flag, "decoded:rot47", 0.86 if confidence >= 0.9 else 0.78, [short(value), short(rot47)]))
        reversed_value = value[::-1]
        for flag, confidence in extract_flags_with_confidence(reversed_value):
            candidates.append(SolveCandidate(flag, "decoded:reverse", 0.84 if confidence >= 0.9 else 0.76, [short(value), short(reversed_value)]))
        for decoded, method in recursive_decode_string_variants(reversed_value, max_depth=2):
            for flag, confidence in extract_flags_with_confidence(decoded):
                candidates.append(
                    SolveCandidate(
                        flag,
                        f"decoded:reverse->{method}",
                        0.88 if confidence >= 0.9 else 0.78,
                        [short(value), short(decoded)],
                    )
                )
        for shift in range(1, 26):
            shifted = caesar_shift(value, shift)
            for flag in extract_flags(shifted, strict=True):
                candidates.append(SolveCandidate(flag, f"decoded:caesar+{shift}", 0.84, [short(value), short(shifted)]))
        atbash = atbash_text(value)
        for flag in extract_flags(atbash, strict=True):
            candidates.append(SolveCandidate(flag, "decoded:atbash", 0.84, [short(value), short(atbash)]))
    return candidates


def hint_value_candidates(strings: list[str], source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for value in strings:
        for match in HINT_VALUE_RE.finditer(value):
            candidate = match.group(1).strip(".,;:'\"`)]}")
            if extract_flags(candidate):
                confidence = 0.94
            elif likely_probe_input(candidate):
                confidence = 0.82
            else:
                continue
            candidates.append(
                SolveCandidate(
                    value=candidate,
                    source=source,
                    confidence=confidence,
                    evidence=[short(value)],
                )
            )
    return dedupe_candidates(candidates)


def caesar_shift(value: str, shift: int) -> str:
    chars: list[str] = []
    for ch in value:
        if "a" <= ch <= "z":
            chars.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            chars.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            chars.append(ch)
    return "".join(chars)


def atbash_text(value: str) -> str:
    chars: list[str] = []
    for ch in value:
        if "a" <= ch <= "z":
            chars.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            chars.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            chars.append(ch)
    return "".join(chars)


def rot47_text(value: str) -> str:
    chars: list[str] = []
    for ch in value:
        code = ord(ch)
        if 33 <= code <= 126:
            chars.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            chars.append(ch)
    return "".join(chars)


def recursive_decode_string_variants(value: str, max_depth: int = 3) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    queue: list[tuple[str, str, int]] = [(value, "", 0)]
    seen = {value}
    while queue:
        current, chain, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for decoded, method in decode_string_variants(current):
            next_chain = f"{chain}->{method}" if chain else method
            marker = f"{next_chain}\0{decoded}"
            if marker in seen:
                continue
            seen.add(marker)
            results.append((decoded, next_chain))
            if decoded not in seen:
                seen.add(decoded)
                queue.append((decoded, next_chain, depth + 1))
    return results


def decode_string_variants(value: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    compact = value.strip()
    for match in BASE64_RE.finditer(compact):
        token = match.group(0)
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
            results.extend(decoded_bytes_variants(decoded, "base64"))
        except (ValueError, base64.binascii.Error):
            pass
    for match in BASE64URL_RE.finditer(compact):
        token = match.group(0)
        if "+" in token or "/" in token:
            continue
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            results.extend(decoded_bytes_variants(decoded, "base64url"))
        except (ValueError, base64.binascii.Error):
            pass
    for match in HEX_RE.finditer(compact):
        token = match.group(0)
        if len(token) % 2:
            continue
        try:
            decoded = bytes.fromhex(token)
            results.extend(decoded_bytes_variants(decoded, "hex"))
        except ValueError:
            pass
    for match in BINARY_RE.finditer(compact):
        token = match.group(0)
        try:
            decoded = bytes(int(token[index : index + 8], 2) for index in range(0, len(token), 8))
            if is_mostly_printable(decoded):
                results.append((decoded.decode("utf-8", errors="replace"), "binary"))
        except ValueError:
            pass
    for match in BASE32_RE.finditer(compact.upper()):
        token = match.group(0)
        padded = token + "=" * ((8 - len(token) % 8) % 8)
        try:
            decoded = base64.b32decode(padded, casefold=True)
            results.extend(decoded_bytes_variants(decoded, "base32"))
        except (ValueError, base64.binascii.Error):
            pass
    for match in BASE58_RE.finditer(compact):
        try:
            decoded = base58_decode(match.group(0))
        except ValueError:
            continue
        results.extend(decoded_bytes_variants(decoded, "base58"))
    for decoder_name, decoder in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
        if len(compact) < 10:
            continue
        try:
            decoded = decoder(compact.encode("ascii"))
            results.extend(decoded_bytes_variants(decoded, decoder_name))
        except (ValueError, UnicodeEncodeError, base64.binascii.Error):
            pass
    if "=" in compact:
        try:
            decoded = quopri.decodestring(compact.encode("ascii"))
        except UnicodeEncodeError:
            decoded = b""
        if decoded and decoded != compact.encode("ascii", errors="ignore"):
            results.extend(decoded_bytes_variants(decoded, "quoted-printable"))
    for match in PERCENT_RE.finditer(compact):
        decoded = urllib.parse.unquote(match.group(0))
        if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
            results.append((decoded, "percent"))
    for match in ESCAPE_RE.finditer(compact):
        try:
            decoded = bytes(match.group(0), "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            continue
        if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
            results.append((decoded, "escape"))
    unescaped = html.unescape(compact)
    if unescaped != compact and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in unescaped):
        results.append((unescaped, "html"))
    for match in MORSE_RE.finditer(compact):
        decoded = decode_morse(match.group(0))
        if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
            results.append((decoded, "morse"))
    return results


def base58_decode(value: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for ch in value:
        if ch not in alphabet:
            raise ValueError("invalid base58 character")
        number = number * 58 + alphabet.index(ch)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + raw


def decode_morse(value: str) -> str:
    words = re.split(r"\s*/\s*|\s*\|\s*", value.strip())
    decoded_words: list[str] = []
    for word in words:
        letters = [token for token in re.split(r"\s+", word.strip()) if token]
        if not letters:
            continue
        decoded = []
        for token in letters:
            if token not in MORSE_TABLE:
                return ""
            decoded.append(MORSE_TABLE[token])
        decoded_words.append("".join(decoded))
    return " ".join(decoded_words)


def decoded_bytes_variants(data: bytes, method: str) -> list[tuple[str, str]]:
    results = [(text, f"{method}{suffix}") for text, suffix in printable_decodings(data)]
    for decoded, submethod in decompress_bytes_variants(data):
        results.extend((text, f"{method}->{submethod}{suffix}") for text, suffix in printable_decodings(decoded))
    return list(dict.fromkeys(results))


def decompress_bytes_variants(data: bytes) -> list[tuple[bytes, str]]:
    results: list[tuple[bytes, str]] = []
    if data.startswith(b"\x1f\x8b\x08"):
        try:
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = obj.decompress(data, 1_000_000)
            if decoded:
                results.append((decoded, "gzip"))
        except zlib.error:
            pass
    for wbits, name in ((zlib.MAX_WBITS, "zlib"), (-zlib.MAX_WBITS, "deflate")):
        try:
            decoded = zlib.decompress(data, wbits)
            if decoded:
                results.append((decoded, name))
        except zlib.error:
            pass
    if data.startswith(b"BZh"):
        try:
            decoded = bz2.decompress(data)
            if decoded:
                results.append((decoded, "bzip2"))
        except (OSError, ValueError):
            pass
    if data.startswith(b"\xfd7zXZ\x00"):
        try:
            decoded = lzma.decompress(data)
            if decoded:
                results.append((decoded, "xz"))
        except (lzma.LZMAError, ValueError):
            pass
    return results


def printable_decodings(data: bytes) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    if is_mostly_printable(data):
        results.append((data.decode("utf-8", errors="replace"), ""))
    if len(data) >= 8 and len(data) % 2 == 0:
        try:
            decoded = data.decode("utf-16le")
        except UnicodeDecodeError:
            decoded = ""
        if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
            results.append((decoded, ":utf16le"))
        try:
            decoded = data.decode("utf-16be")
        except UnicodeDecodeError:
            decoded = ""
        if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
            results.append((decoded, ":utf16be"))
    if len(data) >= 16 and len(data) % 4 == 0:
        for encoding, suffix in (("utf-32le", ":utf32le"), ("utf-32be", ":utf32be")):
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                decoded = ""
            if decoded and all(ch in "\r\n\t" or 32 <= ord(ch) <= 126 for ch in decoded):
                results.append((decoded, suffix))
    return list(dict.fromkeys(results))


def python_artifact_candidates(path: Path) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    strings: list[str] = []
    try:
        if path.suffix == ".py":
            data = path.read_bytes()
            text = data.decode("utf-8", errors="replace")
            strings.extend(extract_strings(data))
            try:
                quoted = extract_quoted_strings(text)
            except UnicodeDecodeError:
                quoted = []
            strings.extend(quoted)
            candidates.extend(hint_value_candidates(strings, "python:hint-value"))
            candidates.extend(literal_probe_candidates(quoted, "python:quoted-literal"))
            candidates.extend(comparison_literal_candidates_from_text(text, "python:comparison-literal"))
            candidates.extend(python_ast_constant_candidates(text))
            candidates.extend(charcode_candidates_from_text(text, "python:charcode"))
            candidates.extend(char_literal_sequence_candidates_from_text(text, "python:char-literal-sequence"))
            candidates.extend(char_constraint_candidates_from_text(text, "python:char-constraints"))
            candidates.extend(numeric_sequence_candidates_from_bytes(data, "python:numeric-sequence"))
            candidates.extend(source_context_decoded_input_candidates(text, "python:context-decoded-input"))
        elif path.suffix == ".pyc":
            data = path.read_bytes()
            strings.extend(extract_pyc_strings(data))
            candidates.extend(extract_pyc_numeric_candidates(data))
    except OSError:
        return []
    candidates.extend(find_flags_in_string_list(strings, "python:constant"))
    fake_static = {"strings": {"top": strings}}
    for item in decode_embedded_encodings(fake_static):
        item.source = f"python:{item.source}"
        candidates.append(item)
    return candidates


def script_artifact_candidates(path: Path) -> list[SolveCandidate]:
    if path.suffix.lower() not in SCRIPT_AND_SOURCE_SUFFIXES:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    strings = extract_quoted_strings(text)
    strings.extend(extract_strings(text.encode("utf-8", errors="replace")))
    candidates = find_flags_in_string_list(strings, f"script:{path.suffix.lower()}")
    candidates.extend(hint_value_candidates(strings, f"script:{path.suffix.lower()}:hint-value"))
    candidates.extend(literal_probe_candidates(strings, f"script:{path.suffix.lower()}:quoted-literal"))
    candidates.extend(comparison_literal_candidates_from_text(text, f"script:{path.suffix.lower()}:comparison-literal"))
    candidates.extend(charcode_candidates_from_text(text, f"script:{path.suffix.lower()}:charcode"))
    candidates.extend(char_literal_sequence_candidates_from_text(text, f"script:{path.suffix.lower()}:char-literal-sequence"))
    candidates.extend(concatenated_literal_candidates(text, f"script:{path.suffix.lower()}:concat-literal"))
    candidates.extend(char_constraint_candidates_from_text(text, f"script:{path.suffix.lower()}:char-constraints"))
    candidates.extend(numeric_sequence_candidates_from_text(text, f"script:{path.suffix.lower()}:numeric-sequence"))
    candidates.extend(source_context_decoded_input_candidates(text, f"script:{path.suffix.lower()}:context-decoded-input"))
    candidates.extend(brainfuck_candidates_from_text(text, f"script:{path.suffix.lower()}:brainfuck"))
    fake_static = {"strings": {"top": strings}}
    for item in decode_embedded_encodings(fake_static):
        item.source = f"script:{item.source}"
        candidates.append(item)
    return candidates


def zip_entry_candidates(path: Path, custom_inputs: list[str] | None = None) -> list[SolveCandidate]:
    if path.suffix.lower() not in {".zip", ".apk", ".jar"} and not looks_like_zip(path):
        return []
    candidates: list[SolveCandidate] = []
    passwords = build_archive_passwords(custom_inputs or [])
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.comment:
                candidates.extend(archive_blob_candidates("zip-comment.txt", archive.comment, "zip-comment"))
            for info in archive.infolist()[:300]:
                if info.comment:
                    candidates.extend(archive_blob_candidates(f"{info.filename}.comment", info.comment, f"zip-entry-comment:{info.filename}"))
                if info.is_dir() or info.file_size > 3_000_000:
                    continue
                blobs: list[tuple[bytes, str]] = []
                try:
                    blobs.append((archive.read(info.filename), "plain"))
                except RuntimeError:
                    for password in passwords:
                        try:
                            blobs.append((archive.read(info.filename, pwd=password.encode("utf-8")), f"password:{password}"))
                            break
                        except (RuntimeError, zipfile.BadZipFile):
                            continue
                except (KeyError, zipfile.BadZipFile):
                    continue
                for blob, mode in blobs:
                    source = f"zip-entry:{info.filename}:{mode}"
                    candidates.extend(archive_blob_candidates(info.filename, blob, source))
    except (OSError, zipfile.BadZipFile):
        return []
    return dedupe_candidates(candidates)


def tar_entry_candidates(path: Path) -> list[SolveCandidate]:
    if path.suffix.lower() not in {".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".gz", ".bz2", ".xz"}:
        try:
            if not tarfile.is_tarfile(path):
                return []
        except OSError:
            return []
    candidates: list[SolveCandidate] = []
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive.getmembers()[:300]:
                if not member.isfile() or member.size > 3_000_000:
                    continue
                extracted = archive.extractfile(member)
                if not extracted:
                    continue
                blob = extracted.read(3_000_001)
                candidates.extend(archive_blob_candidates(member.name, blob, f"tar-entry:{member.name}"))
    except (OSError, tarfile.TarError, EOFError):
        return []
    return dedupe_candidates(candidates)


def tar_blob_entry_candidates(blob: bytes, source_prefix: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as archive:
            for member in archive.getmembers()[:200]:
                if not member.isfile() or member.size > 2_000_000:
                    continue
                extracted = archive.extractfile(member)
                if not extracted:
                    continue
                nested = extracted.read(2_000_001)
                candidates.extend(archive_blob_candidates(member.name, nested, f"{source_prefix}:{member.name}"))
    except (OSError, tarfile.TarError, EOFError):
        return []
    return dedupe_candidates(candidates)


def archive_blob_candidates(name: str, blob: bytes, source: str) -> list[SolveCandidate]:
    text = blob.decode("utf-8", errors="replace")
    strings = extract_strings(blob)
    candidates: list[SolveCandidate] = []
    candidates.extend(find_flags_in_string_list(strings + [text], source))
    candidates.extend(hint_value_candidates(strings + [text], f"{source}:hint-value"))
    candidates.extend(literal_probe_candidates(strings, f"{source}:literal"))
    candidates.extend(numeric_sequence_candidates_from_bytes(blob, f"{source}:numeric-sequence"))
    for item in compressed_stream_candidates(blob):
        item.source = f"{source}:{item.source}"
        candidates.append(item)
    fake_static = {"strings": {"top": strings[:1000]}}
    for item in decode_embedded_encodings(fake_static):
        item.source = f"{source}:{item.source}"
        candidates.append(item)
    if looks_like_zip_blob(blob):
        candidates.extend(zip_blob_entry_candidates(blob, f"{source}:nested-zip"))
    if looks_like_tar_blob(blob):
        candidates.extend(tar_blob_entry_candidates(blob, f"{source}:nested-tar"))
    if entry_name_is_source(name):
        candidates.extend(comparison_literal_candidates_from_text(text, f"{source}:comparison-literal"))
        candidates.extend(charcode_candidates_from_text(text, f"{source}:charcode"))
        candidates.extend(char_literal_sequence_candidates_from_text(text, f"{source}:char-literal-sequence"))
        candidates.extend(concatenated_literal_candidates(text, f"{source}:concat-literal"))
        candidates.extend(char_constraint_candidates_from_text(text, f"{source}:char-constraints"))
        candidates.extend(numeric_sequence_candidates_from_text(text, f"{source}:numeric-sequence"))
        candidates.extend(source_context_decoded_input_candidates(text, f"{source}:context-decoded-input"))
        candidates.extend(brainfuck_candidates_from_text(text, f"{source}:brainfuck"))
    return dedupe_candidates(candidates)


def zip_blob_entry_candidates(blob: bytes, source_prefix: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            if archive.comment:
                candidates.extend(archive_blob_candidates("zip-comment.txt", archive.comment, f"{source_prefix}:zip-comment"))
            for info in archive.infolist()[:200]:
                if info.comment:
                    candidates.extend(archive_blob_candidates(f"{info.filename}.comment", info.comment, f"{source_prefix}:entry-comment:{info.filename}"))
                if info.is_dir() or info.file_size > 2_000_000:
                    continue
                try:
                    nested = archive.read(info.filename)
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
                candidates.extend(archive_blob_candidates(info.filename, nested, f"{source_prefix}:{info.filename}"))
    except (OSError, zipfile.BadZipFile):
        return []
    return dedupe_candidates(candidates)


def looks_like_zip(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] == b"PK\x03\x04" or zipfile.is_zipfile(path)
    except OSError:
        return False


def looks_like_zip_blob(blob: bytes) -> bool:
    return blob[:4] == b"PK\x03\x04" or (b"PK\x03\x04" in blob[:4096] and zipfile.is_zipfile(io.BytesIO(blob)))


def looks_like_tar_blob(blob: bytes) -> bool:
    if len(blob) < 512:
        return False
    if blob[257:262] in {b"ustar", b"ustar\x00"}:
        return True
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*"):
            return True
    except (OSError, tarfile.TarError):
        return False


def build_archive_passwords(custom_inputs: list[str]) -> list[str]:
    values = [
        "infected",
        "password",
        "1234",
        "0000",
        "dreamhack",
        "flag",
        "secret",
        "ctf",
        "rev",
        "reversing",
        "malware",
        "sample",
    ]
    values.extend(custom_inputs)
    return list(dict.fromkeys(value for value in values if 1 <= len(value) <= 64))


def entry_name_is_source(name: str) -> bool:
    suffix = Path(name).suffix.lower()
    return suffix in SCRIPT_AND_SOURCE_SUFFIXES or suffix in {".txt", ".json", ".xml", ".html"}


def literal_probe_candidates(strings: list[str], source: str) -> list[SolveCandidate]:
    candidates = []
    for value in strings:
        if likely_probe_input(value) and not extract_flags(value):
            candidates.append(SolveCandidate(value, source, 0.5, ["quoted literal suitable for dynamic probing"]))
    return dedupe_candidates(candidates)


def python_ast_constant_candidates(text: str) -> list[SolveCandidate]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    env: dict[str, Any] = {}
    candidates: list[SolveCandidate] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = eval_python_constant(node.value, env)
            for target in node.targets:
                if isinstance(target, ast.Name) and value is not None:
                    env[target.id] = value
            candidates.extend(candidates_from_constant(value, "python:ast-constant", 0.79))
        elif isinstance(node, ast.AnnAssign):
            value = eval_python_constant(node.value, env) if node.value else None
            if isinstance(node.target, ast.Name) and value is not None:
                env[node.target.id] = value
            candidates.extend(candidates_from_constant(value, "python:ast-constant", 0.79))
        elif isinstance(node, ast.Compare):
            values = [eval_python_constant(item, env) for item in [node.left, *node.comparators]]
            for value in values:
                candidates.extend(candidates_from_constant(value, "python:ast-comparison", 0.84))
        elif isinstance(node, ast.Call):
            candidates.extend(candidates_from_constant(eval_python_constant(node, env), "python:ast-call", 0.8))
    return dedupe_candidates(candidates)


def eval_python_constant(node: ast.AST | None, env: dict[str, Any], depth: int = 0) -> Any:
    if node is None or depth > 8:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = eval_python_constant(node.left, env, depth + 1)
        right = eval_python_constant(node.right, env, depth + 1)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, bytes) and isinstance(right, bytes):
            return left + right
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [eval_python_constant(item, env, depth + 1) for item in node.elts]
        if all(isinstance(item, int) and 0 <= item <= 255 for item in values):
            return bytes(values)
        if all(isinstance(item, str) for item in values):
            return "".join(values)
        return values
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            receiver = eval_python_constant(node.func.value, env, depth + 1)
            encoding = eval_python_constant(node.args[0], env, depth + 1) if node.args else "utf-8"
            if isinstance(receiver, bytes) and isinstance(encoding, str):
                try:
                    return receiver.decode(encoding)
                except (LookupError, UnicodeDecodeError):
                    return None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and node.args:
            separator = eval_python_constant(node.func.value, env, depth + 1)
            values = eval_python_constant(node.args[0], env, depth + 1)
            if separator == "" and isinstance(values, str):
                return values
        name = python_call_name(node.func)
        args = [eval_python_constant(arg, env, depth + 1) for arg in node.args]
        try:
            if name == "chr" and args and isinstance(args[0], int):
                return chr(args[0])
            if name in {"bytes", "bytearray"} and args:
                if isinstance(args[0], (list, tuple)) and all(isinstance(item, int) and 0 <= item <= 255 for item in args[0]):
                    return bytes(args[0])
                if isinstance(args[0], bytes):
                    return bytes(args[0])
            if name == "bytes.fromhex" and args and isinstance(args[0], str):
                return bytes.fromhex(args[0])
            if name in {"base64.b64decode", "b64decode"} and args and isinstance(args[0], (str, bytes)):
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return base64.b64decode(raw)
            if name in {"base64.urlsafe_b64decode", "urlsafe_b64decode"} and args and isinstance(args[0], (str, bytes)):
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return base64.urlsafe_b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4))
            if name in {"base64.b32decode", "b32decode"} and args and isinstance(args[0], (str, bytes)):
                raw = args[0].encode() if isinstance(args[0], str) else args[0]
                return base64.b32decode(raw + b"=" * ((8 - len(raw) % 8) % 8), casefold=True)
        except (ValueError, TypeError, base64.binascii.Error):
            return None
    return None


def python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = python_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def candidates_from_constant(value: Any, source: str, input_confidence: float) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    if isinstance(value, bytes):
        candidates.extend(candidate_text_from_decoded_bytes(value, source, "evaluated constant"))
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return candidates
    if isinstance(value, str):
        for flag in extract_flags(value):
            candidates.append(SolveCandidate(flag, source, 0.93, ["evaluated constant contains flag-shaped text"]))
        for decoded, method in decode_string_variants(value):
            for flag in extract_flags(decoded):
                candidates.append(SolveCandidate(flag, f"{source}:{method}", 0.9, [short(value), short(decoded)]))
        if likely_probe_input(value) and not extract_flags(value):
            candidates.append(SolveCandidate(value, source, input_confidence, ["evaluated constant suitable as candidate input"]))
    return candidates


def comparison_literal_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    patterns = [
        re.compile(r"(?:==|===|!=)\s*([\"'`])((?:\\.|(?!\1).){3,128})\1", re.DOTALL),
        re.compile(r"([\"'`])((?:\\.|(?!\1).){3,128})\1\s*(?:==|===|!=)", re.DOTALL),
        re.compile(r"(?:-eq|-ceq|-ieq|-ne)\s*([\"'`])((?:\\.|(?!\1).){3,128})\1", re.IGNORECASE | re.DOTALL),
        re.compile(r"\b(?:strcmp|strcasecmp|strncmp|memcmp)\s*\([^;\n]{0,240}?,\s*([\"'])((?:\\.|(?!\1).){3,128})\1", re.DOTALL),
        re.compile(r"\b(?:strcmp|strcasecmp|strncmp|memcmp)\s*\(\s*([\"'])((?:\\.|(?!\1).){3,128})\1\s*,", re.DOTALL),
        re.compile(r"\.(?:includes|contains|startsWith|endsWith)\s*\(\s*([\"'`])((?:\\.|(?!\1).){3,128})\1", re.DOTALL),
        re.compile(r"\.(?:equals|equalsIgnoreCase|contentEquals|compareTo|compareToIgnoreCase)\s*\(\s*([\"'`])((?:\\.|(?!\1).){3,128})\1", re.IGNORECASE | re.DOTALL),
        re.compile(r"([\"'`])((?:\\.|(?!\1).){3,128})\1\s*\.\s*(?:equals|equalsIgnoreCase|contentEquals|compareTo|compareToIgnoreCase)\s*\(", re.IGNORECASE | re.DOTALL),
        re.compile(r"([\"'`])((?:\\.|(?!\1).){3,128})\1\s+in\s+[A-Za-z_][A-Za-z0-9_]*", re.DOTALL),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            raw = match.group(2)
            try:
                value = bytes(raw, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                value = raw
            if likely_probe_input(value):
                candidates.append(
                    SolveCandidate(
                        value=value,
                        source=source,
                        confidence=0.83,
                        evidence=["literal appears in a comparison expression"],
                    )
                )
    return dedupe_candidates(candidates)


def charcode_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for match in FROM_CHAR_CODE_RE.finditer(text):
        values = parse_numeric_sequence(match.group(1))
        if values:
            candidates.extend(candidate_text_from_decoded_bytes(bytes(values), source, "fromCharCode integer sequence"))
    for line in text.splitlines():
        matches = CHR_JOIN_RE.findall(line)
        if len(matches) < 4:
            continue
        values = parse_numeric_sequence(",".join(matches))
        if values:
            candidates.extend(candidate_text_from_decoded_bytes(bytes(values), source, "chr integer sequence"))
    return dedupe_candidates(candidates)


def char_literal_sequence_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for line in text.splitlines():
        if len(line) > 2000 or "," not in line:
            continue
        raw_values = re.findall(r"'((?:\\.|[^'\\])*)'", line)
        if len(raw_values) < 4:
            continue
        values: list[int] = []
        for raw in raw_values:
            try:
                decoded = bytes(raw, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                decoded = raw
            if len(decoded) != 1:
                values = []
                break
            values.append(ord(decoded))
        if len(values) >= 4:
            candidates.extend(candidate_text_from_decoded_bytes(bytes(values), source, "character literal sequence"))
    return dedupe_candidates(candidates)


def concatenated_literal_candidates(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for line in text.splitlines():
        if len(line) > 1200:
            continue
        values = extract_quoted_strings(line)
        if len(values) < 2:
            continue
        if "+" not in line and not re.search(r"""(["'])\s+\1""", line):
            continue
        joined = "".join(values)
        candidates.extend(candidates_from_constant(joined, source, 0.76))
    return dedupe_candidates(candidates)


def source_context_decoded_input_candidates(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for line in text.splitlines():
        if len(line) > 2000 or not SOURCE_DECODE_CONTEXT_RE.search(line):
            continue
        for value in extract_quoted_strings(line):
            for decoded, method in recursive_decode_string_variants(value):
                if extract_flags(decoded):
                    continue
                if likely_probe_input(decoded):
                    candidates.append(
                        SolveCandidate(
                            value=decoded,
                            source=f"{source}:{method}",
                            confidence=0.84,
                            evidence=[short(line), short(decoded)],
                        )
                    )
    return dedupe_candidates(candidates)


def char_constraint_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    constraints: dict[str, dict[int, int]] = {}
    direct = re.compile(
        r"\(*\s*(?:ord\s*\(\s*)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<idx>\d{1,3})\s*\]\s*\)?\s*={2,3}\s*(?P<value>'(?:\\.|[^'])'|\"(?:\\.|[^\"])\"|0x[0-9A-Fa-f]{1,2}|\d{1,3})"
    )
    reverse = re.compile(
        r"(?P<value>'(?:\\.|[^'])'|\"(?:\\.|[^\"])\"|0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*={2,3}\s*\(*\s*(?:ord\s*\(\s*)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<idx>\d{1,3})\s*\]\s*\)?"
    )
    transformed = re.compile(
        r"\(*\s*(?:ord\s*\(\s*)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<idx>\d{1,3})\s*\]\s*\)?\s*(?P<op>[\^\+\-])\s*(?P<key>0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*\)*\s*={2,3}\s*(?P<value>0x[0-9A-Fa-f]{1,2}|\d{1,3})"
    )
    method_direct = re.compile(
        r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?:charAt|charCodeAt)\s*\(\s*(?P<idx>\d{1,3})\s*\)\s*==={0,1}\s*(?P<value>'(?:\\.|[^'])'|\"(?:\\.|[^\"])\"|0x[0-9A-Fa-f]{1,2}|\d{1,3})"
    )
    method_transformed = re.compile(
        r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?:charCodeAt)\s*\(\s*(?P<idx>\d{1,3})\s*\)\s*(?P<op>[\^\+\-])\s*(?P<key>0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*==={0,1}\s*(?P<value>0x[0-9A-Fa-f]{1,2}|\d{1,3})"
    )
    for pattern in (direct, reverse):
        for match in pattern.finditer(text):
            value = parse_char_constraint_value(match.group("value"))
            if value is None:
                continue
            constraints.setdefault(match.group("var"), {})[int(match.group("idx"))] = value
    for match in method_direct.finditer(text):
        value = parse_char_constraint_value(match.group("value"))
        if value is None:
            continue
        constraints.setdefault(match.group("var"), {})[int(match.group("idx"))] = value
    for match in transformed.finditer(text):
        value = parse_char_constraint_value(match.group("value"))
        key = parse_char_constraint_value(match.group("key"))
        if value is None or key is None:
            continue
        op = match.group("op")
        if op == "^":
            solved = value ^ key
        elif op == "+":
            solved = (value - key) & 0xFF
        else:
            solved = (value + key) & 0xFF
        constraints.setdefault(match.group("var"), {})[int(match.group("idx"))] = solved
    for match in method_transformed.finditer(text):
        value = parse_char_constraint_value(match.group("value"))
        key = parse_char_constraint_value(match.group("key"))
        if value is None or key is None:
            continue
        op = match.group("op")
        if op == "^":
            solved = value ^ key
        elif op == "+":
            solved = (value - key) & 0xFF
        else:
            solved = (value + key) & 0xFF
        constraints.setdefault(match.group("var"), {})[int(match.group("idx"))] = solved

    candidates: list[SolveCandidate] = []
    for variable, mapping in constraints.items():
        if len(mapping) < 4:
            continue
        max_index = max(mapping)
        if set(mapping) != set(range(max_index + 1)):
            continue
        raw = bytes(mapping[index] for index in range(max_index + 1))
        for item in candidate_text_from_decoded_bytes(raw, source, f"character constraints for {variable}"):
            if item.confidence < 0.82:
                item.confidence = 0.84
            candidates.append(item)
    return dedupe_candidates(candidates)


def parse_char_constraint_value(value: str) -> int | None:
    value = value.strip()
    if value.lower().startswith("0x"):
        number = int(value, 16)
    elif value.isdigit():
        number = int(value)
    elif len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        try:
            decoded = bytes(value[1:-1], "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return None
        if len(decoded) != 1:
            return None
        number = ord(decoded)
    else:
        return None
    return number if 0 <= number <= 255 else None


def numeric_sequence_candidates_from_bytes(data: bytes, source: str, limit: int = 2_000_000) -> list[SolveCandidate]:
    try:
        text = data[:limit].decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return []
    return numeric_sequence_candidates_from_text(text, source)


def numeric_sequence_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for match in NUMERIC_SEQUENCE_RE.finditer(text):
        values = parse_numeric_sequence(match.group(1))
        if len(values) < 4:
            continue
        raw = bytes(values)
        candidates.extend(candidate_text_from_decoded_bytes(raw, source, "numeric byte sequence"))
        for key in range(1, 256):
            transforms = [
                (f"xor-key=0x{key:02x}", bytes(byte ^ key for byte in raw)),
                (f"sub-{key}", bytes((byte - key) & 0xFF for byte in raw)),
                (f"add-{key}", bytes((byte + key) & 0xFF for byte in raw)),
            ]
            for transform_name, decoded in transforms:
                decoded_text = decoded.decode("latin1", errors="ignore")
                flags = extract_flags(decoded_text, strict=True)
                for flag in flags:
                    candidates.append(
                        SolveCandidate(
                            value=flag,
                            source=f"{source}:{transform_name}",
                            confidence=0.9,
                            evidence=[f"numeric byte sequence {transform_name} reveals flag-shaped text"],
                        )
                    )
                if not flags and is_mostly_printable(decoded):
                    candidate = decoded_text.strip("\x00\r\n\t ")
                    if likely_probe_input(candidate):
                        candidates.append(
                            SolveCandidate(
                                value=candidate,
                                source=f"{source}:{transform_name}",
                                confidence=0.74,
                                evidence=[f"numeric byte sequence {transform_name} yields printable probe input"],
                            )
                        )
    for match in SPACE_NUMERIC_SEQUENCE_RE.finditer(text):
        values = parse_numeric_sequence(match.group(1))
        if len(values) < 6:
            continue
        raw = bytes(values)
        candidates.extend(candidate_text_from_decoded_bytes(raw, source, "whitespace-separated numeric byte sequence"))
    return dedupe_candidates(candidates)


def brainfuck_candidates_from_text(text: str, source: str) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for match in BRAINFUCK_RUN_RE.finditer(text[:2_000_000]):
        program = "".join(ch for ch in match.group(0) if ch in "+-<>[].,")
        if len(program) < 20 or "." not in program:
            continue
        output = run_brainfuck(program)
        if not output:
            continue
        for flag in extract_flags(output):
            candidates.append(
                SolveCandidate(
                    value=flag,
                    source=source,
                    confidence=0.9,
                    evidence=[f"brainfuck output: {short(output)}"],
                )
            )
        if not extract_flags(output) and likely_probe_input(output.strip()):
            candidates.append(
                SolveCandidate(
                    value=output.strip(),
                    source=source,
                    confidence=0.76,
                    evidence=[f"brainfuck output: {short(output)}"],
                )
            )
    return dedupe_candidates(candidates)


def run_brainfuck(program: str, max_steps: int = 300_000, max_output: int = 4096) -> str:
    bracket_stack: list[int] = []
    jumps: dict[int, int] = {}
    for index, op in enumerate(program):
        if op == "[":
            bracket_stack.append(index)
        elif op == "]":
            if not bracket_stack:
                return ""
            start = bracket_stack.pop()
            jumps[start] = index
            jumps[index] = start
    if bracket_stack:
        return ""

    cells = [0] * 30_000
    pointer = 0
    pc = 0
    steps = 0
    out = bytearray()
    while pc < len(program) and steps < max_steps and len(out) < max_output:
        op = program[pc]
        if op == "+":
            cells[pointer] = (cells[pointer] + 1) & 0xFF
        elif op == "-":
            cells[pointer] = (cells[pointer] - 1) & 0xFF
        elif op == ">":
            pointer = (pointer + 1) % len(cells)
        elif op == "<":
            pointer = (pointer - 1) % len(cells)
        elif op == ".":
            out.append(cells[pointer])
        elif op == ",":
            cells[pointer] = 0
        elif op == "[" and cells[pointer] == 0:
            pc = jumps[pc]
        elif op == "]" and cells[pointer] != 0:
            pc = jumps[pc]
        pc += 1
        steps += 1
    if not out or not is_mostly_printable(bytes(out)):
        return ""
    return bytes(out).decode("latin1", errors="ignore")


def png_chunk_candidates(data: bytes) -> list[SolveCandidate]:
    if not data.startswith(PNG_SIGNATURE):
        return []
    candidates: list[SolveCandidate] = []
    offset = len(PNG_SIGNATURE)
    chunks_seen = 0
    while offset + 12 <= len(data) and chunks_seen < 512:
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        chunk_start = offset + 8
        chunk_end = chunk_start + length
        if length < 0 or chunk_end + 4 > len(data):
            break
        chunk = data[chunk_start:chunk_end]
        name = chunk_type.decode("ascii", errors="replace")
        source = f"png:{name}"
        if chunk_type != b"IDAT" and len(chunk) <= 2_000_000:
            candidates.extend(archive_blob_candidates(f"{name}.bin", chunk, source))
        if chunk_type == b"tEXt":
            text = png_latin1_text_chunk(chunk)
            candidates.extend(textual_metadata_candidates(text, f"{source}:text"))
        elif chunk_type == b"zTXt":
            text = png_ztxt_chunk(chunk)
            candidates.extend(textual_metadata_candidates(text, f"{source}:zlib-text"))
        elif chunk_type == b"iTXt":
            text = png_itxt_chunk(chunk)
            candidates.extend(textual_metadata_candidates(text, f"{source}:itxt"))
        offset = chunk_end + 4
        chunks_seen += 1
        if chunk_type == b"IEND":
            break
    return dedupe_candidates(candidates)


def textual_metadata_candidates(text: str, source: str) -> list[SolveCandidate]:
    if not text:
        return []
    strings = extract_strings(text.encode("utf-8", errors="replace"))
    candidates = find_flags_in_string_list(strings + [text], source)
    candidates.extend(hint_value_candidates(strings + [text], f"{source}:hint-value"))
    candidates.extend(decode_embedded_encodings({"strings": {"top": strings + [text]}}))
    for item in candidates:
        if item.source.startswith("decoded"):
            item.source = f"{source}:{item.source}"
    return dedupe_candidates(candidates)


def png_latin1_text_chunk(chunk: bytes) -> str:
    if b"\x00" in chunk:
        _keyword, text = chunk.split(b"\x00", 1)
    else:
        text = chunk
    return text.decode("latin1", errors="replace")


def png_ztxt_chunk(chunk: bytes) -> str:
    try:
        _keyword, rest = chunk.split(b"\x00", 1)
    except ValueError:
        return ""
    if not rest or rest[0] != 0:
        return ""
    try:
        return zlib.decompress(rest[1:]).decode("latin1", errors="replace")
    except zlib.error:
        return ""


def png_itxt_chunk(chunk: bytes) -> str:
    try:
        _keyword, rest = chunk.split(b"\x00", 1)
    except ValueError:
        return ""
    if len(rest) < 3:
        return ""
    compressed = rest[0] == 1
    compression_method = rest[1]
    rest = rest[2:]
    parts = rest.split(b"\x00", 2)
    if len(parts) != 3:
        return ""
    text = parts[2]
    if compressed:
        if compression_method != 0:
            return ""
        try:
            text = zlib.decompress(text)
        except zlib.error:
            return ""
    return text.decode("utf-8", errors="replace")


def parse_numeric_sequence(value: str) -> list[int]:
    numbers: list[int] = []
    for token in re.findall(r"0x[0-9A-Fa-f]{1,2}|\d{1,3}", value):
        number = int(token, 16) if token.lower().startswith("0x") else int(token, 10)
        if not 0 <= number <= 255:
            return []
        numbers.append(number)
    return numbers


def candidate_text_from_decoded_bytes(data: bytes, source: str, evidence: str) -> list[SolveCandidate]:
    if not is_mostly_printable(data):
        return []
    text = data.decode("latin1", errors="ignore").strip("\x00\r\n\t ")
    if not text:
        return []
    flags = extract_flags(text)
    if flags:
        return [SolveCandidate(flag, source, 0.92, [evidence, short(text)]) for flag in flags]
    if likely_probe_input(text):
        return [SolveCandidate(text, source, 0.72, [evidence])]
    return []


def compressed_stream_candidates(data: bytes, limit: int = 4_000_000) -> list[SolveCandidate]:
    sample = data[:limit]
    offsets = set()
    offsets.update(match.start() for match in re.finditer(rb"\x1f\x8b\x08", sample))
    offsets.update(match.start() for match in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", sample))
    offsets.update(match.start() for match in re.finditer(rb"BZh[1-9]", sample))
    offsets.update(match.start() for match in re.finditer(rb"\xfd7zXZ\x00", sample))
    candidates: list[SolveCandidate] = []
    for offset in sorted(offsets)[:64]:
        chunk = sample[offset:]
        decoded_blobs: list[tuple[bytes, str]] = []
        if chunk.startswith(b"\x1f\x8b\x08"):
            try:
                obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
                decoded = obj.decompress(chunk, 1_000_000)
                if decoded:
                    decoded_blobs.append((decoded, "gzip"))
            except zlib.error:
                pass
        try:
            obj = zlib.decompressobj()
            decoded = obj.decompress(chunk, 1_000_000)
            if decoded:
                decoded_blobs.append((decoded, "zlib"))
        except zlib.error:
            pass
        if chunk.startswith(b"BZh"):
            try:
                decoded = bz2.decompress(chunk)
                if decoded:
                    decoded_blobs.append((decoded, "bzip2"))
            except (OSError, ValueError):
                pass
        if chunk.startswith(b"\xfd7zXZ\x00"):
            try:
                decoded = lzma.decompress(chunk)
                if decoded:
                    decoded_blobs.append((decoded, "xz"))
            except (lzma.LZMAError, ValueError):
                pass
        for decoded, method in decoded_blobs:
            if looks_like_tar_blob(decoded):
                for item in tar_blob_entry_candidates(decoded, f"compressed:{method}:tar"):
                    item.evidence.insert(0, f"decompressed tar stream at offset 0x{offset:x}")
                    candidates.append(item)
            text = decoded.decode("latin1", errors="ignore")
            for flag in extract_flags(text):
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"compressed:{method}",
                        confidence=0.91,
                        evidence=[f"decompressed stream at offset 0x{offset:x}"],
                    )
                )
            fake_static = {"strings": {"top": extract_strings(decoded)[:200]}}
            for item in decode_embedded_encodings(fake_static):
                item.source = f"compressed:{method}:{item.source}"
                item.evidence.insert(0, f"decompressed stream at offset 0x{offset:x}")
                candidates.append(item)
    return dedupe_candidates(candidates)


def hash_crack_candidates(static: dict[str, Any], custom_inputs: list[str] | None = None) -> list[SolveCandidate]:
    strings = list(static.get("strings", {}).get("top", [])) + list(static.get("zip", {}).get("embedded_strings", []))
    targets: dict[str, str] = {}
    for value in strings:
        for match in HASH_HEX_RE.finditer(value):
            digest = match.group(1).lower()
            algorithm = HASH_LENGTHS.get(len(digest))
            if algorithm:
                targets[digest] = algorithm
    if not targets:
        return []

    candidates: list[SolveCandidate] = []
    words = build_hash_wordlist(strings, custom_inputs or [])
    encoded_words = [(word, word.encode("utf-8", errors="ignore")) for word in words if word]
    salt_candidates = build_salt_candidates(strings)
    for digest, algorithm in list(targets.items())[:16]:
        cracked = False
        for word, raw in encoded_words:
            if hashlib.new(algorithm, raw).hexdigest() != digest:
                continue
            candidates.append(
                SolveCandidate(
                    value=word,
                    source=f"hash-crack:{algorithm}",
                    confidence=0.87,
                    evidence=[f"{algorithm} digest {digest} matches candidate"],
                )
            )
            cracked = True
            break
        if cracked:
            continue
        for salt in salt_candidates:
            salt_raw = salt.encode("utf-8", errors="ignore")
            for word, raw in encoded_words:
                if hashlib.new(algorithm, salt_raw + raw).hexdigest() == digest:
                    candidates.append(
                        SolveCandidate(
                            value=word,
                            source=f"hash-crack:{algorithm}:salt-prefix",
                            confidence=0.84,
                            evidence=[f"{algorithm} digest {digest} matches {short(salt)} + candidate"],
                        )
                    )
                    cracked = True
                    break
                if hashlib.new(algorithm, raw + salt_raw).hexdigest() == digest:
                    candidates.append(
                        SolveCandidate(
                            value=word,
                            source=f"hash-crack:{algorithm}:salt-suffix",
                            confidence=0.84,
                            evidence=[f"{algorithm} digest {digest} matches candidate + {short(salt)}"],
                        )
                    )
                    cracked = True
                    break
            if cracked:
                break
    return dedupe_candidates(candidates)


def build_salt_candidates(strings: list[str]) -> list[str]:
    salts: list[str] = []
    for value in strings[:500]:
        if HASH_HEX_RE.fullmatch(value):
            continue
        if 1 <= len(value) <= 24 and likely_probe_input(value):
            salts.append(value)
        for token in re.split(r"[^A-Za-z0-9_{}-]+", value):
            if 1 <= len(token) <= 24 and likely_probe_input(token) and not HASH_HEX_RE.fullmatch(token):
                salts.append(token)
    priority = [item for item in salts if any(token in item.lower() for token in ("salt", "key", "secret", "prefix", "suffix"))]
    return list(dict.fromkeys(priority + salts))[:40]


def build_hash_wordlist(strings: list[str], custom_inputs: list[str]) -> list[str]:
    words = [
        "admin",
        "password",
        "pass",
        "secret",
        "key",
        "flag",
        "dreamhack",
        "DreamHack",
        "ctf",
        "guest",
        "root",
        "toor",
        "letmein",
        "open_sesame",
        "correct",
        "success",
        "crackme",
        "rev",
        "reverse",
        "pwn",
        "hello",
        "world",
        "1234",
        "0000",
        "1111",
        "0420",
        "1337",
        "2024",
        "2025",
        "2026",
    ]
    words.extend(custom_inputs)
    for value in strings[:500]:
        if likely_probe_input(value) and not HASH_HEX_RE.fullmatch(value):
            words.append(value)
            for token in re.split(r"[^A-Za-z0-9_{}-]+", value):
                if likely_probe_input(token):
                    words.append(token)
    words.extend(f"{number:04d}" for number in range(10_000))
    words.extend(str(number) for number in range(1000))
    return list(dict.fromkeys(words))


def derive_crypto_keys(strings: list[str]) -> list[bytes]:
    keys: list[str] = []
    priority: list[str] = []
    for value in strings[:1200]:
        lowered = value.lower()
        tokens = [token for token in re.split(r"[^A-Za-z0-9_{}-]+", value) if token]
        for token in tokens:
            if not likely_crypto_key(token):
                continue
            if any(marker in lowered for marker in ("key", "xor", "rc4", "secret", "password", "passphrase")):
                priority.append(token)
            else:
                keys.append(token)
        if likely_crypto_key(value):
            if any(marker in lowered for marker in ("key", "xor", "rc4", "secret", "password", "passphrase")):
                priority.append(value)
            else:
                keys.append(value)
    merged = list(dict.fromkeys(priority[:32] + keys[:16]))[:40]
    return [value.encode("utf-8", errors="ignore") for value in merged if value]


def likely_crypto_key(value: str) -> bool:
    if not 2 <= len(value) <= 32:
        return False
    if extract_flags(value) or HASH_HEX_RE.fullmatch(value):
        return False
    if value.lower() in {"key", "xor", "rc4", "secret", "password", "pass", "flag", "correct", "wrong", "success", "fail"}:
        return False
    if not any(ch.isalpha() for ch in value):
        return False
    allowed = sum(ch.isalnum() or ch in "_-{}" for ch in value)
    return allowed == len(value)


def extract_quoted_strings(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""(["'`])((?:\\.|(?!\1).){4,512})\1""", text, re.DOTALL):
        raw = match.group(2)
        try:
            decoded = bytes(raw, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            decoded = raw
        if len(decoded) >= 4:
            values.append(decoded)
    return list(dict.fromkeys(values))


def extract_pyc_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    for offset in (16, 12, 8):
        if len(data) <= offset:
            continue
        try:
            obj = marshal.loads(data[offset:])
        except (EOFError, ValueError, TypeError):
            continue
        strings.extend(collect_code_strings(obj))
        if strings:
            break
    return sorted(set(strings), key=lambda item: (-len(item), item.lower()))


def extract_pyc_numeric_candidates(data: bytes) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for offset in (16, 12, 8):
        if len(data) <= offset:
            continue
        try:
            obj = marshal.loads(data[offset:])
        except (EOFError, ValueError, TypeError):
            continue
        for values in collect_code_int_sequences(obj):
            raw = bytes(values)
            candidates.extend(candidate_text_from_decoded_bytes(raw, "python:pyc-numeric-sequence", "integer constants"))
            for key in range(1, 256):
                decoded = bytes(byte ^ key for byte in raw)
                for flag in extract_flags(decoded.decode("latin1", errors="ignore"), strict=True):
                    candidates.append(
                        SolveCandidate(
                            value=flag,
                            source=f"python:pyc-numeric-sequence:xor-key=0x{key:02x}",
                            confidence=0.9,
                            evidence=[f"integer constants XOR 0x{key:02x} reveal flag-shaped text"],
                        )
                    )
        break
    return dedupe_candidates(candidates)


def collect_code_int_sequences(obj: Any) -> list[list[int]]:
    sequences: list[list[int]] = []
    if isinstance(obj, types.CodeType):
        for const in obj.co_consts:
            sequences.extend(collect_code_int_sequences(const))
    elif isinstance(obj, (tuple, list)):
        values: list[int] = []
        for item in obj:
            if isinstance(item, int) and 0 <= item <= 255:
                values.append(item)
            else:
                sequences.extend(collect_code_int_sequences(item))
        if len(values) >= 4 and len(values) >= len(obj) - 1:
            sequences.append(values)
    elif isinstance(obj, (set, frozenset)):
        for item in obj:
            sequences.extend(collect_code_int_sequences(item))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            sequences.extend(collect_code_int_sequences(key))
            sequences.extend(collect_code_int_sequences(value))
    return sequences


def collect_code_strings(obj: Any) -> list[str]:
    values: list[str] = []
    if isinstance(obj, str):
        if len(obj) >= 4:
            values.append(obj)
    elif isinstance(obj, bytes):
        values.extend(extract_strings(obj))
    elif isinstance(obj, types.CodeType):
        for const in obj.co_consts:
            values.extend(collect_code_strings(const))
        values.extend(name for name in obj.co_names if len(name) >= 4)
    elif isinstance(obj, (tuple, list, set, frozenset)):
        for item in obj:
            values.extend(collect_code_strings(item))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            values.extend(collect_code_strings(key))
            values.extend(collect_code_strings(value))
    return values


def xor_search(data: bytes, limit: int = 2_000_000) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    sample = data[:limit]
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in sample)
        if b"{" not in decoded or b"}" not in decoded:
            continue
        text = decoded.decode("latin1", errors="ignore")
        for flag in extract_flags(text, strict=True):
            candidates.append(
                SolveCandidate(
                    value=flag,
                    source=f"xor:key=0x{key:02x}",
                    confidence=0.88,
                    evidence=[f"single-byte XOR key 0x{key:02x} reveals flag-shaped text"],
                )
            )
    return candidates


def byte_shift_search(data: bytes, limit: int = 2_000_000) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    sample = data[:limit]
    for delta in range(1, 256):
        for name, decoded in (
            (f"sub-{delta}", bytes((byte - delta) & 0xFF for byte in sample)),
            (f"add-{delta}", bytes((byte + delta) & 0xFF for byte in sample)),
        ):
            if b"{" not in decoded or b"}" not in decoded:
                continue
            text = decoded.decode("latin1", errors="ignore")
            for flag in extract_flags(text, strict=True):
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"byte-shift:{name}",
                        confidence=0.87,
                        evidence=[f"whole-file byte shift {name} reveals flag-shaped text"],
                    )
                )
    return dedupe_candidates(candidates)


def bit_rotate_search(data: bytes, limit: int = 2_000_000) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    sample = data[:limit]
    for bits in range(1, 8):
        for name, decoded in (
            (f"ror-{bits}", bytes(rotate_right(byte, bits) for byte in sample)),
            (f"rol-{bits}", bytes(rotate_left(byte, bits) for byte in sample)),
        ):
            if b"{" not in decoded or b"}" not in decoded:
                continue
            text = decoded.decode("latin1", errors="ignore")
            for flag in extract_flags(text, strict=True):
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"byte-rotate:{name}",
                        confidence=0.87,
                        evidence=[f"whole-file byte rotate {name} reveals flag-shaped text"],
                    )
                )
    return dedupe_candidates(candidates)


def rotate_left(value: int, bits: int) -> int:
    bits %= 8
    return ((value << bits) | (value >> (8 - bits))) & 0xFF


def rotate_right(value: int, bits: int) -> int:
    bits %= 8
    return ((value >> bits) | (value << (8 - bits))) & 0xFF


def repeating_xor_search(data: bytes, limit: int = 2_000_000, extra_keys: list[bytes] | None = None) -> list[SolveCandidate]:
    base_keys = [
        b"key",
        b"flag",
        b"xor",
        b"ctf",
        b"rev",
        b"dreamhack",
        b"password",
        b"secret",
    ]
    derived_keys = list(dict.fromkeys(key for key in (extra_keys or []) if 2 <= len(key) <= 64))
    keys = list(dict.fromkeys(key for key in base_keys + derived_keys if 2 <= len(key) <= 64))
    candidates: list[SolveCandidate] = []
    sample = data[:limit]
    offsets = candidate_crypto_offsets(sample)
    for key in keys:
        decoded = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(sample))
        if b"{" not in decoded or b"}" not in decoded:
            continue
        text = decoded.decode("latin1", errors="ignore")
        for flag in extract_flags(text, strict=True):
            candidates.append(
                SolveCandidate(
                    value=flag,
                    source=f"xor:repeating-key={key.decode('ascii', errors='replace')}",
                    confidence=0.89,
                    evidence=[f"repeating XOR key {key.decode('ascii', errors='replace')} reveals flag-shaped text"],
                )
            )
    for key in derived_keys:
        for offset in offsets:
            if offset == 0:
                continue
            window = sample[offset : offset + 4096]
            decoded = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(window))
            if b"{" not in decoded or b"}" not in decoded:
                continue
            text = decoded.decode("latin1", errors="ignore")
            for flag in extract_flags(text, strict=True):
                key_text = key.decode("ascii", errors="replace")
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"xor:repeating-key={key_text}:offset=0x{offset:x}",
                        confidence=0.9,
                        evidence=[f"repeating XOR key {key_text} reveals flag-shaped text at offset 0x{offset:x}"],
                    )
                )
    return dedupe_candidates(candidates)


def rc4_common_key_search(data: bytes, limit: int = 1_000_000, extra_keys: list[bytes] | None = None) -> list[SolveCandidate]:
    base_keys = [
        b"key",
        b"flag",
        b"ctf",
        b"rev",
        b"dreamhack",
        b"password",
        b"secret",
        b"open_sesame",
    ]
    derived_keys = list(dict.fromkeys(key for key in (extra_keys or []) if 2 <= len(key) <= 64))
    keys = list(dict.fromkeys(key for key in base_keys + derived_keys if 2 <= len(key) <= 64))
    candidates: list[SolveCandidate] = []
    sample = data[:limit]
    offsets = candidate_crypto_offsets(sample)
    for key in keys:
        decoded = rc4_crypt(key, sample)
        if b"{" not in decoded or b"}" not in decoded:
            continue
        text = decoded.decode("latin1", errors="ignore")
        for flag in extract_flags(text, strict=True):
            key_text = key.decode("ascii", errors="replace")
            candidates.append(
                SolveCandidate(
                    value=flag,
                    source=f"rc4:key={key_text}",
                    confidence=0.88,
                    evidence=[f"RC4 with key {key_text} reveals flag-shaped text"],
                )
            )
    for key in derived_keys:
        for offset in offsets:
            if offset == 0:
                continue
            decoded = rc4_crypt(key, sample[offset : offset + 4096])
            if b"{" not in decoded or b"}" not in decoded:
                continue
            text = decoded.decode("latin1", errors="ignore")
            for flag in extract_flags(text, strict=True):
                key_text = key.decode("ascii", errors="replace")
                candidates.append(
                    SolveCandidate(
                        value=flag,
                        source=f"rc4:key={key_text}:offset=0x{offset:x}",
                        confidence=0.89,
                        evidence=[f"RC4 with key {key_text} reveals flag-shaped text at offset 0x{offset:x}"],
                    )
                )
    return dedupe_candidates(candidates)


def candidate_crypto_offsets(sample: bytes, max_offsets: int = 32) -> list[int]:
    offsets = {0}
    for match in re.finditer(rb"[\x00\r\n]", sample[:1_000_000]):
        if match.end() < len(sample):
            offsets.add(match.end())
            if len(offsets) >= max_offsets:
                break
    return sorted(offsets)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(byte ^ k)
    return bytes(out)


def immediate_string_candidates(tools: dict[str, ToolResult]) -> list[SolveCandidate]:
    result = tools.get("objdump_disasm")
    if not result or not result.stdout:
        return []
    candidates: list[SolveCandidate] = []
    function_chunks: list[tuple[str, list[int]]] = []
    indexed_chunks: list[tuple[str, dict[int, int]]] = []
    current_name = ""
    current_values: list[int] = []
    current_indexed: dict[int, int] = {}
    current_register_indexes: dict[str, int] = {}
    for line in result.stdout.splitlines():
        header = re.match(r"^([0-9a-fA-F]+) <([^>]+)>:$", line.strip())
        if header:
            if current_name and current_values:
                function_chunks.append((current_name, current_values))
            if current_name and current_indexed:
                indexed_chunks.append((current_name, current_indexed))
            current_name = header.group(2)
            current_values = []
            current_indexed = {}
            current_register_indexes = {}
            continue
        instruction = objdump_instruction_text(line)
        if not instruction:
            continue
        for register, index in instruction_indexed_loads(instruction):
            for alias in register_aliases(register):
                current_register_indexes[alias] = index
        for register, value in instruction_register_immediate_cmps(instruction):
            index = current_register_indexes.get(register.lower())
            if index is not None:
                current_indexed[index] = value
        for value in instruction_immediates(instruction):
            current_values.append(value if 32 <= value <= 126 else 0)
        for index, value in instruction_indexed_char_constraints(instruction):
            current_indexed[index] = value
    if current_name and current_values:
        function_chunks.append((current_name, current_values))
    if current_name and current_indexed:
        indexed_chunks.append((current_name, current_indexed))

    for name, values in function_chunks:
        for text in printable_runs(values):
            if len(text) < 4:
                continue
            if extract_flags(text):
                confidence = 0.86
            elif likely_probe_input(text):
                confidence = 0.68
            else:
                continue
            candidates.append(
                SolveCandidate(
                    value=text,
                    source="static:objdump-immediates",
                    confidence=confidence,
                    evidence=[f"function {name} contains printable immediate run"],
                )
            )
    for name, mapping in indexed_chunks:
        if len(mapping) < 4:
            continue
        max_index = max(mapping)
        if set(mapping) != set(range(max_index + 1)):
            continue
        text = bytes(mapping[index] for index in range(max_index + 1)).decode("latin1", errors="ignore")
        if extract_flags(text, strict=True):
            confidence = 0.88
        elif likely_probe_input(text):
            confidence = 0.78
        else:
            continue
        candidates.append(
            SolveCandidate(
                value=text,
                source="static:objdump-indexed-char-constraints",
                confidence=confidence,
                evidence=[f"function {name} compares fixed input offsets against character immediates"],
            )
        )
    return candidates


def objdump_instruction_text(line: str) -> str:
    if "\t" in line:
        parts = [part for part in line.split("\t") if part.strip()]
        if parts:
            return parts[-1].strip()
    match = re.match(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+(.+)$", line)
    return match.group(1).strip() if match else ""


def instruction_immediates(instruction: str) -> list[int]:
    values: list[int] = []
    lowered = instruction.lower()
    if not any(op in lowered for op in ("cmp", "mov", "xor", "add", "sub")):
        return values
    for match in re.finditer(r"\b0x([0-9a-f]{4,32})(?![0-9a-f])", lowered):
        token = match.group(1)
        if len(token) % 2:
            continue
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        little = raw[::-1]
        if len(little) >= 2 and is_mostly_printable(little) and any(65 <= byte <= 122 or 48 <= byte <= 57 for byte in little):
            values.extend(little)
    for match in re.finditer(r"(?:byte ptr [^,]+,\s*|,\s*)0x([0-9a-f]{2})(?![0-9a-f])", lowered):
        values.append(int(match.group(1), 16))
    return values


def instruction_indexed_char_constraints(instruction: str) -> list[tuple[int, int]]:
    lowered = instruction.lower().replace(" ", "")
    results: list[tuple[int, int]] = []
    if not lowered.startswith("cmp"):
        return results
    for match in re.finditer(r"byteptr\[[^\]]*(?:\+0x([0-9a-f]+)|\+([0-9]{1,3}))\],0x([0-9a-f]{2})(?![0-9a-f])", lowered):
        index = int(match.group(1), 16) if match.group(1) else int(match.group(2), 10)
        results.append((index, int(match.group(3), 16)))
    for match in re.finditer(r"byteptr\[[a-z0-9]+\],0x([0-9a-f]{2})(?![0-9a-f])", lowered):
        results.append((0, int(match.group(1), 16)))
    return results


def instruction_indexed_loads(instruction: str) -> list[tuple[str, int]]:
    lowered = instruction.lower()
    results: list[tuple[str, int]] = []
    pattern = re.compile(
        r"\b(?:movzx|movsx|mov)\s+(?P<reg>[a-z][a-z0-9]*),\s*byte ptr \[(?P<addr>[^\]]+)\]"
    )
    for match in pattern.finditer(lowered):
        address = match.group("addr")
        index = 0
        indexed = re.search(r"\+(?:0x(?P<hex>[0-9a-f]+)|(?P<dec>\d{1,3}))(?:\]|$)", address)
        if indexed:
            index = int(indexed.group("hex"), 16) if indexed.group("hex") else int(indexed.group("dec"), 10)
        elif "+" in address or "-" in address:
            continue
        results.append((match.group("reg"), index))
    return results


def instruction_register_immediate_cmps(instruction: str) -> list[tuple[str, int]]:
    lowered = instruction.lower()
    results: list[tuple[str, int]] = []
    for match in re.finditer(r"\bcmp\s+(?P<reg>[a-z][a-z0-9]*),\s*(?:0x(?P<hex>[0-9a-f]{1,2})|(?P<dec>\d{1,3}))\b", lowered):
        value = int(match.group("hex"), 16) if match.group("hex") else int(match.group("dec"), 10)
        if 0 <= value <= 255:
            results.append((match.group("reg"), value))
    for match in re.finditer(r"\bcmp\s+(?:0x(?P<hex>[0-9a-f]{1,2})|(?P<dec>\d{1,3})),\s*(?P<reg>[a-z][a-z0-9]*)\b", lowered):
        value = int(match.group("hex"), 16) if match.group("hex") else int(match.group("dec"), 10)
        if 0 <= value <= 255:
            results.append((match.group("reg"), value))
    return results


def register_aliases(register: str) -> set[str]:
    register = register.lower()
    groups = [
        {"rax", "eax", "ax", "al", "ah"},
        {"rbx", "ebx", "bx", "bl", "bh"},
        {"rcx", "ecx", "cx", "cl", "ch"},
        {"rdx", "edx", "dx", "dl", "dh"},
        {"rsi", "esi", "si", "sil"},
        {"rdi", "edi", "di", "dil"},
        {"rbp", "ebp", "bp", "bpl"},
        {"rsp", "esp", "sp", "spl"},
        {"r8", "r8d", "r8w", "r8b"},
        {"r9", "r9d", "r9w", "r9b"},
        {"r10", "r10d", "r10w", "r10b"},
        {"r11", "r11d", "r11w", "r11b"},
        {"r12", "r12d", "r12w", "r12b"},
        {"r13", "r13d", "r13w", "r13b"},
        {"r14", "r14d", "r14w", "r14b"},
        {"r15", "r15d", "r15w", "r15b"},
    ]
    for group in groups:
        if register in group:
            return group
    return {register}


def printable_runs(values: list[int]) -> list[str]:
    runs: list[str] = []
    current: list[int] = []
    for value in values:
        if 32 <= value <= 126:
            current.append(value)
        else:
            if len(current) >= 4:
                runs.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
    if len(current) >= 4:
        runs.append(bytes(current).decode("ascii", errors="ignore"))
    return list(dict.fromkeys(runs))


def run_dynamic_probes(
    path: Path,
    static: dict[str, Any],
    candidates: list[SolveCandidate],
    timeout: float,
    extra_strings: list[str] | None = None,
    custom_inputs: list[str] | None = None,
    bruteforce_pin: bool = False,
    max_probes: int = 80,
) -> dict[str, Any]:
    if os.name == "nt":
        return {"enabled": False, "reason": "dynamic probes are only implemented for POSIX subprocesses"}
    if not execution_command(path):
        return {"enabled": False, "reason": "sample is not executable and no supported interpreter is available"}

    inputs = list(dict.fromkeys(list(custom_inputs or []) + build_probe_inputs(static, candidates, extra_strings or [])))
    runs = []
    probe_limit = max(1, max_probes)
    for value in inputs[:probe_limit]:
        runs.append(run_one(path, value, timeout))
        if runs[-1].get("success_score", 0) >= 2:
            return dynamic_probe_result(runs, [], [], [], {}, runs[-1], path, timeout)
    argv_runs = []
    for value in inputs[:probe_limit]:
        argv_runs.append(run_one_argv(path, value, timeout))
        if argv_runs[-1].get("success_score", 0) >= 2:
            return dynamic_probe_result(runs, argv_runs, [], [], {}, argv_runs[-1], path, timeout)
    env_runs = []
    for value in inputs[: min(40, probe_limit)]:
        env_runs.append(run_one_env(path, value, timeout))
        if env_runs[-1].get("success_score", 0) >= 2:
            return dynamic_probe_result(runs, argv_runs, env_runs, [], {}, env_runs[-1], path, timeout)
    file_runs = []
    for value in inputs[: min(40, probe_limit)]:
        file_runs.append(run_one_file_input(path, value, timeout))
        if file_runs[-1].get("success_score", 0) >= 2:
            return dynamic_probe_result(runs, argv_runs, env_runs, file_runs, {}, file_runs[-1], path, timeout)
    raw_runs = []
    for value in inputs[: min(40, probe_limit)]:
        raw_runs.append(run_one(path, value, timeout, send_newline=False))
        raw_runs[-1]["mode"] = "stdin-raw"
        if raw_runs[-1].get("success_score", 0) >= 2:
            break
    multi_runs = []
    if not any(run.get("success_score", 0) >= 2 for run in raw_runs):
        for value in inputs[: min(24, probe_limit)]:
            for mode, payload in multi_stdin_payloads(value):
                run = run_one_payload(path, payload, timeout, mode=mode, candidate=value)
                multi_runs.append(run)
                if run.get("success_score", 0) >= 2:
                    break
            if multi_runs and multi_runs[-1].get("success_score", 0) >= 2:
                break
    already_solved = any(run.get("success_score", 0) >= 2 for run in raw_runs + multi_runs)
    hook_trace = (
        {"enabled": False, "reason": "skipped after successful dynamic probe"}
        if already_solved
        else run_ld_preload_trace(path, inputs[:24], timeout)
    )
    input_hints = extract_input_hints(hook_trace)
    env_hint_runs = []
    for value in inputs[: min(40, probe_limit)]:
        if not input_hints.get("env_names"):
            break
        env_hint_runs.append(run_one_env(path, value, timeout, names=input_hints["env_names"]))
        if env_hint_runs[-1].get("success_score", 0) >= 2:
            break
    file_hint_runs = []
    for value in inputs[: min(40, probe_limit)]:
        if not input_hints.get("file_names"):
            break
        file_hint_runs.append(run_one_file_input(path, value, timeout, names=input_hints["file_names"]))
        if file_hint_runs[-1].get("success_score", 0) >= 2:
            break
    pin_runs = []
    if bruteforce_pin:
        pin_runs = run_numeric_pin_bruteforce(path, timeout, max_attempts=probe_limit)
    no_input = run_one(path, "", timeout, send_newline=False)
    all_runs = runs + argv_runs + env_runs + file_runs + raw_runs + multi_runs + env_hint_runs + file_hint_runs + pin_runs
    return {
        "enabled": True,
        "no_input": no_input,
        "runs": runs,
        "argv_runs": argv_runs,
        "env_runs": env_runs,
        "file_runs": file_runs,
        "raw_runs": raw_runs,
        "multi_runs": multi_runs,
        "env_hint_runs": env_hint_runs,
        "file_hint_runs": file_hint_runs,
        "pin_bruteforce_runs": pin_runs,
        "hook_trace": hook_trace,
        "input_hints": input_hints,
        "best": max(all_runs, key=lambda item: item.get("success_score", 0), default={}),
    }


def dynamic_probe_result(
    runs: list[dict[str, Any]],
    argv_runs: list[dict[str, Any]],
    env_runs: list[dict[str, Any]],
    file_runs: list[dict[str, Any]],
    hook_trace: dict[str, Any],
    best: dict[str, Any],
    path: Path,
    timeout: float,
) -> dict[str, Any]:
    return {
        "enabled": True,
        "no_input": run_one(path, "", timeout, send_newline=False),
        "runs": runs,
        "argv_runs": argv_runs,
        "env_runs": env_runs,
        "file_runs": file_runs,
        "raw_runs": [],
        "multi_runs": [],
        "env_hint_runs": [],
        "file_hint_runs": [],
        "pin_bruteforce_runs": [],
        "hook_trace": hook_trace,
        "input_hints": {"env_names": [], "file_names": []},
        "best": best,
        "short_circuited": True,
    }


def execution_command(path: Path, resolve: bool = False) -> list[str] | None:
    target = str(path.resolve() if resolve else path)
    suffix = path.suffix.lower()
    interpreter_map = {
        ".py": ["python3"],
        ".pyw": ["python3"],
        ".js": ["node"],
        ".mjs": ["node"],
        ".sh": ["bash"],
        ".rb": ["ruby"],
        ".php": ["php"],
        ".pl": ["perl"],
        ".lua": ["lua"],
    }
    command = interpreter_map.get(suffix)
    if command:
        if not shutil.which(command[0]):
            return None
        return command + [target]
    if suffix in SCRIPT_AND_SOURCE_SUFFIXES:
        return None
    if os.access(path, os.X_OK) and is_native_or_shebang_executable(path):
        return [target]
    return None


def is_native_or_shebang_executable(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4]
    except OSError:
        return False
    return head.startswith(b"\x7fELF") or head.startswith(b"#!")


def run_one(path: Path, value: str, timeout: float, send_newline: bool = True) -> dict[str, Any]:
    started = time.monotonic()
    payload = (value + ("\n" if send_newline else "")).encode("utf-8", errors="replace")
    command = execution_command(path)
    if not command:
        return {"input": value, "error": "sample is not executable and no supported interpreter is available", "success_score": 0}
    try:
        completed = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
        text = out + "\n" + err
        return {
            "input": value,
            "exit_code": completed.returncode,
            "stdout": out[:4000],
            "stderr": err[:2000],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": score_runtime_output(text),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "input": value,
            "timeout": True,
            "stdout": (exc.stdout or b"").decode("utf-8", errors="replace")[:4000] if isinstance(exc.stdout, bytes) else "",
            "stderr": (exc.stderr or b"").decode("utf-8", errors="replace")[:2000] if isinstance(exc.stderr, bytes) else "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": 0,
        }


def run_one_payload(path: Path, payload: str, timeout: float, mode: str, candidate: str | None = None) -> dict[str, Any]:
    started = time.monotonic()
    command = execution_command(path)
    if not command:
        return {"mode": mode, "candidate": candidate, "error": "sample is not executable and no supported interpreter is available", "success_score": 0}
    try:
        completed = subprocess.run(
            command,
            input=payload.encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
        return {
            "mode": mode,
            "candidate": candidate,
            "payload_preview": short(payload),
            "exit_code": completed.returncode,
            "stdout": out[:4000],
            "stderr": err[:2000],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": score_runtime_output(out + "\n" + err),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "mode": mode,
            "candidate": candidate,
            "payload_preview": short(payload),
            "timeout": True,
            "stdout": (exc.stdout or b"").decode("utf-8", errors="replace")[:4000] if isinstance(exc.stdout, bytes) else "",
            "stderr": (exc.stderr or b"").decode("utf-8", errors="replace")[:2000] if isinstance(exc.stderr, bytes) else "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": 0,
        }


def multi_stdin_payloads(value: str) -> list[tuple[str, str]]:
    return [
        ("stdin-repeat", f"{value}\n{value}\n"),
        ("stdin-admin-candidate", f"admin\n{value}\n"),
        ("stdin-user-candidate", f"user\n{value}\n"),
        ("stdin-guest-candidate", f"guest\n{value}\n"),
        ("stdin-candidate-admin", f"{value}\nadmin\n"),
    ]


def run_one_argv(path: Path, value: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    command = execution_command(path)
    if not command:
        return {"mode": "argv", "input": value, "error": "sample is not executable and no supported interpreter is available", "success_score": 0}
    try:
        completed = subprocess.run(
            command + [value],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
        text = out + "\n" + err
        return {
            "mode": "argv",
            "input": value,
            "exit_code": completed.returncode,
            "stdout": out[:4000],
            "stderr": err[:2000],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": score_runtime_output(text),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "mode": "argv",
            "input": value,
            "timeout": True,
            "stdout": (exc.stdout or b"").decode("utf-8", errors="replace")[:4000] if isinstance(exc.stdout, bytes) else "",
            "stderr": (exc.stderr or b"").decode("utf-8", errors="replace")[:2000] if isinstance(exc.stderr, bytes) else "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": 0,
        }


def run_one_env(path: Path, value: str, timeout: float, names: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    env = dict(os.environ)
    env_names = names or DEFAULT_ENV_NAMES
    for name in env_names:
        env[name] = value
    command = execution_command(path, resolve=True)
    if not command:
        return {"mode": "env", "env_names": list(env_names), "input": value, "error": "sample is not executable and no supported interpreter is available", "success_score": 0}
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        out = completed.stdout.decode("utf-8", errors="replace")
        err = completed.stderr.decode("utf-8", errors="replace")
        text = out + "\n" + err
        return {
            "mode": "env",
            "env_names": list(env_names),
            "input": value,
            "exit_code": completed.returncode,
            "stdout": out[:4000],
            "stderr": err[:2000],
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": score_runtime_output(text),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "mode": "env",
            "env_names": list(env_names),
            "input": value,
            "timeout": True,
            "stdout": (exc.stdout or b"").decode("utf-8", errors="replace")[:4000] if isinstance(exc.stdout, bytes) else "",
            "stderr": (exc.stderr or b"").decode("utf-8", errors="replace")[:2000] if isinstance(exc.stderr, bytes) else "",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "success_score": 0,
        }


def run_one_file_input(path: Path, value: str, timeout: float, names: list[str] | tuple[str, ...] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="revbot-input-") as tmp:
        cwd = Path(tmp)
        input_names = safe_input_file_names(names or DEFAULT_INPUT_FILES)
        for name in input_names:
            target = cwd / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value + "\n", encoding="utf-8")
        command = execution_command(path, resolve=True)
        if not command:
            return {"mode": "file", "file_names": input_names, "input": value, "error": "sample is not executable and no supported interpreter is available", "success_score": 0}
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                check=False,
            )
            out = completed.stdout.decode("utf-8", errors="replace")
            err = completed.stderr.decode("utf-8", errors="replace")
            text = out + "\n" + err
            return {
                "mode": "file",
                "file_names": input_names,
                "input": value,
                "exit_code": completed.returncode,
                "stdout": out[:4000],
                "stderr": err[:2000],
                "duration_ms": int((time.monotonic() - started) * 1000),
                "success_score": score_runtime_output(text),
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "mode": "file",
                "file_names": input_names,
                "input": value,
                "timeout": True,
                "stdout": (exc.stdout or b"").decode("utf-8", errors="replace")[:4000] if isinstance(exc.stdout, bytes) else "",
                "stderr": (exc.stderr or b"").decode("utf-8", errors="replace")[:2000] if isinstance(exc.stderr, bytes) else "",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "success_score": 0,
            }


def safe_input_file_names(names: list[str] | tuple[str, ...]) -> list[str]:
    safe: list[str] = []
    for name in names:
        normalized = str(name).replace("\\", "/").strip()
        if not normalized or normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            continue
        if len(normalized) > 120 or any(ch in normalized for ch in "\x00\r\n\t"):
            continue
        if any(part in {"", ".", ".."} for part in normalized.split("/")):
            continue
        safe.append(normalized)
    return list(dict.fromkeys(safe)) or list(DEFAULT_INPUT_FILES)


def run_numeric_pin_bruteforce(path: Path, timeout: float, max_attempts: int) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    values = [f"{number:04d}" for number in range(10_000)]
    values.extend(str(number) for number in range(1000))
    values = list(dict.fromkeys(values))[: max(1, max_attempts)]
    for value in values:
        run = run_one(path, value, timeout)
        run["mode"] = "pin-stdin"
        run["candidate"] = value
        runs.append(run)
        if run.get("success_score", 0) >= 2:
            return runs
    for value in values:
        run = run_one_argv(path, value, timeout)
        run["mode"] = "pin-argv"
        run["candidate"] = value
        runs.append(run)
        if run.get("success_score", 0) >= 2:
            return runs
    return runs


def run_ld_preload_trace(path: Path, inputs: list[str], timeout: float) -> dict[str, Any]:
    if not os.access(path, os.X_OK):
        return {"enabled": False, "reason": "LD_PRELOAD trace requires a native executable path"}
    if not shutil.which("gcc"):
        return {"enabled": False, "reason": "gcc is not available"}
    with tempfile.TemporaryDirectory(prefix="revbot-hook-") as tmp:
        tmp_path = Path(tmp)
        src = tmp_path / "revbot_cmp_hook.c"
        so = tmp_path / "revbot_cmp_hook.so"
        src.write_text(LD_PRELOAD_HOOK_SOURCE, encoding="utf-8")
        compiled = subprocess.run(
            ["gcc", "-shared", "-fPIC", str(src), "-o", str(so), "-ldl"],
            capture_output=True,
            text=True,
            timeout=max(5, timeout),
            check=False,
        )
        if compiled.returncode != 0:
            return {"enabled": False, "reason": "hook compile failed", "stderr": compiled.stderr[:2000]}
        env = dict(os.environ)
        env["LD_PRELOAD"] = str(so)
        traces = []
        for value in inputs:
            for mode in ("stdin", "argv"):
                command = [str(path)] if mode == "stdin" else [str(path), value]
                payload = (value + "\n").encode("utf-8", errors="replace") if mode == "stdin" else None
                try:
                    completed = subprocess.run(
                        command,
                        input=payload,
                        capture_output=True,
                        timeout=timeout,
                        env=env,
                        check=False,
                    )
                    stderr = completed.stderr.decode("utf-8", errors="replace")
                    stdout = completed.stdout.decode("utf-8", errors="replace")
                    parsed = parse_hook_lines(stderr)
                    traces.append(
                        {
                            "mode": mode,
                            "input": value,
                            "exit_code": completed.returncode,
                            "stdout": stdout[:1000],
                            "stderr": stderr[:4000],
                            "comparisons": parsed,
                            "success_score": score_runtime_output(stdout + "\n" + stderr),
                        }
                    )
                    if parsed:
                        return {"enabled": True, "traces": traces, "best": traces[-1]}
                except subprocess.TimeoutExpired:
                    traces.append({"mode": mode, "input": value, "timeout": True})
                except OSError as exc:
                    traces.append({"mode": mode, "input": value, "error": str(exc)})
        return {"enabled": True, "traces": traces, "best": next((item for item in traces if item.get("comparisons")), {})}


def parse_hook_lines(text: str) -> list[dict[str, str]]:
    results = []
    for line in text.splitlines():
        if not line.startswith("REVHOOK|"):
            if line.startswith("REVHOOK_MEM|"):
                parsed_mem = parse_mem_hook_line(line)
                if parsed_mem:
                    results.append(parsed_mem)
            elif line.startswith("REVHOOK_IO|"):
                parsed_io = parse_io_hook_line(line)
                if parsed_io:
                    results.append(parsed_io)
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        name = parts[1]
        arg0 = unescape_hook(parts[2])
        arg1 = unescape_hook(parts[3])
        results.append({"function": name, "arg0": arg0, "arg1": arg1})
    return results


def parse_io_hook_line(line: str) -> dict[str, str] | None:
    parts = line.split("|", 3)
    if len(parts) != 4:
        return None
    _tag, name, arg0, arg1 = parts
    return {"function": name, "arg0": unescape_hook(arg0), "arg1": unescape_hook(arg1), "kind": "io"}


def parse_mem_hook_line(line: str) -> dict[str, str] | None:
    parts = line.split("|", 4)
    if len(parts) != 5:
        return None
    _tag, name, length, hex0, hex1 = parts
    try:
        b0 = bytes.fromhex(hex0)
        b1 = bytes.fromhex(hex1)
    except ValueError:
        return None
    return {
        "function": name,
        "length": length,
        "arg0": bytes_to_candidate_text(b0),
        "arg1": bytes_to_candidate_text(b1),
        "arg0_hex": hex0,
        "arg1_hex": hex1,
    }


def bytes_to_candidate_text(data: bytes) -> str:
    stripped = data.split(b"\x00", 1)[0]
    if stripped and is_mostly_printable(stripped):
        return stripped.decode("latin1", errors="ignore")
    return data.hex()


def extract_input_hints(hook_trace: dict[str, Any]) -> dict[str, list[str]]:
    env_names: list[str] = []
    file_names: list[str] = []
    for trace in hook_trace.get("traces", []):
        for item in trace.get("comparisons", []):
            function = item.get("function", "").lower()
            arg0 = item.get("arg0", "")
            if function == "getenv" and valid_env_name(arg0):
                env_names.append(arg0)
            elif function in {"fopen", "fopen64", "open", "open64", "access"} and valid_relative_input_name(arg0):
                file_names.append(arg0)
    return {
        "env_names": list(dict.fromkeys(env_names))[:20],
        "file_names": list(dict.fromkeys(file_names))[:20],
    }


def valid_env_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", value))


def valid_relative_input_name(value: str) -> bool:
    if not value or value.startswith("/") or value.startswith("../") or "/../" in value:
        return False
    if len(value) > 120 or any(ch in value for ch in "\x00\r\n\t"):
        return False
    lowered = value.lower()
    if lowered.startswith(("/proc/", "/sys/", "/dev/")):
        return False
    return bool(re.search(r"[A-Za-z0-9]", value))


def unescape_hook(value: str) -> str:
    return value.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t").replace("\\x7c", "|").replace("\\\\", "\\")


def build_probe_inputs(static: dict[str, Any], candidates: list[SolveCandidate], extra_strings: list[str] | None = None) -> list[str]:
    values = [
        "test",
        "password",
        "flag",
        "admin",
        "1234",
        "AAAA",
        "dreamhack",
    ]
    values.extend(candidate.value for candidate in candidates)
    for value in static.get("strings", {}).get("top", [])[:500]:
        if 3 <= len(value) <= 96 and not any(ch in value for ch in "\r\n\t"):
            if any(token in value.lower() for token in ["pass", "flag", "key", "serial", "secret", "token", "answer", "login", "admin", "user", "correct", "wrong", "dh{"]):
                values.append(value)
                values.extend(string_probe_variants(value))
    for value in list(static.get("strings", {}).get("top", []))[:250] + list(extra_strings or [])[:5000]:
        if likely_probe_input(value):
            values.append(value)
        values.extend(string_probe_variants(value))
    return list(dict.fromkeys(values))


def string_probe_variants(value: str) -> list[str]:
    if not 3 <= len(value) <= 96:
        return []
    stripped = value.strip()
    lowered = stripped.lower()
    variants = []
    tokens = [token for token in re.split(r"[^A-Za-z0-9{}]+", stripped) if token]
    if len(tokens) >= 2:
        variants.append("_".join(tokens))
        variants.append("-".join(tokens))
        variants.append("".join(tokens))
    for prefix in ("password", "pass", "key", "serial", "token", "answer", "code"):
        if lowered.startswith(prefix):
            tail = stripped[len(prefix) :].strip(" :=-_")
            if tail:
                variants.append(tail)
    return [item for item in dict.fromkeys(variants) if likely_probe_input(item)]


def dynamic_candidates(dynamic: dict[str, Any]) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    no_input = dynamic.get("no_input", {})
    no_input_text = (no_input.get("stdout") or "") + "\n" + (no_input.get("stderr") or "")
    for flag in extract_flags(no_input_text):
        candidates.append(SolveCandidate(flag, "dynamic:no-input-output", 0.96, [short(no_input_text)]))
    best = dynamic.get("best", {})
    if best.get("success_score", 0) >= 2 and best.get("input"):
        candidates.append(
            SolveCandidate(
                value=best["input"],
                source="dynamic:stdin-probe",
                confidence=0.86,
                evidence=[best.get("stdout", ""), best.get("stderr", "")],
            )
        )
    for run in dynamic.get("runs", []):
        text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
        for flag in extract_flags(text):
            candidates.append(SolveCandidate(flag, "dynamic:output", 0.95, [short(text)]))
    for run in dynamic.get("raw_runs", []):
        text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
        if run.get("success_score", 0) >= 2 and run.get("input"):
            candidates.append(SolveCandidate(run["input"], "dynamic:stdin-raw-probe", 0.88, [short(text)]))
        for flag in extract_flags(text):
            candidates.append(SolveCandidate(flag, "dynamic:stdin-raw-output", 0.95, [short(text)]))
    for run in dynamic.get("multi_runs", []):
        text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
        if run.get("success_score", 0) >= 2 and run.get("candidate"):
            candidates.append(SolveCandidate(run["candidate"], f"dynamic:{run.get('mode', 'stdin-multi')}", 0.88, [short(text)]))
        for flag in extract_flags(text):
            candidates.append(SolveCandidate(flag, "dynamic:stdin-multi-output", 0.95, [short(text)]))
    for run in dynamic.get("argv_runs", []):
        text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
        if run.get("success_score", 0) >= 2 and run.get("input"):
            candidates.append(SolveCandidate(run["input"], "dynamic:argv-probe", 0.86, [short(text)]))
        for flag in extract_flags(text):
            candidates.append(SolveCandidate(flag, "dynamic:argv-output", 0.95, [short(text)]))
    for key, source in (
        ("env_runs", "env"),
        ("file_runs", "file"),
        ("env_hint_runs", "env-hint"),
        ("file_hint_runs", "file-hint"),
    ):
        for run in dynamic.get(key, []):
            text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
            if run.get("success_score", 0) >= 2 and run.get("input"):
                confidence = 0.9 if source.endswith("hint") else 0.86
                candidates.append(SolveCandidate(run["input"], f"dynamic:{source}-probe", confidence, [short(text)]))
            for flag in extract_flags(text):
                candidates.append(SolveCandidate(flag, f"dynamic:{source}-output", 0.95, [short(text)]))
    for run in dynamic.get("pin_bruteforce_runs", []):
        text = (run.get("stdout") or "") + "\n" + (run.get("stderr") or "")
        if run.get("success_score", 0) >= 2 and run.get("candidate"):
            candidates.append(
                SolveCandidate(
                    run["candidate"],
                    f"dynamic:{run.get('mode', 'pin-bruteforce')}",
                    0.9,
                    [short(text)],
                )
            )
        for flag in extract_flags(text):
            candidates.append(SolveCandidate(flag, "dynamic:pin-output", 0.95, [short(text)]))
    hook_trace = dynamic.get("hook_trace", {})
    for trace in hook_trace.get("traces", []):
        probe = trace.get("input", "")
        for comparison in trace.get("comparisons", []):
            function = comparison.get("function", "")
            if function.lower() not in COMPARISON_NAMES | STRING_SEARCH_NAMES:
                continue
            candidates.extend(transform_inference_candidates(probe, comparison))
            for arg_name in ("arg0", "arg1"):
                value = comparison.get(arg_name, "")
                other = comparison.get("arg1" if arg_name == "arg0" else "arg0", "")
                if value and value != probe and likely_probe_input(value):
                    confidence = 0.89 if other == probe else 0.8
                    candidates.append(
                        SolveCandidate(
                            value=value,
                            source=f"dynamic:ld-preload:{function}",
                            confidence=confidence,
                            evidence=[f"{function}({short(other)}, {short(value)})"],
                        )
                    )
    return candidates


def validate_candidates(path: Path, candidates: list[SolveCandidate], timeout: float) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        for mode in ("stdin", "stdin-raw", "argv", "env", "file", "stdin-repeat", "stdin-admin-candidate", "stdin-user-candidate"):
            if mode == "stdin":
                run = run_one(path, candidate.value, timeout)
            elif mode == "stdin-raw":
                run = run_one(path, candidate.value, timeout, send_newline=False)
            elif mode == "argv":
                run = run_one_argv(path, candidate.value, timeout)
            elif mode == "env":
                run = run_one_env(path, candidate.value, timeout)
            elif mode == "stdin-repeat":
                run = run_one_payload(path, f"{candidate.value}\n{candidate.value}\n", timeout, mode=mode, candidate=candidate.value)
            elif mode == "stdin-admin-candidate":
                run = run_one_payload(path, f"admin\n{candidate.value}\n", timeout, mode=mode, candidate=candidate.value)
            elif mode == "stdin-user-candidate":
                run = run_one_payload(path, f"user\n{candidate.value}\n", timeout, mode=mode, candidate=candidate.value)
            else:
                run = run_one_file_input(path, candidate.value, timeout)
            run["mode"] = mode
            run["candidate"] = candidate.value
            results.append(run)
            if run.get("success_score", 0) >= 2:
                return results
    return results


def validation_candidates(validations: list[dict[str, Any]]) -> list[SolveCandidate]:
    candidates: list[SolveCandidate] = []
    for item in validations:
        if item.get("success_score", 0) >= 2 and item.get("candidate"):
            candidates.append(
                SolveCandidate(
                    value=item["candidate"],
                    source=f"dynamic:validated-{item.get('mode')}",
                    confidence=0.97,
                    evidence=[short((item.get("stdout") or "") + "\n" + (item.get("stderr") or ""))],
                )
            )
    return candidates


def transform_inference_candidates(probe: str, comparison: dict[str, str]) -> list[SolveCandidate]:
    results: list[SolveCandidate] = []
    arg0 = comparison.get("arg0", "")
    arg1 = comparison.get("arg1", "")
    for transformed, target in ((arg0, arg1), (arg1, arg0)):
        if not probe or not transformed or not target or len(probe) != len(transformed):
            continue
        for method, value in infer_inverse_transform(probe, transformed, target):
            if likely_probe_input(value):
                results.append(
                    SolveCandidate(
                        value=value,
                        source=f"dynamic:transform:{method}:{comparison.get('function')}",
                        confidence=0.91,
                        evidence=[
                            f"probe {short(probe)} became {short(transformed)} before {comparison.get('function')}",
                            f"inverted target {short(target)} -> {short(value)}",
                        ],
                    )
                )
    return results


def infer_inverse_transform(probe: str, transformed: str, target: str) -> list[tuple[str, str]]:
    if not probe or len(probe) != len(transformed):
        return []
    probe_bytes = probe.encode("latin1", errors="ignore")
    transformed_bytes = transformed.encode("latin1", errors="ignore")
    target_bytes = target.encode("latin1", errors="ignore")
    if len(probe_bytes) != len(transformed_bytes) or not target_bytes:
        return []
    results: list[tuple[str, str]] = []

    xor_keys = {a ^ b for a, b in zip(probe_bytes, transformed_bytes)}
    if len(xor_keys) == 1:
        key = next(iter(xor_keys))
        if key:
            decoded = bytes(byte ^ key for byte in target_bytes)
            if is_mostly_printable(decoded):
                results.append((f"xor_0x{key:02x}", decoded.decode("latin1", errors="ignore")))

    add_deltas = {((b - a) & 0xFF) for a, b in zip(probe_bytes, transformed_bytes)}
    if len(add_deltas) == 1:
        delta = next(iter(add_deltas))
        if delta:
            decoded = bytes((byte - delta) & 0xFF for byte in target_bytes)
            if is_mostly_printable(decoded):
                results.append((f"add_{delta}", decoded.decode("latin1", errors="ignore")))

    sub_deltas = {((a - b) & 0xFF) for a, b in zip(probe_bytes, transformed_bytes)}
    if len(sub_deltas) == 1:
        delta = next(iter(sub_deltas))
        if delta:
            decoded = bytes((byte + delta) & 0xFF for byte in target_bytes)
            if is_mostly_printable(decoded):
                results.append((f"sub_{delta}", decoded.decode("latin1", errors="ignore")))

    return list(dict.fromkeys(results))


def build_strategy(
    path: Path,
    static: dict[str, Any],
    tools: dict[str, ToolResult],
    candidates: list[SolveCandidate],
    dynamic: dict[str, Any],
) -> dict[str, Any]:
    imports = collect_imports(static)
    compare_imports = sorted(imports & COMPARISON_NAMES)
    ctf_strings = static.get("strings", {}).get("categories", {}).get("ctf", [])
    commands = [
        f"strings -a -n 4 {shlex.quote(str(path))}",
        f"readelf -Ws {shlex.quote(str(path))}",
        f"objdump -d -M intel {shlex.quote(str(path))}",
    ]
    if compare_imports:
        commands.append(f"gdb -q {shlex.quote(str(path))} -x reports/{path.name}.gdb")
        commands.append(f"ltrace -s 256 {shlex.quote(str(path))}")

    priorities = []
    if candidates:
        priorities.append("Validate the top candidate by running the binary with it as stdin/argv.")
    if ctf_strings:
        priorities.append("Open xrefs to CTF success/failure strings and walk backward to the verifier.")
    if compare_imports:
        priorities.append(f"Break on comparison imports: {', '.join(compare_imports)}.")
    input_hints = dynamic.get("input_hints", {}) if dynamic else {}
    if input_hints.get("env_names"):
        priorities.append(f"Retry candidate values through environment variables: {', '.join(input_hints['env_names'][:8])}.")
    if input_hints.get("file_names"):
        priorities.append(f"Retry candidate values through local input files: {', '.join(input_hints['file_names'][:8])}.")
    if static.get("signals", {}).get("likely_packed"):
        priorities.append("Unpack or dump the real image before trusting static function flow.")

    return {
        "compare_imports": compare_imports,
        "ctf_strings": ctf_strings[:50],
        "input_hints": input_hints,
        "recommended_commands": commands,
        "next_priorities": priorities or ["No direct solve signal found. Export Ghidra/IDA function context and rerun solve."],
        "tool_notes": {
            name: {"available": result.available, "exit_code": result.exit_code, "error": result.error}
            for name, result in tools.items()
        },
    }


def write_solve_reports(result: dict[str, Any], output_dir: Path | str) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = safe_stem(result["file"].get("name", "sample"))
    json_path = out / f"{stem}.solve.json"
    md_path = out / f"{stem}.solve.md"
    gdb_path = out / f"{stem}.gdb"
    angr_path = out / f"{stem}.angr.py"
    frida_path = out / f"{stem}.solve.frida.js"
    candidates_path = out / f"{stem}.candidates.txt"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_solve_markdown(result), encoding="utf-8")
    gdb_path.write_text(render_gdb_script(result), encoding="utf-8")
    angr_path.write_text(render_angr_script(result), encoding="utf-8")
    frida_path.write_text(render_solve_frida_script(result), encoding="utf-8")
    candidates_path.write_text(render_candidates_wordlist(result), encoding="utf-8")
    return {"json": json_path, "markdown": md_path, "gdb": gdb_path, "angr": angr_path, "frida": frida_path, "candidates": candidates_path}


def render_solve_markdown(result: dict[str, Any]) -> str:
    lines = [f"# Solve Report: {result['file'].get('name')}", ""]
    lines.append(f"- Solved: `{result.get('solved')}`")
    lines.append(f"- SHA256: `{result['file'].get('sha256')}`")
    if result.get("candidates"):
        top = result["candidates"][0]
        lines.append(f"- Top candidate: `{top['value']}`")
        lines.append(f"- Top source: `{top['source']}`")
        lines.append(f"- Top confidence: `{top['confidence']}`")
    memory = result.get("memory", {})
    if memory.get("stored"):
        lines.append(f"- Memory: stored in `{memory.get('path')}`")
    lines.append("")
    lines.append("## Candidates")
    if result.get("candidates"):
        for item in result["candidates"][:30]:
            lines.append(f"- `{item['value']}` confidence={item['confidence']} source={item['source']}")
            if item.get("evidence"):
                lines.append(f"  - Evidence: {', '.join(short(str(e)) for e in item['evidence'][:4])}")
    else:
        lines.append("- No direct candidate found.")
    lines.append("")
    lines.append("## Ranked Functions")
    if result.get("ranked_functions"):
        for item in result["ranked_functions"][:30]:
            lines.append(f"- `{item['name']}` score={item['score']} reasons={', '.join(item['reasons'])}")
    else:
        lines.append("- No function priority data was extracted.")
    lines.append("")
    lines.append("## Strategy")
    for item in result.get("strategy", {}).get("next_priorities", []):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Commands")
    for command in result.get("strategy", {}).get("recommended_commands", []):
        lines.append(f"- `{command}`")
    lines.append(f"- `python3 reports/{safe_stem(result['file'].get('name', 'sample'))}.angr.py {shlex.quote(result['file'].get('path', './sample'))}`")
    if result.get("candidates"):
        top_value = result["candidates"][0]["value"]
        sample_path = result["file"].get("path", "./sample")
        lines.append(f"- `printf '%s\\n' {shlex.quote(top_value)} | {shlex.quote(sample_path)}`")
        lines.append(f"- `{shlex.quote(sample_path)} {shlex.quote(top_value)}`")
        lines.append(f"- `KEY={shlex.quote(top_value)} {shlex.quote(sample_path)}`")
        lines.append(f"- `python3 -m revbot.cli solve {shlex.quote(sample_path)} --execute --wordlist reports/{safe_stem(result['file'].get('name', 'sample'))}.candidates.txt`")
    lines.append("")
    dynamic = result.get("dynamic", {})
    if dynamic:
        lines.append("## Dynamic Probes")
        lines.append(f"- Enabled: `{dynamic.get('enabled')}`")
        if dynamic.get("short_circuited"):
            lines.append("- Probe short-circuit: `true`")
        mode_counts = {
            "stdin": len(dynamic.get("runs", [])),
            "stdin_raw": len(dynamic.get("raw_runs", [])),
            "argv": len(dynamic.get("argv_runs", [])),
            "env": len(dynamic.get("env_runs", [])),
            "file": len(dynamic.get("file_runs", [])),
            "env_hint": len(dynamic.get("env_hint_runs", [])),
            "file_hint": len(dynamic.get("file_hint_runs", [])),
            "multi": len(dynamic.get("multi_runs", [])),
            "pin": len(dynamic.get("pin_bruteforce_runs", [])),
        }
        lines.append("- Probe counts: " + ", ".join(f"{name}={count}" for name, count in mode_counts.items()))
        input_hints = dynamic.get("input_hints", {})
        if input_hints.get("env_names") or input_hints.get("file_names"):
            if input_hints.get("env_names"):
                lines.append(f"- Environment names observed: `{', '.join(input_hints['env_names'][:12])}`")
            if input_hints.get("file_names"):
                lines.append(f"- Input files observed: `{', '.join(input_hints['file_names'][:12])}`")
        hook_trace = dynamic.get("hook_trace", {})
        if hook_trace.get("enabled"):
            best_trace = hook_trace.get("best", {})
            comparisons = best_trace.get("comparisons", [])
            if comparisons:
                lines.append("- LD_PRELOAD comparison trace:")
                for comparison in comparisons[:20]:
                    lines.append(
                        f"  - `{comparison.get('function')}({short(comparison.get('arg0', ''))}, {short(comparison.get('arg1', ''))})`"
                    )
        best = dynamic.get("best")
        if best:
            lines.append(f"- Best input: `{best.get('input')}` score={best.get('success_score')}")
            if best.get("stdout"):
                lines.append("")
                lines.append("```text")
                lines.append(best["stdout"][:1000])
                lines.append("```")
        validations = dynamic.get("candidate_validation", [])
        if validations:
            lines.append("")
            lines.append("Candidate validation:")
            for item in validations[:20]:
                lines.append(
                    f"- `{item.get('candidate')}` via {item.get('mode')} score={item.get('success_score')} exit={item.get('exit_code')}"
                )
        lines.append("")
    ai = result.get("ai", {})
    if ai:
        lines.append("## AI Synthesis")
        lines.append(f"- Enabled: `{ai.get('enabled')}`")
        if ai.get("ok"):
            lines.append(f"- Model: `{ai.get('model')}`")
            lines.append("")
            lines.append(str(ai.get("content", "")).strip())
        else:
            lines.append(f"- Error: `{short(str(ai.get('reason') or ai.get('error') or 'unknown'))}`")
        lines.append("")
    return "\n".join(lines)


def render_gdb_script(result: dict[str, Any]) -> str:
    imports = result.get("strategy", {}).get("compare_imports", [])
    lines = ["set pagination off", "set disassembly-flavor intel"]
    for name in imports:
        lines.append(f"break {name}")
    lines.extend(["run", "info registers", "bt", "quit"])
    return "\n".join(lines) + "\n"


def render_angr_script(result: dict[str, Any]) -> str:
    success_terms = ["correct", "success", "congrat", "flag", "well done"]
    fail_terms = ["wrong", "fail", "incorrect", "invalid", "try again"]
    for value in result.get("strategy", {}).get("ctf_strings", []):
        lowered = value.lower()
        if any(term in lowered for term in success_terms):
            success_terms.insert(0, value)
        if any(term in lowered for term in fail_terms):
            fail_terms.insert(0, value)
    success_payload = json.dumps(list(dict.fromkeys(success_terms))[:12])
    fail_payload = json.dumps(list(dict.fromkeys(fail_terms))[:12])
    return f'''#!/usr/bin/env python3
"""Auto-generated angr starter for Reverse Researcher solve output.

Usage:
  python3 {safe_stem(result["file"].get("name", "sample"))}.angr.py ./challenge
"""

import sys

import angr
import claripy


SUCCESS_TERMS = [item.encode() for item in {success_payload}]
FAIL_TERMS = [item.encode() for item in {fail_payload}]


def main(path: str) -> int:
    project = angr.Project(path, auto_load_libs=False)
    length = 64
    symbolic = claripy.BVS("stdin", length * 8)
    state = project.factory.full_init_state(args=[path], stdin=symbolic)
    for byte in symbolic.chop(8):
        state.solver.add(byte >= 0x20)
        state.solver.add(byte <= 0x7e)
    simgr = project.factory.simgr(state)

    def is_success(state):
        out = state.posix.dumps(1) + state.posix.dumps(2)
        return any(term.lower() in out.lower() for term in SUCCESS_TERMS)

    def should_avoid(state):
        out = state.posix.dumps(1) + state.posix.dumps(2)
        return any(term.lower() in out.lower() for term in FAIL_TERMS)

    simgr.explore(find=is_success, avoid=should_avoid, num_find=1)
    if not simgr.found:
        print("no solution found")
        return 1
    found = simgr.found[0]
    solution = found.solver.eval(symbolic, cast_to=bytes).split(b"\\x00", 1)[0]
    print(solution.decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else {json.dumps(result["file"].get("path", "./sample"))}))
'''


def render_solve_frida_script(result: dict[str, Any]) -> str:
    candidates = [item.get("value", "") for item in result.get("candidates", [])[:20]]
    candidate_payload = json.dumps([value for value in candidates if value], ensure_ascii=False)
    return f'''// Auto-generated by revbot solve.
// Usage examples:
//   frida -f ./challenge -l {safe_stem(result["file"].get("name", "sample"))}.solve.frida.js --no-pause
//   frida -U -f com.example.app -l {safe_stem(result["file"].get("name", "sample"))}.solve.frida.js --no-pause

const REV_CANDIDATES = {candidate_payload};

function readCString(ptrValue) {{
  if (ptrValue.isNull()) return "<null>";
  try {{
    return ptrValue.readCString();
  }} catch (e) {{
    return "<unreadable>";
  }}
}}

function hookExport(name, callback) {{
  const address = Module.findExportByName(null, name);
  if (!address) return;
  Interceptor.attach(address, callback(address));
  console.log("[revbot] hooked " + name + " @ " + address);
}}

["strcmp", "strcasecmp"].forEach(function(name) {{
  hookExport(name, function() {{
    return {{
      onEnter(args) {{
        console.log("[revbot] " + name + "(" + readCString(args[0]) + ", " + readCString(args[1]) + ")");
      }}
    }};
  }});
}});

["strncmp", "strncasecmp"].forEach(function(name) {{
  hookExport(name, function() {{
    return {{
      onEnter(args) {{
        console.log("[revbot] " + name + "(" + readCString(args[0]) + ", " + readCString(args[1]) + ", " + args[2].toInt32() + ")");
      }}
    }};
  }});
}});

hookExport("memcmp", function() {{
  return {{
    onEnter(args) {{
      const n = args[2].toInt32();
      if (n > 0 && n <= 128) {{
        console.log("[revbot] memcmp a=" + hexdump(args[0], {{ length: n, ansi: false }}) +
                    " b=" + hexdump(args[1], {{ length: n, ansi: false }}));
      }}
    }}
  }};
}});

hookExport("getenv", function() {{
  return {{
    onEnter(args) {{
      console.log("[revbot] getenv(" + readCString(args[0]) + ")");
    }}
  }};
}});

hookExport("fopen", function() {{
  return {{
    onEnter(args) {{
      console.log("[revbot] fopen(" + readCString(args[0]) + ", " + readCString(args[1]) + ")");
    }}
  }};
}});

if (Java.available) {{
  Java.perform(function() {{
    const StringCls = Java.use("java.lang.String");
    const equalsOverload = StringCls.equals.overload("java.lang.Object");
    equalsOverload.implementation = function(other) {{
      console.log("[revbot] java.lang.String.equals(" + this.toString() + ", " + other + ")");
      return equalsOverload.call(this, other);
    }};
    console.log("[revbot] hooked java.lang.String.equals");
  }});
}}

console.log("[revbot] top candidates: " + REV_CANDIDATES.join(", "));
'''


def render_candidates_wordlist(result: dict[str, Any]) -> str:
    values = []
    for item in result.get("candidates", []):
        value = str(item.get("value", ""))
        if value and "\n" not in value and "\r" not in value:
            values.append(value)
    return "\n".join(dict.fromkeys(values)) + ("\n" if values else "")


def summarize_static_for_solve(static: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": static.get("identity", {}).get("format"),
        "string_count": static.get("strings", {}).get("count"),
        "ctf_strings": static.get("strings", {}).get("categories", {}).get("ctf", [])[:80],
        "signals": static.get("signals", {}),
        "imports": sorted(collect_imports(static))[:500],
    }


def summarize_tools_for_solve(tools: dict[str, ToolResult]) -> dict[str, Any]:
    return {
        name: {
            "available": result.available,
            "exit_code": result.exit_code,
            "error": result.error,
            "stdout_head": result.stdout[:2000],
        }
        for name, result in tools.items()
    }


def rank_objdump_functions(tools: dict[str, ToolResult]) -> list[dict[str, Any]]:
    result = tools.get("objdump_disasm")
    if not result or not result.stdout:
        return []
    functions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in result.stdout.splitlines():
        header = re.match(r"^([0-9a-fA-F]+) <([^>]+)>:$", line.strip())
        if header:
            if current:
                functions.append(current)
            current = {
                "address": int(header.group(1), 16),
                "name": header.group(2),
                "score": 0,
                "reasons": [],
                "calls": [],
            }
            name = current["name"].lower()
            if name in {"main", "win", "check", "verify", "auth", "login"} or any(token in name for token in ["main", "check", "verify", "flag", "auth", "login"]):
                current["score"] += 4
                current["reasons"].append("interesting-name")
            continue
        if current is None:
            continue
        call = re.search(r"\bcall\w*\s+[0-9a-fx ]+<([^>]+)>", line)
        if call:
            target = call.group(1)
            current["calls"].append(target)
            lowered = target.lower()
            if any(name in lowered for name in COMPARISON_NAMES):
                current["score"] += 8
                current["reasons"].append(f"calls-{target}")
            elif any(token in lowered for token in ["scanf", "fgets", "gets", "read"]):
                current["score"] += 4
                current["reasons"].append(f"input-{target}")
            elif any(token in lowered for token in ["puts", "printf", "write"]):
                current["score"] += 2
                current["reasons"].append(f"output-{target}")
    if current:
        functions.append(current)
    ranked = [item for item in functions if item["score"] > 0]
    return sorted(ranked, key=lambda item: (item["score"], item["name"]), reverse=True)[:100]


def collect_imports(static: dict[str, Any]) -> set[str]:
    names = set()
    for source in (static.get("pe", {}), static.get("elf", {})):
        for item in source.get("imports", []):
            name = str(item.get("name", "")).lower()
            if name:
                names.add(name)
    return names


def extract_flags(text: str, strict: bool = False) -> list[str]:
    flags: list[str] = []
    patterns = FLAG_PATTERNS[:1] if strict else FLAG_PATTERNS
    for pattern in patterns:
        flags.extend(match.group(0) for match in pattern.finditer(text))
    return list(dict.fromkeys(flags))


def extract_flags_with_confidence(text: str) -> list[tuple[str, float]]:
    results: dict[str, float] = {}
    for index, pattern in enumerate(FLAG_PATTERNS):
        confidence = 0.98 if index == 0 else 0.82
        for match in pattern.finditer(text):
            value = match.group(0)
            results[value] = max(results.get(value, 0), confidence)
    return list(results.items())


def is_mostly_printable(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(byte in b"\r\n\t" or 32 <= byte <= 126 for byte in data)
    return printable / len(data) >= 0.85


def score_runtime_output(text: str) -> int:
    score = 0
    if SUCCESS_RE.search(text):
        score += 2
    if extract_flags(text):
        score += 4
    if FAIL_RE.search(text):
        score -= 1
    return score


def dedupe_candidates(candidates: list[SolveCandidate]) -> list[SolveCandidate]:
    merged: dict[str, SolveCandidate] = {}
    for candidate in candidates:
        key = candidate.value
        if key not in merged or candidate.confidence > merged[key].confidence:
            merged[key] = candidate
        else:
            merged[key].evidence.extend(candidate.evidence)
    return sorted(merged.values(), key=lambda item: item.confidence, reverse=True)


def likely_probe_input(value: str) -> bool:
    if not 3 <= len(value) <= 48:
        return False
    if any(ch in value for ch in "\r\n\t"):
        return False
    if value.startswith(("/", "./", "../", "http://", "https://")):
        return False
    if "%" in value and any(marker in value for marker in ("%s", "%d", "%x")):
        return False
    allowed = sum(ch.isalnum() or ch in "_{}-!@#$^&*+=:,.?" for ch in value)
    return allowed / len(value) >= 0.9


def safe_stem(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in name).strip("._") or "sample"


def short(value: str, limit: int = 160) -> str:
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return value if len(value) <= limit else value[: limit - 3] + "..."


LD_PRELOAD_HOOK_SOURCE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

static void print_escaped(const char *s) {
  if (!s) {
    fputs("<null>", stderr);
    return;
  }
  for (int i = 0; s[i] && i < 160; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\n') fputs("\\n", stderr);
    else if (c == '\r') fputs("\\r", stderr);
    else if (c == '\t') fputs("\\t", stderr);
    else if (c == '|') fputs("\\x7c", stderr);
    else if (c == '\\') fputs("\\\\", stderr);
    else if (c >= 32 && c <= 126) fputc(c, stderr);
    else fprintf(stderr, "\\x%02x", c);
  }
}

static void log_cmp(const char *name, const char *a, const char *b) {
  fputs("REVHOOK|", stderr);
  fputs(name, stderr);
  fputc('|', stderr);
  print_escaped(a);
  fputc('|', stderr);
  print_escaped(b);
  fputc('\n', stderr);
}

static void log_io(const char *name, const char *a, const char *b) {
  fputs("REVHOOK_IO|", stderr);
  fputs(name, stderr);
  fputc('|', stderr);
  print_escaped(a);
  fputc('|', stderr);
  print_escaped(b);
  fputc('\n', stderr);
}

static void print_hex(const unsigned char *p, size_t n) {
  size_t limit = n < 160 ? n : 160;
  for (size_t i = 0; i < limit; i++) {
    fprintf(stderr, "%02x", p[i]);
  }
}

static void log_memcmp(const void *a, const void *b, size_t n) {
  fputs("REVHOOK_MEM|memcmp|", stderr);
  fprintf(stderr, "%zu|", n);
  print_hex((const unsigned char *)a, n);
  fputc('|', stderr);
  print_hex((const unsigned char *)b, n);
  fputc('\n', stderr);
}

int strcmp(const char *a, const char *b) {
  static int (*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strcmp");
  log_cmp("strcmp", a, b);
  return real_fn(a, b);
}

int strncmp(const char *a, const char *b, size_t n) {
  static int (*real_fn)(const char *, const char *, size_t) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strncmp");
  log_cmp("strncmp", a, b);
  return real_fn(a, b, n);
}

int strcasecmp(const char *a, const char *b) {
  static int (*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strcasecmp");
  log_cmp("strcasecmp", a, b);
  return real_fn(a, b);
}

int strncasecmp(const char *a, const char *b, size_t n) {
  static int (*real_fn)(const char *, const char *, size_t) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strncasecmp");
  log_cmp("strncasecmp", a, b);
  return real_fn(a, b, n);
}

char *strstr(const char *a, const char *b) {
  static char *(*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strstr");
  log_cmp("strstr", a, b);
  return real_fn(a, b);
}

char *strcasestr(const char *a, const char *b) {
  static char *(*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strcasestr");
  log_cmp("strcasestr", a, b);
  return real_fn(a, b);
}

int memcmp(const void *a, const void *b, size_t n) {
  static int (*real_fn)(const void *, const void *, size_t) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "memcmp");
  if (n > 0 && n <= 160) log_memcmp(a, b, n);
  return real_fn(a, b, n);
}

char *getenv(const char *name) {
  static char *(*real_fn)(const char *) = NULL;
  static int resolving = 0;
  if (!real_fn) {
    if (resolving) return NULL;
    resolving = 1;
    real_fn = dlsym(RTLD_NEXT, "getenv");
    resolving = 0;
  }
  if (!real_fn) return NULL;
  char *value = real_fn(name);
  log_io("getenv", name, value ? value : "<null>");
  return value;
}

FILE *fopen(const char *path, const char *mode) {
  static FILE *(*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "fopen");
  log_io("fopen", path, mode);
  return real_fn(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
  static FILE *(*real_fn)(const char *, const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "fopen64");
  log_io("fopen64", path, mode);
  return real_fn(path, mode);
}

int open(const char *path, int flags, ...) {
  static int (*real_fn)(const char *, int, ...) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "open");
  log_io("open", path, "");
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real_fn(path, flags, mode);
  }
  return real_fn(path, flags);
}

int open64(const char *path, int flags, ...) {
  static int (*real_fn)(const char *, int, ...) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "open64");
  log_io("open64", path, "");
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real_fn(path, flags, mode);
  }
  return real_fn(path, flags);
}

int access(const char *path, int mode) {
  static int (*real_fn)(const char *, int) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "access");
  log_io("access", path, "");
  return real_fn(path, mode);
}

char *fgets(char *s, int size, FILE *stream) {
  static char *(*real_fn)(char *, int, FILE *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "fgets");
  if (!real_fn) return NULL;
  char *result = real_fn(s, size, stream);
  if (result) log_io("fgets", s, "");
  return result;
}

int scanf(const char *format, ...) {
  static int (*real_vscanf)(const char *, va_list) = NULL;
  if (!real_vscanf) real_vscanf = dlsym(RTLD_NEXT, "vscanf");
  log_io("scanf", format, "");
  if (!real_vscanf) return EOF;
  va_list ap;
  va_start(ap, format);
  int result = real_vscanf(format, ap);
  va_end(ap);
  return result;
}

int __isoc99_scanf(const char *format, ...) {
  static int (*real_vscanf)(const char *, va_list) = NULL;
  if (!real_vscanf) {
    real_vscanf = dlsym(RTLD_NEXT, "__isoc99_vscanf");
    if (!real_vscanf) real_vscanf = dlsym(RTLD_NEXT, "vscanf");
  }
  log_io("__isoc99_scanf", format, "");
  if (!real_vscanf) return EOF;
  va_list ap;
  va_start(ap, format);
  int result = real_vscanf(format, ap);
  va_end(ap);
  return result;
}

int atoi(const char *nptr) {
  static int (*real_fn)(const char *) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "atoi");
  log_io("atoi", nptr, "");
  return real_fn(nptr);
}

long strtol(const char *nptr, char **endptr, int base) {
  static long (*real_fn)(const char *, char **, int) = NULL;
  if (!real_fn) real_fn = dlsym(RTLD_NEXT, "strtol");
  log_io("strtol", nptr, "");
  return real_fn(nptr, endptr, base);
}
'''
