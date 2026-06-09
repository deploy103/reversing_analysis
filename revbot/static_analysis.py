from __future__ import annotations

import hashlib
import io
import math
import re
import struct
import zipfile
from pathlib import Path
from typing import Any


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|kr|cn|ru|xyz|top|info|biz)\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
REGISTRY_RE = re.compile(r"\bHK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|LM|CU)\\[^\s\"']+", re.IGNORECASE)
WINDOWS_PATH_RE = re.compile(r"\b[A-Z]:\\[^\r\n\t\"']+", re.IGNORECASE)
CTF_ANCHOR_RE = re.compile(
    r"(flag\{|dreamhack|password|serial|keygen|congrat|(?<![A-Za-z0-9_])wrong(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])correct(?![A-Za-z0-9_]))",
    re.IGNORECASE,
)
CRYPTO_ANCHOR_RE = re.compile(
    r"(sha-?256|(?<![A-Za-z0-9_])(?:aes|rsa|md5|base64|xor|rc4|chacha|salsa20)(?![A-Za-z0-9_]))",
    re.IGNORECASE,
)


MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    5: "os2_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    14: "xbox",
}

ELF_MACHINES = {
    0x03: "x86",
    0x28: "ARM",
    0x3E: "x64",
    0xB7: "ARM64",
    0x08: "MIPS",
    0xF3: "RISC-V",
}

ELF_TYPES = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared",
    4: "core",
}


class StaticAnalyzer:
    def __init__(self, max_bytes: int = 128 * 1024 * 1024) -> None:
        self.max_bytes = max_bytes

    def analyze(self, path: Path | str) -> dict[str, Any]:
        sample_path = Path(path)
        data = sample_path.read_bytes()
        truncated = False
        if len(data) > self.max_bytes:
            data = data[: self.max_bytes]
            truncated = True

        identity = self._identity(sample_path, data, truncated)
        strings = extract_strings(data)
        string_index = categorize_strings(strings)
        sections: list[dict[str, Any]] = []
        pe: dict[str, Any] = {}
        elf: dict[str, Any] = {}
        zip_info: dict[str, Any] = {}
        binary_info: dict[str, Any] = {}

        if identity["format"] == "pe":
            pe = parse_pe(data)
            sections = pe.get("sections", [])
            binary_info = pe
        elif identity["format"] == "elf":
            elf = parse_elf(data)
            sections = elf.get("sections", [])
            binary_info = elf
        elif identity["format"] == "zip_or_apk":
            zip_info = parse_zip_artifact(sample_path)

        entropy = {
            "overall": shannon_entropy(data),
            "chunks": chunk_entropy(data),
            "high_entropy_chunks": [
                item for item in chunk_entropy(data) if item["entropy"] >= 7.2
            ][:32],
        }

        return {
            "identity": identity,
            "entropy": entropy,
            "strings": {
                "count": len(strings),
                "top": strings[:500],
                "categories": string_index,
            },
            "pe": pe,
            "elf": elf,
            "zip": zip_info,
            "sections": sections,
            "signals": derive_static_signals(identity, entropy, strings, binary_info),
        }

    def _identity(self, path: Path, data: bytes, truncated: bool) -> dict[str, Any]:
        return {
            "path": str(path),
            "name": path.name,
            "size": path.stat().st_size,
            "truncated_for_analysis": truncated,
            "sha256": hash_file(path, "sha256"),
            "sha1": hash_file(path, "sha1"),
            "md5": hash_file(path, "md5"),
            "magic_hex": data[:32].hex(),
            "format": detect_format(data),
        }


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "macho"
    if data.startswith(b"dex\n"):
        return "dex"
    if data.startswith(b"PK\x03\x04"):
        return "zip_or_apk"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"%PDF"):
        return "pdf"
    return "unknown"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def chunk_entropy(data: bytes, chunk_size: int = 4096) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]
        if not chunk:
            continue
        chunks.append(
            {
                "offset": offset,
                "size": len(chunk),
                "entropy": shannon_entropy(chunk),
            }
        )
    return chunks[:4096]


def extract_strings(data: bytes, minimum: int = 4) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []

    for match in ASCII_RE.finditer(data):
        value = match.group(0).decode("utf-8", errors="replace")
        if len(value) >= minimum and value not in seen:
            seen.add(value)
            results.append(value)

    for value in extract_utf16le_strings(data, minimum):
        if value not in seen:
            seen.add(value)
            results.append(value)
    for value in extract_utf16be_strings(data, minimum):
        if value not in seen:
            seen.add(value)
            results.append(value)

    return sorted(results, key=lambda item: (-len(item), item.lower()))


def extract_utf16le_strings(data: bytes, minimum: int = 4) -> list[str]:
    results: list[str] = []
    for alignment in (0, 1):
        pos = alignment
        while pos + 1 < len(data):
            start = pos
            chars: list[str] = []
            while pos + 1 < len(data) and 0x20 <= data[pos] <= 0x7E and data[pos + 1] == 0:
                chars.append(chr(data[pos]))
                pos += 2
            if len(chars) >= minimum:
                if start > 0 and 0x20 <= data[start - 1] <= 0x7E:
                    pos = start + 2
                    continue
                results.append("".join(chars))
            if pos == start:
                pos += 2
    return results


def extract_utf16be_strings(data: bytes, minimum: int = 4) -> list[str]:
    results: list[str] = []
    for alignment in (0, 1):
        pos = alignment
        while pos + 1 < len(data):
            start = pos
            chars: list[str] = []
            while pos + 1 < len(data) and data[pos] == 0 and 0x20 <= data[pos + 1] <= 0x7E:
                chars.append(chr(data[pos + 1]))
                pos += 2
            if len(chars) >= minimum:
                if start > 1 and 0x20 <= data[start - 1] <= 0x7E:
                    pos = start + 2
                    continue
                results.append("".join(chars))
            if pos == start:
                pos += 2
    return results


def categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    joined = "\n".join(strings)
    categories = {
        "urls": sorted(set(URL_RE.findall(joined)))[:200],
        "ips": sorted(set(IP_RE.findall(joined)))[:200],
        "domains": sorted(set(DOMAIN_RE.findall(joined)))[:200],
        "emails": sorted(set(EMAIL_RE.findall(joined)))[:200],
        "registry": sorted(set(REGISTRY_RE.findall(joined)))[:200],
        "windows_paths": sorted(set(WINDOWS_PATH_RE.findall(joined)))[:200],
        "ctf": [item for item in strings if CTF_ANCHOR_RE.search(item)][:200],
    }
    return categories


def read_c_string(data: bytes, offset: int, max_len: int = 4096) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_pe(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "sections": [], "imports": []}
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return result
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 0x18 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return result

        coff_offset = pe_offset + 4
        machine, number_of_sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, coff_offset
        )
        optional_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        is_64 = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            return result

        entry_point_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
        image_base = struct.unpack_from("<Q" if is_64 else "<I", data, optional_offset + (24 if is_64 else 28))[0]
        subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
        dll_characteristics = struct.unpack_from("<H", data, optional_offset + 70)[0]
        data_directory_offset = optional_offset + (112 if is_64 else 96)

        directories: list[dict[str, Any]] = []
        for index in range(16):
            offset = data_directory_offset + index * 8
            if offset + 8 <= len(data):
                rva, size = struct.unpack_from("<II", data, offset)
                directories.append({"index": index, "rva": rva, "size": size})

        section_offset = optional_offset + optional_size
        sections = []
        for index in range(number_of_sections):
            offset = section_offset + index * 40
            if offset + 40 > len(data):
                break
            raw_name = data[offset : offset + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("utf-8", errors="replace")
            virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", data, offset + 8)
            characteristics_section = struct.unpack_from("<I", data, offset + 36)[0]
            raw = data[raw_ptr : raw_ptr + raw_size] if raw_ptr < len(data) else b""
            sections.append(
                {
                    "name": name,
                    "virtual_address": virtual_address,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                    "entropy": shannon_entropy(raw),
                    "executable": bool(characteristics_section & 0x20000000),
                    "writable": bool(characteristics_section & 0x80000000),
                    "readable": bool(characteristics_section & 0x40000000),
                    "characteristics": hex(characteristics_section),
                }
            )

        imports = parse_pe_imports(data, directories, sections, is_64)
        result.update(
            {
                "valid": True,
                "machine": MACHINE_TYPES.get(machine, hex(machine)),
                "is_64": is_64,
                "timestamp": timestamp,
                "characteristics": hex(characteristics),
                "entry_point_rva": entry_point_rva,
                "image_base": image_base,
                "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
                "dll_characteristics": hex(dll_characteristics),
                "directories": directories,
                "sections": sections,
                "imports": imports,
                "import_dlls": sorted({item["dll"] for item in imports}),
            }
        )
    except (struct.error, ValueError, IndexError):
        result["error"] = "PE parser failed on malformed or truncated input"
    return result


def parse_elf(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "sections": [], "imports": [], "symbols": []}
    try:
        if len(data) < 0x40 or data[:4] != b"\x7fELF":
            return result
        elf_class = data[4]
        elf_data = data[5]
        if elf_class not in (1, 2) or elf_data not in (1, 2):
            return result
        is_64 = elf_class == 2
        endian = "<" if elf_data == 1 else ">"

        if is_64:
            header_fmt = endian + "HHIQQQIHHHHHH"
            header_size = struct.calcsize(header_fmt)
            values = struct.unpack_from(header_fmt, data, 16)
            (
                elf_type,
                machine,
                _version,
                entry,
                _phoff,
                shoff,
                _flags,
                _ehsize,
                _phentsize,
                _phnum,
                shentsize,
                shnum,
                shstrndx,
            ) = values
        else:
            header_fmt = endian + "HHIIIIIHHHHHH"
            header_size = struct.calcsize(header_fmt)
            values = struct.unpack_from(header_fmt, data, 16)
            (
                elf_type,
                machine,
                _version,
                entry,
                _phoff,
                shoff,
                _flags,
                _ehsize,
                _phentsize,
                _phnum,
                shentsize,
                shnum,
                shstrndx,
            ) = values
        if 16 + header_size > len(data) or shoff <= 0 or shnum <= 0:
            result.update(
                {
                    "valid": True,
                    "is_64": is_64,
                    "machine": ELF_MACHINES.get(machine, hex(machine)),
                    "type": ELF_TYPES.get(elf_type, str(elf_type)),
                    "entry_point": entry,
                }
            )
            return result

        raw_sections = []
        for index in range(shnum):
            offset = shoff + index * shentsize
            if offset + shentsize > len(data):
                break
            if is_64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    endian + "IIQQQQIIQQ", data, offset
                )
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                    endian + "IIIIIIIIII", data, offset
                )
            raw_sections.append(
                {
                    "name_offset": sh_name,
                    "type": sh_type,
                    "flags": sh_flags,
                    "address": sh_addr,
                    "offset": sh_offset,
                    "size": sh_size,
                    "link": sh_link,
                    "info": sh_info,
                    "addralign": sh_addralign,
                    "entsize": sh_entsize,
                }
            )

        shstr = b""
        if 0 <= shstrndx < len(raw_sections):
            shstr_section = raw_sections[shstrndx]
            shstr = read_range(data, shstr_section["offset"], shstr_section["size"])

        sections = []
        for section in raw_sections:
            name = read_c_string(shstr, section["name_offset"]) if shstr else ""
            raw = read_range(data, section["offset"], section["size"])
            flags = int(section["flags"])
            sections.append(
                {
                    "name": name,
                    "virtual_address": section["address"],
                    "virtual_size": section["size"],
                    "raw_size": len(raw),
                    "raw_ptr": section["offset"],
                    "entropy": shannon_entropy(raw),
                    "executable": bool(flags & 0x4),
                    "writable": bool(flags & 0x1),
                    "readable": bool(flags & 0x2),
                    "characteristics": hex(flags),
                    "type": section["type"],
                    "link": section["link"],
                    "entsize": section["entsize"],
                }
            )

        symbols = parse_elf_symbols(data, raw_sections, sections, is_64, endian)
        imports = [
            {"dll": "elf", "name": symbol["name"]}
            for symbol in symbols
            if symbol.get("undefined") and symbol.get("name")
        ]
        needed = parse_elf_needed_libraries(data, raw_sections, sections, is_64, endian)
        result.update(
            {
                "valid": True,
                "is_64": is_64,
                "machine": ELF_MACHINES.get(machine, hex(machine)),
                "type": ELF_TYPES.get(elf_type, str(elf_type)),
                "entry_point": entry,
                "sections": sections,
                "symbols": symbols[:5000],
                "imports": imports[:5000],
                "needed_libraries": needed,
            }
        )
    except (struct.error, ValueError, IndexError):
        result["error"] = "ELF parser failed on malformed or truncated input"
    return result


def parse_zip_artifact(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "valid": False,
        "entries": [],
        "interesting_entries": [],
        "embedded_strings": [],
        "is_apk": False,
    }
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            entries = [
                {
                    "name": info.filename,
                    "compressed_size": info.compress_size,
                    "size": info.file_size,
                }
                for info in infos[:5000]
            ]
            names = [info.filename for info in infos]
            interesting = [
                name
                for name in names
                if name.endswith((".dex", ".so", ".arsc", ".xml"))
                or name.startswith(("lib/", "assets/", "res/raw/"))
                or name.endswith((".jar", ".zip", ".apk", ".class"))
                or name in {"AndroidManifest.xml", "classes.dex"}
            ][:500]
            embedded_strings: list[str] = []
            for info in infos[:200]:
                if info.file_size > 2_000_000:
                    continue
                if not (
                    info.filename.endswith((".dex", ".so", ".txt", ".json", ".xml", ".js", ".bin", ".class", ".zip", ".jar", ".apk"))
                    or info.filename in {"AndroidManifest.xml", "classes.dex"}
                ):
                    continue
                try:
                    blob = archive.read(info.filename)
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
                embedded_strings.extend(extract_strings(blob)[:200])
                if info.filename.endswith((".zip", ".jar", ".apk")) and info.file_size <= 2_000_000:
                    embedded_strings.extend(extract_nested_zip_strings(blob)[:200])
            result.update(
                {
                    "valid": True,
                    "entries": entries,
                    "interesting_entries": interesting,
                    "embedded_strings": sorted(set(embedded_strings), key=lambda item: (-len(item), item.lower()))[:1000],
                    "is_apk": "AndroidManifest.xml" in names or any(name.endswith(".dex") for name in names),
                }
            )
    except (zipfile.BadZipFile, OSError):
        result["error"] = "ZIP/APK parser failed"
    return result


def extract_nested_zip_strings(blob: bytes) -> list[str]:
    strings: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as nested:
            for info in nested.infolist()[:100]:
                if info.file_size > 1_000_000:
                    continue
                if not info.filename.endswith((".dex", ".so", ".txt", ".json", ".xml", ".js", ".bin", ".class")):
                    continue
                try:
                    strings.extend(extract_strings(nested.read(info.filename))[:100])
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
    except (zipfile.BadZipFile, OSError):
        return []
    return strings


def read_range(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset >= len(data):
        return b""
    return data[offset : min(len(data), offset + size)]


def parse_elf_symbols(
    data: bytes,
    raw_sections: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    is_64: bool,
    endian: str,
) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for index, raw_section in enumerate(raw_sections):
        if raw_section["type"] not in (2, 11):
            continue
        entsize = int(raw_section["entsize"]) or (24 if is_64 else 16)
        if entsize <= 0:
            continue
        linked = int(raw_section["link"])
        strtab = b""
        if 0 <= linked < len(raw_sections):
            strtab = read_range(data, raw_sections[linked]["offset"], raw_sections[linked]["size"])
        table = read_range(data, raw_section["offset"], raw_section["size"])
        count = min(len(table) // entsize, 20000)
        section_name = sections[index]["name"] if index < len(sections) else ""
        for sym_index in range(count):
            offset = sym_index * entsize
            if is_64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    endian + "IBBHQQ", table, offset
                )
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    endian + "IIIBBH", table, offset
                )
            name = read_c_string(strtab, st_name) if strtab and st_name else ""
            if not name:
                continue
            symbols.append(
                {
                    "name": name,
                    "value": st_value,
                    "size": st_size,
                    "info": st_info,
                    "other": st_other,
                    "section_index": st_shndx,
                    "undefined": st_shndx == 0,
                    "table": section_name,
                }
            )
    return symbols


def parse_elf_needed_libraries(
    data: bytes,
    raw_sections: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    is_64: bool,
    endian: str,
) -> list[str]:
    needed: list[str] = []
    for index, raw_section in enumerate(raw_sections):
        if raw_section["type"] != 6:
            continue
        linked = int(raw_section["link"])
        dynstr = b""
        if 0 <= linked < len(raw_sections):
            dynstr = read_range(data, raw_sections[linked]["offset"], raw_sections[linked]["size"])
        table = read_range(data, raw_section["offset"], raw_section["size"])
        entsize = int(raw_section["entsize"]) or (16 if is_64 else 8)
        count = min(len(table) // entsize, 20000)
        for entry_index in range(count):
            offset = entry_index * entsize
            if is_64:
                tag, value = struct.unpack_from(endian + "QQ", table, offset)
            else:
                tag, value = struct.unpack_from(endian + "II", table, offset)
            if tag == 0:
                break
            if tag == 1 and dynstr:
                name = read_c_string(dynstr, value)
                if name and name not in needed:
                    needed.append(name)
    return needed


def rva_to_offset(rva: int, sections: list[dict[str, Any]]) -> int | None:
    for section in sections:
        start = int(section["virtual_address"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < start + span:
            return int(section["raw_ptr"]) + (rva - start)
    return None


def parse_pe_imports(
    data: bytes,
    directories: list[dict[str, Any]],
    sections: list[dict[str, Any]],
    is_64: bool,
) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    if len(directories) < 2 or not directories[1]["rva"]:
        return imports
    import_offset = rva_to_offset(int(directories[1]["rva"]), sections)
    if import_offset is None:
        return imports

    thunk_size = 8 if is_64 else 4
    ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000
    unpack_thunk = "<Q" if is_64 else "<I"

    for descriptor_index in range(4096):
        descriptor_offset = import_offset + descriptor_index * 20
        if descriptor_offset + 20 > len(data):
            break
        original_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor_offset)
        if not any((original_thunk, name_rva, first_thunk)):
            break
        name_offset = rva_to_offset(name_rva, sections)
        dll_name = read_c_string(data, name_offset) if name_offset is not None else f"dll_{descriptor_index}"
        thunk_rva = original_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva, sections)
        if thunk_offset is None:
            continue

        for thunk_index in range(8192):
            offset = thunk_offset + thunk_index * thunk_size
            if offset + thunk_size > len(data):
                break
            thunk_value = struct.unpack_from(unpack_thunk, data, offset)[0]
            if thunk_value == 0:
                break
            if thunk_value & ordinal_mask:
                imports.append({"dll": dll_name, "name": f"ordinal_{thunk_value & 0xFFFF}"})
                continue
            hint_name_offset = rva_to_offset(thunk_value, sections)
            if hint_name_offset is None or hint_name_offset + 2 >= len(data):
                continue
            function_name = read_c_string(data, hint_name_offset + 2)
            imports.append({"dll": dll_name, "name": function_name})
    return imports


def derive_static_signals(
    identity: dict[str, Any],
    entropy: dict[str, Any],
    strings: list[str],
    pe: dict[str, Any],
) -> dict[str, Any]:
    lower_strings = [item.lower() for item in strings]
    imports = [item.get("name", "") for item in pe.get("imports", [])]
    import_names = {item.lower() for item in imports}
    sections = pe.get("sections", [])

    high_entropy_sections = [
        item for item in sections if item.get("entropy", 0) >= 7.2 and item.get("raw_size", 0) > 1024
    ]
    writable_exec_sections = [
        item for item in sections if item.get("writable") and item.get("executable")
    ]

    indicators = {
        "likely_packed": bool(high_entropy_sections or writable_exec_sections or entropy["overall"] >= 7.4),
        "anti_debug_imports": sorted(import_names & {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw"}),
        "injection_imports": sorted(import_names & {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "setwindowshookexa", "queueuserapc"}),
        "network_imports": sorted(import_names & {"internetopenurla", "internetopenurla", "internetconnecta", "winhttpopen", "winhttpconnect", "wsastartup", "connect", "send", "recv"}),
        "crypto_imports": sorted(import_names & {"cryptacquirecontexta", "cryptdecrypt", "cryptencrypt", "bcryptdecrypt", "bcryptencrypt", "cryptgenrandom", "systemfunction032"}),
        "ctf_strings": [item for item in strings if CTF_ANCHOR_RE.search(item)][:100],
        "format": identity.get("format"),
        "high_entropy_sections": high_entropy_sections,
        "writable_exec_sections": writable_exec_sections,
        "mentions_vm_or_debug": [
            item
            for item in strings
            if any(token in item.lower() for token in ["debugger", "vmware", "virtualbox", "vbox", "qemu", "sandbox"])
        ][:100],
        "mentions_crypto": [item for item in strings if CRYPTO_ANCHOR_RE.search(item)][:100],
    }
    indicators["score"] = sum(
        [
            2 if indicators["likely_packed"] else 0,
            len(indicators["anti_debug_imports"]),
            len(indicators["injection_imports"]),
            len(indicators["network_imports"]),
            len(indicators["crypto_imports"]),
            min(len(indicators["ctf_strings"]), 5),
        ]
    )
    return indicators
