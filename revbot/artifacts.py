from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


CTF_RE = re.compile(r"flag\{|dreamhack|password|serial|correct|wrong|congrat", re.IGNORECASE)
CRYPTO_RE = re.compile(r"sha-?256|md5|aes|rsa|base64|xor|rc4|chacha|salsa20", re.IGNORECASE)
ANTI_RE = re.compile(r"debug|vmware|virtualbox|vbox|qemu|sandbox|isdebuggerpresent", re.IGNORECASE)
NET_RE = re.compile(r"https?://|socket|connect|send|recv|winhttp|internetopen", re.IGNORECASE)
VULN_RE = re.compile(r"strcpy|strcat|sprintf|vsprintf|gets|scanf|memcpy|memcmp|strcmp|strncmp", re.IGNORECASE)


def load_extra_json(paths: list[Path]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in paths:
        item: dict[str, Any] = {"path": str(path), "loaded": False}
        try:
            item["data"] = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            item["loaded"] = True
        except (OSError, json.JSONDecodeError) as exc:
            item["error"] = str(exc)
        artifacts.append(item)
    return artifacts


def normalize_artifacts(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "loaded_count": sum(1 for item in artifacts if item.get("loaded")),
        "artifacts": [],
        "imports": [],
        "strings": [],
        "functions": [],
        "ranked_functions": [],
    }

    for artifact in artifacts:
        data = artifact.get("data")
        summary = {
            "path": artifact.get("path"),
            "loaded": artifact.get("loaded"),
            "source": data.get("source") if isinstance(data, dict) else None,
            "error": artifact.get("error"),
        }
        normalized["artifacts"].append(summary)
        if not isinstance(data, dict):
            continue

        normalized["imports"].extend(normalize_imports(data.get("imports", []), summary))
        normalized["strings"].extend(normalize_strings(data.get("strings", []), summary))
        normalized["functions"].extend(normalize_functions(data.get("functions", []), summary))

    normalized["imports"] = dedupe_dicts(normalized["imports"], ("name", "library", "dll"))
    normalized["strings"] = dedupe_dicts(normalized["strings"], ("value",))
    normalized["ranked_functions"] = rank_functions(normalized["functions"])[:100]
    return normalized


def normalize_imports(values: Any, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    imports: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return imports
    for item in values:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("symbol") or "")
            library = str(item.get("library") or item.get("dll") or item.get("module") or "")
            if name:
                imports.append(
                    {
                        "name": name,
                        "library": library,
                        "address": item.get("ea") or item.get("address"),
                        "source": artifact.get("source"),
                    }
                )
    return imports


def normalize_strings(values: Any, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return strings
    for item in values:
        if isinstance(item, dict):
            value = str(item.get("value") or item.get("string") or "")
            address = item.get("ea") or item.get("address")
        else:
            value = str(item)
            address = None
        if len(value) >= 4:
            strings.append({"value": value, "address": address, "source": artifact.get("source")})
    return strings


def normalize_functions(values: Any, artifact: dict[str, Any]) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return functions
    for item in values:
        if not isinstance(item, dict):
            continue
        strings = normalize_function_strings(item.get("strings", []))
        calls = normalize_function_calls(item.get("calls", []))
        name = str(item.get("name") or item.get("entry") or item.get("ea") or "sub_unknown")
        functions.append(
            {
                "name": name,
                "entry": item.get("ea") or item.get("entry") or item.get("offset"),
                "end": item.get("end"),
                "size": item.get("size"),
                "source": artifact.get("source"),
                "calls": calls,
                "strings": strings,
                "score": 0,
                "reasons": [],
            }
        )
    return functions


def normalize_function_strings(values: Any) -> list[str]:
    results: list[str] = []
    if not isinstance(values, list):
        return results
    for item in values:
        if isinstance(item, dict):
            value = str(item.get("value") or "")
        else:
            value = str(item)
        if len(value) >= 4:
            results.append(value)
    return results[:200]


def normalize_function_calls(values: Any) -> list[str]:
    calls: list[str] = []
    if not isinstance(values, list):
        return calls
    for item in values:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("target") or "")
        else:
            name = str(item)
        if name:
            calls.append(name)
    return calls[:200]


def rank_functions(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for function in functions:
        haystack = "\n".join([function.get("name", ""), *function.get("calls", []), *function.get("strings", [])])
        score = 0
        reasons: list[str] = []
        for label, regex, weight in [
            ("ctf-anchor", CTF_RE, 8),
            ("crypto", CRYPTO_RE, 5),
            ("anti-analysis", ANTI_RE, 5),
            ("network", NET_RE, 4),
            ("comparison-or-unsafe-api", VULN_RE, 3),
        ]:
            if regex.search(haystack):
                score += weight
                reasons.append(label)
        if "main" in function.get("name", "").lower():
            score += 2
            reasons.append("main-like-name")
        if score:
            item = dict(function)
            item["score"] = score
            item["reasons"] = reasons
            ranked.append(item)
    return sorted(ranked, key=lambda item: (item["score"], str(item.get("name"))), reverse=True)


def dedupe_dicts(values: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    results: list[dict[str, Any]] = []
    for item in values:
        marker = tuple(str(item.get(key, "")).lower() for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        results.append(item)
    return results

