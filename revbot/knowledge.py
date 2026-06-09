from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from revbot.models import Finding


class KnowledgeBase:
    def __init__(self, patterns: list[dict[str, Any]]) -> None:
        self.patterns = patterns

    @classmethod
    def load(cls, path: Path | str | None = None) -> "KnowledgeBase":
        if path and Path(path).exists():
            return cls(json.loads(Path(path).read_text(encoding="utf-8")))
        bundled = Path(__file__).resolve().parent.parent / "knowledge" / "patterns.json"
        if bundled.exists():
            return cls(json.loads(bundled.read_text(encoding="utf-8")))
        return cls([])

    def match(self, static: dict[str, Any], tool_text: str = "") -> list[Finding]:
        haystack = build_haystack(static, tool_text)
        strings = haystack["strings"]
        imports = haystack["imports"]
        sections = haystack["sections"]
        full_text = haystack["full_text"]
        findings: list[Finding] = []

        for pattern in self.patterns:
            evidence: list[str] = []
            indicators = pattern.get("indicators", {})

            for needle in indicators.get("strings", []):
                if string_indicator_match(needle, strings):
                    evidence.append(f"string:{needle}")
            for needle in indicators.get("imports", []):
                if needle.lower() in imports:
                    evidence.append(f"import:{needle}")
            for needle in indicators.get("sections", []):
                if needle.lower() in sections:
                    evidence.append(f"section:{needle}")
            for regex in indicators.get("regex", []):
                try:
                    if re.search(regex, "\n".join(strings), re.IGNORECASE):
                        evidence.append(f"regex:{regex}")
                except re.error:
                    continue

            entropy_min = indicators.get("entropy_min")
            if entropy_min is not None:
                overall = static.get("entropy", {}).get("overall", 0)
                if overall >= float(entropy_min):
                    evidence.append(f"entropy>={entropy_min}")

            if evidence:
                confidence = min(0.98, float(pattern.get("confidence", 0.5)) + 0.08 * (len(evidence) - 1))
                findings.append(
                    Finding(
                        category=pattern.get("category", "knowledge"),
                        title=pattern.get("name", pattern.get("id", "pattern match")),
                        severity=pattern.get("severity", "medium"),
                        confidence=round(confidence, 2),
                        evidence=evidence[:20],
                        source=f"knowledge:{pattern.get('id', 'unknown')}",
                        recommendation=pattern.get("recommendation"),
                    )
                )

        return sorted(findings, key=lambda item: severity_rank(item.severity), reverse=True)


def build_haystack(static: dict[str, Any], tool_text: str = "") -> dict[str, Any]:
    string_values = static.get("strings", {}).get("top", [])
    import_rows = static.get("pe", {}).get("imports", []) + static.get("elf", {}).get("imports", [])
    imports = [item.get("name", "").lower() for item in import_rows if item.get("name")]
    import_dlls = [item.get("dll", "").lower() for item in import_rows if item.get("dll")]
    sections = [item.get("name", "").lower() for item in static.get("sections", []) if item.get("name")]
    full_text = "\n".join(string_values + imports + import_dlls + sections + [tool_text]).lower()
    return {
        "strings": string_values,
        "imports": "\n".join(imports + import_dlls),
        "sections": "\n".join(sections),
        "full_text": full_text,
    }


def string_indicator_match(needle: str, values: list[str]) -> bool:
    if not needle:
        return False
    lowered = needle.lower()
    if re.fullmatch(r"[A-Za-z0-9_ -]+", needle):
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(lowered)}(?![A-Za-z0-9_])", re.IGNORECASE)
        return any(pattern.search(value) for value in values)
    return any(lowered in value.lower() for value in values)


def severity_rank(severity: str) -> int:
    return {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}.get(severity, 0)


def compact_tool_text(tools: dict[str, Any], limit: int = 200_000) -> str:
    chunks: list[str] = []
    for name, result in tools.items():
        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        if stdout:
            chunks.append(f"[{name}:stdout]\n{stdout[:limit]}")
        if stderr:
            chunks.append(f"[{name}:stderr]\n{stderr[:limit // 5]}")
    return "\n".join(chunks)[:limit]
