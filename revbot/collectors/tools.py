from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from revbot.models import ToolResult


CommandBuilder = Callable[[Path], list[str]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    command: CommandBuilder
    json_output: bool = False


def default_tool_specs() -> list[ToolSpec]:
    return [
        ToolSpec("file", "file", lambda path: ["file", "-b", str(path)]),
        ToolSpec("strings_ascii", "strings", lambda path: ["strings", "-a", "-n", "4", str(path)]),
        ToolSpec("readelf_header", "readelf", lambda path: ["readelf", "-h", str(path)]),
        ToolSpec("readelf_sections", "readelf", lambda path: ["readelf", "-SW", str(path)]),
        ToolSpec("readelf_symbols", "readelf", lambda path: ["readelf", "-Ws", str(path)]),
        ToolSpec("readelf_relocs", "readelf", lambda path: ["readelf", "-Wr", str(path)]),
        ToolSpec("objdump_imports", "objdump", lambda path: ["objdump", "-T", str(path)]),
        ToolSpec("objdump_disasm", "objdump", lambda path: ["objdump", "-d", "-M", "intel", str(path)]),
        ToolSpec("nm_symbols", "nm", lambda path: ["nm", "-an", str(path)]),
        ToolSpec("rabin2_info", "rabin2", lambda path: ["rabin2", "-Ij", str(path)], True),
        ToolSpec("rabin2_imports", "rabin2", lambda path: ["rabin2", "-ij", str(path)], True),
        ToolSpec("rabin2_sections", "rabin2", lambda path: ["rabin2", "-Sj", str(path)], True),
        ToolSpec("rabin2_strings", "rabin2", lambda path: ["rabin2", "-zzj", str(path)], True),
        ToolSpec("rabin2_symbols", "rabin2", lambda path: ["rabin2", "-sj", str(path)], True),
        ToolSpec("r2_functions", "r2", lambda path: ["r2", "-2", "-q", "-c", "aaa;aflj", str(path)], True),
        ToolSpec("capa", "capa", lambda path: ["capa", "-j", str(path)], True),
        ToolSpec("floss", "floss", lambda path: ["floss", "-j", str(path)], True),
        ToolSpec("die", "diec", lambda path: ["diec", "-j", str(path)], True),
    ]


class ExternalToolCollector:
    def __init__(self, timeout_seconds: int = 60, specs: list[ToolSpec] | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.specs = specs or default_tool_specs()

    def collect(self, sample_path: Path | str) -> dict[str, ToolResult]:
        path = Path(sample_path)
        results: dict[str, ToolResult] = {}
        for spec in self.specs:
            results[spec.name] = self._run_tool(spec, path)
        return results

    def availability(self) -> dict[str, bool]:
        return {spec.name: bool(shutil.which(spec.binary)) for spec in self.specs}

    def _run_tool(self, spec: ToolSpec, path: Path) -> ToolResult:
        resolved = shutil.which(spec.binary)
        if not resolved:
            return ToolResult(
                name=spec.name,
                available=False,
                command=spec.command(path),
                error=f"{spec.binary} is not installed or not on PATH",
            )

        command = spec.command(path)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            parsed = None
            if spec.json_output and completed.stdout.strip():
                try:
                    parsed = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    parsed = None
            return ToolResult(
                name=spec.name,
                available=True,
                command=command,
                exit_code=completed.returncode,
                duration_ms=duration_ms,
                stdout=completed.stdout[:2_000_000],
                stderr=completed.stderr[:500_000],
                parsed=parsed,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                name=spec.name,
                available=True,
                command=command,
                duration_ms=int((time.monotonic() - started) * 1000),
                stdout=(exc.stdout or "")[:500_000] if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "")[:500_000] if isinstance(exc.stderr, str) else "",
                error=f"timed out after {self.timeout_seconds}s",
            )
