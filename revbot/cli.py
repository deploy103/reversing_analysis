from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from revbot.artifacts import load_extra_json
from revbot.collectors.tools import ExternalToolCollector
from revbot.config import api_config_from_env, env_status
from revbot.llm import LLMClient
from revbot.memory import AnalysisMemory
from revbot.pipeline import INTENSITIES, AnalysisPipeline
from revbot.reports import write_reports
from revbot.solver import SolveEngine, write_solve_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revbot",
        description="Semi-automated reverse engineering collector, agent, and report pipeline.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze one binary or challenge artifact.")
    analyze.add_argument("sample", type=Path, help="Path to the sample to analyze.")
    analyze.add_argument("--out", type=Path, default=Path("reports"), help="Report output directory.")
    analyze.add_argument("--env", type=Path, default=Path(".env"), help="Environment file containing API settings.")
    analyze.add_argument("--knowledge", type=Path, default=Path("knowledge/patterns.json"), help="Knowledgebase pattern JSON.")
    analyze.add_argument(
        "--api-intensity",
        choices=sorted(INTENSITIES),
        default="standard",
        help="LLM usage level. Use max/unlimited for aggressive multi-agent API usage.",
    )
    analyze.add_argument("--llm-rounds", type=int, default=2, help="Extra final synthesis rounds for max/unlimited modes.")
    analyze.add_argument("--llm-workers", type=int, default=4, help="Concurrent specialist LLM calls.")
    analyze.add_argument("--api-timeout", type=int, help="Override API timeout seconds for this run.")
    analyze.add_argument("--api-max-tokens", type=int, help="Override max output tokens per API call for this run.")
    analyze.add_argument("--tool-timeout", type=int, default=60, help="Per-tool timeout in seconds.")
    analyze.add_argument("--max-file-mb", type=int, default=128, help="Maximum bytes to load for static extraction.")
    analyze.add_argument("--no-tools", action="store_true", help="Skip external tool collectors.")
    analyze.add_argument("--memory", type=Path, default=Path("memory/revbot.sqlite3"), help="Long-term memory SQLite path.")
    analyze.add_argument("--no-memory", action="store_true", help="Do not store this analysis in long-term memory.")
    analyze.add_argument(
        "--extra-json",
        type=Path,
        action="append",
        default=[],
        help="Attach exported JSON from IDA, Ghidra, Frida, r2, Wireshark, or other lab tools.",
    )

    solve = sub.add_parser("solve", help="Try to solve a CTF/crackme artifact directly.")
    solve.add_argument("sample", type=Path, help="Path to the challenge artifact.")
    solve.add_argument("--out", type=Path, default=Path("reports"), help="Report output directory.")
    solve.add_argument("--tool-timeout", type=int, default=20)
    solve.add_argument("--max-file-mb", type=int, default=128)
    solve.add_argument("--execute", action="store_true", help="Run short stdin probes against the sample.")
    solve.add_argument("--exec-timeout", type=float, default=2.0)
    solve.add_argument("--wordlist", type=Path, action="append", default=[], help="Extra candidate inputs, one per line.")
    solve.add_argument("--candidate", action="append", default=[], help="Extra candidate input value.")
    solve.add_argument("--bruteforce-pin", action="store_true", help="Try bounded numeric PIN probes when --execute is enabled.")
    solve.add_argument("--max-probes", type=int, default=80, help="Maximum dynamic probes per mode or PIN width.")
    solve.add_argument("--validate-candidates", type=int, default=24, help="Number of ranked candidates to re-run across stdin/argv/env/file modes.")
    solve.add_argument("--aggressive", action="store_true", help="Enable execution probes, PIN probing, and a larger probe budget.")
    solve.add_argument("--ai", action="store_true", help="Use the configured API to synthesize solve evidence and next experiments.")
    solve.add_argument("--env", type=Path, default=Path(".env"), help="Environment file containing API settings.")
    solve.add_argument("--api-timeout", type=int, help="Override API timeout seconds for solve AI synthesis.")
    solve.add_argument("--api-max-tokens", type=int, help="Override max output tokens for solve AI synthesis.")
    solve.add_argument("--ai-rounds", type=int, default=1, help="Number of solve AI synthesis rounds.")
    solve.add_argument("--memory", type=Path, default=Path("memory/revbot.sqlite3"), help="Long-term memory SQLite path.")
    solve.add_argument("--no-memory", action="store_true", help="Do not store this solve result in long-term memory.")
    solve.add_argument(
        "--extra-json",
        type=Path,
        action="append",
        default=[],
        help="Attach exported JSON from IDA, Ghidra, r2, Frida, or other lab tools to solve evidence.",
    )

    batch = sub.add_parser("solve-dir", help="Solve every file in a directory.")
    batch.add_argument("directory", type=Path)
    batch.add_argument("--out", type=Path, default=Path("reports"))
    batch.add_argument("--execute", action="store_true")
    batch.add_argument("--recursive", action="store_true")
    batch.add_argument("--include-source", action="store_true", help="Include source files such as C/C++/Java/Go/Rust in solve-dir.")
    batch.add_argument("--include-text", action="store_true", help="Include text/JSON/Markdown files in solve-dir.")
    batch.add_argument("--tool-timeout", type=int, default=10)
    batch.add_argument("--exec-timeout", type=float, default=1.0)
    batch.add_argument("--wordlist", type=Path, action="append", default=[])
    batch.add_argument("--candidate", action="append", default=[])
    batch.add_argument("--bruteforce-pin", action="store_true", help="Try bounded numeric PIN probes when --execute is enabled.")
    batch.add_argument("--max-probes", type=int, default=80, help="Maximum dynamic probes per mode or PIN width.")
    batch.add_argument("--validate-candidates", type=int, default=24, help="Number of ranked candidates to re-run across stdin/argv/env/file modes.")
    batch.add_argument("--aggressive", action="store_true", help="Enable execution probes, PIN probing, and a larger probe budget.")
    batch.add_argument("--memory", type=Path, default=Path("memory/revbot.sqlite3"), help="Long-term memory SQLite path.")
    batch.add_argument("--no-memory", action="store_true", help="Do not store solve results in long-term memory.")
    batch.add_argument("--extra-json", type=Path, action="append", default=[], help="Attach exported JSON to every solve run.")

    tools = sub.add_parser("tools", help="Show external collector availability.")
    tools.add_argument("--json", action="store_true", help="Print machine-readable JSON.")

    env = sub.add_parser("env", help="Show API environment status without printing secret values.")
    env.add_argument("--env", type=Path, default=Path(".env"))

    probe = sub.add_parser("api-probe", help="Run a short API connectivity probe without analyzing a sample.")
    probe.add_argument("--env", type=Path, default=Path(".env"))
    probe.add_argument("--timeout", type=int, default=20)
    probe.add_argument("--max-tokens", type=int, default=64)

    memory = sub.add_parser("memory", help="Inspect long-term analysis memory.")
    memory.add_argument("--db", type=Path, default=Path("memory/revbot.sqlite3"))
    memory.add_argument("--limit", type=int, default=20)
    memory.add_argument("--similar", help="Show samples similar to this SHA256.")
    memory.add_argument("--solves", action="store_true", help="List stored direct solve results instead of analysis samples.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "tools":
        availability = ExternalToolCollector().availability()
        if args.json:
            print(json.dumps(availability, indent=2))
        else:
            for name, available in availability.items():
                print(f"{name}: {'available' if available else 'missing'}")
        return 0

    if args.command == "env":
        for key, present in env_status(args.env).items():
            print(f"{key}: {'set' if present else 'missing'}")
        return 0

    if args.command == "api-probe":
        api_config = replace(
            api_config_from_env(args.env),
            timeout_seconds=args.timeout,
            max_tokens=args.max_tokens,
        )
        response = LLMClient(api_config).chat(
            [
                {"role": "system", "content": "Reply with exactly: ok"},
                {"role": "user", "content": "probe"},
            ],
            temperature=0,
            max_tokens=args.max_tokens,
        )
        if response.ok:
            endpoint = response.raw.get("_revbot_endpoint") if response.raw else "unknown"
            print(f"ok: model={api_config.model} endpoint={endpoint}")
            print(response.content.strip())
            return 0
        print(f"failed: model={api_config.model}")
        print(response.error)
        print("Set APIM_CHAT_COMPLETIONS_URL or OPENAI_CHAT_COMPLETIONS_URL if your gateway uses a custom route.")
        return 1

    if args.command == "analyze":
        if not args.sample.exists():
            print(f"sample not found: {args.sample}", file=sys.stderr)
            return 2
        api_config = api_config_from_env(args.env)
        if args.api_timeout or args.api_max_tokens:
            api_config = replace(
                api_config,
                timeout_seconds=args.api_timeout or api_config.timeout_seconds,
                max_tokens=args.api_max_tokens or api_config.max_tokens,
            )
        pipeline = AnalysisPipeline(
            api_config=api_config,
            knowledge_path=args.knowledge,
            tool_timeout=args.tool_timeout,
            max_bytes=args.max_file_mb * 1024 * 1024,
            enable_tools=not args.no_tools,
            memory_path=args.memory,
            enable_memory=not args.no_memory,
        )
        extra_artifacts = load_extra_json(args.extra_json) if args.extra_json else []
        result = pipeline.analyze(
            args.sample,
            api_intensity=args.api_intensity,
            llm_rounds=args.llm_rounds,
            llm_workers=args.llm_workers,
            extra_artifacts=extra_artifacts,
        )
        paths = write_reports(result, args.out)
        print(f"JSON report: {paths['json']}")
        print(f"Markdown report: {paths['markdown']}")
        print(f"Experiments: {paths['experiments']}")
        print(f"Frida script: {paths['frida']}")
        llm = result.llm
        if llm.get("enabled"):
            print(f"LLM calls: {len(llm.get('calls', []))}")
        else:
            print(f"LLM: disabled ({llm.get('reason')})")
        return 0

    if args.command == "solve":
        if not args.sample.exists():
            print(f"sample not found: {args.sample}", file=sys.stderr)
            return 2
        engine = SolveEngine(
            tool_timeout=args.tool_timeout,
            execute=args.execute or args.aggressive,
            exec_timeout=args.exec_timeout,
            max_bytes=args.max_file_mb * 1024 * 1024,
            custom_inputs=load_wordlists(args.wordlist) + args.candidate,
            bruteforce_pin=args.bruteforce_pin or args.aggressive,
            max_probes=max(args.max_probes, 10_000) if args.aggressive else args.max_probes,
            validation_limit=args.validate_candidates,
        )
        extra_artifacts = load_extra_json(args.extra_json) if args.extra_json else []
        result = engine.solve(args.sample, extra_artifacts=extra_artifacts)
        if args.ai:
            result["ai"] = run_solve_ai(result, args.env, args.api_timeout, args.api_max_tokens, args.ai_rounds)
        if not args.no_memory:
            memory = AnalysisMemory(args.memory)
            try:
                result["memory"] = memory.store_solve(result)
            finally:
                memory.close()
        paths = write_solve_reports(result, args.out)
        print(f"Solve JSON: {paths['json']}")
        print(f"Solve Markdown: {paths['markdown']}")
        print(f"GDB script: {paths['gdb']}")
        print(f"angr script: {paths['angr']}")
        print(f"Frida script: {paths['frida']}")
        print(f"Candidate wordlist: {paths['candidates']}")
        candidates = result.get("candidates", [])
        if candidates:
            top = candidates[0]
            print(f"Top candidate: {top['value']} (confidence={top['confidence']}, source={top['source']})")
        else:
            print("Top candidate: none")
        return 0 if result.get("solved") else 1

    if args.command == "solve-dir":
        if not args.directory.exists() or not args.directory.is_dir():
            print(f"directory not found: {args.directory}", file=sys.stderr)
            return 2
        paths = discover_solve_targets(
            args.directory,
            recursive=args.recursive,
            include_source=args.include_source,
            include_text=args.include_text,
        )
        custom_inputs = load_wordlists(args.wordlist) + args.candidate
        extra_artifacts = load_extra_json(args.extra_json) if args.extra_json else []
        memory = AnalysisMemory(args.memory) if not args.no_memory else None
        solved = 0
        failed = 0
        summary_rows = []
        try:
            for path in paths:
                engine = SolveEngine(
                    tool_timeout=args.tool_timeout,
                    execute=args.execute or args.aggressive,
                    exec_timeout=args.exec_timeout,
                    custom_inputs=custom_inputs,
                    bruteforce_pin=args.bruteforce_pin or args.aggressive,
                    max_probes=max(args.max_probes, 10_000) if args.aggressive else args.max_probes,
                    validation_limit=args.validate_candidates,
                )
                result = engine.solve(path, extra_artifacts=extra_artifacts)
                if memory:
                    result["memory"] = memory.store_solve(result)
                out_dir = args.out / path.stem
                report_paths = write_solve_reports(result, out_dir)
                candidates = result.get("candidates", [])
                top = candidates[0] if candidates else None
                summary_rows.append(
                    {
                        "path": str(path),
                        "solved": bool(result.get("solved")),
                        "top_candidate": top.get("value") if top else None,
                        "top_source": top.get("source") if top else None,
                        "top_confidence": top.get("confidence") if top else None,
                        "report": str(report_paths["markdown"]),
                    }
                )
                if result.get("solved"):
                    solved += 1
                    print(f"[SOLVED] {path} -> {top['value']} ({top['source']})")
                else:
                    failed += 1
                    print(f"[TODO] {path} -> {report_paths['markdown']}")
        finally:
            if memory:
                memory.close()
        args.out.mkdir(parents=True, exist_ok=True)
        summary_path = args.out / "solve-dir-summary.json"
        summary_path.write_text(json.dumps(summary_rows, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"summary: solved={solved} unsolved={failed} total={len(paths)}")
        print(f"summary_json: {summary_path}")
        return 0 if failed == 0 else 1

    if args.command == "memory":
        memory = AnalysisMemory(args.db)
        try:
            if args.solves:
                rows = memory.list_solves(limit=args.limit)
            elif args.similar:
                rows = memory.similar(args.similar, limit=args.limit)
            else:
                rows = memory.list_samples(limit=args.limit)
        finally:
            memory.close()
        for row in rows:
            if args.solves:
                print(
                    f"{row['solved_at']} solved={row['solved']} {row['sha256']} {row['name']} "
                    f"top={row['top_candidate']} ({row['top_source']}, {row['top_confidence']})"
                )
            elif "score" in row:
                print(f"{row['score']:.4f} {row['sha256']} {row['name']} ({row['format']}, {row['size']} bytes)")
            else:
                print(f"{row['analyzed_at']} {row['sha256']} {row['name']} ({row['format']}, {row['size']} bytes)")
        return 0

    parser.print_help()
    return 1


def load_wordlists(paths: list[Path]) -> list[str]:
    values: list[str] = []
    for path in paths:
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
        except OSError as exc:
            print(f"wordlist read failed: {path}: {exc}", file=sys.stderr)
    return list(dict.fromkeys(values))


def run_solve_ai(
    result: dict[str, object],
    env_path: Path,
    timeout: int | None = None,
    max_tokens: int | None = None,
    rounds: int = 1,
) -> dict[str, object]:
    api_config = api_config_from_env(env_path)
    if timeout or max_tokens:
        api_config = replace(
            api_config,
            timeout_seconds=timeout or api_config.timeout_seconds,
            max_tokens=max_tokens or api_config.max_tokens,
        )
    if not api_config.enabled:
        return {"enabled": False, "reason": "API key or model is not configured"}
    client = LLMClient(api_config)
    outputs = []
    calls = []
    for index in range(max(1, rounds)):
        compact = json.dumps({**result, "previous_ai_outputs": outputs}, ensure_ascii=False, indent=2)[:80_000]
        response = client.chat(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a senior CTF reverse engineering analyst. Use only the provided solve evidence. "
                        "Separate confirmed facts from hypotheses. Be concrete and concise."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Review round {index + 1}. Return Markdown with: "
                        "confirmed solution status, candidate confidence review, likely verifier logic, "
                        "next experiments if unsolved, exact commands/hooks to try next, and what evidence would falsify the current hypothesis.\n\n"
                        f"Solve JSON:\n{compact}"
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=api_config.max_tokens,
        )
        calls.append({"round": index + 1, "ok": response.ok, "usage": response.usage, "error": response.error})
        outputs.append(response.content if response.ok else f"ERROR: {response.error}")
    return {
        "enabled": True,
        "ok": all(call["ok"] for call in calls),
        "model": api_config.model,
        "rounds": max(1, rounds),
        "content": "\n\n".join(outputs),
        "calls": calls,
        "usage": {"rounds": [call["usage"] for call in calls]},
        "error": "; ".join(str(call["error"]) for call in calls if call.get("error")) or None,
    }


def discover_solve_targets(
    directory: Path,
    recursive: bool = False,
    include_source: bool = False,
    include_text: bool = False,
) -> list[Path]:
    iterator = directory.rglob("*") if recursive else directory.iterdir()
    targets = []
    source_suffixes = {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".cs", ".go", ".rs"}
    text_suffixes = {".md", ".txt", ".json", ".map"}
    for path in iterator:
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        suffix = path.suffix.lower()
        if not include_source and suffix in source_suffixes:
            continue
        if not include_text and suffix in text_suffixes:
            continue
        targets.append(path)
    return sorted(targets)


if __name__ == "__main__":
    raise SystemExit(main())
