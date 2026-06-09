from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from revbot.models import AnalysisResult, Finding


def write_reports(result: AnalysisResult, output_dir: Path | str) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = safe_stem(result.file.get("name", "sample"))
    json_path = out / f"{stem}.analysis.json"
    md_path = out / f"{stem}.report.md"
    experiments_path = out / f"{stem}.experiments.md"
    frida_path = out / f"{stem}.frida.js"
    json_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(result), encoding="utf-8")
    experiments_path.write_text(render_experiments_markdown(result.experiments), encoding="utf-8")
    frida_path.write_text(render_frida_script(result.experiments), encoding="utf-8")
    return {"json": json_path, "markdown": md_path, "experiments": experiments_path, "frida": frida_path}


def safe_stem(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in name).strip("._") or "sample"


def render_markdown(result: AnalysisResult) -> str:
    data = result.to_dict()
    lines: list[str] = []
    file_info = data["file"]
    lines.append(f"# Reverse Research Report: {file_info.get('name')}")
    lines.append("")
    lines.append("## Executive Snapshot")
    lines.append(f"- Format: `{file_info.get('format')}`")
    lines.append(f"- Size: `{file_info.get('size')}` bytes")
    lines.append(f"- SHA256: `{file_info.get('sha256')}`")
    lines.append(f"- API intensity: `{data.get('metadata', {}).get('api_intensity')}`")
    lines.append("")

    signals = data["static"].get("signals", {})
    lines.append("## Static Signals")
    for key in [
        "likely_packed",
        "anti_debug_imports",
        "injection_imports",
        "network_imports",
        "crypto_imports",
        "ctf_strings",
        "mentions_vm_or_debug",
        "mentions_crypto",
    ]:
        value = signals.get(key)
        if value:
            lines.append(f"- `{key}`: {json.dumps(value, ensure_ascii=False)[:1200]}")
    if not any(signals.get(key) for key in signals):
        lines.append("- No high-confidence static signals were found.")
    lines.append("")

    lines.append("## Sections")
    sections = data["static"].get("sections", [])
    if sections:
        lines.append("| Name | RVA | Raw Size | Entropy | R | W | X |")
        lines.append("|---|---:|---:|---:|:--:|:--:|:--:|")
        for section in sections[:40]:
            lines.append(
                f"| `{section.get('name')}` | `{section.get('virtual_address')}` | `{section.get('raw_size')}` | "
                f"`{section.get('entropy')}` | {'Y' if section.get('readable') else ''} | "
                f"{'Y' if section.get('writable') else ''} | {'Y' if section.get('executable') else ''} |"
            )
    else:
        lines.append("- No section table was parsed.")
    lines.append("")

    lines.append("## Knowledge Matches")
    add_findings(lines, [Finding(**item) for item in data.get("knowledge_matches", [])])

    lines.append("## Ranked Functions")
    ranked = data.get("artifacts", {}).get("ranked_functions", [])
    if ranked:
        for function in ranked[:20]:
            reasons = ", ".join(function.get("reasons", []))
            lines.append(f"- `{function.get('name')}` score={function.get('score')} reasons={reasons}")
    else:
        lines.append("- No ranked functions are available. Export IDA/Ghidra evidence to enable this.")
    lines.append("")

    lines.append("## Agent Findings")
    for agent in data.get("agents", []):
        lines.append(f"### {agent['name']}")
        lines.append(agent.get("summary", ""))
        add_findings(lines, [Finding(**item) for item in agent.get("findings", [])])
        hypotheses = agent.get("hypotheses", [])
        if hypotheses:
            lines.append("Hypotheses:")
            for hypothesis in hypotheses:
                lines.append(f"- **{hypothesis['title']}** ({hypothesis['confidence']:.2f})")
                for step in hypothesis.get("validation_steps", [])[:6]:
                    lines.append(f"  - {step}")
        actions = agent.get("next_actions", [])
        if actions:
            lines.append("Next actions:")
            for action in actions[:8]:
                lines.append(f"- {action}")
        lines.append("")

    lines.append("## External Tools")
    for name, item in data.get("tools", {}).items():
        status = "available" if item.get("available") else "missing"
        detail = item.get("error") or f"exit={item.get('exit_code')}"
        lines.append(f"- `{name}`: {status}, {detail}")
    if not data.get("tools"):
        lines.append("- External tool collection was disabled.")
    lines.append("")

    artifacts = data.get("metadata", {}).get("extra_artifacts", [])
    if artifacts:
        lines.append("## Extra Artifacts")
        for artifact in artifacts:
            status = "loaded" if artifact.get("loaded") else "failed"
            source = artifact.get("data", {}).get("source") if isinstance(artifact.get("data"), dict) else None
            lines.append(f"- `{artifact.get('path')}`: {status}" + (f", source={source}" if source else ""))
        lines.append("")

    experiments = data.get("experiments", {})
    lines.append("## Validation Plan")
    for item in experiments.get("checklist", []):
        lines.append(f"- {item}")
    targets = experiments.get("hook_targets", [])
    if targets:
        lines.append("")
        lines.append("Hook targets:")
        for target in targets[:30]:
            lines.append(f"- `{target.get('name')}`: {target.get('category')}")
    lines.append("")

    memory = data.get("memory", {})
    lines.append("## Long-Term Memory")
    if memory.get("stored"):
        lines.append(f"- Stored in `{memory.get('path')}`")
        similar = memory.get("similar", [])
        if similar:
            lines.append("- Similar prior samples:")
            for item in similar:
                lines.append(f"  - `{item.get('name')}` score={item.get('score')} sha256={item.get('sha256')}")
        else:
            lines.append("- No similar prior samples were found.")
    else:
        lines.append("- Memory storage was disabled or unavailable.")
    lines.append("")

    llm = data.get("llm", {})
    lines.append("## LLM Synthesis")
    if not llm.get("enabled"):
        lines.append(f"- Disabled: {llm.get('reason')}")
    else:
        lines.append(f"- Model: `{llm.get('model')}`")
        lines.append(f"- Calls: `{len(llm.get('calls', []))}`")
        for index, content in enumerate(llm.get("final", []), start=1):
            lines.append(f"### Final Round {index}")
            lines.append(content or "(empty)")
            lines.append("")
    lines.append("")

    lines.append("## Limitations")
    lines.append("- Static analysis does not prove runtime behavior.")
    lines.append("- Dynamic execution, memory dumps, and debugger traces must be collected separately.")
    lines.append("- Findings are prioritized hypotheses unless validated by tool output or execution evidence.")
    lines.append("")
    return "\n".join(lines)


def render_experiments_markdown(plan: dict[str, Any]) -> str:
    lines = ["# Validation Experiments", ""]
    lines.append("## Checklist")
    for item in plan.get("checklist", []):
        lines.append(f"- {item}")
    if not plan.get("checklist"):
        lines.append("- No checklist items were generated.")
    lines.append("")
    lines.append("## Hook Targets")
    targets = plan.get("hook_targets", [])
    if targets:
        for target in targets:
            lines.append(f"- `{target['name']}`: {target['category']}")
    else:
        lines.append("- No high-priority hook targets were detected from imports.")
    lines.append("")
    lines.append("## Ranked Functions")
    ranked = plan.get("ranked_functions", [])
    if ranked:
        for function in ranked[:30]:
            reasons = ", ".join(function.get("reasons", []))
            lines.append(f"- `{function.get('name')}` score={function.get('score')} reasons={reasons}")
    else:
        lines.append("- No exported function ranking is available. Run the IDA or Ghidra exporter for this.")
    lines.append("")
    lines.append("## Hypotheses")
    hypotheses = plan.get("hypotheses", [])
    if hypotheses:
        for hypothesis in hypotheses[:40]:
            lines.append(f"- **{hypothesis.get('title')}** confidence={hypothesis.get('confidence')}")
            for step in hypothesis.get("validation_steps", [])[:6]:
                lines.append(f"  - {step}")
    else:
        lines.append("- No hypotheses were generated.")
    lines.append("")
    return "\n".join(lines)


def render_frida_script(plan: dict[str, Any]) -> str:
    targets = [target["name"] for target in plan.get("hook_targets", [])]
    if not targets:
        targets = ["strcmp", "strncmp", "memcmp", "send", "recv", "IsDebuggerPresent"]
    payload = json.dumps(targets, indent=2)
    return f"""// Auto-generated by Reverse Researcher.
// Usage: frida -f ./sample -l this_file.js --no-pause

const targets = {payload};

function tryReadString(ptrValue) {{
  try {{
    if (ptrValue.isNull()) return "";
    return ptrValue.readCString();
  }} catch (e) {{
    return "";
  }}
}}

function hookExport(name) {{
  const address = Module.findExportByName(null, name);
  if (!address) return;
  Interceptor.attach(address, {{
    onEnter(args) {{
      send({{
        type: "enter",
        name,
        args: [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()],
        s0: tryReadString(args[0]),
        s1: tryReadString(args[1])
      }});
    }},
    onLeave(retval) {{
      send({{ type: "leave", name, retval: retval.toString() }});
    }}
  }});
}}

for (const name of targets) {{
  hookExport(name);
}}
"""


def add_findings(lines: list[str], findings: list[Finding]) -> None:
    if not findings:
        lines.append("- No findings.")
        lines.append("")
        return
    for finding in findings:
        lines.append(
            f"- **{finding.title}** [{finding.severity}, confidence={finding.confidence:.2f}]"
        )
        if finding.evidence:
            lines.append(f"  - Evidence: {', '.join(finding.evidence[:12])}")
        if finding.recommendation:
            lines.append(f"  - Recommendation: {finding.recommendation}")
    lines.append("")
