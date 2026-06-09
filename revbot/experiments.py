from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from revbot.models import AnalysisResult
from revbot.reports import safe_stem


HOOK_CANDIDATES = {
    "IsDebuggerPresent": "anti-debug",
    "CheckRemoteDebuggerPresent": "anti-debug",
    "NtQueryInformationProcess": "anti-debug",
    "strcmp": "comparison",
    "strncmp": "comparison",
    "memcmp": "comparison",
    "lstrcmpA": "comparison",
    "lstrcmpW": "comparison",
    "CryptDecrypt": "crypto",
    "CryptEncrypt": "crypto",
    "BCryptDecrypt": "crypto",
    "BCryptEncrypt": "crypto",
    "send": "network",
    "recv": "network",
    "connect": "network",
    "InternetOpenUrlA": "network",
    "InternetOpenUrlW": "network",
    "VirtualAlloc": "memory",
    "VirtualAllocEx": "injection",
    "WriteProcessMemory": "injection",
    "CreateRemoteThread": "injection",
}


def build_experiment_plan(result: AnalysisResult) -> dict[str, Any]:
    imports = collect_import_names(result)
    hook_targets = [
        {"name": name, "category": category}
        for name, category in HOOK_CANDIDATES.items()
        if name.lower() in imports
    ]
    hypotheses = []
    for agent in result.agents:
        for hypothesis in agent.hypotheses:
            hypotheses.append(hypothesis.to_dict())

    ranked_functions = result.artifacts.get("ranked_functions", []) if result.artifacts else []
    checklist = [
        "Open the sample in Ghidra/IDA and rename ranked functions first.",
        "Set breakpoints or Frida hooks on listed hook targets.",
        "Dump input/output buffers around comparison and crypto calls.",
        "Re-run this pipeline with exported JSON after each manual analysis pass.",
    ]
    if result.static.get("signals", {}).get("likely_packed"):
        checklist.insert(0, "Unpack or dump the original image before trusting function-level static analysis.")
    if result.static.get("strings", {}).get("categories", {}).get("ctf"):
        checklist.insert(0, "Trace xrefs to CTF success/failure strings before broad exploration.")

    return {
        "hook_targets": hook_targets,
        "hypotheses": hypotheses,
        "ranked_functions": ranked_functions[:30],
        "checklist": checklist,
    }


def collect_import_names(result: AnalysisResult) -> set[str]:
    imports = set()
    for source in (result.static.get("pe", {}), result.static.get("elf", {})):
        for item in source.get("imports", []):
            name = str(item.get("name", ""))
            if name:
                imports.add(name.lower())
    for item in result.artifacts.get("imports", []) if result.artifacts else []:
        name = str(item.get("name", ""))
        if name:
            imports.add(name.lower())
    return imports


def write_experiment_artifacts(result: AnalysisResult, output_dir: Path | str) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = safe_stem(result.file.get("name", "sample"))
    plan = build_experiment_plan(result)
    result.experiments = plan

    md_path = out / f"{stem}.experiments.md"
    frida_path = out / f"{stem}.frida.js"
    md_path.write_text(render_experiments_markdown(plan), encoding="utf-8")
    frida_path.write_text(render_frida_script(plan), encoding="utf-8")
    return {"experiments": md_path, "frida": frida_path}


def render_experiments_markdown(plan: dict[str, Any]) -> str:
    lines = ["# Validation Experiments", ""]
    lines.append("## Checklist")
    for item in plan.get("checklist", []):
        lines.append(f"- {item}")
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
    for function in plan.get("ranked_functions", [])[:30]:
        reasons = ", ".join(function.get("reasons", []))
        lines.append(f"- `{function.get('name')}` score={function.get('score')} reasons={reasons}")
    if not plan.get("ranked_functions"):
        lines.append("- No exported function ranking is available. Run the IDA or Ghidra exporter for this.")
    lines.append("")
    lines.append("## Hypotheses")
    for hypothesis in plan.get("hypotheses", [])[:40]:
        lines.append(f"- **{hypothesis.get('title')}** confidence={hypothesis.get('confidence')}")
        for step in hypothesis.get("validation_steps", [])[:6]:
            lines.append(f"  - {step}")
    if not plan.get("hypotheses"):
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
      this.name = name;
      this.arg0 = args[0];
      this.arg1 = args[1];
      send({{
        type: "enter",
        name,
        args: [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()],
        s0: tryReadString(args[0]),
        s1: tryReadString(args[1])
      }});
    }},
    onLeave(retval) {{
      send({{ type: "leave", name: this.name, retval: retval.toString() }});
    }}
  }});
}}

for (const name of targets) {{
  hookExport(name);
}}
"""

