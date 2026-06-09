# Reverse Researcher Architecture

Reverse Researcher is designed as a semi-automated analyst, not as a fake decompiler. The system collects evidence from tools, normalizes it into JSON, runs deterministic specialist agents, and optionally spends OpenAI/APIM calls for deeper synthesis.

## Pipeline

1. File identity: hashes, magic, format, size.
2. Static extraction: strings, entropy, PE sections, PE imports, CTF anchors.
3. Tool collectors: `file`, `rabin2`, `capa`, `floss`, `diec` when installed.
4. Knowledgebase matching: packers, protectors, anti-debugging, crypto, network, licensing, CTF patterns.
5. Specialist agents: packer, anti-analysis, crypto, network, malware, Windows internals, license, vulnerability, CTF.
6. Artifact normalization: IDA/Ghidra/r2/Frida JSON is merged into ranked function and import evidence.
7. Experiment planning: Markdown validation checklist and Frida hook script generation.
8. Solve engine: direct CTF candidates from literals, encodings, XOR, compressed blobs, hash cracking, comparator imports, stdin/raw-stdin/argv/env/file/multi-line probes, optional bounded PIN brute force, LD_PRELOAD comparison and input-source hooks, Python/script constants, objdump char-check recovery, and ZIP/APK/JAR/TAR embedded strings.
9. Long-term memory: SQLite feature storage and similarity lookup.
10. LLM synthesis: optional multi-call analysis using `.env` API settings.
11. Reports: full JSON and portfolio-grade Markdown.

## API Intensity

`--api-intensity` controls how aggressively the LLM is used:

- `off`: no API calls.
- `light`: one final synthesis call.
- `standard`: selected specialist calls plus final synthesis.
- `max`: all specialist agents plus multiple final synthesis rounds.
- `unlimited`: no local call-budget cap beyond bounded evidence and configured rounds.

Use this for high-spend analysis:

```bash
python3 -m revbot.cli analyze ./samples/challenge.exe --api-intensity unlimited --llm-rounds 8
```

Increase concurrent specialist calls:

```bash
python3 -m revbot.cli analyze ./samples/challenge.exe --api-intensity unlimited --llm-rounds 8 --llm-workers 12
```

The code intentionally does not print secret values from `.env`.

## Output Files

- `*.analysis.json`: complete evidence graph.
- `*.report.md`: analyst-facing report.
- `*.experiments.md`: validation plan.
- `*.frida.js`: generated hook starter.
- `memory/revbot.sqlite3`: reusable long-term memory.

## Why This Shape

Reverse engineering accuracy comes from evidence. The LLM receives structured context and is asked to separate facts from hypotheses. Dynamic execution, memory analysis, and patching remain external tool responsibilities and are represented as validation steps unless tool output proves they happened.
