# Roadmap

## Phase 1: Current MVP

- Static file identification and hashing.
- PE section/import parser.
- String, URL, registry, path, CTF anchor extraction.
- External tool collector interface.
- Knowledgebase matching.
- Specialist agent reports.
- OpenAI/APIM-backed multi-agent synthesis.
- Markdown and JSON reports.
- SQLite long-term memory and similarity lookup.
- Experiment checklist and Frida starter generation.

## Phase 2: Tool Plugins

- Ghidra headless exporter for functions, xrefs, decompiler output, call graphs.
- IDA Python exporter for names, comments, functions, imports, strings, and pseudocode.
- Binary Ninja exporter for MLIL/HLIL summaries.
- radare2 project exporter for functions, xrefs, strings, sections, and graph data.
- x64dbg/WinDbg trace import.
- Frida experiment runner for hook scripts and buffer dumps.
- Wireshark/tshark and Burp log import.

The first IDA, Ghidra, Frida, and r2 integration templates are already present under `integrations/`.

## Phase 3: Verification Loop

- Generate hypotheses from agent findings.
- Convert hypotheses into debugger or Frida experiments.
- Execute in a disposable lab when explicitly enabled.
- Ingest traces, memory dumps, packet captures, and API logs.
- Re-rank hypotheses based on observed behavior.

## Phase 4: Long-Term Memory

- Store sample hashes, extracted features, solved CTF patterns, unpacking notes, crypto routines, and protocol notes.
- Similarity search across old samples.
- Reuse prior solve paths for related DreamHack-style challenges.
