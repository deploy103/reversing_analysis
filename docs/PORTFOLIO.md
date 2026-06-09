# Portfolio Brief

Reverse Researcher is a semi-automated reverse engineering lab assistant. It is built around a strict separation of responsibilities:

- External tools collect evidence.
- Deterministic agents rank and explain evidence.
- OpenAI/APIM performs synthesis when high-spend analysis is requested.
- Reports preserve uncertainty instead of pretending static analysis proves runtime behavior.

## What It Demonstrates

- Binary triage for PE and ELF.
- Extensible collector architecture for `rabin2`, `capa`, `floss`, Detect-It-Easy, IDA, Ghidra, Frida, and r2.
- Multi-agent analysis with packer, anti-analysis, crypto, network, malware, Windows internals, license, vulnerability, and CTF perspectives.
- Knowledgebase-backed detection for common packers, anti-debugging, crypto APIs, network indicators, licensing signals, and CTF anchors.
- Long-term memory with SQLite similarity search.
- Validation experiment generation with Markdown checklists and Frida hook scripts.
- Direct solve mode for CTF/crackme tasks using literal flags, base64/base64url/base32/base58/hex/percent/escape/HTML/morse/rot47 decoding, single-byte and repeating-key XOR search, gzip/zlib/bzip2/xz extraction, embedded hash cracking, numeric-array recovery, comparison import detection, stdin/raw-stdin/argv/env/file/multi-line probes, optional bounded PIN brute force, objdump function ranking and char-check recovery, Python bytecode constants, ZIP/APK/JAR/TAR embedded strings, script decoding, transform inference, and temporary `LD_PRELOAD` hooks for comparisons plus input-source discovery.
- API intensity modes that allow aggressive OpenAI/APIM usage for deep analysis.
- Optional `revbot solve --ai` synthesis that feeds deterministic solve evidence back through the configured API for analyst-style next-step planning.

## Demo Flow

1. Put a challenge binary in `samples/`.
2. Run static triage:

```bash
python3 -m revbot.cli analyze ./samples/challenge --api-intensity off
```

Run direct solve mode:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute
```

3. Export function context from IDA or Ghidra.
4. Re-run with exported evidence and full API synthesis:

```bash
python3 -m revbot.cli analyze ./samples/challenge \
  --extra-json ./challenge.revbot.ida.json \
  --api-intensity unlimited \
  --llm-rounds 8 \
  --llm-workers 12
```

5. Review:

- `reports/*.report.md`
- `reports/*.analysis.json`
- `reports/*.experiments.md`
- `reports/*.frida.js`

## Engineering Notes

- The project intentionally avoids third-party Python dependencies so it runs in constrained lab environments.
- The `.env` checker reports only whether credentials exist; it does not print secrets.
- Missing external tools are represented as evidence, not hard failures.
- Generated Frida scripts are validation aids; dynamic execution stays under analyst control.

## Limitations

- Exact decompilation and memory inspection require IDA/Ghidra/debugger/Frida exports.
- Static heuristics can produce false positives, so the report labels findings as hypotheses until validated.
- The current core implements PE and ELF parsing; Mach-O, Android DEX, and full packet importers are extension targets.
