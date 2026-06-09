# Reverse Researcher

Semi-automated reverse engineering research assistant for CTF, malware triage, license-check analysis, and binary audit workflows.

The project follows the model you described: tools collect evidence, deterministic agents prioritize it, and OpenAI/APIM produces high-spend synthesis when requested.

## Quick Start

Check API configuration without leaking secrets:

```bash
python3 -m revbot.cli env
```

Probe the configured API route:

```bash
python3 -m revbot.cli api-probe
```

Check installed collectors:

```bash
python3 -m revbot.cli tools
```

Analyze a sample without API calls:

```bash
python3 -m revbot.cli analyze ./samples/challenge.exe --api-intensity off
```

Try to solve a CTF/crackme directly:

```bash
python3 -m revbot.cli solve ./samples/challenge
```

Allow short stdin execution probes for local trusted CTF binaries:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute
```

`--execute` also tries argv, raw stdin, multi-line login/password stdin payloads, common environment variables, and common input files (`input.txt`, `key.txt`, `flag.txt`, `password.txt`, `serial.txt`, `secret.txt`, `license.key`, and related names). On dynamically linked ELF files, it compiles a temporary `LD_PRELOAD` hook for `strcmp`, `strncmp`, `strcasecmp`, `memcmp`, `strstr`, `getenv`, `fopen`, `open`, `access`, `fgets`, `scanf`, `atoi`, and `strtol`. This often reveals comparisons such as `strcmp(test, real_password)` without needing `ltrace`, and it can discover non-standard environment variable names or local input files before retrying candidates there.

Current direct-solve coverage includes:

- ELF crackmes using stdin, argv, environment variables, or local input files.
- `strcmp`, `strncmp`, `strcasecmp`, and `memcmp` comparison extraction.
- Simple add/sub/xor transform inference from comparison traces.
- Literal, base64/base64url, base32, base58, base85/ascii85, quoted-printable, hex, binary, percent, escape, HTML entity, morse, UTF-16/UTF-32 wrapped encodings, rot13, rot47, Caesar, Atbash, reverse/reversed-encoding, single-byte XOR, byte shift, byte rotate, repeating-key XOR, and RC4 flag recovery.
- Embedded gzip/zlib/bzip2/xz stream decompression, including tar archives inside compressed streams.
- Embedded MD5/SHA1/SHA256/SHA512 digest cracking against CTF wordlists and numeric PIN ranges.
- Static char-check candidates from `objdump` immediates, indexed byte compares, and `movzx`-then-register-compare patterns.
- ZIP/APK/JAR/TAR embedded string and source extraction, archive comments, file comments, and nested archives.
- PNG `tEXt`, `zTXt`, and `iTXt` metadata extraction.
- Python `.py` and `.pyc` string and numeric constants.
- Script/source files such as `.js`, `.py`, `.lua`, `.rb`, `.php`, `.sh`, `.c`, `.cpp`, `.java`, `.cs`, `.go`, and `.rs`, including numeric byte arrays, direct comparison literals, char literal arrays, source-context decoded inputs, and Brainfuck output programs.
- Repeating-XOR and RC4 retries with key strings recovered from the sample, including appended encrypted payloads after metadata or null separators.

Bounded numeric PIN probing is opt-in:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute --bruteforce-pin --max-probes 10000
```

For local trusted CTF binaries where speed matters more than caution:

```bash
python3 -m revbot.cli solve ./samples/challenge --aggressive
```

Add your own probes:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute --wordlist ./candidates.txt --candidate admin123
```

Ask the configured OpenAI/APIM route to synthesize solve evidence and next experiments:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute --ai --ai-rounds 3 --api-max-tokens 4000
```

Batch solve a directory:

```bash
python3 -m revbot.cli solve-dir ./samples --execute --recursive
```

Include source or text-heavy challenge folders when needed:

```bash
python3 -m revbot.cli solve-dir ./challenges --recursive --include-source --include-text
```

Batch runs write `solve-dir-summary.json` under the output directory.

Aggressive OpenAI/APIM analysis:

```bash
python3 -m revbot.cli analyze ./samples/challenge.exe --api-intensity unlimited --llm-rounds 8 --llm-workers 12 --tool-timeout 120
```

Short API smoke test:

```bash
python3 -m revbot.cli analyze /bin/true --api-intensity light --api-timeout 15 --api-max-tokens 800 --no-memory
```

Attach exported disassembler evidence:

```bash
python3 -m revbot.cli analyze ./samples/challenge.exe --api-intensity max --extra-json ./challenge.revbot.ida.json
```

The same exported evidence can feed direct solve mode:

```bash
python3 -m revbot.cli solve ./samples/challenge --execute --extra-json ./challenge.revbot.ghidra.json
```

Reports are written to `reports/` as:

- `*.analysis.json`: complete machine-readable evidence.
- `*.report.md`: analyst-facing report.
- `*.experiments.md`: validation checklist.
- `*.frida.js`: generated Frida hook starter.
- `*.solve.md` / `*.solve.json`: direct CTF solve candidates from `revbot solve`.
- `*.candidates.txt`: ranked candidate wordlist for reuse in debuggers or custom probes.
- `*.gdb`: breakpoints for comparison functions detected during solve.
- `*.angr.py`: symbolic-execution starter using stdout find/avoid conditions.
- `*.solve.frida.js`: comparison and input-source hook starter from solve output.

Long-term memory is stored in `memory/revbot.sqlite3` by default. Inspect it with:

```bash
python3 -m revbot.cli memory
```

Direct solve results are stored there too:

```bash
python3 -m revbot.cli memory --solves
```

## Environment

The existing `.env` format is supported:

```env
APIM_BASE_URL=...
APIM_KEY=...
CHAT_MODEL=...
EMBEDDING_MODEL=...
VISION_MODEL=...
```

Native OpenAI-style variables are also supported:

```env
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=...
```

For custom gateways, set:

```env
APIM_AUTH_HEADER=your-header-name
```

If your gateway already exposes an exact chat-completions or responses URL, use:

```env
APIM_CHAT_COMPLETIONS_URL=https://gateway.example/v1/chat/completions
APIM_RESPONSES_URL=https://gateway.example/v1/responses
```

Azure/OpenAI deployment-style gateways are also supported:

```env
APIM_BASE_URL=https://gateway.example/openai/deployments/my-deployment
APIM_API_VERSION=2024-02-15-preview
OPENAI_OMIT_MODEL=true
```

The client also retries the common Microsoft Foundry paths automatically:

- `/openai/v1/chat/completions`
- `/models/chat/completions?api-version=2024-05-01-preview`
- `/openai/deployments/{deployment}/chat/completions?api-version=...`
- `/openai/v1/responses`
- `/models/responses?api-version=2024-05-01-preview`

## Design

Reverse Researcher does not pretend that an LLM can accurately execute, decompile, patch, or inspect memory. The LLM is used as an analyst over collected evidence.

Current agents:

- Packer Agent
- Anti-Analysis Agent
- Crypto Agent
- Network Agent
- Malware Agent
- Windows Internals Agent
- License Agent
- Vulnerability Agent
- CTF Agent

See `docs/ARCHITECTURE.md`, `docs/API_GATEWAY.md`, `docs/INTEGRATIONS.md`, and `docs/ROADMAP.md` for the portfolio architecture.
For a concise submission-oriented explanation, use `docs/PORTFOLIO.md`.
