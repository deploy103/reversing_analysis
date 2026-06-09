from __future__ import annotations

from typing import Any

from revbot.models import AgentReport, Finding, Hypothesis


def run_agents(static: dict[str, Any], knowledge_matches: list[Finding]) -> list[AgentReport]:
    ctx = AgentContext(static, knowledge_matches)
    agents = [
        PackerAgent(),
        AntiAnalysisAgent(),
        CryptoAgent(),
        NetworkAgent(),
        MalwareAgent(),
        WindowsInternalsAgent(),
        LicenseAgent(),
        VulnerabilityAgent(),
        CtfAgent(),
    ]
    return [agent.run(ctx) for agent in agents]


class AgentContext:
    def __init__(self, static: dict[str, Any], knowledge_matches: list[Finding]) -> None:
        self.static = static
        self.knowledge_matches = knowledge_matches
        self.strings = static.get("strings", {}).get("top", [])
        self.lower_strings = [item.lower() for item in self.strings]
        self.pe_imports = static.get("pe", {}).get("imports", []) + static.get("elf", {}).get("imports", [])
        self.import_names = {item.get("name", "").lower() for item in self.pe_imports}
        self.dlls = {item.get("dll", "").lower() for item in self.pe_imports}
        self.sections = static.get("sections", [])
        self.signals = static.get("signals", {})

    def has_import(self, *names: str) -> list[str]:
        needles = {name.lower() for name in names}
        return sorted(self.import_names & needles)

    def strings_containing(self, *needles: str, limit: int = 25) -> list[str]:
        lowered = [needle.lower() for needle in needles]
        return [
            value
            for value in self.strings
            if any(needle in value.lower() for needle in lowered)
        ][:limit]

    def strings_matching_regex(self, *patterns: str, limit: int = 25) -> list[str]:
        import re

        compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        return [value for value in self.strings if any(pattern.search(value) for pattern in compiled)][:limit]


class BaseAgent:
    name = "Base Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        raise NotImplementedError


class PackerAgent(BaseAgent):
    name = "Packer Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        findings: list[Finding] = []
        hypotheses: list[Hypothesis] = []
        packed_matches = [item for item in ctx.knowledge_matches if item.category in {"packer", "obfuscation"}]
        high_entropy = ctx.signals.get("high_entropy_sections", [])
        wx_sections = ctx.signals.get("writable_exec_sections", [])

        if packed_matches:
            findings.extend(packed_matches)
        if ctx.signals.get("likely_packed"):
            evidence = []
            if high_entropy:
                evidence.append(f"high entropy sections: {', '.join(item['name'] for item in high_entropy[:8])}")
            if wx_sections:
                evidence.append(f"writable+executable sections: {', '.join(item['name'] for item in wx_sections[:8])}")
            findings.append(
                Finding(
                    category="packer",
                    title="Packing or heavy obfuscation is likely",
                    severity="high",
                    confidence=0.78,
                    evidence=evidence or [f"overall entropy {ctx.static.get('entropy', {}).get('overall')}"],
                    source="PackerAgent",
                    recommendation="Run DIE/PE-sieve and unpack before deep function-level reasoning.",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title="Entry point may be a loader stub",
                    confidence=0.72,
                    rationale=["Packing indicators were observed in entropy or section permissions."],
                    validation_steps=[
                        "Debug until original entry point is reached.",
                        "Dump process memory after unpacking.",
                        "Re-run static analysis on the dumped image.",
                    ],
                    owner_agent=self.name,
                )
            )

        return AgentReport(
            name=self.name,
            summary="Assesses packers, protectors, entropy, and section anomalies.",
            findings=findings,
            hypotheses=hypotheses,
            next_actions=["Run Detect-It-Easy and PE-sieve if available.", "Compare raw entry point bytes against section entropy."],
        )


class AntiAnalysisAgent(BaseAgent):
    name = "Anti-Analysis Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        findings: list[Finding] = []
        imports = ctx.has_import(
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "QueryPerformanceCounter",
        )
        strings = ctx.strings_containing("debugger", "vmware", "virtualbox", "vbox", "qemu", "sandbox", "wine")
        if imports or strings:
            findings.append(
                Finding(
                    category="anti_analysis",
                    title="Anti-debugging or anti-VM behavior indicators",
                    severity="medium",
                    confidence=0.75,
                    evidence=[*(f"import:{item}" for item in imports), *strings[:10]],
                    source=self.name,
                    recommendation="Patch or hook checks during dynamic validation; log branch decisions around these calls.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Looks for anti-debugging, anti-VM, sandbox, and timing checks.",
            findings=findings,
            hypotheses=[
                Hypothesis(
                    title="A guarded branch may hide the real logic",
                    confidence=0.55 if findings else 0.25,
                    rationale=["Anti-analysis indicators often gate license, malware, or CTF verification paths."],
                    validation_steps=["Hook the listed APIs with Frida/x64dbg and force benign return values."],
                    owner_agent=self.name,
                )
            ] if findings else [],
            next_actions=["Set breakpoints on anti-debug imports.", "Trace conditional branches after each check."],
        )


class CryptoAgent(BaseAgent):
    name = "Crypto Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        imports = ctx.has_import(
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptDecrypt",
            "CryptEncrypt",
            "CryptGenRandom",
            "BCryptDecrypt",
            "BCryptEncrypt",
            "SystemFunction032",
        )
        strings = ctx.strings_matching_regex(
            r"(?<![A-Za-z0-9_])aes(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])rsa(?![A-Za-z0-9_])",
            r"sha-?256",
            r"(?<![A-Za-z0-9_])md5(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])base64(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])xor(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])rc4(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])chacha(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])salsa20(?![A-Za-z0-9_])",
        )
        findings: list[Finding] = []
        if imports or strings:
            findings.append(
                Finding(
                    category="crypto",
                    title="Cryptographic or encoding logic is present",
                    severity="medium",
                    confidence=0.76,
                    evidence=[*(f"import:{item}" for item in imports), *strings[:12]],
                    source=self.name,
                    recommendation="Prioritize xrefs to crypto APIs/constants and inspect buffers before and after calls.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Prioritizes encryption, hashing, random generation, and simple encodings.",
            findings=findings,
            hypotheses=[
                Hypothesis(
                    title="Input may be transformed before comparison",
                    confidence=0.66,
                    rationale=["Crypto or encoding strings/imports are present."],
                    validation_steps=[
                        "Break before comparison APIs and inspect transformed buffers.",
                        "Hook crypto APIs and dump input/output buffers.",
                    ],
                    owner_agent=self.name,
                )
            ] if findings else [],
            next_actions=["Search for AES/SHA constants.", "Rank functions that reference CTF/password strings and crypto indicators together."],
        )


class NetworkAgent(BaseAgent):
    name = "Network Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        imports = ctx.has_import(
            "WSAStartup",
            "connect",
            "send",
            "recv",
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "WinHttpOpen",
            "WinHttpConnect",
            "HttpSendRequestA",
            "HttpSendRequestW",
        )
        categories = ctx.static.get("strings", {}).get("categories", {})
        endpoints = categories.get("urls", []) + categories.get("ips", []) + categories.get("domains", [])
        findings: list[Finding] = []
        if imports or endpoints:
            findings.append(
                Finding(
                    category="network",
                    title="Network behavior indicators",
                    severity="medium",
                    confidence=0.78,
                    evidence=[*(f"import:{item}" for item in imports), *endpoints[:20]],
                    source=self.name,
                    recommendation="Replay in an isolated lab and capture traffic with Wireshark or mitmproxy/Burp.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Extracts URLs, IPs, domains, and network API usage.",
            findings=findings,
            hypotheses=[],
            next_actions=["Create a packet-capture run profile.", "Map endpoints to code references in disassembler output."],
        )


class MalwareAgent(BaseAgent):
    name = "Malware Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        injection = ctx.has_import("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC")
        persistence = ctx.strings_containing("\\run", "currentversion\\run", "schtasks", "startup", "service")
        filesystem = ctx.has_import("CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA", "DeleteFileW")
        findings: list[Finding] = []
        if injection:
            findings.append(
                Finding(
                    category="malware",
                    title="Process injection capability indicators",
                    severity="high",
                    confidence=0.82,
                    evidence=[f"import:{item}" for item in injection],
                    source=self.name,
                    recommendation="Trace target process handle creation and buffer writes.",
                )
            )
        if persistence:
            findings.append(
                Finding(
                    category="malware",
                    title="Persistence-related strings",
                    severity="medium",
                    confidence=0.65,
                    evidence=persistence[:15],
                    source=self.name,
                    recommendation="Validate registry/service/task creation dynamically.",
                )
            )
        if filesystem and ctx.signals.get("network_imports"):
            findings.append(
                Finding(
                    category="malware",
                    title="Network plus filesystem capability combination",
                    severity="medium",
                    confidence=0.58,
                    evidence=[*(f"import:{item}" for item in filesystem[:8]), "network imports present"],
                    source=self.name,
                )
            )
        return AgentReport(
            name=self.name,
            summary="Correlates behavior that often matters in malware triage.",
            findings=findings,
            hypotheses=[],
            next_actions=["Build an isolated dynamic profile.", "Monitor process, registry, filesystem, and network events."],
        )


class WindowsInternalsAgent(BaseAgent):
    name = "Windows Internals Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        imports = [
            name
            for name in sorted(ctx.import_names)
            if name.startswith("nt") or name in {"deviceiocontrol", "adjusttokenprivileges", "openprocess", "rtlcreateuserthread"}
        ]
        findings = []
        if imports:
            findings.append(
                Finding(
                    category="windows_internals",
                    title="Native API or privileged Windows behavior",
                    severity="medium",
                    confidence=0.7,
                    evidence=[f"import:{item}" for item in imports[:25]],
                    source=self.name,
                    recommendation="Map native API calls to documented behavior and inspect structure arguments.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Highlights native API, token, process, driver, and low-level Windows usage.",
            findings=findings,
            hypotheses=[],
            next_actions=["Resolve Nt* prototypes.", "Inspect handles, access masks, and IOCTL values."],
        )


class LicenseAgent(BaseAgent):
    name = "License Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        strings = ctx.strings_matching_regex(
            r"license (?:key|check|invalid|expired|file)",
            r"(?<![A-Za-z0-9_])serial(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])activation(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])trial(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])flexnet(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])lmgrd(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])armadillo(?![A-Za-z0-9_])",
            r"(?<![A-Za-z0-9_])hwid(?![A-Za-z0-9_])",
        )
        imports = ctx.has_import("GetVolumeInformationA", "GetVolumeInformationW", "GetAdaptersInfo", "GetComputerNameA", "GetComputerNameW")
        findings = []
        if strings or imports:
            findings.append(
                Finding(
                    category="license",
                    title="License, activation, or hardware fingerprinting indicators",
                    severity="medium",
                    confidence=0.73,
                    evidence=[*strings[:15], *(f"import:{item}" for item in imports)],
                    source=self.name,
                    recommendation="Trace string references and compare branches near failure messages.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Tracks license checks, serial validation, DRM, and hardware fingerprint hints.",
            findings=findings,
            hypotheses=[
                Hypothesis(
                    title="Validation likely compares transformed user input against embedded state",
                    confidence=0.62,
                    rationale=["License or serial indicators were found."],
                    validation_steps=["Find xrefs to failure/success strings.", "Trace backward from comparison and branch instructions."],
                    owner_agent=self.name,
                )
            ] if findings else [],
            next_actions=["Prioritize xrefs to success/failure strings.", "Identify hardware fingerprint collection APIs."],
        )


class VulnerabilityAgent(BaseAgent):
    name = "Vulnerability Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        unsafe = ctx.has_import("strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "memcpy")
        format_strings = [item for item in ctx.strings if "%n" in item or ("%s" in item and len(item) < 200)][:20]
        findings = []
        if unsafe or format_strings:
            findings.append(
                Finding(
                    category="vulnerability",
                    title="Potential memory-safety review targets",
                    severity="medium",
                    confidence=0.55,
                    evidence=[*(f"import:{item}" for item in unsafe), *format_strings],
                    source=self.name,
                    recommendation="Use dynamic instrumentation or fuzzing to confirm controllability.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Ranks possible bug-hunting targets for CTF and audit workflows.",
            findings=findings,
            hypotheses=[],
            next_actions=["Check whether user input reaches unsafe APIs.", "Enable ASAN/QEMU/WinAFL where applicable."],
        )


class CtfAgent(BaseAgent):
    name = "CTF Agent"

    def run(self, ctx: AgentContext) -> AgentReport:
        ctf_strings = ctx.static.get("strings", {}).get("categories", {}).get("ctf", [])
        compare_imports = ctx.has_import("strcmp", "strncmp", "memcmp", "lstrcmpA", "lstrcmpW", "CompareStringA", "CompareStringW")
        findings = []
        hypotheses = []
        if ctf_strings:
            findings.append(
                Finding(
                    category="ctf",
                    title="Challenge-solving anchors found",
                    severity="high",
                    confidence=0.8,
                    evidence=[*ctf_strings[:25], *(f"import:{item}" for item in compare_imports)],
                    source=self.name,
                    recommendation="Start from success/failure strings, then walk backward through comparisons and transforms.",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title="The fastest solve path is likely xrefs from visible challenge strings",
                    confidence=0.78,
                    rationale=["CTF/password/success/failure strings or comparison imports exist."],
                    validation_steps=[
                        "Open xrefs to listed strings in Ghidra/IDA/r2.",
                        "Name the verification function.",
                        "Trace input transformation and comparison operands.",
                    ],
                    owner_agent=self.name,
                )
            )
        elif compare_imports:
            findings.append(
                Finding(
                    category="ctf",
                    title="Comparison APIs available, but no CTF string anchors",
                    severity="low",
                    confidence=0.35,
                    evidence=[f"import:{item}" for item in compare_imports],
                    source=self.name,
                    recommendation="Treat this as a weak hint only; prioritize it after concrete success/failure strings or input paths are found.",
                )
            )
        return AgentReport(
            name=self.name,
            summary="Optimizes for DreamHack/CTF reverse engineering solve paths.",
            findings=findings,
            hypotheses=hypotheses,
            next_actions=["Find xrefs to listed strings.", "Break on comparison imports and inspect arguments."],
        )
