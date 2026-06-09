from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


JsonDict = dict[str, Any]


@dataclass
class ToolResult:
    name: str
    available: bool
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_ms: int | None = None
    stdout: str = ""
    stderr: str = ""
    parsed: Any = None
    error: str | None = None

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    source: str = "heuristic"
    recommendation: str | None = None

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class Hypothesis:
    title: str
    confidence: float
    rationale: list[str]
    validation_steps: list[str]
    status: str = "needs_validation"
    owner_agent: str = "general"

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass
class AgentReport:
    name: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonDict:
        return {
            "name": self.name,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "next_actions": list(self.next_actions),
        }


@dataclass
class AnalysisResult:
    file: JsonDict
    static: JsonDict
    tools: dict[str, ToolResult]
    knowledge_matches: list[Finding]
    agents: list[AgentReport]
    artifacts: JsonDict = field(default_factory=dict)
    experiments: JsonDict = field(default_factory=dict)
    memory: JsonDict = field(default_factory=dict)
    llm: JsonDict = field(default_factory=dict)
    metadata: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return {
            "file": self.file,
            "static": self.static,
            "tools": {name: result.to_dict() for name, result in self.tools.items()},
            "knowledge_matches": [item.to_dict() for item in self.knowledge_matches],
            "agents": [item.to_dict() for item in self.agents],
            "artifacts": self.artifacts,
            "experiments": self.experiments,
            "memory": self.memory,
            "llm": self.llm,
            "metadata": self.metadata,
        }
