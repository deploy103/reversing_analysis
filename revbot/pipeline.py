from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from revbot.agents import run_agents
from revbot.artifacts import normalize_artifacts
from revbot.collectors.tools import ExternalToolCollector
from revbot.config import ApiConfig
from revbot.experiments import build_experiment_plan
from revbot.knowledge import KnowledgeBase, compact_tool_text
from revbot.llm import LLMClient, compact_for_llm, final_prompt, specialist_prompt
from revbot.memory import AnalysisMemory
from revbot.models import AnalysisResult
from revbot.static_analysis import StaticAnalyzer


INTENSITIES = {"off", "light", "standard", "max", "unlimited"}


class AnalysisPipeline:
    def __init__(
        self,
        api_config: ApiConfig,
        knowledge_path: Path | str | None = None,
        tool_timeout: int = 60,
        max_bytes: int = 128 * 1024 * 1024,
        enable_tools: bool = True,
        memory_path: Path | str | None = Path("memory/revbot.sqlite3"),
        enable_memory: bool = True,
    ) -> None:
        self.api_config = api_config
        self.knowledge = KnowledgeBase.load(knowledge_path)
        self.tool_collector = ExternalToolCollector(timeout_seconds=tool_timeout)
        self.static_analyzer = StaticAnalyzer(max_bytes=max_bytes)
        self.enable_tools = enable_tools
        self.memory_path = Path(memory_path) if memory_path else None
        self.enable_memory = enable_memory

    def analyze(
        self,
        sample_path: Path | str,
        api_intensity: str = "standard",
        llm_rounds: int = 2,
        llm_workers: int = 4,
        extra_artifacts: list[dict[str, Any]] | None = None,
    ) -> AnalysisResult:
        if api_intensity not in INTENSITIES:
            raise ValueError(f"unknown API intensity: {api_intensity}")
        started = time.monotonic()
        path = Path(sample_path)
        static = self.static_analyzer.analyze(path)
        tools = self.tool_collector.collect(path) if self.enable_tools else {}
        tool_text = compact_tool_text(tools)
        knowledge_matches = self.knowledge.match(static, tool_text)
        agents = run_agents(static, knowledge_matches)
        artifacts = normalize_artifacts(extra_artifacts or [])
        result = AnalysisResult(
            file=static["identity"],
            static=static,
            tools=tools,
            knowledge_matches=knowledge_matches,
            agents=agents,
            artifacts=artifacts,
            metadata={
                "api_intensity": api_intensity,
                "tooling_enabled": self.enable_tools,
                "extra_artifacts": extra_artifacts or [],
                "elapsed_ms_without_llm": int((time.monotonic() - started) * 1000),
            },
        )

        result.experiments = build_experiment_plan(result)
        if self.enable_memory and self.memory_path:
            memory = AnalysisMemory(self.memory_path)
            try:
                result.memory = memory.store(result)
            finally:
                memory.close()
        result.llm = self._run_llm(result, api_intensity, llm_rounds, llm_workers)
        result.metadata["elapsed_ms_total"] = int((time.monotonic() - started) * 1000)
        return result

    def _run_llm(self, result: AnalysisResult, intensity: str, llm_rounds: int, llm_workers: int) -> dict[str, Any]:
        if intensity == "off":
            return {"enabled": False, "reason": "api_intensity=off"}
        if not self.api_config.enabled:
            return {"enabled": False, "reason": "API key or model is not configured"}

        client = LLMClient(self.api_config)
        context = result.to_dict()

        if intensity == "light":
            max_chars = 35_000
            specialist_names: list[str] = []
            final_rounds = 1
        elif intensity == "standard":
            max_chars = 55_000
            specialist_names = ["Packer Agent", "Crypto Agent", "CTF Agent"]
            final_rounds = 1
        elif intensity == "max":
            max_chars = 90_000
            specialist_names = [agent.name for agent in result.agents]
            final_rounds = max(2, llm_rounds)
        else:
            max_chars = 180_000
            specialist_names = [agent.name for agent in result.agents]
            final_rounds = max(4, llm_rounds)

        context_json = compact_for_llm(context, max_chars=max_chars)
        calls: list[dict[str, Any]] = []
        specialist_outputs: dict[str, Any] = {}

        if specialist_names:
            worker_count = max(1, llm_workers)
            if intensity == "unlimited":
                worker_count = max(worker_count, min(12, len(specialist_names)))
            worker_count = min(worker_count, len(specialist_names))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {
                    executor.submit(
                        client.chat,
                        specialist_prompt(name, context_json),
                        max_tokens=self.api_config.max_tokens,
                    ): name
                    for name in specialist_names
                }
                for future in as_completed(futures):
                    name = futures[future]
                    response = future.result()
                    calls.append({"type": "specialist", "name": name, "ok": response.ok, "usage": response.usage, "error": response.error})
                    specialist_outputs[name] = response.content if response.ok else f"ERROR: {response.error}"

        final_outputs = []
        rolling_context = context_json
        for round_index in range(final_rounds):
            if round_index > 0:
                rolling_context = compact_for_llm(
                    {
                        **context,
                        "previous_llm_outputs": {
                            "specialists": specialist_outputs,
                            "final": final_outputs,
                        },
                    },
                    max_chars=max_chars,
                )
            response = client.chat(final_prompt(rolling_context, intensity), max_tokens=self.api_config.max_tokens)
            calls.append({"type": "final", "round": round_index + 1, "ok": response.ok, "usage": response.usage, "error": response.error})
            final_outputs.append(response.content if response.ok else f"ERROR: {response.error}")

        return {
            "enabled": True,
            "model": self.api_config.model,
            "intensity": intensity,
            "workers": llm_workers,
            "calls": calls,
            "specialists": specialist_outputs,
            "final": final_outputs,
        }
