from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from revbot.artifacts import load_extra_json, normalize_artifacts
from revbot.experiments import build_experiment_plan
from revbot.memory import AnalysisMemory
from revbot.models import AgentReport, AnalysisResult, Finding, ToolResult


class ArtifactMemoryExperimentTests(unittest.TestCase):
    def test_normalizes_and_ranks_disassembler_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "export.json"
            path.write_text(
                """
                {
                  "source": "ida",
                  "imports": [{"dll": "msvcrt.dll", "name": "strcmp"}],
                  "strings": [{"ea": 4096, "value": "correct password"}],
                  "functions": [
                    {
                      "ea": 4198400,
                      "name": "main",
                      "calls": [{"name": "strcmp"}],
                      "strings": [{"value": "wrong password"}, {"value": "flag{demo}"}]
                    }
                  ]
                }
                """,
                encoding="utf-8",
            )
            artifacts = normalize_artifacts(load_extra_json([path]))
            self.assertEqual(artifacts["loaded_count"], 1)
            self.assertEqual(artifacts["ranked_functions"][0]["name"], "main")
            self.assertIn("ctf-anchor", artifacts["ranked_functions"][0]["reasons"])

    def test_memory_similarity_and_experiment_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            memory = AnalysisMemory(Path(tmp) / "memory.sqlite3")
            first = make_result("a" * 64, "one")
            second = make_result("b" * 64, "two")
            first.memory = memory.store(first)
            second.memory = memory.store(second)
            similar = memory.similar("b" * 64)
            memory.close()
            self.assertTrue(similar)
            self.assertEqual(similar[0]["sha256"], "a" * 64)

            plan = build_experiment_plan(second)
            self.assertTrue(any(item["name"] == "strcmp" for item in plan["hook_targets"]))

    def test_memory_stores_solve_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            memory = AnalysisMemory(Path(tmp) / "memory.sqlite3")
            try:
                stored = memory.store_solve(
                    {
                        "file": {"sha256": "c" * 64, "name": "solve", "format": "elf"},
                        "solved": True,
                        "candidates": [{"value": "open_sesame", "source": "test", "confidence": 0.9}],
                        "strategy": {"next_priorities": ["validate"]},
                    }
                )
                rows = memory.list_solves()
            finally:
                memory.close()
            self.assertTrue(stored["stored"])
            self.assertEqual(rows[0]["top_candidate"], "open_sesame")


def make_result(sha256: str, name: str) -> AnalysisResult:
    static = {
        "identity": {"sha256": sha256, "name": name, "format": "elf", "size": 123},
        "strings": {"top": ["wrong password", "flag{demo}"], "categories": {"ctf": ["wrong password", "flag{demo}"]}},
        "sections": [{"name": ".text"}],
        "pe": {},
        "elf": {"imports": [{"name": "strcmp", "dll": "elf"}]},
        "signals": {},
    }
    return AnalysisResult(
        file=static["identity"],
        static=static,
        tools={"file": ToolResult(name="file", available=True)},
        knowledge_matches=[
            Finding(category="ctf", title="CTF anchors", severity="high", confidence=0.9)
        ],
        agents=[AgentReport(name="CTF Agent", summary="test")],
        artifacts={"imports": [], "strings": [], "ranked_functions": []},
    )


if __name__ == "__main__":
    unittest.main()
