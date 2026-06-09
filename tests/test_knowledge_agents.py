from __future__ import annotations

import unittest

from revbot.agents import run_agents
from revbot.knowledge import KnowledgeBase


class KnowledgeAgentTests(unittest.TestCase):
    def test_ctf_pattern_and_agent_fire(self) -> None:
        static = {
            "entropy": {"overall": 4.2},
            "strings": {
                "top": ["wrong password", "correct", "flag{demo}"],
                "categories": {"ctf": ["wrong password", "correct", "flag{demo}"]},
            },
            "sections": [],
            "pe": {"imports": [{"dll": "msvcrt.dll", "name": "strcmp"}]},
            "signals": {"likely_packed": False},
        }
        kb = KnowledgeBase.load("knowledge/patterns.json")
        matches = kb.match(static)
        self.assertTrue(any(item.category == "ctf" for item in matches))
        reports = run_agents(static, matches)
        ctf = next(item for item in reports if item.name == "CTF Agent")
        self.assertTrue(ctf.findings)

    def test_knowledge_matches_elf_imports(self) -> None:
        static = {
            "entropy": {"overall": 4.2},
            "strings": {"top": [], "categories": {}},
            "sections": [],
            "pe": {"imports": []},
            "elf": {"imports": [{"dll": "elf", "name": "connect"}]},
            "signals": {"likely_packed": False},
        }
        kb = KnowledgeBase.load("knowledge/patterns.json")
        matches = kb.match(static)
        self.assertTrue(any(item.category == "network" for item in matches))


if __name__ == "__main__":
    unittest.main()
