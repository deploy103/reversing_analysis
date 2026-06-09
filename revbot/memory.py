from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from revbot.models import AnalysisResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
  sha256 TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  format TEXT NOT NULL,
  size INTEGER NOT NULL,
  analyzed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  features_json TEXT NOT NULL,
  summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS solves (
  sha256 TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  format TEXT NOT NULL,
  solved INTEGER NOT NULL,
  top_candidate TEXT,
  top_source TEXT,
  top_confidence REAL,
  solved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  candidates_json TEXT NOT NULL,
  strategy_json TEXT NOT NULL
);
"""


class AnalysisMemory:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def store(self, result: AnalysisResult) -> dict[str, Any]:
        features = extract_features(result)
        summary = {
            "knowledge_matches": [item.to_dict() for item in result.knowledge_matches[:30]],
            "agent_findings": [
                finding.to_dict()
                for agent in result.agents
                for finding in agent.findings
            ][:50],
            "ranked_functions": result.artifacts.get("ranked_functions", [])[:30] if result.artifacts else [],
        }
        self.conn.execute(
            """
            INSERT INTO samples (sha256, name, format, size, features_json, summary_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              name=excluded.name,
              format=excluded.format,
              size=excluded.size,
              analyzed_at=CURRENT_TIMESTAMP,
              features_json=excluded.features_json,
              summary_json=excluded.summary_json
            """,
            (
                result.file.get("sha256"),
                result.file.get("name"),
                result.file.get("format"),
                result.file.get("size"),
                json.dumps(features, ensure_ascii=False),
                json.dumps(summary, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        similar = self.similar_to_features(features, exclude_sha256=str(result.file.get("sha256")), limit=5)
        return {"stored": True, "path": str(self.path), "similar": similar}

    def list_samples(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT sha256, name, format, size, analyzed_at FROM samples ORDER BY analyzed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"sha256": row[0], "name": row[1], "format": row[2], "size": row[3], "analyzed_at": row[4]}
            for row in rows
        ]

    def store_solve(self, result: dict[str, Any]) -> dict[str, Any]:
        file_info = result.get("file", {})
        candidates = result.get("candidates", [])
        top = candidates[0] if candidates else {}
        self.conn.execute(
            """
            INSERT INTO solves (sha256, name, format, solved, top_candidate, top_source, top_confidence, candidates_json, strategy_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              name=excluded.name,
              format=excluded.format,
              solved=excluded.solved,
              top_candidate=excluded.top_candidate,
              top_source=excluded.top_source,
              top_confidence=excluded.top_confidence,
              solved_at=CURRENT_TIMESTAMP,
              candidates_json=excluded.candidates_json,
              strategy_json=excluded.strategy_json
            """,
            (
                file_info.get("sha256"),
                file_info.get("name"),
                file_info.get("format"),
                1 if result.get("solved") else 0,
                top.get("value"),
                top.get("source"),
                top.get("confidence"),
                json.dumps(candidates[:100], ensure_ascii=False),
                json.dumps(result.get("strategy", {}), ensure_ascii=False),
            ),
        )
        self.conn.commit()
        return {"stored": True, "path": str(self.path), "similar_solves": self.similar_solves(result, limit=5)}

    def list_solves(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT sha256, name, format, solved, top_candidate, top_source, top_confidence, solved_at
            FROM solves ORDER BY solved_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "sha256": row[0],
                "name": row[1],
                "format": row[2],
                "solved": bool(row[3]),
                "top_candidate": row[4],
                "top_source": row[5],
                "top_confidence": row[6],
                "solved_at": row[7],
            }
            for row in rows
        ]

    def similar_solves(self, result: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
        file_info = result.get("file", {})
        target_sha = str(file_info.get("sha256", ""))
        target_values = {item.get("value", "").lower() for item in result.get("candidates", [])[:30] if item.get("value")}
        rows = self.conn.execute(
            "SELECT sha256, name, format, solved, top_candidate, top_source, top_confidence, candidates_json FROM solves"
        ).fetchall()
        scored = []
        for sha256, name, fmt, solved, top_candidate, top_source, top_confidence, raw_candidates in rows:
            if sha256 == target_sha:
                continue
            try:
                values = {item.get("value", "").lower() for item in json.loads(raw_candidates)[:30] if item.get("value")}
            except (TypeError, json.JSONDecodeError):
                values = set()
            if not target_values or not values:
                continue
            score = len(target_values & values) / len(target_values | values)
            if score > 0:
                scored.append(
                    {
                        "sha256": sha256,
                        "name": name,
                        "format": fmt,
                        "solved": bool(solved),
                        "top_candidate": top_candidate,
                        "top_source": top_source,
                        "top_confidence": top_confidence,
                        "score": round(score, 4),
                    }
                )
        return sorted(scored, key=lambda item: item["score"], reverse=True)[:limit]

    def similar(self, sha256: str, limit: int = 10) -> list[dict[str, Any]]:
        row = self.conn.execute("SELECT features_json FROM samples WHERE sha256=?", (sha256,)).fetchone()
        if not row:
            return []
        return self.similar_to_features(json.loads(row[0]), exclude_sha256=sha256, limit=limit)

    def similar_to_features(self, features: dict[str, list[str]], exclude_sha256: str, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT sha256, name, format, size, features_json FROM samples").fetchall()
        scored = []
        for row in rows:
            sha256, name, fmt, size, raw_features = row
            if sha256 == exclude_sha256:
                continue
            other = json.loads(raw_features)
            score = feature_similarity(features, other)
            if score > 0:
                scored.append({"sha256": sha256, "name": name, "format": fmt, "size": size, "score": round(score, 4)})
        return sorted(scored, key=lambda item: item["score"], reverse=True)[:limit]


def extract_features(result: AnalysisResult) -> dict[str, list[str]]:
    static = result.static
    categories = static.get("strings", {}).get("categories", {})
    imports = []
    for source in (static.get("pe", {}), static.get("elf", {})):
        imports.extend(str(item.get("name", "")).lower() for item in source.get("imports", []))
    imports.extend(str(item.get("name", "")).lower() for item in result.artifacts.get("imports", []) if item.get("name"))

    sections = [str(item.get("name", "")).lower() for item in static.get("sections", []) if item.get("name")]
    strings = [str(item).lower() for item in static.get("strings", {}).get("top", [])[:200]]
    strings.extend(str(item.get("value", "")).lower() for item in result.artifacts.get("strings", [])[:200])

    return {
        "imports": sorted(set(filter(None, imports))),
        "sections": sorted(set(filter(None, sections))),
        "ctf": sorted(set(item.lower() for item in categories.get("ctf", []))),
        "network": sorted(set(item.lower() for key in ("urls", "ips", "domains") for item in categories.get(key, []))),
        "strings": sorted(set(filter(None, strings))),
    }


def feature_similarity(left: dict[str, list[str]], right: dict[str, list[str]]) -> float:
    weights = {"imports": 4.0, "sections": 1.0, "ctf": 5.0, "network": 3.0, "strings": 1.0}
    numerator = 0.0
    denominator = 0.0
    for key, weight in weights.items():
        a = set(left.get(key, []))
        b = set(right.get(key, []))
        if not a and not b:
            continue
        union = a | b
        if not union:
            continue
        numerator += weight * (len(a & b) / len(union))
        denominator += weight
    return numerator / denominator if denominator else 0.0
