from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from revbot.config import ApiConfig


@dataclass
class LLMCallResult:
    ok: bool
    content: str
    usage: dict[str, Any]
    raw: dict[str, Any] | None = None
    error: str | None = None


class LLMClient:
    def __init__(self, config: ApiConfig) -> None:
        self.config = config
        self._working_url: str | None = None
        self._working_style: str | None = None
        self._working_mode: str | None = None

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> LLMCallResult:
        if not self.config.enabled:
            return LLMCallResult(False, "", {}, error="API is not configured")

        errors: list[str] = []

        for mode, url in self._candidate_endpoints():
            for style in self._candidate_styles(mode):
                payload = self._build_payload(messages, temperature, max_tokens, style, url, mode)
                response = self._post(url, payload)
                if response.ok:
                    self._working_url = url
                    self._working_style = style
                    self._working_mode = mode
                    return response
                errors.append(f"{short_url(url)} [{mode}/{style}]: {response.error}")

                error = response.error or ""
                if "HTTP 404" in error:
                    break
                if "HTTP 401" in error or "HTTP 403" in error:
                    break

        return LLMCallResult(False, "", {}, error="; ".join(errors[-6:]))

    def _post(self, url: str, payload: dict[str, Any]) -> LLMCallResult:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            content = parsed.get("choices", [{}])[0].get("message", {}).get("content", "")
            if not content:
                content = extract_response_text(parsed)
            parsed["_revbot_endpoint"] = short_url(url)
            return LLMCallResult(True, content, parsed.get("usage", {}), raw=parsed)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:3000]
            return LLMCallResult(False, "", {}, error=f"HTTP {exc.code}: {body}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            return LLMCallResult(False, "", {}, error=str(exc))

    def _candidate_endpoints(self) -> list[tuple[str, str]]:
        endpoints = [("chat", url) for url in self.config.candidate_chat_urls]
        endpoints.extend(("responses", url) for url in self.config.candidate_response_urls)
        if self._working_url and self._working_mode:
            marker = (self._working_mode, self._working_url)
            if marker in endpoints:
                endpoints.remove(marker)
                endpoints.insert(0, marker)
        return endpoints

    def _candidate_styles(self, mode: str) -> list[str]:
        if mode == "responses":
            styles = ["standard", "no_temperature", "deployment_no_model"]
        else:
            styles = ["standard", "no_temperature", "max_completion_tokens", "deployment_no_model"]
        if self._working_style and self._working_style in styles:
            styles.remove(self._working_style)
            styles.insert(0, self._working_style)
        return styles

    def _build_payload(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int | None,
        style: str,
        url: str,
        mode: str,
    ) -> dict[str, Any]:
        limit = max_tokens or self.config.max_tokens
        if mode == "responses":
            payload: dict[str, Any] = {
                "input": messages,
                "max_output_tokens": limit,
            }
        else:
            payload = {
                "messages": messages,
                "max_tokens": limit,
            }
        include_model = not self.config.omit_model and style != "deployment_no_model"
        if include_model:
            payload["model"] = self.config.model
        if style != "no_temperature":
            payload["temperature"] = temperature
        if mode == "chat" and style == "max_completion_tokens":
            payload.pop("max_tokens", None)
            payload["max_completion_tokens"] = limit
        if "/openai/deployments/" in url and style == "deployment_no_model":
            payload.pop("model", None)
        return payload

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.auth_header:
            headers[self.config.auth_header] = self.config.api_key
            return headers

        base = self.config.base_url.lower()
        if "api.openai.com" in base:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        else:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
            headers["api-key"] = self.config.api_key
            headers["Ocp-Apim-Subscription-Key"] = self.config.api_key
        return headers


def short_url(url: str) -> str:
    for marker in ("?", "#"):
        if marker in url:
            url = url.split(marker, 1)[0]
    return url


def extract_response_text(parsed: dict[str, Any]) -> str:
    if parsed.get("output_text"):
        return str(parsed["output_text"])
    chunks: list[str] = []
    output = parsed.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text") or part.get("output_text")
                        if text:
                            chunks.append(str(text))
            elif isinstance(content, str):
                chunks.append(content)
    return "\n".join(chunks)


def compact_for_llm(context: dict[str, Any], max_chars: int = 55_000) -> str:
    reduced = {
        "file": context.get("file", {}),
        "static_identity": context.get("static", {}).get("identity", {}),
        "entropy": context.get("static", {}).get("entropy", {}),
        "signals": context.get("static", {}).get("signals", {}),
        "string_categories": context.get("static", {}).get("strings", {}).get("categories", {}),
        "top_strings": context.get("static", {}).get("strings", {}).get("top", [])[:220],
        "pe": {
            "machine": context.get("static", {}).get("pe", {}).get("machine"),
            "subsystem": context.get("static", {}).get("pe", {}).get("subsystem"),
            "entry_point_rva": context.get("static", {}).get("pe", {}).get("entry_point_rva"),
            "imports": context.get("static", {}).get("pe", {}).get("imports", [])[:500],
            "sections": context.get("static", {}).get("sections", [])[:80],
        },
        "elf": {
            "machine": context.get("static", {}).get("elf", {}).get("machine"),
            "type": context.get("static", {}).get("elf", {}).get("type"),
            "entry_point": context.get("static", {}).get("elf", {}).get("entry_point"),
            "needed_libraries": context.get("static", {}).get("elf", {}).get("needed_libraries", [])[:100],
            "imports": context.get("static", {}).get("elf", {}).get("imports", [])[:500],
        },
        "knowledge_matches": context.get("knowledge_matches", [])[:80],
        "agent_reports": context.get("agents", [])[:20],
        "artifacts": {
            "loaded_count": context.get("artifacts", {}).get("loaded_count"),
            "imports": context.get("artifacts", {}).get("imports", [])[:500],
            "strings": context.get("artifacts", {}).get("strings", [])[:300],
            "ranked_functions": context.get("artifacts", {}).get("ranked_functions", [])[:100],
        },
        "experiments": context.get("experiments", {}),
        "memory": context.get("memory", {}),
        "tools": summarize_tools(context.get("tools", {})),
        "extra_artifacts": summarize_extra_artifacts(context.get("metadata", {}).get("extra_artifacts", [])),
    }
    text = json.dumps(reduced, ensure_ascii=False, indent=2)
    return text[:max_chars]


def summarize_tools(tools: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for name, result in tools.items():
        if hasattr(result, "to_dict"):
            item = result.to_dict()
        else:
            item = result
        summary[name] = {
            "available": item.get("available"),
            "exit_code": item.get("exit_code"),
            "error": item.get("error"),
            "parsed_type": type(item.get("parsed")).__name__ if item.get("parsed") is not None else None,
            "stdout_head": (item.get("stdout") or "")[:2000],
            "stderr_head": (item.get("stderr") or "")[:1000],
        }
    return summary


def summarize_extra_artifacts(artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for artifact in artifacts:
        data = artifact.get("data")
        if isinstance(data, dict):
            summary.append(
                {
                    "path": artifact.get("path"),
                    "loaded": artifact.get("loaded"),
                    "source": data.get("source"),
                    "keys": sorted(data.keys())[:30],
                    "functions_count": len(data.get("functions", [])) if isinstance(data.get("functions"), list) else None,
                    "imports_count": len(data.get("imports", [])) if isinstance(data.get("imports"), list) else None,
                    "strings_count": len(data.get("strings", [])) if isinstance(data.get("strings"), list) else None,
                    "head": json.dumps(data, ensure_ascii=False)[:8000],
                }
            )
        else:
            summary.append({"path": artifact.get("path"), "loaded": artifact.get("loaded"), "error": artifact.get("error")})
    return summary


def specialist_prompt(agent_name: str, context_json: str) -> list[dict[str, str]]:
    system = (
        "You are a senior reverse engineering specialist. "
        "Use only the provided evidence. Separate facts from hypotheses. "
        "Return concise Markdown with: findings, reasoning, validation plan, and priority."
    )
    user = f"Specialist: {agent_name}\n\nEvidence JSON:\n{context_json}"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def final_prompt(context_json: str, intensity: str) -> list[dict[str, str]]:
    system = (
        "You are the lead analyst for a semi-automated reverse engineering lab. "
        "Synthesize tool output, heuristics, and specialist reports into a practical plan. "
        "Do not claim dynamic execution happened unless evidence says so."
    )
    user = (
        f"API intensity: {intensity}\n\n"
        "Produce a portfolio-grade reverse engineering report section with:\n"
        "1. executive assessment\n"
        "2. highest-priority functions or artifacts to inspect next\n"
        "3. packer/anti-analysis/network/crypto/license/malware/CTF conclusions\n"
        "4. concrete experiments for IDA/Ghidra/r2/x64dbg/Frida/Wireshark\n"
        "5. uncertainty and missing evidence\n\n"
        f"Evidence JSON:\n{context_json}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
