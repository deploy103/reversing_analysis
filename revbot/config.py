from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_AZURE_API_VERSIONS = ("2024-05-01-preview", "2025-05-01")


def load_dotenv(path: Path | str = ".env") -> dict[str, str]:
    env_path = Path(path)
    values: dict[str, str] = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


@dataclass(frozen=True)
class ApiConfig:
    base_url: str
    api_key: str
    model: str
    chat_url: str | None = None
    responses_url: str | None = None
    auth_header: str | None = None
    api_version: str | None = None
    omit_model: bool = False
    timeout_seconds: int = 90
    max_tokens: int = 2400

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.model)

    @property
    def chat_completions_url(self) -> str:
        if self.chat_url:
            return self.chat_url
        base = self.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        if "/openai/deployments/" in base:
            url = f"{base}/chat/completions"
            if "?" not in url and self.api_version:
                url = f"{url}?api-version={self.api_version}"
            return url
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    @property
    def candidate_chat_urls(self) -> list[str]:
        if self.chat_url:
            return [self.chat_url]

        base = self.base_url.rstrip("/")
        versions = [self.api_version] if self.api_version else list(DEFAULT_AZURE_API_VERSIONS)
        urls = [
            self.chat_completions_url,
            f"{base}/chat/completions",
            f"{base}/v1/chat/completions",
            f"{base}/openai/v1/chat/completions",
        ]
        for version in versions:
            urls.append(f"{base}/models/chat/completions?api-version={version}")
        for version in versions:
            urls.append(f"{base}/openai/deployments/{self.model}/chat/completions?api-version={version}")

        deduped: list[str] = []
        seen: set[str] = set()
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped

    @property
    def candidate_response_urls(self) -> list[str]:
        if self.responses_url:
            return [self.responses_url]
        if self.chat_url:
            return []

        base = self.base_url.rstrip("/")
        versions = [self.api_version] if self.api_version else list(DEFAULT_AZURE_API_VERSIONS)
        urls = [
            f"{base}/responses",
            f"{base}/v1/responses",
            f"{base}/openai/v1/responses",
        ]
        for version in versions:
            urls.append(f"{base}/models/responses?api-version={version}")
        for version in versions:
            urls.append(f"{base}/openai/deployments/{self.model}/responses?api-version={version}")

        deduped: list[str] = []
        seen: set[str] = set()
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped


def api_config_from_env(dotenv_path: Path | str = ".env") -> ApiConfig:
    values = load_dotenv(dotenv_path)
    base_url = (
        values.get("APIM_BASE_URL")
        or values.get("OPENAI_BASE_URL")
        or "https://api.openai.com/v1"
    )
    chat_url = values.get("APIM_CHAT_COMPLETIONS_URL") or values.get("OPENAI_CHAT_COMPLETIONS_URL")
    responses_url = values.get("APIM_RESPONSES_URL") or values.get("OPENAI_RESPONSES_URL")
    api_key = values.get("APIM_KEY") or values.get("OPENAI_API_KEY") or ""
    model = values.get("CHAT_MODEL") or values.get("OPENAI_MODEL") or "gpt-4.1-mini"
    auth_header = values.get("APIM_AUTH_HEADER") or values.get("OPENAI_AUTH_HEADER")
    api_version = values.get("APIM_API_VERSION") or values.get("AZURE_OPENAI_API_VERSION")

    def int_value(name: str, default: int) -> int:
        try:
            return int(values.get(name, default))
        except (TypeError, ValueError):
            return default

    return ApiConfig(
        base_url=base_url,
        api_key=api_key,
        model=model,
        chat_url=chat_url,
        responses_url=responses_url,
        auth_header=auth_header,
        api_version=api_version,
        omit_model=values.get("OPENAI_OMIT_MODEL", "").lower() in {"1", "true", "yes"},
        timeout_seconds=int_value("OPENAI_TIMEOUT_SECONDS", 90),
        max_tokens=int_value("OPENAI_MAX_TOKENS", 2400),
    )


def env_status(dotenv_path: Path | str = ".env") -> dict[str, bool]:
    values = load_dotenv(dotenv_path)
    watched = [
        "APIM_BASE_URL",
        "APIM_KEY",
        "APIM_CHAT_COMPLETIONS_URL",
        "APIM_RESPONSES_URL",
        "OPENAI_API_KEY",
        "CHAT_MODEL",
        "EMBEDDING_MODEL",
        "VISION_MODEL",
    ]
    return {name: bool(values.get(name)) for name in watched}
