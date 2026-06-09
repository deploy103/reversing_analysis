from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from revbot.config import api_config_from_env, env_status, load_dotenv


class ConfigTests(unittest.TestCase):
    def test_load_dotenv_and_status_without_secret_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text("APIM_BASE_URL=https://gateway.test\nAPIM_KEY=secret\nCHAT_MODEL=model\n", encoding="utf-8")
            values = load_dotenv(env)
            self.assertEqual(values["APIM_KEY"], "secret")
            status = env_status(env)
            self.assertTrue(status["APIM_KEY"])
            config = api_config_from_env(env)
            self.assertTrue(config.enabled)
            self.assertTrue(config.chat_completions_url.endswith("/v1/chat/completions"))

    def test_exact_and_azure_style_chat_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "APIM_CHAT_COMPLETIONS_URL=https://gateway.test/custom/chat/completions\n"
                "APIM_KEY=secret\n"
                "CHAT_MODEL=model\n",
                encoding="utf-8",
            )
            self.assertEqual(api_config_from_env(env).chat_completions_url, "https://gateway.test/custom/chat/completions")

            env.write_text(
                "APIM_BASE_URL=https://gateway.test/openai/deployments/demo\n"
                "APIM_API_VERSION=2024-02-15-preview\n"
                "APIM_KEY=secret\n"
                "CHAT_MODEL=model\n"
                "OPENAI_OMIT_MODEL=true\n",
                encoding="utf-8",
            )
            config = api_config_from_env(env)
            self.assertTrue(config.chat_completions_url.endswith("/chat/completions?api-version=2024-02-15-preview"))
            self.assertTrue(config.omit_model)

    def test_candidate_urls_include_foundry_and_v1_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "APIM_BASE_URL=https://gateway.test/foundry\n"
                "APIM_KEY=secret\n"
                "CHAT_MODEL=deployment\n",
                encoding="utf-8",
            )
            config = api_config_from_env(env)
            urls = config.candidate_chat_urls
            self.assertIn("https://gateway.test/foundry/v1/chat/completions", urls)
            self.assertIn("https://gateway.test/foundry/openai/v1/chat/completions", urls)
            self.assertTrue(any("/models/chat/completions?api-version=" in item for item in urls))
            self.assertTrue(any("/openai/deployments/deployment/chat/completions?api-version=" in item for item in urls))
            response_urls = config.candidate_response_urls
            self.assertIn("https://gateway.test/foundry/v1/responses", response_urls)
            self.assertIn("https://gateway.test/foundry/openai/v1/responses", response_urls)

    def test_exact_responses_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".env"
            env.write_text(
                "APIM_RESPONSES_URL=https://gateway.test/custom/responses\n"
                "APIM_KEY=secret\n"
                "CHAT_MODEL=model\n",
                encoding="utf-8",
            )
            config = api_config_from_env(env)
            self.assertEqual(config.candidate_response_urls, ["https://gateway.test/custom/responses"])
            self.assertTrue(env_status(env)["APIM_RESPONSES_URL"])


if __name__ == "__main__":
    unittest.main()
