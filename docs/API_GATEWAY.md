# API Gateway Configuration

Reverse Researcher reads `.env` and never prints secret key values.

Minimum APIM-style configuration:

```env
APIM_BASE_URL=https://your-gateway.example/base
APIM_KEY=...
CHAT_MODEL=...
```

If your gateway uses a nonstandard route, set the exact endpoint:

```env
APIM_CHAT_COMPLETIONS_URL=https://your-gateway.example/path/to/chat/completions
```

Probe connectivity:

```bash
python3 -m revbot.cli api-probe
```

A `404 Resource not found` result usually means the key was accepted by the gateway layer but the configured route path is wrong. Fix this by setting `APIM_CHAT_COMPLETIONS_URL` to the exact chat-completions route exposed by the gateway.

The client automatically retries common routes:

- OpenAI-compatible chat: `/v1/chat/completions`
- Microsoft Foundry v1 chat: `/openai/v1/chat/completions`
- Foundry model inference: `/models/chat/completions?api-version=...`
- Azure OpenAI deployment chat: `/openai/deployments/{deployment}/chat/completions?api-version=...`
- Responses API variants under `/responses`, `/v1/responses`, and `/openai/v1/responses`

