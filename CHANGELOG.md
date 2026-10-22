# Changelog

## [1.0.0] - 2026-10-22

### Added
- Terminal chatbot (`secure_chatbot_gateway.py`) that sends each turn through
  the Prisma AIRS AI Gateway with one HTTP call and renders the gateway's
  guardrail verdicts (`hook_results`), diagnostic headers, and token usage.
- Web front end (`web_app.py` + `static/index.html`): single-page chat with a
  verdict panel, quick test prompts (benign, injection, sensitive data,
  malicious URL, malicious code), and a config/health endpoint. Runs on a
  laptop or a VM with Flask, no build step.
- Optional side-by-side comparison with a direct Prisma AIRS scan API call
  (`PANW_AI_SEC_API_KEY` + `PANW_AI_SEC_PROFILE_NAME`) for "API vs gateway"
  demos.
- `tools/mock_gateway.py`: a stand-in gateway that returns the real
  200/246/446 shapes so the UI can be tried with no tenant or keys.
- `tools/selftest.py`: starts the mock and the web app and checks every
  verdict path end to end.
- Dockerfile and docker-compose for VM deployment.

[1.0.0]: https://github.com/scthornton/secure-chatbot-panw-gateway/releases/tag/v1.0.0
