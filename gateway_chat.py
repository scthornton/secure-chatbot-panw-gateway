"""
Shared core for the Prisma AIRS AI Gateway chatbot.

One HTTP call per turn: the app sends an OpenAI-style chat completion to the
AI Gateway, and the gateway does the rest (route to the provider, run the
AIRS guardrail on the prompt and the reply, log everything). The app never
talks to the Prisma AIRS scan API itself unless you turn on the optional
side-by-side comparison, which is there to show the difference between
"app calls the scan API" (the three sibling repos) and "gateway does it".

Both the terminal chatbot and the web UI import this module.
"""

import json
import os
import time
import uuid
import getpass

import requests

# Load .env if present. Real environment variables win over .env values.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

__version__ = "1.0.1"

# ---------------------------------------------------------------------------
# Configuration (all from the environment; see .env.example)
# ---------------------------------------------------------------------------

# Hosted (SaaS) gateway for every AIRS tenant is https://aigw.portkey.ai/v1.
# A hybrid data plane is https://<your-gateway-host>/v1. Standalone Portkey
# accounts use https://api.portkey.ai/v1 (keys are not interchangeable).
AIGW_BASE_URL = os.getenv("AIGW_BASE_URL", "https://aigw.portkey.ai/v1").rstrip("/")

# Service key minted under Security Keys in Strata Cloud Manager. One key per
# app is what makes per-app attribution, budgets, and revocation work.
AIGW_API_KEY = os.getenv("AIGW_API_KEY", "")

# Model in catalog form: @<provider-slug>/<model>, for example @openai/gpt-4o-mini.
AIGW_MODEL = os.getenv("AIGW_MODEL", "")

# Optional routing config. Either a saved config id (pc-...) that carries the
# AIRS guardrail in input_guardrails/output_guardrails, or an inline JSON
# config (used with the open-source gateway). Leave empty when the service
# key already has a default config attached.
AIGW_CONFIG = os.getenv("AIGW_CONFIG", "").strip()

# Optional provider header for bare-type routing (openai, anthropic, ...).
# Not needed when AIGW_MODEL uses the @slug form or a config names the provider.
AIGW_PROVIDER = os.getenv("AIGW_PROVIDER", "").strip()

# Attribution metadata. Shows up in the gateway's Observability view and
# drives per-user budgets and rate limits. _user is Portkey's reserved key.
AIGW_APP_NAME = os.getenv("AIGW_APP_NAME", "secure-chatbot-gateway")
AIGW_USER = os.getenv("AIGW_USER", getpass.getuser())

# Optional system prompt and generation knobs.
CHAT_SYSTEM_PROMPT = os.getenv("CHAT_SYSTEM_PROMPT", "You are a helpful, concise assistant.")
CHAT_MAX_TOKENS = int(os.getenv("CHAT_MAX_TOKENS", "600"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "60"))

# Optional side-by-side comparison with a direct Prisma AIRS scan API call.
PANW_AI_SEC_API_KEY = os.getenv("PANW_AI_SEC_API_KEY", "")
PANW_AI_SEC_PROFILE_NAME = os.getenv("PANW_AI_SEC_PROFILE_NAME", "")
PANW_AI_SEC_ENDPOINT = os.getenv(
    "PANW_AI_SEC_ENDPOINT", "https://service.api.aisecurity.paloaltonetworks.com"
).rstrip("/")

# Cloudflare in front of the hosted gateway returns "error code: 1010" to the
# default Python/urllib User-Agent. A descriptive UA avoids that.
USER_AGENT = f"secure-chatbot-panw-gateway/{__version__} (+https://github.com/scthornton/secure-chatbot-panw-gateway)"


def compare_enabled():
    """True when the optional direct-scan comparison is configured."""
    return bool(PANW_AI_SEC_API_KEY and PANW_AI_SEC_PROFILE_NAME)


def config_summary():
    """Non-secret view of the active configuration, for the UI and the CLI banner."""
    mode = "none"
    if AIGW_CONFIG.startswith("pc-"):
        mode = "saved config " + AIGW_CONFIG
    elif AIGW_CONFIG.startswith("{"):
        mode = "inline config"
    return {
        "base_url": AIGW_BASE_URL,
        "model": AIGW_MODEL,
        "config": mode,
        "provider_header": AIGW_PROVIDER or None,
        "app_name": AIGW_APP_NAME,
        "user": AIGW_USER,
        "api_key_present": bool(AIGW_API_KEY),
        "compare_direct_airs": compare_enabled(),
        "airs_profile": PANW_AI_SEC_PROFILE_NAME or None,
        "version": __version__,
    }


def validate_config():
    """Return a list of human-readable problems, empty when the config is usable."""
    problems = []
    if not AIGW_API_KEY:
        problems.append("AIGW_API_KEY is not set (mint a service key under Security Keys in SCM)")
    if not AIGW_MODEL and not AIGW_CONFIG:
        problems.append("Set AIGW_MODEL (for example @openai/gpt-4o-mini) or an AIGW_CONFIG that names a model")
    if AIGW_CONFIG.startswith("pg-"):
        problems.append("AIGW_CONFIG looks like a guardrail id (pg-...). It needs a config id (pc-...) that references the guardrail")
    if AIGW_CONFIG.startswith("{"):
        try:
            json.loads(AIGW_CONFIG)
        except json.JSONDecodeError as exc:
            problems.append(f"AIGW_CONFIG is not valid JSON: {exc}")
    if not AIGW_BASE_URL.endswith("/v1"):
        problems.append(f"AIGW_BASE_URL should end in /v1 (got {AIGW_BASE_URL})")
    return problems


# ---------------------------------------------------------------------------
# Gateway call
# ---------------------------------------------------------------------------

def _gateway_headers(trace_id):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        # The service key authenticates the app to the gateway. The OpenAI SDK
        # pattern puts it in Authorization; x-portkey-api-key is the explicit
        # gateway header. Sending both works on hosted, hybrid, and OSS.
        "Authorization": f"Bearer {AIGW_API_KEY}",
        "x-portkey-api-key": AIGW_API_KEY,
        # Without this the guardrail verdicts (hook_results) are stripped from
        # the response body so it stays strictly OpenAI-shaped.
        "x-portkey-strict-open-ai-compliance": "false",
        # Groups every turn of this chat session in the gateway's trace view.
        "x-portkey-trace-id": trace_id,
        # Attribution for Observability, budgets, and rate limits.
        "x-portkey-metadata": json.dumps({"_user": AIGW_USER, "app": AIGW_APP_NAME}),
    }
    if AIGW_CONFIG:
        headers["x-portkey-config"] = AIGW_CONFIG
    if AIGW_PROVIDER:
        headers["x-portkey-provider"] = AIGW_PROVIDER
    return headers


def _summarize_hooks(body):
    """
    Flatten Portkey hook_results into something a UI can render.

    Returns a dict:
      {
        "present": bool,
        "input":  [ {id, verdict, deny, async, checks:[{id, verdict, ms, airs:{...}}]} ],
        "output": [ ... same ... ],
        "failed": bool,  # any sync guardrail failed
        "denied": bool   # a failed sync guardrail had deny=true (request or response withheld)
      }
    """
    hooks = (body or {}).get("hook_results") or {}
    out = {"present": bool(hooks), "input": [], "output": [], "failed": False, "denied": False}
    for stage, key in (("input", "before_request_hooks"), ("output", "after_request_hooks")):
        for hook in hooks.get(key) or []:
            checks = []
            for check in hook.get("checks") or []:
                data = check.get("data") or {}
                # The AIRS check returns the scan verdict in data when it ran.
                airs = None
                if isinstance(data, dict) and ("prompt_detected" in data or "response_detected" in data or "action" in data):
                    airs = {
                        "action": data.get("action"),
                        "category": data.get("category"),
                        "prompt_detected": data.get("prompt_detected"),
                        "response_detected": data.get("response_detected"),
                        "scan_id": data.get("scan_id"),
                        "report_id": data.get("report_id"),
                    }
                checks.append({
                    "id": check.get("id"),
                    "verdict": check.get("verdict"),
                    "ms": check.get("execution_time"),
                    "error": check.get("error") or (data.get("error") if isinstance(data, dict) else None),
                    "airs": airs,
                })
            entry = {
                "id": hook.get("id"),
                "verdict": hook.get("verdict"),
                "deny": hook.get("deny"),
                "async": hook.get("async"),
                "ms": hook.get("execution_time"),
                "checks": checks,
            }
            if hook.get("verdict") is False and not hook.get("async"):
                out["failed"] = True
                if hook.get("deny"):
                    out["denied"] = True
            out[stage].append(entry)
    return out


def chat(messages, trace_id=None):
    """
    Send one chat turn through the AI Gateway.

    messages: OpenAI-style list of {role, content}. The system prompt is
    prepended here.

    Returns a dict the UI and CLI both understand:
      status      HTTP status from the gateway (200 ok, 246 guardrail failed but
                  allowed, 446 blocked by guardrail, other = error)
      blocked     True when the gateway refused the request
      text        assistant reply ("" when blocked or errored)
      error       error message when status is not 200/246
      hooks       guardrail summary from _summarize_hooks
      headers     diagnostic response headers (trace id, provider, cache, version)
      usage       token usage dict if the provider returned one
      model       model the provider reported
      latency_ms  round trip as measured by this app
    """
    trace_id = trace_id or str(uuid.uuid4())
    payload = {
        "messages": [{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + messages,
        "max_tokens": CHAT_MAX_TOKENS,
    }
    if AIGW_MODEL:
        payload["model"] = AIGW_MODEL

    result = {
        "status": None, "blocked": False, "text": "", "error": None,
        "hooks": {"present": False, "input": [], "output": [], "failed": False, "denied": False},
        "headers": {}, "usage": None, "model": None, "latency_ms": None,
        "trace_id": trace_id,
    }

    started = time.time()
    try:
        resp = requests.post(
            f"{AIGW_BASE_URL}/chat/completions",
            headers=_gateway_headers(trace_id),
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        result["error"] = f"Could not reach the gateway at {AIGW_BASE_URL}: {exc}"
        result["latency_ms"] = round((time.time() - started) * 1000)
        return result

    result["latency_ms"] = round((time.time() - started) * 1000)
    result["status"] = resp.status_code

    # Diagnostic headers. If none are present the request never reached a
    # Portkey-based gateway (a proxy, WAF, or wrong base URL answered).
    for h in ("x-portkey-trace-id", "x-portkey-provider", "x-portkey-cache-status",
              "x-portkey-retry-attempt-count", "x-portkey-version", "x-portkey-last-used-option-index"):
        if h in resp.headers:
            result["headers"][h] = resp.headers[h]

    try:
        body = resp.json()
    except ValueError:
        body = {}
        if resp.status_code == 403 and "1010" in resp.text:
            result["error"] = "Cloudflare blocked the request (error 1010). This usually means the User-Agent was rejected or egress is from a blocked range."
        else:
            result["error"] = f"Gateway returned HTTP {resp.status_code} with a non-JSON body: {resp.text[:300]}"
        return result

    result["hooks"] = _summarize_hooks(body)

    if resp.status_code in (200, 246):
        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content = message.get("content")
        if isinstance(content, list):  # some providers return content blocks
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        result["usage"] = body.get("usage")
        result["model"] = body.get("model")
        # Gateway 2.30+ (hosted) answers a denied request with HTTP 200, a
        # canned "guardrail checks ... failed" message in choices, zero usage
        # and model "unknown" instead of HTTP 446. The hook_results carry the
        # real verdict, so treat a failed deny guardrail as a block either way.
        if result["hooks"]["denied"]:
            result["blocked"] = True
            result["error"] = content or "Blocked by a gateway guardrail."
            return result
        result["text"] = content or ""
        return result

    if resp.status_code == 446:
        result["blocked"] = True
        err = body.get("error") or {}
        result["error"] = err.get("message") if isinstance(err, dict) else str(err)
        return result

    err = body.get("error") or body.get("message") or body
    result["error"] = err.get("message", json.dumps(err)) if isinstance(err, dict) else str(err)
    if resp.status_code == 401:
        if body.get("provider") or "error:" in (result["error"] or ""):
            # The gateway accepted AIGW_API_KEY and ran the input guardrail; the
            # upstream provider rejected the key stored in the provider
            # integration (for example "anthropic error: invalid x-api-key").
            result["error"] += (f" (the gateway authenticated this app and the input guardrail ran; "
                                f"the provider integration behind {AIGW_MODEL or 'the model'} holds an "
                                f"invalid or expired provider key. Fix it under AI Gateway > Providers / "
                                f"Model Catalog in Strata Cloud Manager, or point AIGW_MODEL at another slug)")
        else:
            result["error"] += (" (Invalid API Key / Error Code 03 means the key is not from this gateway's "
                                "tenant: an SCM Security Key only works on aigw.portkey.ai or your hybrid data plane, "
                                "a standalone Portkey key only on api.portkey.ai)")
    return result


def gateway_health():
    """GET /health on the gateway. Returns (ok, detail)."""
    try:
        resp = requests.get(
            f"{AIGW_BASE_URL}/health",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=15,
        )
    except requests.exceptions.RequestException as exc:
        return False, str(exc)
    try:
        return resp.status_code == 200, resp.json()
    except ValueError:
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"


# ---------------------------------------------------------------------------
# Optional: direct Prisma AIRS scan for side-by-side comparison
# ---------------------------------------------------------------------------

def direct_airs_scan(prompt, response=None, trace_id=None):
    """
    Call the Prisma AIRS scan API directly, the way the sibling repos do.

    Only used when PANW_AI_SEC_API_KEY and PANW_AI_SEC_PROFILE_NAME are set.
    Returns the raw verdict dict, or {"error": "..."}.
    """
    if not compare_enabled():
        return None
    content = {"prompt": prompt}
    if response is not None:
        content["response"] = response
    payload = {
        "tr_id": trace_id or str(uuid.uuid4()),
        "ai_profile": {"profile_name": PANW_AI_SEC_PROFILE_NAME},
        "metadata": {"app_name": AIGW_APP_NAME + "-direct", "app_user": AIGW_USER, "ai_model": AIGW_MODEL or "unknown"},
        "contents": [content],
    }
    try:
        resp = requests.post(
            f"{PANW_AI_SEC_ENDPOINT}/v1/scan/sync/request",
            headers={"Content-Type": "application/json", "x-pan-token": PANW_AI_SEC_API_KEY, "User-Agent": USER_AGENT},
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        return {"error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except requests.exceptions.RequestException as exc:
        return {"error": str(exc)}


def fired_detectors(detected):
    """Names of detectors that are True in a prompt_detected/response_detected map."""
    return sorted(k for k, v in (detected or {}).items() if v)
