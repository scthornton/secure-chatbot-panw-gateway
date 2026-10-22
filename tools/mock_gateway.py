#!/usr/bin/env python3
"""
Tiny stand-in for the AI Gateway so you can try the chatbot and the web UI on a
laptop with no tenant, no keys, and no network.

It speaks just enough of the gateway's API: GET /v1/health and
POST /v1/chat/completions, and it returns the same hook_results shape the real
gateway returns when a Prisma AIRS guardrail is attached with Async=FALSE.

Verdict rules (keyword based, this is a mock):
  prompt contains "ignore all previous instructions"  -> 446, input guardrail FAIL (injection)
  prompt contains "system prompt"                      -> 200 + canned denial message (hosted gateway 2.30+ shape)
  prompt contains "ssn" or "social security"           -> reply leaks an SSN, output guardrail FAIL -> 446
  prompt starts with "246 "                            -> 246, input guardrail FAIL but allowed (Deny off)
  anything else                                        -> 200, guardrails PASS, echo-style reply

Run:   python3 tools/mock_gateway.py            (listens on 127.0.0.1:8790; MOCK_PORT overrides)
Then:  AIGW_BASE_URL=http://127.0.0.1:8790/v1 AIGW_API_KEY=mock AIGW_MODEL=@mock/echo python3 web_app.py

8790 rather than the real gateway's 8787 so it does not collide with a local
Portkey gateway or an ssh tunnel to one.
"""

import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.getenv("MOCK_PORT", "8790"))


def airs_data(action, prompt_hits=(), response_hits=None):
    base = {"agent": False, "dlp": False, "injection": False, "malicious_code": False, "toxic_content": False, "url_cats": False}
    pd = dict(base, **{k: True for k in prompt_hits})
    data = {
        "action": action,
        "category": "malicious" if action == "block" else "benign",
        "prompt_detected": pd,
        "scan_id": str(uuid.uuid4()),
    }
    data["report_id"] = "R" + data["scan_id"]
    if response_hits is not None:
        rd = {"dlp": False, "db_security": False, "toxic_content": False, "url_cats": False, "malicious_code": False}
        rd.update({k: True for k in response_hits})
        data["response_detected"] = rd
    return data


def hook(stage_id, verdict, data, deny=True):
    return {
        "verdict": verdict, "id": stage_id, "transformed": False, "deny": deny, "async": False,
        "type": "guardrail", "execution_time": 180,
        "checks": [{"id": "default.panwPrismaAirs", "verdict": verdict, "execution_time": 175, "transformed": False, "data": data}],
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("x-portkey-trace-id", self.headers.get("x-portkey-trace-id", str(uuid.uuid4())))
        self.send_header("x-portkey-provider", "mock")
        self.send_header("x-portkey-cache-status", "DISABLED")
        self.send_header("x-portkey-version", "mock-0.1")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):  # quieter console
        print(f"[mock] {self.command} {self.path} {args[1] if len(args) > 1 else ''}")

    def do_GET(self):
        if self.path.rstrip("/").endswith("/health"):
            return self._send(200, {"status": "success", "message": "Server is healthy", "version": "mock-0.1"})
        self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            return self._send(404, {"error": {"message": "not found"}})
        if not (self.headers.get("x-portkey-api-key") or self.headers.get("Authorization")):
            return self._send(401, {"status": "failure", "message": "Portkey Error: Invalid API Key. Error Code: 03"})
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        user = [m for m in body.get("messages", []) if m.get("role") == "user"]
        prompt = (user[-1]["content"] if user else "").strip()
        low = prompt.lower()
        time.sleep(0.2)

        if "ignore all previous instructions" in low or "ignore previous instructions" in low:
            data = airs_data("block", prompt_hits=("injection", "agent"))
            return self._send(446, {
                "error": {"message": "The guardrail checks defined in the config failed. You can find more information in the `hook_results` object.", "type": "hooks_failed", "param": None, "code": None},
                "hook_results": {"before_request_hooks": [hook("pg-mock-airs", False, data)], "after_request_hooks": []},
            })

        if "system prompt" in low:
            # Hosted gateway 2.30+ shape: HTTP 200, canned text in choices, zero
            # usage, model "unknown", verdict only in hook_results (deny=true).
            data = airs_data("block", prompt_hits=("injection",))
            canned = "The guardrail checks defined in the config failed. You can find more information in the `hook_results` object."
            resp = self._completion(body, canned, before=hook("pg-mock-airs", False, data))
            resp["model"] = "unknown"
            resp["usage"] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            return self._send(200, resp)

        if low.startswith("246 "):
            data = airs_data("block", prompt_hits=("injection",))
            reply = "This reply was returned even though a guardrail failed, because Deny is off on this guardrail."
            return self._send(246, self._completion(body, reply, before=hook("pg-mock-airs", False, data, deny=False)))

        if "ssn" in low or "social security" in low:
            reply = "Sure. Your SSN on file is 078-05-1120 and your card ends in 1111."
            pdata = airs_data("allow")
            rdata = airs_data("block", response_hits=("dlp",))
            return self._send(446, {
                "error": {"message": "The guardrail checks defined in the config failed. You can find more information in the `hook_results` object.", "type": "hooks_failed", "param": None, "code": None},
                "hook_results": {"before_request_hooks": [hook("pg-mock-airs", True, pdata)], "after_request_hooks": [hook("pg-mock-airs", False, rdata)]},
            })

        reply = f"(mock gateway) You said: {prompt}"
        pdata = airs_data("allow")
        rdata = airs_data("allow", response_hits=())
        return self._send(200, self._completion(body, reply, before=hook("pg-mock-airs", True, pdata), after=hook("pg-mock-airs", True, rdata)))

    def _completion(self, body, reply, before=None, after=None):
        return {
            "id": "chatcmpl-mock-" + uuid.uuid4().hex[:8],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model") or "@mock/echo",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 42, "completion_tokens": len(reply.split()), "total_tokens": 42 + len(reply.split())},
            "hook_results": {"before_request_hooks": [before] if before else [], "after_request_hooks": [after] if after else []},
        }


if __name__ == "__main__":
    try:
        server = HTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        print(f"Cannot listen on 127.0.0.1:{PORT}: {exc}. Set MOCK_PORT to a free port.", file=sys.stderr)
        sys.exit(1)
    print(f"Mock AI Gateway listening on http://127.0.0.1:{PORT}/v1  (Ctrl+C to stop)", flush=True)
    server.serve_forever()
