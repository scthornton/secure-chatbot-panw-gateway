#!/usr/bin/env python3
"""
Web front end for the Prisma AIRS AI Gateway chatbot.

A single-page chat UI plus three JSON endpoints, all served by Flask from one
process. Nothing else to install or build. Run it on a laptop and open
http://127.0.0.1:8000, or set WEB_HOST=0.0.0.0 on a VM and open it from your
browser.

Endpoints
  GET  /            the chat page
  GET  /api/config  non-secret configuration summary + gateway health
  POST /api/chat    {"messages": [...]} -> gateway result (see gateway_chat.chat)
"""

import os
import uuid

from flask import Flask, jsonify, request, send_from_directory

import gateway_chat as gw

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

MAX_HISTORY = int(os.getenv("CHAT_MAX_HISTORY", "20"))


@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/api/config")
def api_config():
    ok, detail = gw.gateway_health()
    return jsonify({
        "config": gw.config_summary(),
        "problems": gw.validate_config(),
        "gateway_health": {"ok": ok, "detail": detail},
    })


@app.post("/api/chat")
def api_chat():
    body = request.get_json(silent=True) or {}
    messages = body.get("messages") or []
    trace_id = body.get("trace_id") or str(uuid.uuid4())

    # Keep only well-formed user/assistant turns, and only the recent ones.
    clean = [
        {"role": m["role"], "content": str(m["content"])[:20000]}
        for m in messages
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and m.get("content")
    ][-MAX_HISTORY:]
    if not clean or clean[-1]["role"] != "user":
        return jsonify({"error": "messages must end with a user turn"}), 400

    problems = gw.validate_config()
    if problems:
        return jsonify({"error": "configuration problems", "problems": problems}), 500

    result = gw.chat(clean, trace_id=trace_id)

    # Optional side-by-side direct scan (prompt, and prompt + reply when there is one).
    prompt = clean[-1]["content"]
    result["direct"] = None
    if gw.compare_enabled():
        result["direct"] = {
            "prompt": gw.direct_airs_scan(prompt, trace_id=trace_id),
            "response": gw.direct_airs_scan(prompt, response=result["text"], trace_id=trace_id) if result["text"] else None,
        }
    return jsonify(result)


if __name__ == "__main__":
    host = os.getenv("WEB_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_PORT", "8000"))
    print(f"Secure chatbot web UI on http://{host}:{port}  (gateway {gw.AIGW_BASE_URL})")
    for p in gw.validate_config():
        print(f"  CONFIG PROBLEM: {p}")
    app.run(host=host, port=port, debug=os.getenv("FLASK_DEBUG") == "1")
