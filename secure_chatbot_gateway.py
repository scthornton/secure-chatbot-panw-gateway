#!/usr/bin/env python3
"""
Terminal chatbot that talks to an LLM through the Prisma AIRS AI Gateway.

Compare with the three sibling repos (secure_chatbot, secure-chatbot-panw-openai,
secure-chatbot-panw-claude): those call the Prisma AIRS scan API from the app,
before and after the LLM call. This one makes a single call to the gateway and
lets the gateway run the AIRS guardrail. The app code is smaller, the provider
key never lives on the laptop, and every turn shows up in the gateway's
Observability view with attribution.

Run:  python3 secure_chatbot_gateway.py
Web:  python3 web_app.py
"""

import sys
import uuid

import gateway_chat as gw


def banner():
    cfg = gw.config_summary()
    print("=" * 64)
    print("SECURE CHATBOT via the PRISMA AIRS AI GATEWAY")
    print("=" * 64)
    print(f"Gateway:   {cfg['base_url']}")
    print(f"Model:     {cfg['model'] or '(from config)'}")
    print(f"Config:    {cfg['config']}")
    if cfg["provider_header"]:
        print(f"Provider:  {cfg['provider_header']}")
    print(f"Metadata:  app={cfg['app_name']} _user={cfg['user']}")
    print(f"Compare:   direct AIRS scan {'ON (profile ' + cfg['airs_profile'] + ')' if cfg['compare_direct_airs'] else 'off'}")
    print("=" * 64)


def print_hooks(hooks):
    if not hooks["present"]:
        print("   (no guardrail results in the response: the config has no sync "
              "guardrail, or the key's default config does not include one)")
        return
    for stage in ("input", "output"):
        for hook in hooks[stage]:
            verdict = "PASS" if hook["verdict"] else "FAIL"
            run = "async" if hook["async"] else "sync"
            # The gateway reports deny only on a failed hook, so the deny /
            # log-only mode is known only when the verdict is FAIL.
            mode = "" if hook["verdict"] else (", deny" if hook["deny"] else ", log-only")
            print(f"   {stage:6s} guardrail {hook['id']}: {verdict} ({run}{mode}, {hook['ms']} ms)")
            for check in hook["checks"]:
                mark = "ok  " if check["verdict"] else "FAIL"
                line = f"      [{mark}] {check['id']} ({check['ms']} ms)"
                if check["airs"]:
                    a = check["airs"]
                    fired = gw.fired_detectors(a["prompt_detected"]) + gw.fired_detectors(a["response_detected"])
                    line += f"  airs action={a['action']} category={a['category']}"
                    if fired:
                        line += f" detectors={','.join(fired)}"
                if check["error"]:
                    line += f"  error={check['error']}"
                print(line)


def print_direct(label, verdict):
    if verdict is None:
        return
    # A failed call returns {"error": "<message>"}; a real verdict may carry
    # an "error": false field, so test the value, not the key.
    if verdict.get("error"):
        print(f"   direct AIRS ({label}): error {verdict['error']}")
        return
    fired = gw.fired_detectors(verdict.get("prompt_detected")) + gw.fired_detectors(verdict.get("response_detected"))
    print(f"   direct AIRS ({label}): action={verdict.get('action')} category={verdict.get('category')}"
          f"{' detectors=' + ','.join(fired) if fired else ''}  scan_id={verdict.get('scan_id')}")


def main():
    banner()
    problems = gw.validate_config()
    if problems:
        print("\nConfiguration problems:")
        for p in problems:
            print(f"  - {p}")
        print("\nCopy .env.example to .env and fill it in, then run again.")
        sys.exit(1)

    ok, detail = gw.gateway_health()
    print(f"\nGateway health: {'OK' if ok else 'FAILED'} {detail}")
    if not ok:
        print("Fix the base URL or network path before chatting.")
        sys.exit(1)

    print("\nType a message and press Enter. 'exit' quits. Every turn is one call")
    print("to the gateway; the AIRS guardrail runs there, not in this app.\n")

    history = []
    trace_id = str(uuid.uuid4())
    print(f"Session trace id: {trace_id} (search this in the gateway's Logs view)")

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if user_input.lower() in ("exit", "quit"):
            print("Bye.")
            break
        if not user_input:
            continue

        history.append({"role": "user", "content": user_input})
        result = gw.chat(history, trace_id=trace_id)

        print(f"\n-- gateway: HTTP {result['status']} in {result['latency_ms']} ms", end="")
        if result["headers"].get("x-portkey-provider"):
            print(f", provider {result['headers']['x-portkey-provider']}", end="")
        if result["headers"].get("x-portkey-cache-status"):
            print(f", cache {result['headers']['x-portkey-cache-status']}", end="")
        print()
        print_hooks(result["hooks"])

        direct_prompt = gw.direct_airs_scan(user_input, trace_id=trace_id)
        print_direct("prompt", direct_prompt)

        if result["blocked"]:
            print(f"\nBLOCKED by the gateway guardrail (HTTP {result['status']}). The prompt never reached the model, or the reply was withheld.")
            if result["error"]:
                print(f"   {result['error']}")
            history.pop()  # keep the blocked turn out of the conversation
            continue

        if result["status"] not in (200, 246):
            print(f"\nERROR: {result['error']}")
            history.pop()
            continue

        if result["status"] == 246:
            print("\nNOTE: a guardrail failed but the request was allowed (HTTP 246). "
                  "Set Deny=TRUE on the guardrail to block instead of log.")

        direct_resp = gw.direct_airs_scan(user_input, response=result["text"], trace_id=trace_id)
        print_direct("prompt + response", direct_resp)

        print(f"\nAssistant: {result['text']}")
        if result["usage"]:
            u = result["usage"]
            print(f"   ({u.get('prompt_tokens')} prompt + {u.get('completion_tokens')} completion tokens, model {result['model']})")
        history.append({"role": "assistant", "content": result["text"]})


if __name__ == "__main__":
    main()
