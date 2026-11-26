#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CMOR — CORS Misconfiguration & Open Redirect scanner
coded by e4zyy | NOEL BUNSIAU

"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests
from requests.adapters import HTTPAdapter

# --------------------------------------------------------------------------- #
# CONFIG
# --------------------------------------------------------------------------- #

SCRIPT = "CMOR"
VERSION = "1.0"
AUTHOR = "coded by e4zyy | NOEL BUNSIAU"

# --- SCOPE ------------------------------------------------------------------ #
ALLOWED_DOMAINS = ["example.com"]
EXCLUDED_DOMAINS = ["://example.com", "://example.com"]

# --- PAYLOADS / CANARIES ---------------------------------------------------- #
EVIL_ORIGIN = "https://evil-test.com"
REDIRECT_CANARY = "https://example.org"
REDIRECT_PARAMS = ("next", "url", "redirect", "returnto")

SENSITIVE_FILES = (
    ("/.git/config", "Exposed .git/config"),
    ("/.env", "Exposed .env"),
)

# --- POLITENESS ------------------------------------------------------------- #
MAX_RPS = 3
JITTER_MIN, JITTER_MAX = 0.05, 0.20
BACKOFF_THRESHOLD = 3
BACKOFF_PAUSE = 30.0
TIMEOUT = 15
SNIPPET_LEN = 200

BASE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Bug-Bounty": "YourUsername",
    "Connection": "keep-alive",
}

# --------------------------------------------------------------------------- #
# TERMINAL
# --------------------------------------------------------------------------- #

class C:
    on = sys.stdout.isatty()
    R = "\033[0m" if on else ""
    DIM = "\033[2m" if on else ""
    B = "\033[1m" if on else ""
    RED = "\033[31m" if on else ""
    GRN = "\033[32m" if on else ""
    YEL = "\033[33m" if on else ""
    CYN = "\033[36m" if on else ""
    MAG = "\033[35m" if on else ""


_PRINT_LOCK = threading.Lock()


def log(msg: str, color: str = "") -> None:
    with _PRINT_LOCK:
        print(f"{color}{msg}{C.R}", flush=True)


def log_finding(kind: str, url: str, status: int, evidence: str) -> None:
    with _PRINT_LOCK:
        print(
            f"  {C.GRN}{C.B}[FOUND]{C.R} {C.MAG}{kind}{C.R} "
            f"{C.DIM}({status}){C.R} {url}\n         {C.DIM}-> {evidence}{C.R}",
            flush=True,
        )


def banner() -> None:
    log(f"{C.CYN}{C.B}"
        r"   ______ __  __ ____  ____  " "\n"
        r"  / ____/  |/  /  _ \/ __ \ " "\n"
        r" / /   / /|_/ /  / / / /_/ / " "\n"
        r"/ /___/ /  / /  /_/ / _, _/  " "\n"
        r"\____/_/  /_/\____/_/ |_|    " f"{C.R}")
    log(f"{C.DIM}{SCRIPT} v{VERSION} — CORS / sensitive files / open redirects{C.R}")
    log(f"{C.DIM}{AUTHOR}{C.R}")
    log(f"{C.DIM}allow={ALLOWED_DOMAINS} deny={EXCLUDED_DOMAINS} "
        f"rate={MAX_RPS}/s jitter={JITTER_MIN}-{JITTER_MAX}s{C.R}\n")


# --------------------------------------------------------------------------- #
# RATE LIMITING + BACKOFF
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Thread-safe global gate: never more than MAX_RPS, plus per-request jitter."""

    def __init__(self, max_per_second: int = MAX_RPS) -> None:
        self._min_interval = 1.0 / max_per_second
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()
        self._pause_until = 0.0
        self._waited_total = 0.0

    def pause(self, seconds: float) -> None:
        with self._lock:
            until = time.monotonic() + max(0.0, seconds)
            if until > self._pause_until:
                self._pause_until = until

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot, self._pause_until)
            self._next_slot = slot + self._min_interval
            waited = slot - now
        if waited > 0:
            time.sleep(waited)
        self._waited_total += waited
        time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))


class Backoff:
    """Trips a global cooldown after N consecutive 403/429 responses."""

    def __init__(self, limiter: RateLimiter) -> None:
        self._limiter = limiter
        self._lock = threading.Lock()
        self._streak = 0
        self.trips = 0

    def record(self, status: int, headers: dict | None = None) -> None:
        with self._lock:
            if status in (429, 403):
                self._streak += 1
                streak = self._streak
            else:
                self._streak = 0
                return

        if streak < BACKOFF_THRESHOLD:
            return

        wait = BACKOFF_PAUSE
        ra = (headers or {}).get("Retry-After")
        if ra:
            try:
                wait = max(float(str(ra).strip()), 1.0)
            except ValueError:
                pass  # HTTP-date form → keep default

        with self._lock:
            self._streak = 0
            self.trips += 1

        log(f"  {C.YEL}[!] {streak} consecutive 403/429 — cooling down {wait:.0f}s{C.R}")
        self._limiter.pause(wait)


# --------------------------------------------------------------------------- #
# SESSIONS
# --------------------------------------------------------------------------- #

_TLS = threading.local()


def session() -> requests.Session:
    s = getattr(_TLS, "s", None)
    if s is None:
        s = requests.Session()
        s.headers.update(BASE_HEADERS)
        adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _TLS.s = s
    return s


# --------------------------------------------------------------------------- #
# SCOPE
# --------------------------------------------------------------------------- #

def _strip(domain: str) -> str:
    d = domain.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    return d.strip("/").lstrip(".")


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def scope_verdict(url: str) -> str:
    host = host_of(url)
    if not host:
        return "no-host"
    if any(host == _strip(d) for d in EXCLUDED_DOMAINS):
        return "excluded"
    if any(host == _strip(d) or host.endswith("." + _strip(d)) for d in ALLOWED_DOMAINS):
        return "in-scope"
    return "not-allowed"


def load_targets(path: str) -> list[str]:
    out: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "://" not in line:
                    line = "https://" + line
                out.append(line)
    except FileNotFoundError:
        log(f"{C.RED}[x] {path} not found{C.R}")
        sys.exit(1)
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def fetch(url: str, limiter: RateLimiter, backoff: Backoff,
          extra: dict | None = None, stream: bool = False):
    limiter.acquire()
    headers = dict(extra) if extra else None
    try:
        r = session().get(url, headers=headers, allow_redirects=False,
                          timeout=TIMEOUT, stream=stream)
    except requests.RequestException as exc:
        log(f"  {C.RED}[ERR]{C.R} {url} {C.DIM}({type(exc).__name__}){C.R}")
        return None, b""

    body = b""
    if stream:
        try:
            body = next(r.iter_content(512), b"") or b""
        except requests.RequestException:
            pass
        finally:
            r.close()

    backoff.record(r.status_code, r.headers)
    return r, body


def snippet(text: str, limit: int = SNIPPET_LEN) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


# --------------------------------------------------------------------------- #
# CHECKS
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    url: str
    type: str
    severity: str
    status_code: int
    evidence: str
    timestamp: str


def check_cors(url: str, limiter: RateLimiter, backoff: Backoff) -> Finding | None:
    r, _ = fetch(url, limiter, backoff, extra={"Origin": EVIL_ORIGIN})
    if r is None:
        return None
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao.strip() in (EVIL_ORIGIN, "*") and acac == "true":
        return Finding(url, "CORS Misconfiguration", "low", r.status_code,
                       f"ACAO={acao} ACAC={acac}", now())
    return None


def check_sensitive(url: str, limiter: RateLimiter, backoff: Backoff,
                    path: str, label: str) -> Finding | None:
    r, body = fetch(url, limiter, backoff, stream=True)
    if r is None or r.status_code != 200:
        return None

    text = body.decode("utf-8", "replace")
    low = text.lower()

    if path == "/.git/config":
        if "[core]" not in low:
            return None
        return Finding(url, label, "medium", r.status_code, snippet(text), now())

    # /.env — reject HTML catch-all pages
    if "<html" in low or "<!doctype" in low:
        return None
    if not re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", text):
        return None
    return Finding(url, label, "medium", r.status_code, snippet(text), now())


def check_redirect(url: str, limiter: RateLimiter, backoff: Backoff) -> Finding | None:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    hit = [k for k, _ in pairs if k.lower() in REDIRECT_PARAMS]
    if not hit:
        return None

    rebuilt = [(k, REDIRECT_CANARY if k.lower() in REDIRECT_PARAMS else v) for k, v in pairs]
    probe = urlunparse(parsed._replace(query=urlencode(rebuilt, doseq=True)))

    r, _ = fetch(probe, limiter, backoff)
    if r is None or r.status_code not in (301, 302, 303, 307, 308):
        return None

    location = r.headers.get("Location", "")
    if not location:
        return None
    target = host_of(location) or host_of("https://" + location.lstrip("/"))
    if target != "example.org":
        return None

    return Finding(probe, "Open Redirect", "low", r.status_code,
                   f"Location: {snippet(location)}", now())


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# RUNNER
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description=f"{SCRIPT} — {AUTHOR}")
    ap.add_argument("-t", "--targets", default="targets.txt")
    ap.add_argument("-o", "--output", default="findings.json")
    ap.add_argument("-w", "--workers", type=int, default=4,
                    help="concurrency (rate limit is global, not per worker)")
    args = ap.parse_args()

    banner()

    raw = load_targets(args.targets)
    log(f"{C.DIM}[*] loaded {len(raw)} target(s) from {args.targets}{C.R}")

    in_scope: list[str] = []
    for u in raw:
        verdict = scope_verdict(u)
        if verdict == "in-scope":
            in_scope.append(u)
        else:
            log(f"  {C.YEL}[skip]{C.R} {u} {C.DIM}({verdict}){C.R}")

    if not in_scope:
        log(f"{C.RED}[x] nothing in scope{C.R}")
        return 1

    origins = list(dict.fromkeys(
        f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in in_scope
    ))

    limiter = RateLimiter()
    backoff = Backoff(limiter)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    lock = threading.Lock()
    counter = {"done": 0, "total": len(in_scope) + len(in_scope) + len(origins) * len(SENSITIVE_FILES)}

    log(f"{C.CYN}[*] {len(in_scope)} URL(s), {len(origins)} origin(s) — "
        f"~{counter['total']} requests planned{C.R}\n")

    def record(f: Finding | None) -> None:
        with lock:
            counter["done"] += 1
            done = counter["done"]
        if f and (f.url, f.type) not in seen:
            with lock:
                seen.add((f.url, f.type))
                findings.append(f)
            log_finding(f.type, f.url, f.status_code, f.evidence)

    def job_cors(u: str) -> None:
        r = check_cors(u, limiter, backoff)
        if not r:
            with lock:
                counter["done"] += 1
        else:
            record(r)

    def job_redirect(u: str) -> None:
        r = check_redirect(u, limiter, backoff)
        if not r:
            with lock:
                counter["done"] += 1
        else:
            record(r)

    def job_file(o: str, path: str, label: str) -> None:
        r = check_sensitive(o, limiter, backoff, path, label)
        if not r:
            with lock:
                counter["done"] += 1
        else:
            record(r)

    jobs = []
    for u in in_scope:
        jobs.append((job_cors, (u,)))
        jobs.append((job_redirect, (u,)))
    for o in origins:
        for path, label in SENSITIVE_FILES:
            jobs.append((job_file, (o, path, label)))

    started = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(fn, *a) for fn, a in jobs]
        try:
            for fut in futures:
                fut.result()
        except KeyboardInterrupt:
            log(f"\n{C.YEL}[!] interrupted — flushing findings{C.R}")
            pool.shutdown(wait=False, cancel_futures=True)

    with lock:
        payload = [asdict(f) for f in findings]

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "tool": SCRIPT,
                "version": VERSION,
                "author": AUTHOR,
                "generated": now(),
                "scope": {"allow": ALLOWED_DOMAINS, "deny": EXCLUDED_DOMAINS},
                "stats": {
                    "targets": len(in_scope),
                    "requests": counter["done"],
                    "backoff_trips": backoff.trips,
                    "elapsed_s": round(time.time() - started, 1),
                },
                "findings": payload,
            },
            fh,
            indent=2,
        )

    log(f"\n{C.B}{'=' * 52}{C.R}")
    log(f"{C.B}[*] {len(payload)} verified finding(s) -> {args.output}{C.R}")
    log(f"{C.DIM}    requests={counter['done']} cooldowns={backoff.trips} "
        f"elapsed={time.time() - started:.1f}s{C.R}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log(f"\n{C.YEL}[!] aborted{C.R}")
        sys.exit(130)
