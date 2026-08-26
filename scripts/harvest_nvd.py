#!/usr/bin/env python3
"""
harvest_nvd.py -- WordPress-ecosystem CVE harvester for wpsentinel.

Pulls CVEs from the NVD 2.0 REST API (https://services.nvd.nist.gov/rest/json/cves/2.0)
for the WordPress ecosystem (plugins / themes / core), normalizes them, and writes
newline-delimited JSON to data/raw/nvd.ndjson.

Design notes
------------
* Two complementary query routes are unioned, because neither alone has full recall:

    1. CPE route:  virtualMatchString=cpe:2.3:a:*:*:*:*:*:*:*:wordpress:*:*
       Matches the CPE `target_sw` field == "wordpress". High precision and the
       best recall for *analyzed* CVEs (NVD has attached CPE data). Wins by a
       large margin on Patchstack-sourced CVEs whose descriptions never contain
       the literal word "wordpress".

    2. Keyword route: keywordSearch=wordpress
       Catches CVEs NVD has not finished enriching (no CPE yet) -- which is the
       dominant case for recently published CVEs -- plus a small tail of
       oddly-CPE'd entries.

  Measured on a 2024-01-01..2024-03-01 probe window:
       keyword only :  565   (7 unique)
       CPE only     :  807   (249 unique)
       union        :  814
  => run both, dedupe by CVE id.

* NVD caps pubStartDate/pubEndDate ranges at 120 days, so the scope is chunked
  into <=120-day windows.

* Unauthenticated rate limit is 5 requests / 30 seconds. We sleep SLEEP_SECONDS
  (default 8) between every request and back off exponentially on 403/429/5xx.

* Resumable: each (window, route) pagination task is checkpointed in
  data/raw/nvd_checkpoint.json. Already-emitted CVE ids are recovered by
  re-reading data/raw/nvd.ndjson, so re-running is safe and idempotent.

PROJECT RULE: we deliberately do NOT record plugin/vendor/product names or
researcher credits. We keep the description (it describes the FLAW), the CWE
list, and the CVSS score/vector -- those are the fields that drive our taxonomy
and priority ranking.

Usage
-----
    python3 scripts/harvest_nvd.py                  # harvest full scope + derive refs
    python3 scripts/harvest_nvd.py --refs-only      # just re-derive ref files from nvd.ndjson
    python3 scripts/harvest_nvd.py --start 2023-01-01 --end 2026-08-26
    python3 scripts/harvest_nvd.py --reset          # drop checkpoint + outputs, start clean

Stdlib only. No third-party deps.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta

# --------------------------------------------------------------------------
# Paths / constants
# --------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(REPO_ROOT, "data", "raw")

NDJSON_PATH = os.path.join(RAW_DIR, "nvd.ndjson")
CHECKPOINT_PATH = os.path.join(RAW_DIR, "nvd_checkpoint.json")
TRAC_REFS_PATH = os.path.join(RAW_DIR, "trac_refs_nvd.txt")
XREF_URLS_PATH = os.path.join(RAW_DIR, "xref_urls.txt")

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "wpsentinel-oss-security-audit/1.0 (+https://github.com/wpsentinel)"

SCOPE_START = "2023-01-01"          # hard floor -- do not go earlier
SCOPE_END = "2026-08-26"

WINDOW_DAYS = 115                   # NVD caps date ranges at 120 days
RESULTS_PER_PAGE = 2000             # NVD max
SLEEP_SECONDS = 12.0                # >= 6s required; 12s for headroom, because the
                                    # 5-req/30s budget is per-IP and may be shared
                                    # with other harvesters running concurrently
MAX_RETRIES = 9
BACKOFF_CAP = 300.0
REQUEST_TIMEOUT = 180

ROUTES = [
    # (route_id, extra query params)
    ("cpe", {"virtualMatchString": "cpe:2.3:a:*:*:*:*:*:*:*:wordpress:*:*"}),
    ("keyword", {"keywordSearch": "wordpress"}),
]


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def api_get(params, verbose=True):
    """GET the NVD API with exponential backoff on 403/429/5xx. Returns parsed JSON."""
    url = API_BASE + "?" + urllib.parse.urlencode(params)
    delay = 15.0
    last_err = None

    for attempt in range(1, MAX_RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            last_err = "HTTP %s" % e.code
            retryable = e.code in (403, 429) or 500 <= e.code < 600
            if not retryable:
                raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionError) as e:
            last_err = "%s: %s" % (type(e).__name__, e)

        if attempt == MAX_RETRIES:
            raise RuntimeError("NVD request failed after %d attempts (%s): %s"
                               % (MAX_RETRIES, last_err, url))
        if verbose:
            print("    [retry %d/%d] %s -- sleeping %.0fs"
                  % (attempt, MAX_RETRIES, last_err, delay), flush=True)
        time.sleep(delay)
        delay = min(delay * 2, BACKOFF_CAP)

    raise RuntimeError("unreachable")


# --------------------------------------------------------------------------
# Normalization helpers
# --------------------------------------------------------------------------

CWE_RE = re.compile(r"^CWE-\d+$")


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    return None


def extract_cwes(cve):
    """Return de-duplicated real CWE ids. NVD-CWE-noinfo / NVD-CWE-Other are dropped."""
    out = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") != "en":
                continue
            val = (d.get("value") or "").strip()
            if CWE_RE.match(val) and val not in out:
                out.append(val)
    return out


def pick_cvss(cve):
    """
    Choose the best CVSS v3.x metric.

    Preference: v3.1 Primary > v3.1 nvd@nist.gov > v3.1 first
                > v3.0 Primary > v3.0 first.
    The returned vector string self-identifies its version ("CVSS:3.1/..." vs
    "CVSS:3.0/..."), so nothing is misrepresented by the shared field.

    Returns (base_score, vector_string, severity, version) or (None, None, None, None).
    """
    metrics = cve.get("metrics", {}) or {}

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = None
        for e in entries:
            if e.get("type") == "Primary":
                chosen = e
                break
        if chosen is None:
            for e in entries:
                if e.get("source") == "nvd@nist.gov":
                    chosen = e
                    break
        if chosen is None:
            chosen = entries[0]

        data = chosen.get("cvssData", {}) or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        severity = data.get("baseSeverity")
        return (
            float(score) if isinstance(score, (int, float)) else None,
            vector or None,
            severity or None,
            data.get("version") or ("3.1" if key == "cvssMetricV31" else "3.0"),
        )

    return (None, None, None, None)


def parse_vector(vector):
    """CVSS vector string -> dict of metric abbreviations."""
    if not vector:
        return {}
    out = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            out[k] = v
    return out


def derive_auth_required(vector):
    """
    Map the CVSS vector onto the WordPress privilege model.

      AV:N + PR:N -> "unauthenticated"          (anyone on the internet)
      PR:N, AV!=N -> "unauthenticated-local"    (no creds, but not remote)
      PR:L        -> "subscriber+/contributor+"
      PR:H        -> "admin+"
      no vector   -> None
    """
    v = parse_vector(vector)
    pr = v.get("PR")
    av = v.get("AV")
    if pr is None:
        return None
    if pr == "N":
        return "unauthenticated" if av == "N" else "unauthenticated-local"
    if pr == "L":
        return "subscriber+/contributor+"
    if pr == "H":
        return "admin+"
    return None


def cpe_criteria(cve):
    out = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                c = m.get("criteria")
                if c:
                    out.append(c)
    return out


PLUGIN_URL_HINTS = (
    "wordpress.org/plugins/",
    "plugins.trac.wordpress.org",
    "plugins.svn.wordpress.org",
    "/wordpress-plugins/",
    "wpscan.com/plugin/",
)
THEME_URL_HINTS = (
    "wordpress.org/themes/",
    "themes.trac.wordpress.org",
    "themes.svn.wordpress.org",
    "/wordpress-themes/",
    "wpscan.com/theme/",
)

# Patchstack advisory slugs encode the artifact type, e.g.
#   /database/vulnerability/footer-putter/wordpress-footer-putter-plugin-1-17-cross-site-scripting-...
#   /database/vulnerability/<slug>/wordpress-<name>-theme-<ver>-<flaw>-vulnerability
# These CVEs are Patchstack-sourced and their descriptions usually never say
# "plugin"/"theme", so the URL is the only structured signal available.
RE_PS_PLUGIN = re.compile(r"patchstack\.com/database/[^\s]*?-plugin-", re.I)
RE_PS_THEME = re.compile(r"patchstack\.com/database/[^\s]*?-theme-", re.I)

RE_WP_PLUGIN = re.compile(r"(wordpress\s+plugin|plugin\s+for\s+wordpress|wp\s+plugin)", re.I)
RE_WP_THEME = re.compile(r"(wordpress\s+theme|theme\s+for\s+wordpress|wp\s+theme)", re.I)
RE_PLUGIN = re.compile(r"\bplug-?ins?\b", re.I)
RE_THEME = re.compile(r"\bthemes?\b", re.I)
RE_WP_CORE = re.compile(r"wordpress\s+core|core\s+of\s+wordpress", re.I)


def classify_software_type(cve, description, references):
    """plugin | theme | core | unknown -- evidence ordered strongest-first."""
    refs_blob = " ".join(references).lower()
    desc = description or ""

    ref_plugin = (any(h in refs_blob for h in PLUGIN_URL_HINTS)
                  or bool(RE_PS_PLUGIN.search(refs_blob)))
    ref_theme = (any(h in refs_blob for h in THEME_URL_HINTS)
                 or bool(RE_PS_THEME.search(refs_blob)))
    if ref_plugin and not ref_theme:
        return "plugin"
    if ref_theme and not ref_plugin:
        return "theme"

    if RE_WP_PLUGIN.search(desc):
        return "plugin"
    if RE_WP_THEME.search(desc):
        return "theme"

    cpes = cpe_criteria(cve)
    if any(c.startswith("cpe:2.3:a:wordpress:wordpress:") for c in cpes):
        return "core"
    if RE_WP_CORE.search(desc):
        return "core"

    if ref_plugin:
        return "plugin"
    if ref_theme:
        return "theme"
    if RE_PLUGIN.search(desc):
        return "plugin"
    if RE_THEME.search(desc):
        return "theme"
    return "unknown"


def normalize(item):
    """NVD vulnerability item -> our normalized record (or None if unusable)."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    # Skip withdrawn entries -- they carry no real flaw data.
    if cve.get("vulnStatus") == "Rejected":
        return None

    description = english_description(cve)
    if description and description.lstrip().startswith("** REJECT **"):
        return None

    references = []
    for r in cve.get("references", []) or []:
        u = r.get("url")
        if u and u not in references:
            references.append(u)

    score, vector, severity, _version = pick_cvss(cve)
    published = cve.get("published") or ""

    return {
        "source": "nvd",
        "cve": cve_id,
        "title": description if description else None,
        "cwe": extract_cwes(cve),
        "cvss_v31": score,
        "cvss_vector": vector,
        "severity": severity,
        "auth_required": derive_auth_required(vector),
        "published": published[:10] if len(published) >= 10 else None,
        "software_type": classify_software_type(cve, description, references),
        "references": references,
        "source_url": "https://nvd.nist.gov/vuln/detail/%s" % cve_id,
    }


# --------------------------------------------------------------------------
# Checkpointing
# --------------------------------------------------------------------------

def load_checkpoint():
    if os.path.exists(CHECKPOINT_PATH):
        try:
            with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print("  [warn] checkpoint unreadable, starting fresh", flush=True)
    return {"completed_tasks": [], "started": datetime.utcnow().isoformat() + "Z"}


def save_checkpoint(ck):
    ck["updated"] = datetime.utcnow().isoformat() + "Z"
    tmp = CHECKPOINT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ck, f, indent=1)
    os.replace(tmp, CHECKPOINT_PATH)


def load_seen_ids():
    """Recover already-emitted CVE ids from the ndjson so resume never duplicates."""
    seen = set()
    if not os.path.exists(NDJSON_PATH):
        return seen
    with open(NDJSON_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                seen.add(json.loads(line)["cve"])
            except (json.JSONDecodeError, KeyError):
                continue
    return seen


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

def build_windows(start_str, end_str, window_days=WINDOW_DAYS):
    start = datetime.strptime(start_str, "%Y-%m-%d").date()
    end = datetime.strptime(end_str, "%Y-%m-%d").date()
    out = []
    cur = start
    while cur <= end:
        stop = min(cur + timedelta(days=window_days), end)
        out.append((cur.isoformat(), stop.isoformat()))
        cur = stop + timedelta(days=1)
    return out


# --------------------------------------------------------------------------
# Harvest
# --------------------------------------------------------------------------

class _Stats(object):
    """Mutable counters shared across tasks within one process run."""
    def __init__(self):
        self.requests = 0
        self.new_records = 0


def run_task(route_id, route_params, w_start, w_end, seen, out, stats):
    """
    Paginate one (route, window) task to exhaustion.

    Returns True if the task completed fully (safe to checkpoint), False if it
    was abandoned partway. Records already written stay written -- `seen` and the
    ndjson are append-only, so a retry of a partial task simply re-skips whatever
    was already stored.
    """
    start_index = 0
    task_new = 0

    while True:
        params = dict(route_params)
        params.update({
            "pubStartDate": w_start + "T00:00:00.000",
            "pubEndDate": w_end + "T23:59:59.999",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
            "noRejected": "",
        })

        if stats.requests > 0:
            time.sleep(SLEEP_SECONDS)

        try:
            data = api_get(params)
        except Exception as e:
            print("  [FAILED] %-8s %s..%s idx=%d -- %s"
                  % (route_id, w_start, w_end, start_index, e), flush=True)
            return False
        stats.requests += 1

        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", []) or []

        for item in vulns:
            try:
                rec = normalize(item)
            except Exception as e:
                print("  [warn] normalize failed: %s" % e, flush=True)
                continue
            if rec is None or rec["cve"] in seen:
                continue
            seen.add(rec["cve"])
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            task_new += 1
            stats.new_records += 1
        out.flush()

        print("  %-8s %s..%s  idx=%-5d got=%-5d total=%-5d new=%d"
              % (route_id, w_start, w_end, start_index,
                 len(vulns), total, task_new), flush=True)

        start_index += len(vulns)
        if not vulns or start_index >= total:
            return True


def harvest(start_str, end_str):
    """
    Run every outstanding (window, route) task.

    A task that exhausts its retries is *skipped, not fatal* -- it stays out of
    the checkpoint so a later run picks it up. This matters because a transient
    429 storm must never abort the run before reference extraction happens.

    Returns (stored_cve_count, completed_task_count, total_task_count).
    """
    os.makedirs(RAW_DIR, exist_ok=True)

    windows = build_windows(start_str, end_str)
    ck = load_checkpoint()
    completed = set(ck.get("completed_tasks", []))
    seen = load_seen_ids()

    all_tasks = [("%s|%s|%s" % (r, ws, we), r, rp, ws, we)
                 for (ws, we) in windows for (r, rp) in ROUTES]

    print("NVD harvest: %s .. %s  (%d windows x %d routes = %d tasks)"
          % (start_str, end_str, len(windows), len(ROUTES), len(all_tasks)), flush=True)
    print("Resuming with %d CVEs already stored, %d/%d tasks already done."
          % (len(seen), len(completed), len(all_tasks)), flush=True)

    stats = _Stats()
    failed = []
    out = open(NDJSON_PATH, "a", encoding="utf-8")

    try:
        for (task_key, route_id, route_params, w_start, w_end) in all_tasks:
            if task_key in completed:
                continue
            ok = run_task(route_id, route_params, w_start, w_end, seen, out, stats)
            if ok:
                completed.add(task_key)
                ck["completed_tasks"] = sorted(completed)
                ck["cve_count"] = len(seen)
                save_checkpoint(ck)
            else:
                failed.append(task_key)
    except KeyboardInterrupt:
        print("\n[interrupted] checkpoint saved -- re-run to resume.", flush=True)
    finally:
        out.close()
        ck["completed_tasks"] = sorted(completed)
        ck["cve_count"] = len(seen)
        ck["total_tasks"] = len(all_tasks)
        save_checkpoint(ck)

    print("\nHarvest pass done: %d requests, %d new CVEs, %d total stored, %d/%d tasks complete."
          % (stats.requests, stats.new_records, len(seen),
             len(completed), len(all_tasks)), flush=True)
    if failed:
        print("Tasks left for a later pass (%d): %s" % (len(failed), ", ".join(failed)), flush=True)
    return len(seen), len(completed), len(all_tasks)


# --------------------------------------------------------------------------
# Reference extraction
# --------------------------------------------------------------------------

def derive_reference_files():
    """Pull trac + wordfence/patchstack URLs out of nvd.ndjson into flat dedup'd lists."""
    trac = set()
    xref = set()

    if not os.path.exists(NDJSON_PATH):
        print("  [warn] no ndjson to derive refs from", flush=True)
        return 0, 0

    with open(NDJSON_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            for url in rec.get("references", []) or []:
                low = url.lower()
                if "plugins.trac.wordpress.org" in low:
                    trac.add(url)
                if "wordfence.com" in low or "patchstack.com" in low:
                    xref.add(url)

    with open(TRAC_REFS_PATH, "w", encoding="utf-8") as f:
        for u in sorted(trac):
            f.write(u + "\n")
    with open(XREF_URLS_PATH, "w", encoding="utf-8") as f:
        for u in sorted(xref):
            f.write(u + "\n")

    print("Refs: %d plugins.trac URLs -> %s" % (len(trac), TRAC_REFS_PATH), flush=True)
    print("Refs: %d wordfence/patchstack URLs -> %s" % (len(xref), XREF_URLS_PATH), flush=True)
    return len(trac), len(xref)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Harvest WordPress-ecosystem CVEs from NVD.")
    ap.add_argument("--start", default=SCOPE_START, help="pubStartDate floor (YYYY-MM-DD)")
    ap.add_argument("--end", default=SCOPE_END, help="pubEndDate ceiling (YYYY-MM-DD)")
    ap.add_argument("--refs-only", action="store_true",
                    help="skip fetching; just re-derive trac/xref files from nvd.ndjson")
    ap.add_argument("--reset", action="store_true",
                    help="delete checkpoint and output files before harvesting")
    ap.add_argument("--passes", type=int, default=6,
                    help="max harvest passes; each pass retries whatever the previous "
                         "one could not finish (default 6)")
    ap.add_argument("--pass-pause", type=float, default=45.0,
                    help="seconds to wait between passes, letting rate limits recover")
    args = ap.parse_args()

    if args.start < SCOPE_START:
        print("Refusing to harvest before %s (project scope floor)." % SCOPE_START)
        return 2

    os.makedirs(RAW_DIR, exist_ok=True)

    if args.reset:
        for p in (NDJSON_PATH, CHECKPOINT_PATH, TRAC_REFS_PATH, XREF_URLS_PATH):
            if os.path.exists(p):
                os.remove(p)
                print("removed %s" % p)

    if not args.refs_only:
        # Retry passes: a 429 storm can leave tasks unfinished. Each pass resumes
        # from the checkpoint and only re-attempts what is still outstanding.
        for attempt in range(1, args.passes + 1):
            print("\n===== harvest pass %d/%d =====" % (attempt, args.passes), flush=True)
            try:
                _count, done, total = harvest(args.start, args.end)
            except Exception as e:
                print("[pass %d aborted] %s" % (attempt, e), flush=True)
                done, total = -1, 0
            if total and done >= total:
                print("All %d tasks complete." % total, flush=True)
                break
            if attempt < args.passes:
                print("Pausing %.0fs before next pass..." % args.pass_pause, flush=True)
                time.sleep(args.pass_pause)

    # Always derive reference files, even if some tasks are still outstanding --
    # partial data is still useful and this must never be skipped by a fetch error.
    derive_reference_files()
    return 0


if __name__ == "__main__":
    sys.exit(main())
