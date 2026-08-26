#!/usr/bin/env python3
"""
harvest_patchstack.py -- harvest the Patchstack WordPress vulnerability database
into wpsentinel's normalized NDJSON format.

Stdlib only (urllib + json + re + zipfile + sqlite3-free). Python 3.7+.

--------------------------------------------------------------------------
ACCESS NOTES (why this script works the way it does)
--------------------------------------------------------------------------
patchstack.com/database/ is a Nuxt 3 SSR app. Three access routes exist:

  1. SSR payload  (USED, robots-allowed)
     GET https://patchstack.com/database/ returns HTML containing a
     <script id="__NUXT_DATA__"> devalue-encoded payload with the 20 most
     recently disclosed vulnerabilities, fully structured. The `page` query
     param is NOT honoured server-side (pagination is client-side only), so
     this route yields at most the latest 20 records per fetch. Detail pages
     (/database/<slug>) render a 404 body server-side and hydrate entirely
     client-side, so they carry no harvestable data.

  2. Upstream JSON API  (NOT USED -- blocked)
     https://hub-vdp-api-production-csruhi.patchstack.cloud/public/home?page=N
     Returns HTTP 403 with an anti-bot interstitial to non-browser clients.

  3. Same-origin proxy /api/database/home  (NOT USED -- robots.txt)
     patchstack.com/robots.txt has `Disallow: /api/` in the `User-agent: *`
     group, which is the group a generic client like this one matches.

Because routes 2 and 3 are off-limits and route 1 caps at 20 records, bulk
harvesting uses Patchstack's *own* authoritative machine-readable publication
channel: Patchstack is a CVE Numbering Authority (CNA), and every vulnerability
they assign a CVE to is published as a CVE Record (CNA container authored by
Patchstack) in the CVE Program's open cvelistV5 dataset. Filtering that dataset
on `cveMetadata.assignerShortName == "Patchstack"` yields Patchstack's records,
with Patchstack's own taxonomy strings, CVSS scores, advisory titles and
patchstack.com/database/ provenance URLs intact.

  4. cvelistV5 bulk release  (USED, primary)
     https://github.com/CVEProject/cvelistV5/releases/latest
     ~590MB zip, refreshed several times daily, no rate limits, open licence.

--------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------
  python3 scripts/harvest_patchstack.py --limit 50        # smoke run
  python3 scripts/harvest_patchstack.py --all             # full run
  python3 scripts/harvest_patchstack.py --source ssr      # live SSR only
  python3 scripts/harvest_patchstack.py --all --reset     # ignore checkpoint

Resumable: progress is checkpointed to data/raw/patchstack_checkpoint.json
after every batch; re-running continues where it stopped and never emits a
duplicate source_id.
"""

import argparse
import gzip
import json
import os
import re
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import quote_plus

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW_DIR = os.path.join(ROOT, "data", "raw")
OUT_NDJSON = os.path.join(RAW_DIR, "patchstack.ndjson")
OUT_TRAC = os.path.join(RAW_DIR, "trac_refs_patchstack.txt")
CHECKPOINT = os.path.join(RAW_DIR, "patchstack_checkpoint.json")

# Cache for the (large, ~1.2GB unpacked) cvelistV5 bundle. Deliberately kept
# OUTSIDE the repo so the working tree only ever contains harvested output.
DEFAULT_CACHE = os.path.join(tempfile.gettempdir(), "wpsentinel-cvelist-cache")

USER_AGENT = (
    "wpsentinel-harvester/0.1 (open-source WordPress security audit; "
    "+https://github.com/wpsentinel) python-urllib"
)

SSR_URL = "https://patchstack.com/database/"
CVELIST_LATEST = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

SCOPE_START = "2023-01-01"          # project scope floor -- never go earlier
MIN_INTERVAL = 1.0                  # >= 1 request/second, politeness floor
MAX_RETRIES = 5


# ---------------------------------------------------------------------------
# Polite HTTP
# ---------------------------------------------------------------------------

_last_request_at = [0.0]


def http_get(url, accept=None, timeout=120, to_file=None):
    """GET with a descriptive UA, >=1s spacing, and backoff on 429/5xx."""
    delay = 2.0
    for attempt in range(1, MAX_RETRIES + 1):
        wait = MIN_INTERVAL - (time.time() - _last_request_at[0])
        if wait > 0:
            time.sleep(wait)
        _last_request_at[0] = time.time()

        req = urlrequest.Request(url)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept-Encoding", "gzip")
        if accept:
            req.add_header("Accept", accept)
        try:
            with urlrequest.urlopen(req, timeout=timeout) as resp:
                if to_file:
                    total = 0
                    with open(to_file, "wb") as fh:
                        while True:
                            chunk = resp.read(1 << 20)
                            if not chunk:
                                break
                            fh.write(chunk)
                            total += len(chunk)
                            if total % (32 << 20) < (1 << 20):
                                sys.stderr.write(
                                    "\r    downloaded %d MB" % (total // (1 << 20))
                                )
                                sys.stderr.flush()
                    if total > (1 << 20):
                        sys.stderr.write("\r    downloaded %d MB\n" % (total // (1 << 20)))
                    return total
                body = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return body
        except urlerror.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                sleep_for = float(retry_after) if (retry_after or "").isdigit() else delay
                sys.stderr.write(
                    "    HTTP %d on %s -- retry %d/%d in %.0fs\n"
                    % (exc.code, url, attempt, MAX_RETRIES, sleep_for)
                )
                time.sleep(sleep_for)
                delay = min(delay * 2, 60)
                continue
            raise
        except (urlerror.URLError, TimeoutError, OSError) as exc:
            if attempt < MAX_RETRIES:
                sys.stderr.write(
                    "    %s on %s -- retry %d/%d in %.0fs\n"
                    % (type(exc).__name__, url, attempt, MAX_RETRIES, delay)
                )
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            raise
    raise RuntimeError("unreachable")


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

# Patchstack advisory titles encode the required privilege inline, e.g.
#   "WordPress Foo Plugin <= 1.2 - Authenticated (Contributor+) Stored XSS"
#   "WordPress Bar Plugin <= 3.4 - Unauthenticated SQL Injection"
_ROLE_RE = re.compile(
    r"authenticated\s*\(\s*([a-z][a-z /+-]{0,30}?)\s*\+?\s*\)", re.I
)
# Slug form, where the parentheses are lost:
#   "...-authenticated-contributor-stored-cross-site-scripting-..."
# `\bauthenticated` cannot match inside "unauthenticated" (preceding char is a
# word char, so the word boundary fails), so the two forms stay distinct.
_ROLE_SLUG_RE = re.compile(
    r"\bauthenticated[\s-]+("
    r"subscriber|contributor|author|editor|administrator|admin|"
    r"customer|shop[\s-]manager|employee"
    r")\b",
    re.I,
)
_UNAUTH_RE = re.compile(r"\bunauthenticated\b", re.I)

# Canonical ladder. NOTE: "editor+" is emitted verbatim -- it is a real and
# frequent Patchstack tier that sits between author and admin, and collapsing
# it into either neighbour would misstate the taxonomy. See research report.
_ROLE_MAP = {
    "subscriber": "subscriber+",
    "customer": "subscriber+",
    "shop subscriber": "subscriber+",
    "contributor": "contributor+",
    "author": "author+",
    "editor": "editor+",
    "shop manager": "editor+",
    "employee": "editor+",
    "admin": "admin+",
    "administrator": "admin+",
    "super admin": "admin+",
    "super administrator": "admin+",
}


def parse_auth(*texts):
    """Derive auth_required from Patchstack's own advisory title/slug wording.

    Only explicit wording is honoured -- nothing is inferred from CVSS
    privileges-required or from the vulnerability class, so a record whose
    source text is silent stays "unknown" rather than being guessed at.
    """
    for rx in (_ROLE_RE, _ROLE_SLUG_RE):
        for text in texts:
            if not text:
                continue
            m = rx.search(text)
            if m:
                role = re.sub(r"[\s-]+", " ", m.group(1).strip().lower()).rstrip("+ ")
                return _ROLE_MAP.get(role, "unknown"), role
    for text in texts:
        if text and _UNAUTH_RE.search(text):
            return "unauthenticated", "unauthenticated"
    for text in texts:
        if text and re.search(r"\bauthenticated\b", text, re.I):
            return "unknown", "authenticated-unspecified"
    return "unknown", None


_PS_DB_RE = re.compile(
    r"https?://(?:www\.)?patchstack\.com/database/([^\s\"'<>?#]+)", re.I
)
_TRAC_RE = re.compile(
    r"https?://plugins\.trac\.wordpress\.org/[^\s\"'<>\\]+", re.I
)


def parse_patchstack_ref(refs):
    """Return (source_url, slug, software_type_hint) from patchstack.com refs.

    Patchstack CVE references look like either

        https://patchstack.com/database/Wordpress/Plugin/<pkg>/vulnerability/<slug>?_s_id=cve
        https://patchstack.com/database/<slug>

    so the path segment carries an authoritative plugin/theme/core hint.
    Segment casing varies ("Plugin" vs "plugin"), hence the lowercasing.
    """
    for url in refs or []:
        m = _PS_DB_RE.search(url or "")
        if not m:
            continue
        path = m.group(1).rstrip("/")
        clean = (url or "").split("?")[0].rstrip("/")
        parts = [p.lower() for p in path.split("/")]
        hint = None
        for token, value in (("plugin", "plugin"), ("plugins", "plugin"),
                             ("theme", "theme"), ("themes", "theme"),
                             ("core", "core")):
            if token in parts:
                hint = value
                break
        slug = path.split("/")[-1] if path else path
        return clean, slug, hint
    return None, None, None


def infer_software_type(slug, title, refs, cpes, collection_hint=None):
    """plugin | theme | core -- derived WITHOUT retaining any product name."""
    hay = " ".join(x for x in ([slug or "", title or ""] + list(cpes or [])) if x).lower()

    _, _, hint = parse_patchstack_ref(refs or [])
    if hint:
        return hint
    if collection_hint:
        return collection_hint

    # WordPress core advisories
    if re.search(r"\bwordpress\s+core\b", hay) or re.search(r"\bwp[-_ ]?core\b", hay):
        return "core"
    if re.search(r"cpe:2\.3:a:wordpress:wordpress:", hay):
        return "core"

    if re.search(r"\btheme\b", hay):
        return "theme"
    if re.search(r"\bplugins?\b", hay):
        return "plugin"

    # plugins.trac / theme repo reference URLs are a strong signal
    joined = " ".join(refs or []).lower()
    if "themes.trac.wordpress.org" in joined or "/themes/" in joined:
        return "theme"
    if "plugins.trac.wordpress.org" in joined or "/plugins/" in joined:
        return "plugin"
    return None


def severity_from(score, stated):
    if stated:
        s = str(stated).strip().lower()
        if s in ("critical", "high", "medium", "low", "none"):
            return None if s == "none" else s
    if score is None:
        return None
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def blank_record():
    return {
        "source": "patchstack",
        "source_id": None,
        "cve": None,
        "title": None,
        "vuln_type": None,
        "cvss": None,
        "severity": None,
        "auth_required": "unknown",
        "software_type": None,
        "disclosed": None,
        "source_url": None,
        "references": [],
        "patched_version": None,
    }


# ---------------------------------------------------------------------------
# Source 1: live SSR payload from patchstack.com/database/
# ---------------------------------------------------------------------------

_NUXT_RE = re.compile(
    r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>', re.S
)


def devalue_resolve(arr):
    """Resolve Nuxt's flat 'devalue' payload array into plain Python data."""
    wrappers = {
        "ShallowReactive", "Reactive", "Ref", "ShallowRef",
        "EmptyRef", "EmptyShallowRef", "NuxtError",
    }

    def walk(idx, depth=0):
        if not isinstance(idx, int) or depth > 30:
            return idx if not isinstance(idx, int) else None
        if idx < 0 or idx >= len(arr):
            return None
        node = arr[idx]
        if isinstance(node, list):
            if node and node[0] in wrappers:
                return walk(node[1], depth + 1)
            return [walk(x, depth + 1) for x in node]
        if isinstance(node, dict):
            return {k: walk(v, depth + 1) for k, v in node.items()}
        return node

    return walk(0)


def fetch_ssr_records(search=None):
    """Up to 20 disclosures straight from patchstack.com (robots-allowed).

    The `search` query parameter IS honoured server-side (it changes the SSR
    fetch key and the returned rows); `page` is NOT, so each distinct search
    term is a separate 20-row window onto the corpus. Sweeping a keyword list
    is therefore the only way to widen this route.
    """
    url = SSR_URL
    if search:
        url = "%s?search=%s" % (SSR_URL, quote_plus(search))
    html = http_get(url, accept="text/html").decode("utf-8", "replace")
    m = _NUXT_RE.search(html)
    if not m:
        raise RuntimeError("__NUXT_DATA__ payload not found in %s" % url)
    data = devalue_resolve(json.loads(m.group(1)))
    out = []
    for _key, node in (data.get("data") or {}).items():
        if not isinstance(node, dict):
            continue
        vulns = node.get("vulnerabilities")
        if isinstance(vulns, dict) and isinstance(vulns.get("data"), list):
            out.extend(vulns["data"])
    return out


# Keyword sweep: privilege tiers + Patchstack's own vulnerability-type
# vocabulary + common advisory phrasing. Each term returns its own 20 rows.
SEARCH_TERMS = [
    "", "unauthenticated", "contributor", "subscriber", "author", "editor",
    "administrator", "customer", "shop manager", "employee", "privilege",
    "cross site scripting", "xss", "stored xss", "reflected xss", "dom xss",
    "sql injection", "sqli", "blind sql", "csrf", "cross site request forgery",
    "local file inclusion", "lfi", "remote file inclusion",
    "remote code execution", "rce", "arbitrary code execution",
    "server side request forgery", "ssrf", "idor",
    "insecure direct object reference", "arbitrary file upload", "file upload",
    "arbitrary file read", "arbitrary file deletion", "arbitrary file write",
    "path traversal", "directory traversal", "deserialization",
    "object injection", "php object", "privilege escalation",
    "open redirect", "information disclosure", "sensitive data exposure",
    "broken access control", "missing authorization", "authorization bypass",
    "authentication bypass", "broken authentication", "code injection",
    "command injection", "xml external entity", "xxe", "race condition",
    "denial of service", "dos", "account takeover", "password reset",
    "email verification", "user enumeration", "backup disclosure",
    "log disclosure", "api key", "nonce", "capability check", "ajax",
    "rest api", "shortcode", "widget", "block", "gutenberg", "elementor",
    "woocommerce", "form", "contact form", "slider", "gallery", "seo",
    "backup", "migration", "import", "export", "media", "upload handler",
    "settings update", "options update", "plugin installation",
    "theme installation", "user creation", "role change", "wp core",
    "wordpress core", "multisite", "cron", "webhook", "oauth", "sso",
    "two factor", "captcha", "membership", "booking", "calendar", "ecommerce",
    "payment", "invoice", "newsletter", "popup", "analytics", "chat",
    "live chat", "forum", "learning management", "quiz", "poll", "rating",
    "review", "directory listing", "real estate", "job board", "event",
    "social", "share", "translation", "multilingual", "cache", "optimization",
    "security", "firewall", "malware", "login", "registration", "profile",
]


def normalize_ssr(raw):
    kind = (raw.get("kind") or "").strip().lower()
    if kind not in ("plugin", "theme", "core"):
        return None                      # npm/other ecosystems -- out of scope
    slug = raw.get("slug") or raw.get("url")
    if not slug:
        return None

    disclosed = (raw.get("disclosure_date") or "")[:10] or None
    title = raw.get("clean_title") or None
    auth, _raw_role = parse_auth(title, slug.replace("-", " "))

    rec = blank_record()
    rec.update({
        "source_id": slug,
        "cve": raw.get("cve") or None,
        "title": title,
        "vuln_type": raw.get("type") or None,
        "cvss": raw.get("cvss") if isinstance(raw.get("cvss"), (int, float)) else None,
        "software_type": kind,
        "disclosed": disclosed,
        "source_url": "https://patchstack.com/database/%s" % slug,
        "references": [],
        "patched_version": raw.get("fixed_in") or None,
        "auth_required": auth,
    })
    rec["severity"] = severity_from(rec["cvss"], None)
    return rec


# ---------------------------------------------------------------------------
# Source 2: Patchstack CNA records in the CVE Program's cvelistV5 bundle
# ---------------------------------------------------------------------------

def resolve_cvelist_asset():
    body = http_get(CVELIST_LATEST, accept="application/vnd.github+json")
    rel = json.loads(body)
    for asset in rel.get("assets", []):
        if "all_CVEs" in asset.get("name", ""):
            return rel.get("tag_name"), asset["name"], asset["browser_download_url"], asset.get("size")
    raise RuntimeError("no all_CVEs asset in cvelistV5 latest release")


def ensure_cvelist(cache_dir):
    """Download the bulk CVE bundle once; reuse the cached copy afterwards.

    The release asset is named `*.zip.zip` and really is doubly nested: the
    outer archive holds a single member `cves.zip`, which holds the per-CVE
    JSON tree. Returns the path to the INNER archive.
    """
    os.makedirs(cache_dir, exist_ok=True)
    tag, name, url, size = resolve_cvelist_asset()
    outer = os.path.join(cache_dir, name)
    inner = os.path.join(cache_dir, "cves-%s.zip" % (tag or "latest"))

    if os.path.exists(inner) and zipfile.is_zipfile(inner):
        print("  using cached CVE bundle: %s" % inner)
        return tag, inner

    if not (os.path.exists(outer) and zipfile.is_zipfile(outer)):
        print("  downloading CVE bundle %s (%s MB) ..."
              % (name, round((size or 0) / 1e6, 1)))
        http_get(url, to_file=outer)
        if not zipfile.is_zipfile(outer):
            raise RuntimeError("downloaded CVE bundle is not a valid zip: %s" % outer)

    with zipfile.ZipFile(outer) as z:
        members = [m for m in z.namelist() if m.endswith(".zip")]
        if not members:
            # Not nested after all -- use the outer archive directly.
            return tag, outer
        print("  unpacking inner archive %s ..." % members[0])
        with z.open(members[0]) as src, open(inner, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
    return tag, inner


def _collect_refs(cna, root):
    refs = []
    for container in (cna, root):
        for r in (container or {}).get("references", []) or []:
            u = r.get("url")
            if u and u not in refs:
                refs.append(u)
    return refs


def _collect_cvss(cna, root):
    best_score, best_sev = None, None
    for container in (cna, root):
        for m in (container or {}).get("metrics", []) or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                cv = m.get(key)
                if not isinstance(cv, dict):
                    continue
                score = cv.get("baseScore")
                sev = cv.get("baseSeverity")
                if score is not None and best_score is None:
                    best_score, best_sev = score, sev
    return best_score, best_sev


def _collect_vuln_type(cna):
    for pt in (cna or {}).get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            desc = (d.get("description") or "").strip()
            if not desc:
                continue
            # Strip a leading "CWE-79 " prefix so the human taxonomy string survives
            cleaned = re.sub(r"^CWE-\d+\s*[:\-]?\s*", "", desc).strip()
            return cleaned or desc
    return None


_BAD_VER = ("*", "unspecified", "n/a", "0", "")


def _collect_patched(cna, title):
    """First *unaffected* (i.e. patched) version -- never the last affected one.

    Patchstack encodes the fix as `versions[].changes[] {at, status:unaffected}`.
    `lessThan` is also safe (affected "< X" means X is the fixed release), but
    `lessThanOrEqual` is the LAST AFFECTED version -- the fix is some later
    release that the record does not state, so it must stay null rather than be
    guessed. Likewise the "<= 1.2.3" in a title is the last vulnerable version.
    """
    for aff in (cna or {}).get("affected", []) or []:
        for v in aff.get("versions", []) or []:
            for ch in v.get("changes", []) or []:
                if (ch.get("status") or "").lower() == "unaffected":
                    at = str(ch.get("at") or "")
                    if at and at not in _BAD_VER:
                        return at
    for aff in (cna or {}).get("affected", []) or []:
        for v in aff.get("versions", []) or []:
            for key in ("fixed", "lessThan"):
                val = str(v.get(key) or "")
                if val and val not in _BAD_VER:
                    return val
    m = re.search(r"fixed\s+in\s+v?([0-9][0-9A-Za-z.\-_]*)", title or "", re.I)
    return m.group(1) if m else None


def _collection_hint(cna):
    """wordpress.org/plugins vs /themes from the CNA `collectionURL`."""
    for aff in (cna or {}).get("affected", []) or []:
        url = (aff.get("collectionURL") or "").lower()
        if "wordpress.org/plugins" in url:
            return "plugin"
        if "wordpress.org/themes" in url:
            return "theme"
    return None


def _collect_cpes(cna):
    out = []
    for aff in (cna or {}).get("affected", []) or []:
        for c in aff.get("cpes", []) or []:
            out.append(c)
        for pl in aff.get("platforms", []) or []:
            out.append(str(pl))
    return out


def normalize_cve_record(doc):
    meta = doc.get("cveMetadata") or {}
    if meta.get("assignerShortName") != "Patchstack":
        return None
    if (meta.get("state") or "").upper() == "REJECTED":
        return None

    published = meta.get("datePublished") or meta.get("dateReserved") or ""
    disclosed = published[:10] if len(published) >= 10 else None
    if not disclosed or disclosed < SCOPE_START:
        return None

    containers = doc.get("containers") or {}
    cna = containers.get("cna") or {}
    adp_list = containers.get("adp") or []
    adp = adp_list[0] if adp_list else {}

    title = cna.get("title") or None
    descs = cna.get("descriptions") or []
    desc_text = None
    for d in descs:
        if (d.get("lang") or "en").lower().startswith("en"):
            desc_text = d.get("value")
            break
    if not title and desc_text:
        title = desc_text.strip().split("\n")[0][:300]

    refs = _collect_refs(cna, adp)
    source_url, slug, _hint = parse_patchstack_ref(refs)
    cve_id = meta.get("cveId")

    score, stated_sev = _collect_cvss(cna, adp)
    # The Patchstack database slug carries the privilege tier even when the CVE
    # title does not, e.g. "...-authenticated-contributor-stored-xss-...".
    slug_text = (slug or "").replace("-", " ")
    auth, raw_role = parse_auth(title, desc_text, slug_text)
    sw = infer_software_type(slug, " ".join(x for x in (title, desc_text) if x),
                             refs, _collect_cpes(cna), _collection_hint(cna))
    if sw not in ("plugin", "theme", "core"):
        return None                      # non-WordPress ecosystems: out of scope

    rec = blank_record()
    rec.update({
        "source_id": slug or cve_id,
        "cve": cve_id,
        "title": title,
        "vuln_type": _collect_vuln_type(cna),
        "cvss": float(score) if score is not None else None,
        "software_type": sw,
        "disclosed": disclosed,
        "source_url": source_url or ("https://www.cve.org/CVERecord?id=%s" % cve_id),
        "references": refs,
        "patched_version": _collect_patched(cna, title),
        "auth_required": auth,
    })
    rec["severity"] = severity_from(rec["cvss"], stated_sev)
    return rec, raw_role


# ---------------------------------------------------------------------------
# Checkpointing
# ---------------------------------------------------------------------------

def load_checkpoint(reset=False):
    if reset or not os.path.exists(CHECKPOINT):
        return {
            "version": 1,
            "started": datetime.now(timezone.utc).isoformat(),
            "seen_ids": [],
            "cvelist_tag": None,
            "cvelist_done": False,
            "cvelist_index": 0,
            "ssr_done": False,
            "ssr_terms_done": [],
            "record_count": 0,
            "raw_roles": {},
        }
    with open(CHECKPOINT, "r", encoding="utf-8") as fh:
        cp = json.load(fh)
    cp.setdefault("seen_ids", [])
    cp.setdefault("raw_roles", {})
    cp.setdefault("ssr_terms_done", [])
    return cp


def save_checkpoint(cp, seen):
    cp["seen_ids"] = sorted(seen)
    cp["updated"] = datetime.now(timezone.utc).isoformat()
    tmp = CHECKPOINT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cp, fh, indent=1)
    os.replace(tmp, CHECKPOINT)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--limit", type=int, help="stop after N new normalized records")
    g.add_argument("--all", action="store_true", help="harvest everything in scope")
    ap.add_argument("--source", choices=("both", "ssr", "cvelist"), default="both")
    ap.add_argument("--no-sweep", dest="sweep", action="store_false",
                    help="fetch only the SSR front page instead of sweeping "
                         "the search-term list")
    ap.add_argument("--since", default=SCOPE_START, help="scope floor (YYYY-MM-DD)")
    ap.add_argument("--cache-dir", default=DEFAULT_CACHE)
    ap.add_argument("--reset", action="store_true", help="ignore existing checkpoint")
    args = ap.parse_args()

    if not args.limit and not args.all:
        ap.error("specify --limit N (smoke run) or --all (full run)")

    since = max(args.since, SCOPE_START)   # never harvest earlier than 2023
    os.makedirs(RAW_DIR, exist_ok=True)

    cp = load_checkpoint(reset=args.reset)
    seen = set(cp["seen_ids"])
    raw_roles = Counter(cp.get("raw_roles") or {})

    mode = "w" if args.reset else "a"
    if args.reset:
        for p in (OUT_NDJSON, OUT_TRAC):
            if os.path.exists(p):
                os.remove(p)

    trac = set()
    if os.path.exists(OUT_TRAC):
        with open(OUT_TRAC, "r", encoding="utf-8") as fh:
            trac = {ln.strip() for ln in fh if ln.strip()}

    # slug -> raw SSR row, used to recover the privilege tier that Patchstack
    # states on its own site but omits from the CVE records it publishes.
    ssr_index = {}
    enriched = [0]

    limit = args.limit if args.limit else None
    written = 0
    types = Counter()
    auths = Counter()
    swtypes = Counter()
    dates = []

    out = open(OUT_NDJSON, mode, encoding="utf-8")

    def emit(rec):
        nonlocal written
        sid = rec.get("source_id")
        if not sid or sid in seen:
            return False
        seen.add(sid)
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        written += 1
        types[rec.get("vuln_type") or "(none)"] += 1
        auths[rec.get("auth_required") or "unknown"] += 1
        swtypes[rec.get("software_type") or "(none)"] += 1
        if rec.get("disclosed"):
            dates.append(rec["disclosed"])
        for u in rec.get("references") or []:
            for m in _TRAC_RE.finditer(u):
                trac.add(m.group(0))
        return True

    try:
        # ---- Source 1: live SSR keyword sweep ----------------------------
        # Runs first so its stated privilege tiers can enrich the CVE pass.
        if args.source in ("both", "ssr"):
            terms = SEARCH_TERMS if args.sweep else [""]
            done_terms = set(cp.get("ssr_terms_done") or [])
            print("[1/2] live SSR sweep over %d search term(s) at %s"
                  % (len(terms), SSR_URL))
            for ti, term in enumerate(terms):
                if term in done_terms:
                    continue
                try:
                    rows = fetch_ssr_records(term or None)
                except Exception as exc:                   # noqa: BLE001
                    print("      !! term %r failed: %s: %s"
                          % (term, type(exc).__name__, exc))
                    continue
                for raw in rows:
                    slug = raw.get("slug") or raw.get("url")
                    if slug and slug not in ssr_index:
                        ssr_index[slug] = raw
                    rec = normalize_ssr(raw)
                    if rec and rec["disclosed"] and rec["disclosed"] >= since:
                        emit(rec)
                done_terms.add(term)
                if ti % 20 == 0 and ti:
                    cp["ssr_terms_done"] = sorted(done_terms)
                    save_checkpoint(cp, seen)
                    print("      ... %d/%d terms, %d unique rows seen"
                          % (ti, len(terms), len(ssr_index)))
                if limit and written >= limit:
                    break
            cp["ssr_terms_done"] = sorted(done_terms)
            cp["ssr_done"] = len(done_terms) >= len(terms)
            print("      -> %d records emitted, %d unique SSR rows indexed"
                  % (written, len(ssr_index)))

        # ---- Source 2: Patchstack CNA records in cvelistV5 ---------------
        if args.source in ("both", "cvelist") and not (limit and written >= limit):
            print("[2/2] Patchstack CNA records from CVE Program cvelistV5")
            tag, zpath = ensure_cvelist(args.cache_dir)
            if cp.get("cvelist_tag") != tag:
                cp["cvelist_tag"] = tag
                cp["cvelist_index"] = 0
            start_at = int(cp.get("cvelist_index") or 0)

            # Only CVE-year directories at/after the scope floor can contain
            # in-scope records, so the rest of the tree is never opened.
            min_year = int(since[:4])
            year_re = re.compile(r"(?:^|/)cves/(\d{4})/")
            with zipfile.ZipFile(zpath) as z:
                names = []
                for n in z.namelist():
                    if not n.endswith(".json"):
                        continue
                    m = year_re.search(n)
                    if m and int(m.group(1)) >= min_year:
                        names.append(n)
                names.sort()
                print("      scanning %d CVE records from %d+ (resuming at %d)"
                      % (len(names), min_year, start_at))
                for i, name in enumerate(names):
                    if i < start_at:
                        continue

                    doc = None
                    try:
                        blob = z.read(name)
                        # Cheap bytes prefilter: skip JSON parsing for the ~97%
                        # of records assigned by some other CNA.
                        if b"Patchstack" in blob:
                            doc = json.loads(blob)
                    except Exception:                      # noqa: BLE001
                        doc = None

                    if doc is not None:
                        res = normalize_cve_record(doc)
                        if res:
                            rec, raw_role = res
                            # Join on the Patchstack slug: if the live site
                            # states a privilege tier this CVE record omits,
                            # take it (same publisher, same advisory).
                            if rec["auth_required"] == "unknown":
                                row = ssr_index.get(rec["source_id"])
                                if row:
                                    a2, r2 = parse_auth(row.get("clean_title"))
                                    if a2 != "unknown":
                                        rec["auth_required"] = a2
                                        raw_role = r2
                                        enriched[0] += 1
                            if rec["disclosed"] >= since and emit(rec):
                                if raw_role:
                                    raw_roles[raw_role] += 1

                    if i and i % 20000 == 0:
                        cp["cvelist_index"] = i
                        cp["record_count"] = len(seen)
                        cp["raw_roles"] = dict(raw_roles)
                        save_checkpoint(cp, seen)
                        print("      ... %d/%d scanned, %d kept"
                              % (i, len(names), written))
                    if limit and written >= limit:
                        cp["cvelist_index"] = i + 1
                        break
                else:
                    cp["cvelist_done"] = True
                    cp["cvelist_index"] = len(names)
    finally:
        out.close()
        with open(OUT_TRAC, "w", encoding="utf-8") as fh:
            for u in sorted(trac):
                fh.write(u + "\n")
        cp["record_count"] = len(seen)
        cp["raw_roles"] = dict(raw_roles)
        save_checkpoint(cp, seen)

    print()
    print("wrote %d new records -> %s (total unique: %d)"
          % (written, OUT_NDJSON, len(seen)))
    print("auth tiers recovered by SSR slug-join: %d" % enriched[0])
    print("trac refs -> %s (%d unique)" % (OUT_TRAC, len(trac)))
    if dates:
        print("date range: %s .. %s" % (min(dates), max(dates)))
    print("\nsoftware_type: %s" % dict(swtypes.most_common()))
    print("\nauth_required:")
    for k, v in auths.most_common():
        print("  %-18s %d" % (k, v))
    print("\ntop vuln_type:")
    for k, v in types.most_common(25):
        print("  %-52s %d" % (k[:52], v))


if __name__ == "__main__":
    main()
