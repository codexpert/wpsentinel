#!/usr/bin/env python3
"""Consolidate harvested CVE data and the class knowledge base into a queryable SQLite DB.

Reads:
    data/raw/*.ndjson      normalized vulnerability records from the harvesters
    kb/classes/*.md        vulnerability-class files (YAML frontmatter per kb/SCHEMA.md)

Writes:
    data/wpsentinel.db     SQLite database
    data/classes.json      class + detection-rule export for the scanner and skill

CVEs are mapped to classes through the CWE ids each class declares, so adding a class
requires no change here. The priority ranking is computed from the mapped data rather
than hand-assigned, which is the point: prevalence should come from evidence.

Python 3.8+. Standard library only (PyYAML is used when present, with a fallback
parser for the frontmatter subset defined in kb/SCHEMA.md).
"""

import json
import math
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vuln_type_map import vuln_type_to_cwe  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
CLASSES = ROOT / "kb" / "classes"
DB_PATH = ROOT / "data" / "wpsentinel.db"
JSON_PATH = ROOT / "data" / "classes.json"


# --------------------------------------------------------------------------- YAML

def _parse_yaml(text):
    """Parse frontmatter. Prefers PyYAML; falls back to a small indentation parser
    covering the subset kb/SCHEMA.md defines (nested maps, lists of maps, scalars)."""
    try:
        import yaml  # noqa: WPS433
        return yaml.safe_load(text) or {}
    except ImportError:
        pass

    def scalar(v):
        v = v.strip()
        if not v:
            return None
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            return v[1:-1]
        if v in ("true", "True"):
            return True
        if v in ("false", "False"):
            return False
        if v in ("null", "~"):
            return None
        if re.fullmatch(r"-?\d+", v):
            return int(v)
        if re.fullmatch(r"-?\d*\.\d+", v):
            return float(v)
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            return [scalar(x) for x in inner.split(",")] if inner else []
        return v

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]

    def indent_of(ln):
        return len(ln) - len(ln.lstrip())

    def block(idx, level):
        """Return (value, next_index) for the block starting at idx at the given indent."""
        # list?
        if idx < len(lines) and lines[idx].lstrip().startswith("- "):
            out = []
            while idx < len(lines) and indent_of(lines[idx]) == level and lines[idx].lstrip().startswith("- "):
                rest = lines[idx].lstrip()[2:]
                if ":" in rest and not rest.strip().startswith("http"):
                    # list of maps: re-read as a map whose first key sits inline
                    sub, idx = _inline_map(lines, idx, level, rest, block, indent_of, scalar)
                    out.append(sub)
                else:
                    out.append(scalar(rest))
                    idx += 1
            return out, idx
        # map
        out = {}
        while idx < len(lines) and indent_of(lines[idx]) == level and not lines[idx].lstrip().startswith("- "):
            k, _, v = lines[idx].lstrip().partition(":")
            k = k.strip()
            if v.strip():
                out[k] = scalar(v)
                idx += 1
            else:
                idx += 1
                if idx < len(lines) and indent_of(lines[idx]) > level:
                    out[k], idx = block(idx, indent_of(lines[idx]))
                else:
                    out[k] = None
        return out, idx

    def _inline_map(lines_, idx_, level_, rest_, block_, indent_, scalar_):
        k, _, v = rest_.partition(":")
        item = {}
        if v.strip():
            item[k.strip()] = scalar_(v)
        idx_ += 1
        child = level_ + 2
        while idx_ < len(lines_) and indent_(lines_[idx_]) >= child and not (
            indent_(lines_[idx_]) == level_ and lines_[idx_].lstrip().startswith("- ")
        ):
            kk, _, vv = lines_[idx_].lstrip().partition(":")
            if vv.strip():
                item[kk.strip()] = scalar_(vv)
                idx_ += 1
            else:
                idx_ += 1
                if idx_ < len(lines_) and indent_(lines_[idx_]) > child:
                    item[kk.strip()], idx_ = block_(idx_, indent_(lines_[idx_]))
                else:
                    item[kk.strip()] = None
        return item, idx_

    value, _ = block(0, indent_of(lines[0]) if lines else 0)
    return value or {}


def read_frontmatter(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        return None, text
    end = text.find("\n---", 3)
    if end == -1:
        return None, text
    raw = text[3:end]
    body = text[end + 4:]
    try:
        return _parse_yaml(raw), body
    except Exception as exc:  # noqa: BLE001
        print("  ! frontmatter parse failed for {}: {}".format(path.name, exc), file=sys.stderr)
        return None, body


# ---------------------------------------------------------------------------- DB

SCHEMA = """
DROP TABLE IF EXISTS vulns;
DROP TABLE IF EXISTS classes;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS class_stats;

CREATE TABLE vulns (
    id            INTEGER PRIMARY KEY,
    source        TEXT NOT NULL,
    cve           TEXT,
    title         TEXT,
    vuln_type     TEXT,
    cwe           TEXT,            -- JSON array
    cvss          REAL,
    severity      TEXT,
    auth_required TEXT,
    software_type TEXT,
    published     TEXT,            -- YYYY-MM-DD
    source_url    TEXT,            -- REQUIRED by data license; see ATTRIBUTION.md
    class_id      TEXT
);
CREATE INDEX idx_vulns_cve      ON vulns(cve);
CREATE INDEX idx_vulns_class    ON vulns(class_id);
CREATE INDEX idx_vulns_auth     ON vulns(auth_required);
CREATE INDEX idx_vulns_pub      ON vulns(published);

CREATE TABLE classes (
    class_id              TEXT PRIMARY KEY,
    title                 TEXT,
    cwe                   TEXT,   -- JSON array
    owasp                 TEXT,
    severity_typical      TEXT,
    auth_required_typical TEXT,
    fix_apis              TEXT,   -- JSON array
    example_count         INTEGER,
    rule_count            INTEGER,
    path                  TEXT
);

CREATE TABLE rules (
    rule_id              TEXT,
    class_id             TEXT,
    description          TEXT,
    regex                TEXT,
    confidence           TEXT,
    false_positive_notes TEXT,
    multiline            INTEGER DEFAULT 0
);
CREATE INDEX idx_rules_class ON rules(class_id);

CREATE TABLE class_stats (
    class_id       TEXT PRIMARY KEY,
    cve_count      INTEGER,
    avg_cvss       REAL,
    max_cvss       REAL,
    unauth_count   INTEGER,
    unauth_frac    REAL,
    priority_score REAL,
    priority_rank  INTEGER,
    basis          TEXT
);
"""


def norm_cwe(v):
    """Normalize a CWE reference to the canonical 'CWE-89' form."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    m = re.search(r"(\d+)", s)
    return "CWE-{}".format(m.group(1)) if m else None


# Sources disagree on shape: NVD ships CWE ids, Patchstack ships CWE *names* in its
# vuln_type field and states the required privilege in the title rather than a field.
# Normalizing here (instead of in each harvester) keeps the harvesters dumb and makes
# the rules visible in one place.

CWE_BY_NAME = [
    (r"cross[- ]site scripting|\bxss\b",                     "CWE-79"),
    (r"cross[- ]site request forgery|\bcsrf\b",              "CWE-352"),
    (r"missing authorization",                               "CWE-862"),
    (r"incorrect authorization",                             "CWE-863"),
    (r"improper access control",                             "CWE-284"),
    (r"sql injection|sql command",                           "CWE-89"),
    (r"remote file inclusion|include/require statement",     "CWE-98"),
    (r"local file inclusion",                                "CWE-98"),
    (r"deserialization of untrusted data",                   "CWE-502"),
    (r"unrestricted upload",                                 "CWE-434"),
    (r"path traversal|restricted directory",                 "CWE-22"),
    (r"server-side request forgery|\bssrf\b",                "CWE-918"),
    (r"authorization bypass through user-controlled key",    "CWE-639"),
    (r"incorrect privilege assignment",                      "CWE-266"),
    (r"improper privilege management",                       "CWE-269"),
    (r"privilege escalation",                                "CWE-269"),
    (r"insertion of sensitive information into sent data",   "CWE-201"),
    (r"exposure of sensitive system information",            "CWE-497"),
    (r"exposure of sensitive information|information disclosure", "CWE-200"),
    (r"authentication bypass using an alternate path",       "CWE-288"),
    (r"improper authentication|authentication bypass",       "CWE-287"),
    (r"code injection|control of generation of code",        "CWE-94"),
    (r"command injection|os command",                        "CWE-78"),
    (r"open redirect|url redirection",                       "CWE-601"),
    (r"formula elements in a csv file|csv injection",        "CWE-1236"),
    (r"xml external entity|xxe",                             "CWE-611"),
    (r"xml entity expansion|billion laughs",                 "CWE-776"),
    (r"hard-coded credentials",                              "CWE-798"),
    (r"insufficiently random|insecure randomness",           "CWE-330"),
    (r"weak password requirements",                          "CWE-521"),
    (r"cryptographic",                                       "CWE-327"),
    (r"uncontrolled resource consumption|denial of service", "CWE-400"),
    (r"file deletion|deletion of.*file",                     "CWE-73"),
    (r"external control of file name or path",               "CWE-73"),
    (r"session fixation",                                    "CWE-384"),
    (r"race condition|time-of-check",                        "CWE-367"),
]
CWE_BY_NAME = [(re.compile(p, re.I), c) for p, c in CWE_BY_NAME]

AUTH_BY_TEXT = [
    (r"\bunauthenticated\b",                        "unauthenticated"),
    (r"authenticated\s*\(?\s*subscriber",           "subscriber+"),
    (r"authenticated\s*\(?\s*contributor",          "contributor+"),
    (r"authenticated\s*\(?\s*author",               "author+"),
    (r"authenticated\s*\(?\s*editor",               "editor+"),
    (r"authenticated\s*\(?\s*(admin|administrator)", "admin+"),
]
AUTH_BY_TEXT = [(re.compile(p, re.I), a) for p, a in AUTH_BY_TEXT]


def infer_cwes(rec, existing):
    """Fill in CWE ids from a source that only names the weakness in prose."""
    if existing:
        return existing
    text = " ".join(str(rec.get(k) or "") for k in ("vuln_type", "title"))
    if not text.strip():
        return []
    # scripts/vuln_type_map.py is the authority here: it is order-sensitive and
    # self-tested against the real Patchstack vocabulary, which is what makes the
    # Patchstack half of the corpus (no CWE field at all) attributable.
    cwe = vuln_type_to_cwe(text)
    if cwe:
        return [cwe]
    for pattern, fallback in CWE_BY_NAME:
        if pattern.search(text):
            return [fallback]
    return []


def infer_auth(rec):
    """Recover the required privilege level, which drives the whole priority model."""
    current = (rec.get("auth_required") or "").strip().lower()
    if current and current != "unknown":
        return current
    text = " ".join(str(rec.get(k) or "") for k in ("title", "source_url", "vuln_type"))
    for pattern, auth in AUTH_BY_TEXT:
        if pattern.search(text):
            return auth
    return "unknown"


def load_classes(conn):
    """Load kb/classes/*.md, returning a CWE -> class_id map for CVE attribution."""
    cwe_map = {}
    # Seed from the taxonomy first. Class files land incrementally, but the taxonomy
    # lists all planned classes, so corpus attribution stays complete and stable
    # regardless of how many class files have been written so far. A real class file
    # still wins: setdefault below never overwrites, and the taxonomy is loaded first
    # only for classes that have no file yet.
    tax_path = ROOT / "kb" / "taxonomy.json"
    if tax_path.exists():
        try:
            tax = json.loads(tax_path.read_text(encoding="utf-8"))
            for entry in tax.get("classes", []):
                cid_t = entry.get("class_id")
                for w in entry.get("cwe", []):
                    w = norm_cwe(w)
                    if w and cid_t:
                        cwe_map.setdefault(w, cid_t)
        except (ValueError, OSError) as exc:
            print("  ! could not read taxonomy.json ({})".format(exc), file=sys.stderr)
    n_classes = n_rules = 0
    if not CLASSES.is_dir():
        return cwe_map, 0, 0

    for path in sorted(CLASSES.glob("*.md")):
        fm, _ = read_frontmatter(path)
        if not fm or not isinstance(fm, dict):
            print("  ! skipping {} (no usable frontmatter)".format(path.name), file=sys.stderr)
            continue
        cid = (fm.get("class_id") or path.stem).strip()

        raw_cwe = fm.get("cwe") or []
        if not isinstance(raw_cwe, list):
            raw_cwe = [raw_cwe]
        cwes = [c for c in (norm_cwe(x) for x in raw_cwe) if c]

        fix_apis = fm.get("fix_apis") or []
        if not isinstance(fix_apis, list):
            fix_apis = [fix_apis]

        examples = fm.get("examples") or []
        if not isinstance(examples, list):
            examples = []

        detection = fm.get("detection") or []
        if not isinstance(detection, list):
            detection = []

        conn.execute(
            "INSERT OR REPLACE INTO classes VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cid, fm.get("title"), json.dumps(cwes), fm.get("owasp"),
             fm.get("severity_typical"), fm.get("auth_required_typical"),
             json.dumps(fix_apis), len(examples), len(detection),
             str(path.relative_to(ROOT))),
        )
        n_classes += 1

        for rule in detection:
            if not isinstance(rule, dict):
                continue
            conn.execute(
                "INSERT INTO rules VALUES (?,?,?,?,?,?,?)",
                (rule.get("id"), cid, rule.get("description"), rule.get("regex"),
                 rule.get("confidence") or "medium", rule.get("false_positive_notes"),
                  1 if rule.get("multiline") else 0),
            )
            n_rules += 1

        # First class to claim a CWE owns it; ties are rare and reported.
        for c in cwes:
            if c in cwe_map and cwe_map[c] != cid:
                print("  ~ CWE {} claimed by both {} and {}; keeping {}".format(
                    c, cwe_map[c], cid, cwe_map[c]), file=sys.stderr)
            else:
                cwe_map.setdefault(c, cid)

    return cwe_map, n_classes, n_rules


def load_vulns(conn, cwe_map):
    """Load every data/raw/*.ndjson record, attributing each to a class via its CWEs."""
    total = mapped = 0
    if not RAW.is_dir():
        return 0, 0

    for path in sorted(RAW.glob("*.ndjson")):
        count = 0
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                raw_cwe = rec.get("cwe") or []
                if not isinstance(raw_cwe, list):
                    raw_cwe = [raw_cwe]
                cwes = [c for c in (norm_cwe(x) for x in raw_cwe) if c]
                cwes = infer_cwes(rec, cwes)
                auth = infer_auth(rec)

                class_id = None
                for c in cwes:
                    if c in cwe_map:
                        class_id = cwe_map[c]
                        break
                if class_id:
                    mapped += 1

                conn.execute(
                    "INSERT INTO vulns (source,cve,title,vuln_type,cwe,cvss,severity,"
                    "auth_required,software_type,published,source_url,class_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rec.get("source") or path.stem, rec.get("cve"), rec.get("title"),
                     rec.get("vuln_type"), json.dumps(cwes),
                     rec.get("cvss_v31") if rec.get("cvss_v31") is not None else rec.get("cvss"),
                     rec.get("severity"), auth,
                     rec.get("software_type"), rec.get("published") or rec.get("disclosed"),
                     rec.get("source_url"), class_id),
                )
                count += 1
        total += count
        print("  {:<28} {:>6} records".format(path.name, count))
    return total, mapped


def compute_priority(conn):
    """priority = severity x exploitability x prevalence.

    Exploitability is dominated by required privilege: an unauthenticated flaw is
    worth far more to an attacker than an Admin+ one, because an administrator can
    already install arbitrary code on a default WordPress install. Prevalence is
    damped logarithmically so a very common low-impact class cannot outrank a rarer
    critical one on volume alone.
    """
    rows = conn.execute("""
        SELECT class_id,
               COUNT(*)                                        AS n,
               AVG(COALESCE(cvss, 5.0))                        AS avg_cvss,
               MAX(COALESCE(cvss, 0))                          AS max_cvss,
               SUM(CASE WHEN LOWER(COALESCE(auth_required,'')) LIKE '%unauth%'
                        THEN 1 ELSE 0 END)                     AS unauth
        FROM vulns WHERE class_id IS NOT NULL GROUP BY class_id
    """).fetchall()

    corpus = {r[0]: r[1:] for r in rows}

    # Every class must appear. CWE attribution is first-wins, so a class whose CWEs are
    # all claimed by a sibling (WP-AJAX and WP-REST share CWE-862 with WP-AUTHZ; the three
    # XSS classes share CWE-79) would otherwise be silently dropped from the ranking and
    # read as "not a real risk". For those, fall back to the class's own verified examples
    # and record basis='examples' so the number is never mistaken for corpus prevalence.
    # The taxonomy is the authoritative class list -- not the classes table, which only
    # holds classes whose file exists yet. Sourcing it from the table silently dropped
    # WP-AUTHBYPASS from the ranking while its 662 records were still attributed.
    all_classes = []
    tax_path = ROOT / "kb" / "taxonomy.json"
    if tax_path.exists():
        try:
            all_classes = [c["class_id"] for c in
                           json.loads(tax_path.read_text(encoding="utf-8")).get("classes", [])]
        except (ValueError, OSError, KeyError):
            all_classes = []
    for row in conn.execute("SELECT class_id FROM classes"):
        if row[0] not in all_classes:
            all_classes.append(row[0])
    for row in conn.execute("SELECT DISTINCT class_id FROM vulns WHERE class_id IS NOT NULL"):
        if row[0] not in all_classes:
            all_classes.append(row[0])
    example_stats = {}
    for path in sorted((ROOT / "kb" / "classes").glob("*.md")):
        fm, _ = read_frontmatter(path)
        if not fm:
            continue
        cid = (fm.get("class_id") or path.stem).strip()
        exs = fm.get("examples") or []
        scores, unauth_n = [], 0
        for e in exs:
            if not isinstance(e, dict):
                continue
            try:
                scores.append(float(e.get("severity")))
            except (TypeError, ValueError):
                pass
            if "unauth" in str(e.get("auth", "")).lower():
                unauth_n += 1
        if scores:
            example_stats[cid] = (len(scores), sum(scores) / len(scores),
                                  max(scores), unauth_n)

    scored = []
    for class_id in all_classes:
        basis = "corpus"
        corpus_n = corpus[class_id][0] if class_id in corpus else 0
        example_n = example_stats[class_id][0] if class_id in example_stats else 0
        # A class with fewer corpus hits than it has verified examples of its own has been
        # starved by first-wins CWE attribution (WP-OPTIONS shares CWE-862 with WP-AUTHZ).
        # Its own examples are then the better evidence.
        if corpus_n and corpus_n >= example_n:
            n, avg_cvss, max_cvss, unauth = corpus[class_id]
        elif class_id in example_stats:
            n, avg_cvss, max_cvss, unauth = example_stats[class_id]
            basis = "examples"
        else:
            continue
        frac = (unauth / n) if n else 0.0
        severity = (avg_cvss or 5.0) / 10.0          # 0..1
        exploitability = 1.0 + 2.0 * frac            # 1..3
        prevalence = math.log10(n + 1)               # damped
        score = round(severity * exploitability * prevalence * 10, 2)
        scored.append((class_id, n, round(avg_cvss or 0, 2), round(max_cvss or 0, 2),
                       unauth, round(frac, 3), score, basis))

    scored.sort(key=lambda r: r[6], reverse=True)
    ranked = []
    for rank, row in enumerate(scored, 1):
        conn.execute("INSERT OR REPLACE INTO class_stats VALUES (?,?,?,?,?,?,?,?,?)",
                     row[:7] + (rank, row[7]))
        ranked.append(row)
    return ranked


def export_json(conn):
    """Export classes + rules for the scanner and the Claude skill."""
    out = []
    for row in conn.execute("SELECT class_id,title,cwe,owasp,severity_typical,"
                            "auth_required_typical,fix_apis,example_count,path FROM classes "
                            "ORDER BY class_id"):
        cid = row[0]
        stats = conn.execute(
            "SELECT cve_count,avg_cvss,unauth_frac,priority_score,priority_rank "
            "FROM class_stats WHERE class_id=?", (cid,)).fetchone()
        rules = [
            {"id": r[0], "description": r[1], "regex": r[2],
             "confidence": r[3], "false_positive_notes": r[4],
             "multiline": bool(r[5])}
            for r in conn.execute("SELECT rule_id,description,regex,confidence,"
                                  "false_positive_notes,multiline FROM rules WHERE class_id=?", (cid,))
        ]
        out.append({
            "class_id": cid, "title": row[1], "cwe": json.loads(row[2] or "[]"),
            "owasp": row[3], "severity_typical": row[4],
            "auth_required_typical": row[5], "fix_apis": json.loads(row[6] or "[]"),
            "example_count": row[7], "path": row[8],
            "evidence": ({"cve_count": stats[0], "avg_cvss": stats[1],
                          "unauth_frac": stats[2], "priority_score": stats[3],
                          "priority_rank": stats[4]} if stats else None),
            "rules": rules,
        })
    JSON_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return len(out)


def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)

    print("Loading classes from kb/classes/ ...")
    cwe_map, n_classes, n_rules = load_classes(conn)
    print("  {} classes, {} detection rules, {} CWEs mapped".format(
        n_classes, n_rules, len(cwe_map)))

    print("Loading vulnerability records from data/raw/ ...")
    total, mapped = load_vulns(conn, cwe_map)
    pct = (100.0 * mapped / total) if total else 0.0
    print("  {} records, {} attributed to a class ({:.1f}%)".format(total, mapped, pct))

    print("Computing priority ranking ...")
    scored = compute_priority(conn)
    conn.commit()

    n_exported = export_json(conn)

    print("\n{:<4} {:<16} {:>6} {:>9} {:>8} {:>9}".format(
        "#", "CLASS", "CVEs", "avg CVSS", "unauth%", "priority"))
    print("-" * 58)
    for rank, (cid, n, avg, _mx, _u, frac, score, basis) in enumerate(scored, 1):
        # "examples" marks a class starved by first-wins CWE attribution: its numbers
        # come from its own verified CVEs, not from corpus prevalence. Never compare
        # an examples-based count against a corpus-based one as if they were the same.
        note = "" if basis == "corpus" else "  (from examples)"
        print("{:<4} {:<16} {:>6} {:>9.1f} {:>7.0f}% {:>9.1f}{}".format(
            rank, cid, n, avg, frac * 100, score, note))

    unmapped = conn.execute(
        "SELECT COUNT(*) FROM vulns WHERE class_id IS NULL").fetchone()[0]
    if unmapped:
        print("\n{} records could not be attributed to a class.".format(unmapped))
        top = conn.execute("""
            SELECT cwe, COUNT(*) c FROM vulns WHERE class_id IS NULL AND cwe != '[]'
            GROUP BY cwe ORDER BY c DESC LIMIT 8""").fetchall()
        if top:
            print("Most common unattributed CWEs (candidates for new classes):")
            for cwe, c in top:
                print("  {:<24} {}".format(cwe, c))

    print("\nWrote {} and {} ({} classes).".format(
        DB_PATH.relative_to(ROOT), JSON_PATH.relative_to(ROOT), n_exported))
    conn.close()


if __name__ == "__main__":
    main()
