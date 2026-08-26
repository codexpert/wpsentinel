#!/usr/bin/env python3
"""wpsentinel - audit a WordPress plugin or theme against the vulnerability knowledge base.

Reads the detection rules exported to data/classes.json and reports matches, ordered by
the class priority ranking computed in build_db.py and then by rule confidence.

Design notes that matter when reading the output:

* Confidence is a promise about behaviour on CORRECT code (see kb/SCHEMA.md).
  `high`   - act on it; it does not fire on correct code.
  `medium` - real finding shapes, but confirm against the surrounding lines.
  `low`    - a deliberate worklist. Hidden unless you pass --all. These match correct
             code by design; their value is completeness, not precision.
* A single line can match rules from several classes (a dynamic dispatch is both
  WP-AJAX and WP-RCE). Findings are deduped per (file, line, class) so one line
  produces at most one finding per class, never one per rule.
* This is a grep-class tool. It reads one line at a time and cannot follow a variable
  across an assignment, so it finds SHAPES, not proofs. Every finding carries the
  class's triage notes precisely because the next step is reading the code.

Python 3.8+. Standard library only.

Usage:
    python3 scripts/wpscan.py /path/to/plugin
    python3 scripts/wpscan.py /path/to/plugin --all --json report.json
    python3 scripts/wpscan.py /path/to/plugin --class WP-SQLI --class WP-UPLOAD
"""

import argparse
import json
import os
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "classes.json"

SCAN_EXT = {".php", ".phtml", ".inc", ".js"}
# Directories that are someone else's code or not shipped to users. Scanning them
# produces findings the auditor cannot act on and buries the ones they can.
SKIP_DIRS = {
    "node_modules", "vendor", ".git", ".svn", ".hg", "bower_components",
    "tests", "test", "__tests__", "spec", "cypress", "e2e",
    "dist", "build", ".cache", "coverage",
}
SKIP_FILE_RE = re.compile(r"(\.min\.(js|css)$|-min\.js$|\.map$|\.pot?$)", re.I)
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
MAX_LINE = 4000          # a longer line is almost certainly generated/minified
MAX_BYTES = 3_000_000    # skip very large generated files
MULTILINE_WINDOW = 4     # lines joined for rules marked multiline


def load_rules(db_path, only_classes=None):
    """Load and compile rules, ordered by class priority then confidence."""
    try:
        classes = json.loads(Path(db_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("Cannot read rule database {}: {}".format(db_path, exc), file=sys.stderr)
        print("Run:  python3 scripts/build_db.py", file=sys.stderr)
        return None, None

    wanted = {c.upper() for c in only_classes} if only_classes else None
    rules, meta = [], {}
    for entry in classes:
        cid = entry.get("class_id")
        if wanted and cid.upper() not in wanted:
            continue
        ev = entry.get("evidence") or {}
        meta[cid] = {
            "title": entry.get("title") or cid,
            "rank": ev.get("priority_rank") or 999,
            "score": ev.get("priority_score") or 0,
            "severity": entry.get("severity_typical") or "unknown",
            "fix_apis": entry.get("fix_apis") or [],
            "path": entry.get("path"),
        }
        for r in entry.get("rules") or []:
            rx = r.get("regex")
            if not rx:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error")
                    compiled = re.compile(rx)
            except Exception as exc:
                print("  ! skipping {} ({}): {}".format(r.get("id"), cid, exc), file=sys.stderr)
                continue
            rules.append({
                "class_id": cid,
                "id": r.get("id"),
                "multiline": bool(r.get("multiline")),
                "confidence": (r.get("confidence") or "low").lower(),
                "description": r.get("description") or "",
                "notes": r.get("false_positive_notes") or "",
                "compiled": compiled,
            })

    rules.sort(key=lambda r: (meta[r["class_id"]]["rank"],
                              CONF_ORDER.get(r["confidence"], 3)))
    return rules, meta


def iter_files(target):
    """Yield scannable files, skipping dependency and build directories."""
    target = Path(target)
    if target.is_file():
        yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if Path(name).suffix.lower() not in SCAN_EXT:
                continue
            if SKIP_FILE_RE.search(name):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield path


def scan(target, rules, min_conf="medium"):
    """Return (findings, stats). Dedupes to one finding per (file, line, class)."""
    allowed = {c for c, o in CONF_ORDER.items() if o <= CONF_ORDER[min_conf]}
    findings, seen = [], set()
    files = errors = lines_scanned = 0

    # Report paths relative to the scanned plugin, not absolute. An auditor reads these
    # against the plugin's own layout, and absolute paths make the report unusable when
    # it is pasted elsewhere or handed to an agent.
    base = Path(target)
    if base.is_file():
        base = base.parent

    def rel(path):
        try:
            return str(path.relative_to(base))
        except ValueError:
            return str(path)

    for path in iter_files(target):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            errors += 1
            continue
        files += 1
        raw_lines = text.splitlines()

        # Some bug shapes span lines and cannot be seen one line at a time. The one that
        # forced this: `permission_callback => function () { return true; }` written over
        # three lines is semantically identical to `__return_true`, but a line-based rule
        # only ever sees the opening `function () {`. Rules marked multiline are matched
        # against a small forward window with whitespace collapsed, so formatting does not
        # decide whether a vulnerability is found. The window is deliberately short: it is
        # for adjacent-line shapes, not for following a variable across a function.
        joined = []
        for i in range(len(raw_lines)):
            joined.append(" ".join(" ".join(raw_lines[i:i + MULTILINE_WINDOW]).split()))

        for lineno, line in enumerate(raw_lines, 1):
            if len(line) > MAX_LINE:
                continue
            lines_scanned += 1
            stripped = line.strip()
            if not stripped:
                continue
            for rule in rules:
                if rule["confidence"] not in allowed:
                    continue
                if rule["multiline"]:
                    haystack = joined[lineno - 1]
                    m = rule["compiled"].search(haystack)
                    # Overlapping windows would each report the same construct. Keep only
                    # the window whose match STARTS in its own first line, so a multiline
                    # finding is anchored where the construct begins, once.
                    if not m or m.start() > len(" ".join(line.split())):
                        continue
                else:
                    if not rule["compiled"].search(line):
                        continue
                key = (rel(path), lineno, rule["class_id"])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "file": rel(path),
                    "line": lineno,
                    "class_id": rule["class_id"],
                    "rule_id": rule["id"],
                    "confidence": rule["confidence"],
                    "description": rule["description"],
                    "notes": rule["notes"],
                    "code": stripped[:200],
                })
    return findings, {"files": files, "lines": lines_scanned, "unreadable": errors}


def report(findings, meta, stats, target, min_conf, show_notes):
    by_class = {}
    for f in findings:
        by_class.setdefault(f["class_id"], []).append(f)

    print("=" * 78)
    print("wpsentinel audit: {}".format(target))
    print("scanned {} files, {} lines".format(stats["files"], stats["lines"]))
    if stats["unreadable"]:
        print("({} file(s) unreadable)".format(stats["unreadable"]))
    print("=" * 78)

    if not findings:
        print("\nNo findings at confidence >= {}.".format(min_conf))
        if min_conf != "low":
            print("This is not a clean bill of health: low-confidence worklist rules were")
            print("not run. Re-run with --all to see every call site worth reviewing.")
        return

    conf_counts = {}
    for f in findings:
        conf_counts[f["confidence"]] = conf_counts.get(f["confidence"], 0) + 1
    print("\n{} finding(s): {}".format(
        len(findings),
        ", ".join("{} {}".format(v, k) for k, v in
                  sorted(conf_counts.items(), key=lambda kv: CONF_ORDER.get(kv[0], 3)))))

    for cid in sorted(by_class, key=lambda c: meta[c]["rank"]):
        items = sorted(by_class[cid], key=lambda f: (CONF_ORDER.get(f["confidence"], 3),
                                                     f["file"], f["line"]))
        m = meta[cid]
        print("\n" + "-" * 78)
        print("[{:>2}] {} - {}".format(m["rank"], cid, m["title"]))
        print("     typical severity: {} | {} finding(s)".format(m["severity"], len(items)))
        if m.get("path"):
            print("     reference: {}".format(m["path"]))
        print("-" * 78)
        for f in items:
            print("  {}:{}  [{}] {}".format(f["file"], f["line"],
                                            f["confidence"], f["rule_id"]))
            print("      {}".format(f["description"][:110]))
            print("      | {}".format(f["code"]))
            if show_notes and f["notes"]:
                note = " ".join(f["notes"].split())
                print("      triage: {}".format(note[:400]))
            print()


def main():
    ap = argparse.ArgumentParser(
        description="Audit a WordPress plugin or theme against the wpsentinel knowledge base.")
    ap.add_argument("target", help="plugin/theme directory or a single file")
    ap.add_argument("--db", default=str(DEFAULT_DB), help="rule database (data/classes.json)")
    ap.add_argument("--all", action="store_true",
                    help="include low-confidence worklist rules (noisy by design)")
    ap.add_argument("--high-only", action="store_true", help="only high-confidence rules")
    ap.add_argument("--class", dest="classes", action="append",
                    help="restrict to a class id (repeatable), e.g. --class WP-SQLI")
    ap.add_argument("--json", help="also write findings as JSON to this path")
    ap.add_argument("--no-notes", action="store_true", help="omit triage notes")
    ap.add_argument("--quiet", action="store_true", help="suppress the text report")
    args = ap.parse_args()

    if not Path(args.target).exists():
        print("No such path: {}".format(args.target), file=sys.stderr)
        return 2

    min_conf = "high" if args.high_only else ("low" if args.all else "medium")

    rules, meta = load_rules(args.db, args.classes)
    if rules is None:
        return 2
    if not rules:
        print("No rules loaded (check --class values).", file=sys.stderr)
        return 2

    findings, stats = scan(args.target, rules, min_conf)

    if not args.quiet:
        report(findings, meta, stats, args.target, min_conf, not args.no_notes)

    if args.json:
        payload = {
            "target": str(args.target),
            "min_confidence": min_conf,
            "stats": stats,
            "classes": {c: meta[c] for c in {f["class_id"] for f in findings}},
            "findings": findings,
        }
        Path(args.json).write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
        if not args.quiet:
            print("JSON written to {}".format(args.json))

    # Exit 1 when something needs a human decision, so CI can gate on it.
    return 1 if any(f["confidence"] in ("high", "medium") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
