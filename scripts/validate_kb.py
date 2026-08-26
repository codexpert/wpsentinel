#!/usr/bin/env python3
"""Validate the knowledge base against kb/SCHEMA.md.

Checks every kb/classes/*.md file for:
  - parseable YAML frontmatter with all required keys
  - detection rules that actually compile as regexes
  - detection rules that are not so broad they match everything
  - examples that carry a verifiable CVE id and a source URL
    (source_url is a data-license obligation, not a nicety -- see ATTRIBUTION.md)
  - the body sections kb/SCHEMA.md requires, in a usable form
  - class_id agreeing with the filename, and no duplicate ids or rule ids

Exit status is 1 if any ERROR is found, so this can gate CI. Warnings do not fail.

Usage:
    python3 scripts/validate_kb.py [--strict]

--strict also fails on warnings.

Python 3.8+. Standard library only (PyYAML used when available).
"""

import argparse
import re
import warnings
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLASSES = ROOT / "kb" / "classes"

sys.path.insert(0, str(ROOT / "scripts"))
from build_db import read_frontmatter, norm_cwe  # noqa: E402

REQUIRED_KEYS = [
    "class_id", "title", "cwe", "severity_typical",
    "auth_required_typical", "detection", "fix_apis", "examples",
]
REQUIRED_SECTIONS = [
    "What it is",
    "Why it happens in WordPress",
    "Vulnerable pattern",
    "Secure pattern",
    "Real-world case studies",
    "Detection guidance",
    "Audit checklist",
]
VALID_SEVERITY = {"critical", "high", "medium", "low"}
VALID_CONFIDENCE = {"high", "medium", "low"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# A rule this permissive will match almost any PHP file and drown the report.
TOO_BROAD = [
    re.compile(r"^\W*\$\w+\W*$"),          # bare variable
    re.compile(r"^\W*(echo|print)\W*$"),   # bare echo
    re.compile(r"^\.\*$"),
    re.compile(r"^\W{0,3}$"),
]


class Report(object):
    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, where, msg):
        self.errors.append("{}: {}".format(where, msg))

    def warn(self, where, msg):
        self.warnings.append("{}: {}".format(where, msg))


def check_regex(rx, where, rep):
    """Compile the rule and sanity-check its breadth."""
    if not rx or not str(rx).strip():
        rep.error(where, "empty regex")
        return
    # POSIX bracket expressions ([[:space:]]) are valid in ripgrep/Rust-regex, but
    # Python's re parses them as an ordinary character set. The rule then compiles
    # fine and silently stops matching -- a false negative, which is the most
    # dangerous failure mode for a security scanner. Reject outright.
    posix = re.findall(
        r"\[:(?:alpha|digit|alnum|space|upper|lower|punct|xdigit|word|blank|cntrl|graph|print):\]", rx)
    if posix:
        rep.error(where, "POSIX bracket expression {} is unsupported by Python 're' and will "
                         "silently fail to match; use \\s / [A-Za-z0-9], which work in BOTH "
                         "ripgrep and Python: {!r}".format(sorted(set(posix)), rx))
        return

    try:
        with warnings.catch_warnings():
            # A FutureWarning here means the pattern is ambiguous and may change
            # meaning between Python versions. Fail now rather than ship it.
            warnings.simplefilter("error")
            compiled = re.compile(rx)
    except re.error as exc:
        rep.error(where, "regex does not compile: {}".format(exc))
        return
    except FutureWarning as exc:
        rep.error(where, "ambiguous regex ({}); rewrite it explicitly: {!r}".format(exc, rx))
        return
    for pattern in TOO_BROAD:
        if pattern.match(rx):
            rep.warn(where, "regex looks too broad to be useful: {!r}".format(rx))
            break
    # A rule that matches the empty string matches every line.
    if compiled.search(""):
        rep.error(where, "regex matches the empty string, so it matches every line: {!r}".format(rx))
    # ripgrep/Rust regex has no lookaround; flag it so rules stay portable.
    if re.search(r"\(\?<[=!]|\(\?[=!]", rx):
        rep.warn(where, "uses lookaround, which Rust-regex/ripgrep cannot run: {!r}".format(rx))


def validate_file(path, seen_ids, seen_rule_ids, rep):
    fm, body = read_frontmatter(path)
    name = path.name
    if not fm or not isinstance(fm, dict):
        rep.error(name, "frontmatter missing or unparseable")
        return

    for key in REQUIRED_KEYS:
        if key not in fm or fm.get(key) in (None, "", []):
            rep.error(name, "missing required key '{}'".format(key))

    cid = (fm.get("class_id") or "").strip()
    if cid and cid != path.stem:
        rep.error(name, "class_id {!r} does not match filename {!r}".format(cid, path.stem))
    if cid in seen_ids:
        rep.error(name, "duplicate class_id {!r} (also in {})".format(cid, seen_ids[cid]))
    elif cid:
        seen_ids[cid] = name

    sev = str(fm.get("severity_typical") or "").lower()
    if sev and sev not in VALID_SEVERITY:
        rep.error(name, "severity_typical {!r} not one of {}".format(sev, sorted(VALID_SEVERITY)))

    cwes = fm.get("cwe") or []
    if not isinstance(cwes, list):
        cwes = [cwes]
    for c in cwes:
        if not norm_cwe(c):
            rep.error(name, "unparseable CWE entry {!r}".format(c))

    # ---- detection rules
    rules = fm.get("detection") or []
    if not isinstance(rules, list) or not rules:
        rep.error(name, "no detection rules")
        rules = []
    high = 0
    for rule in rules:
        if not isinstance(rule, dict):
            rep.error(name, "detection entry is not a mapping: {!r}".format(rule))
            continue
        rid = rule.get("id") or "<no-id>"
        where = "{} [{}]".format(name, rid)
        if rid == "<no-id>":
            rep.error(where, "rule has no id")
        elif rid in seen_rule_ids:
            rep.error(where, "duplicate rule id (also in {})".format(seen_rule_ids[rid]))
        else:
            seen_rule_ids[rid] = name

        check_regex(rule.get("regex"), where, rep)

        conf = str(rule.get("confidence") or "").lower()
        if conf not in VALID_CONFIDENCE:
            rep.error(where, "confidence {!r} not one of {}".format(conf, sorted(VALID_CONFIDENCE)))
        if conf == "high":
            high += 1
        if not rule.get("description"):
            rep.warn(where, "no description")
        if conf in ("medium", "low") and not rule.get("false_positive_notes"):
            rep.warn(where, "{} confidence rule without false_positive_notes; "
                            "a triaging agent needs these".format(conf))
    if rules and not high:
        rep.warn(name, "no high-confidence rule; findings will all need manual triage")

    # ---- examples
    examples = fm.get("examples") or []
    if not isinstance(examples, list):
        examples = []
    if len(examples) < 2:
        rep.error(name, "only {} example(s); kb/SCHEMA.md requires at least 2 verified "
                        "real-world cases".format(len(examples)))
    for i, ex in enumerate(examples):
        where = "{} example[{}]".format(name, i)
        if not isinstance(ex, dict):
            rep.error(where, "example is not a mapping")
            continue
        cve = str(ex.get("cve") or "")
        if not cve:
            rep.error(where, "no CVE id")
        elif not CVE_RE.match(cve):
            rep.error(where, "malformed CVE id {!r}".format(cve))
        elif "XXXX" in cve.upper():
            rep.error(where, "placeholder CVE id {!r} -- real data only".format(cve))
        if not ex.get("source_url"):
            rep.error(where, "no source_url; this is required by the data license "
                             "(see ATTRIBUTION.md), not just for provenance")
        if not ex.get("root_cause"):
            rep.warn(where, "no root_cause")

    # ---- body
    present = set()
    for line in body.splitlines():
        if line.startswith("## "):
            present.add(line[3:].strip().lower())
    for section in REQUIRED_SECTIONS:
        if section.lower() not in present:
            rep.warn(name, "missing body section '## {}'".format(section))

    if "```php" not in body:
        rep.warn(name, "no PHP code block; vulnerable/secure patterns should be shown as code")

    return {
        "class_id": cid, "rules": len(rules), "high": high,
        "examples": len(examples),
        "trac": sum(1 for e in examples if isinstance(e, dict) and e.get("code_ref")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="fail on warnings too")
    args = ap.parse_args()

    if not CLASSES.is_dir():
        print("No kb/classes/ directory found.", file=sys.stderr)
        return 1

    files = sorted(CLASSES.glob("*.md"))
    if not files:
        print("No class files found in kb/classes/.", file=sys.stderr)
        return 1

    rep = Report()
    seen_ids, seen_rule_ids = {}, {}
    rows = []
    for path in files:
        row = validate_file(path, seen_ids, seen_rule_ids, rep)
        if row:
            rows.append(row)

    print("{:<16} {:>6} {:>6} {:>9} {:>6}".format("CLASS", "RULES", "HIGH", "EXAMPLES", "TRAC"))
    print("-" * 48)
    for r in sorted(rows, key=lambda x: x["class_id"]):
        print("{:<16} {:>6} {:>6} {:>9} {:>6}".format(
            r["class_id"], r["rules"], r["high"], r["examples"], r["trac"]))
    print("-" * 48)
    print("{:<16} {:>6} {:>6} {:>9} {:>6}".format(
        "TOTAL ({})".format(len(rows)),
        sum(r["rules"] for r in rows), sum(r["high"] for r in rows),
        sum(r["examples"] for r in rows), sum(r["trac"] for r in rows)))

    if rep.warnings:
        print("\nWarnings ({}):".format(len(rep.warnings)))
        for w in rep.warnings:
            print("  ! {}".format(w))
    if rep.errors:
        print("\nErrors ({}):".format(len(rep.errors)))
        for e in rep.errors:
            print("  X {}".format(e))

    if rep.errors:
        print("\nFAILED: {} error(s).".format(len(rep.errors)))
        return 1
    if args.strict and rep.warnings:
        print("\nFAILED (--strict): {} warning(s).".format(len(rep.warnings)))
        return 1
    print("\nOK: {} class file(s) valid.".format(len(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
