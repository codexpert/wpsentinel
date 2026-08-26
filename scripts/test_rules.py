#!/usr/bin/env python3
"""Cross-class rule testing against fixture corpora.

Per-class validation cannot see interactions. This runs EVERY detection rule in the
knowledge base against shared fixtures:

  tests/fixtures/safe.php       -- correct WordPress code. Any high- or medium-confidence
                                   rule that fires here is a FALSE POSITIVE and fails.
                                   Low-confidence "worklist" rules may fire; breadth is
                                   their stated purpose.

  tests/fixtures/vulnerable.php -- one reproduction of each documented bug class. A class
                                   planted here that produces NO finding is a FALSE
                                   NEGATIVE and fails. False positives are only half the
                                   problem: a scanner that is silent on real bugs is worse
                                   than one that is noisy, because silence reads as safety.

It also reports cross-class collisions: a single line matched by rules from several
different classes, which in the scanner would surface as duplicate findings.

Usage:  python3 scripts/test_rules.py
Exit 1 if any high/medium rule fires on safe code.
"""

import re
import sys
import warnings
import collections
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from build_db import read_frontmatter  # noqa: E402


def load_rules():
    rules = []
    for path in sorted((ROOT / "kb" / "classes").glob("*.md")):
        fm, _ = read_frontmatter(path)
        if not fm:
            continue
        cid = fm.get("class_id") or path.stem
        for r in fm.get("detection") or []:
            rx = r.get("regex")
            if not rx:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error")
                    compiled = re.compile(rx)
            except Exception:
                continue
            rules.append({
                "class_id": cid,
                "id": r.get("id"),
                "confidence": (r.get("confidence") or "").lower(),
                "regex": rx,
                "compiled": compiled,
            })
    return rules


def main():
    rules = load_rules()
    if not rules:
        print("No rules found.", file=sys.stderr)
        return 1
    classes = len({r["class_id"] for r in rules})
    print("Loaded {} rules across {} classes.\n".format(len(rules), classes))

    safe = ROOT / "tests" / "fixtures" / "safe.php"
    if not safe.exists():
        print("Missing fixture {}".format(safe), file=sys.stderr)
        return 1

    lines = safe.read_text(encoding="utf-8").splitlines()
    false_positives = []
    worklist_hits = collections.Counter()
    per_line = collections.defaultdict(set)

    for n, line in enumerate(lines, 1):
        if not line.strip() or line.strip().startswith("//"):
            continue
        for r in rules:
            if r["compiled"].search(line):
                per_line[n].add(r["class_id"])
                if r["confidence"] in ("high", "medium"):
                    false_positives.append((n, r["class_id"], r["id"], r["confidence"], line.strip()))
                else:
                    worklist_hits[r["class_id"]] += 1

    print("=== FALSE POSITIVES on correct code (high/medium rules) ===")
    if not false_positives:
        print("  none -- no high or medium rule fires on safe.php\n")
    else:
        for n, cid, rid, conf, text in false_positives:
            print("  line {:<3} {:<12} {:<12} [{}]".format(n, cid, rid, conf))
            print("        {}".format(text[:96]))
        print()

    print("=== low-confidence worklist rules firing (expected, by design) ===")
    if worklist_hits:
        for cid, n in worklist_hits.most_common():
            print("  {:<14} {} hit(s)".format(cid, n))
    else:
        print("  none")
    print()

    collisions = {n: c for n, c in per_line.items() if len(c) > 1}
    print("=== cross-class collisions (same line, multiple classes) ===")
    if collisions:
        for n in sorted(collisions):
            print("  line {:<3} -> {}".format(n, ", ".join(sorted(collisions[n]))))
        print("  (expected where classes genuinely overlap; a scanner should dedupe by line)")
    else:
        print("  none")

    # ---- false-negative check: every planted class must be detected
    vuln = ROOT / "tests" / "fixtures" / "vulnerable.php"
    missed = []
    if vuln.exists():
        text = vuln.read_text(encoding="utf-8")
        planted = set(re.findall(r"//\s*(WP-[A-Z0-9-]+(?:\s*/\s*WP-[A-Z0-9-]+)*)", text))
        wanted = set()
        for group in planted:
            for cid in re.findall(r"WP-[A-Z0-9-]+", group):
                wanted.add(cid)
        detected = set()
        for line in text.splitlines():
            if not line.strip():
                continue
            for r in rules:
                if r["compiled"].search(line):
                    detected.add(r["class_id"])
        missed = sorted(wanted - detected)
        print("\n=== DETECTION on planted bugs (tests/fixtures/vulnerable.php) ===")
        print("  classes planted : {}".format(len(wanted)))
        print("  detected        : {}".format(len(wanted) - len(missed)))
        if missed:
            print("  MISSED          : {}".format(", ".join(missed)))
        else:
            print("  missed          : none")

    if false_positives:
        print("\nFAILED: {} high/medium rule hit(s) on correct code.".format(len(false_positives)))
        return 1
    if missed:
        print("\nFAILED: {} planted class(es) produced no finding.".format(len(missed)))
        return 1
    print("\nOK: clean on safe fixtures, all planted bugs detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
