#!/usr/bin/env python3
"""Cross-check every class-file example against the harvested corpus.

Two things go wrong with hand-entered example metadata, both seen in this repo:

1. A CVSS score copied from the wrong NVD metric. NVD returns a Primary score
   (nvd@nist.gov) plus Secondary scores from the reporting CNA, and reading
   `metrics.cvssMetricV31[0]` grabs whichever is listed first -- often the Secondary.
   The corpus in data/raw/nvd.ndjson stores Primary (see harvest_nvd.py:pick_cvss),
   and build_db.py ranks classes from those values, so a Secondary score in a class
   file contradicts the ranking that cites it. Five such cases were found and fixed
   by this check.

2. A CVE id that does not exist, or a typo in one. Any id absent from the corpus is
   reported so it can be verified against the live API before being trusted.

Usage:  python3 scripts/audit_examples.py [--strict]
Exit 1 on a CVSS disagreement. --strict also fails on ids missing from the corpus
(they are not necessarily wrong -- the corpus is a snapshot -- so they warn by default).
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from build_db import read_frontmatter  # noqa: E402

TOLERANCE = 0.05


def load_corpus():
    corpus = {}
    path = ROOT / "data" / "raw" / "nvd.ndjson"
    if not path.exists():
        return corpus
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            cve = rec.get("cve")
            if cve:
                corpus[cve] = rec.get("cvss_v31")
    return corpus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="also fail when a CVE id is absent from the local corpus")
    args = ap.parse_args()

    corpus = load_corpus()
    if not corpus:
        print("No corpus at data/raw/nvd.ndjson -- run scripts/harvest_nvd.py first.",
              file=sys.stderr)
        return 1

    total = agree = 0
    disagree, absent, unparsed = [], [], []

    for path in sorted((ROOT / "kb" / "classes").glob("*.md")):
        fm, _ = read_frontmatter(path)
        if not fm:
            unparsed.append(path.name)
            continue
        cid = fm.get("class_id") or path.stem
        for ex in fm.get("examples") or []:
            if not isinstance(ex, dict):
                continue
            cve = str(ex.get("cve") or "")
            if not cve:
                continue
            total += 1
            if cve not in corpus or corpus[cve] is None:
                absent.append((cid, cve))
                continue
            try:
                if abs(float(ex.get("severity")) - float(corpus[cve])) < TOLERANCE:
                    agree += 1
                else:
                    disagree.append((cid, cve, ex.get("severity"), corpus[cve]))
            except (TypeError, ValueError):
                disagree.append((cid, cve, ex.get("severity"), corpus[cve]))

    print("Examples with a CVE id: {}".format(total))
    print("  agree with corpus Primary CVSS : {}".format(agree))
    print("  absent from local corpus       : {}".format(len(absent)))
    print("  DISAGREE                       : {}".format(len(disagree)))

    if disagree:
        print("\nCVSS disagreements (check Primary vs Secondary before editing):")
        for cid, cve, got, want in disagree:
            print("  {:<14} {:<16} file={!s:<7} corpus={}".format(cid, cve, got, want))
    if absent:
        print("\nNot in local corpus (verify against the live NVD API):")
        for cid, cve in absent:
            print("  {:<14} {}".format(cid, cve))
    if unparsed:
        print("\nUnparseable class files: {}".format(", ".join(unparsed)))

    if disagree:
        print("\nFAILED: {} CVSS disagreement(s).".format(len(disagree)))
        return 1
    if args.strict and absent:
        print("\nFAILED (--strict): {} id(s) absent from corpus.".format(len(absent)))
        return 1
    print("\nOK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
