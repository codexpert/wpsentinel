---
description: Add or refine a detection rule in the wpsentinel knowledge base
argument-hint: [class id and what to detect, e.g. WP-REST closure returning true]
---

Add or refine a detection rule for: $ARGUMENTS

Read `kb/SCHEMA.md` first — especially the confidence contract and the CVSS convention.

Constraints that are not negotiable (each exists because it broke something here):

- **No POSIX bracket expressions** (`[[:space:]]`, `[[:alnum:]]`). Python's `re` silently
  misparses them into an ordinary character set, so the rule compiles and then never
  matches. Use `\s` and `[A-Za-z0-9]`, which work in both Python and ripgrep.
- **No lookaround, no backreferences** — ripgrep's Rust engine cannot run them. To express
  "not `$wpdb`" without lookahead, use the established fragment:
  `\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])`
- **Set `multiline: true`** for a shape that spans lines, so formatting cannot hide a bug.
- **Confidence is a promise about correct code.** If the rule fires on
  `tests/fixtures/safe.php`, it is `low`, not `medium`. Layer instead: one narrow `high`
  rule for the version that admits no innocent reading, one broad `low` worklist.
- Every example needs a real, verified CVE and a `source_url`. Record the NVD **Primary**
  CVSS (`nvd@nist.gov`), not the CNA's Secondary score — reading
  `metrics.cvssMetricV31[0]` returns whichever is listed first and is usually wrong.

Then run all four gates and make sure they pass:

```bash
python3 scripts/validate_kb.py --strict
python3 scripts/test_rules.py
python3 scripts/audit_examples.py
python3 scripts/build_db.py
```
