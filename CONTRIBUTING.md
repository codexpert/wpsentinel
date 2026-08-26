# Contributing to wpsentinel

The knowledge base is the product. A rule that fires on correct code, or an example built
on a CVE nobody verified, does more damage than a missing entry — an auditor who stops
trusting the output stops reading it.

## The four gates

Everything must pass before a change lands:

```bash
python3 scripts/validate_kb.py --strict   # schema, regex safety, license fields
python3 scripts/test_rules.py             # false positives AND false negatives
python3 scripts/audit_examples.py         # CVSS provenance
python3 scripts/build_db.py               # attribution and ranking
```

Each of these exists because it caught a real defect. They are not ceremony.

## Rules

**Confidence is a promise about correct code**, not a feeling:

| level | promise |
|---|---|
| `high` | Does not fire on correct code. An agent may act on it without reading around it. |
| `medium` | May need context, but still does not fire on correct code. |
| `low` | Deliberate worklist. Matches correct code by design; hidden unless `--all`. |

The decisive test: **if your `false_positive_notes` admit the safe idiom also matches, the
rule is `low`.** Two rules shipped as `medium` while their own notes described the correct
code they would flag; integration testing caught both.

The shape to aim for is layered — one narrow `high` rule for the version of the bug that
admits no innocent reading, one broad `low` rule that sweeps the rest into a worklist.
A `medium` rule that is really a worklist wearing a better label spends the credibility
that makes `high` useful.

### Regex constraints

Rules are authored in Rust-regex (ripgrep) syntax and executed through Python's `re`.

- **No POSIX bracket expressions** (`[[:space:]]`, `[[:alnum:]]`). Python's `re` parses
  them as an ordinary character set, so the rule compiles and then silently stops
  matching — a false negative, the worst failure mode for a scanner. Use `\s` and
  `[A-Za-z0-9]`, which are correct in both engines.
- **No lookaround, no backreferences.** Rust's engine cannot run them. To express
  "a variable that is not `$wpdb`" without lookahead, reuse the established fragment:
  `\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])`
- **Use `multiline: true`** when the shape spans lines. A `permission_callback` closure
  returning `true` is as open as `__return_true`, and code formatting must not decide
  whether it gets reported.
- Add both a vulnerable and a safe case to `tests/fixtures/` for anything new.

## Examples

Every example needs a **real, verified CVE** and a `source_url`. The URL is a data-license
obligation, not a nicety — see [ATTRIBUTION.md](ATTRIBUTION.md).

If you cannot retrieve the vulnerable source and describe the root cause from code you
actually read, **drop the example**. Do not describe a root cause from an advisory summary
and present it as analysis. Several contributors' CVEs were dropped for exactly this
reason, and the knowledge base is better for it.

### Record the NVD Primary CVSS

NVD returns several scores per CVE: the NVD analyst's **Primary** (`nvd@nist.gov`) plus
**Secondary** scores from the reporting CNA. They disagree, sometimes by more than a point.

Reading `metrics.cvssMetricV31[0]` returns whichever NVD lists first, which is often the
Secondary one. Five wrong scores reached this repo that way. The corpus and the whole
priority ranking use Primary, so a Secondary score in a class file contradicts the ranking
that cites it. `audit_examples.py` gates this.

## Scope

Defensive only. Document vulnerable and secure patterns so they can be found and fixed; do
not add working exploit payloads.

Record **patterns, not victims** — no plugin names, vendor names, or researcher credits in
the prose. Source links are kept for verification and because the license requires them.

## Adding a class

1. Add it to `kb/taxonomy.json` with its CWEs and a rationale.
2. Write `kb/classes/<ID>.md` following `kb/SCHEMA.md` — all seven body sections.
3. Add fixtures, run the four gates.
4. If it shares a CWE with an existing class, say how they differ in both files and
   cross-reference rather than duplicating rules. Attribution is first-wins, so a shared
   CWE means the ranking may show the class as starved — that is expected and handled.
