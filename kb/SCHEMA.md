# wpsentinel Knowledge Base Schema

Every vulnerability-class file in `kb/classes/` is a single Markdown file with YAML
frontmatter. Audit scripts parse the frontmatter; humans and coding agents read the body.

## Filename

`kb/classes/<class_id>.md` — e.g. `kb/classes/WP-SQLI.md`

## Frontmatter contract

```yaml
---
class_id: WP-SQLI                 # stable ID, uppercase, matches filename
title: SQL Injection via unprepared $wpdb queries
cwe: [CWE-89]                     # one or more CWE IDs
owasp: A03:2021-Injection
severity_typical: high            # critical | high | medium | low
auth_required_typical: unauthenticated   # unauthenticated | subscriber+ | contributor+ | author+ | admin+
prevalence_rank: 2                # 1 = most common in WP ecosystem (set during synthesis)
detection:
  - id: SQLI-001
    description: Interpolated variable inside $wpdb->query/get_results without prepare
    regex: '\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(\s*["''][^"'']*\$'
    confidence: high              # high | medium | low  (low = needs human triage)
    false_positive_notes: Matches are safe if the variable was passed through $wpdb->prepare earlier.
fix_apis:                         # the WordPress APIs that constitute the correct fix
  - $wpdb->prepare()
  - esc_sql()
examples:                         # curated REAL cases, minimum 2
  - cve: CVE-2024-XXXXX
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: One sentence on the flaw.
    source_url: https://patchstack.com/database/...
    code_ref: https://plugins.trac.wordpress.org/browser/...#L125   # optional but preferred
    root_cause: One sentence naming the exact missing control.
---
```

## Body sections (in this order)

1. `## What it is` — 2–4 sentences, plain language.
2. `## Why it happens in WordPress` — the WP-specific trap (hook that runs before auth,
   `$wpdb` not auto-escaping, `wp_ajax_nopriv_`, etc.).
3. `## Vulnerable pattern` — a minimal, realistic PHP snippet (fenced ```php).
4. `## Secure pattern` — the corrected snippet using the `fix_apis` (fenced ```php).
5. `## Real-world case studies` — one subsection per curated example. Where a
   `plugins.trac.wordpress.org` reference exists, quote the *relevant few lines only*
   and explain the root cause at that line.
6. `## Detection guidance` — what the regexes catch, and crucially what they MISS
   (so the audit skill knows when to read code manually).
7. `## Audit checklist` — imperative bullets an agent can execute against a codebase.

## Rules

- **Real data only.** Every `cve` / `source_url` must be one you actually retrieved.
  If you could not verify a CVE ID, omit the example rather than inventing it.
  A class with 2 verified examples beats one with 8 fabricated ones.
- **No plugin shaming.** Name the vulnerable *pattern*, not the vendor. Plugin/theme
  names and researcher credits are deliberately excluded per project scope; the
  `source_url` is retained for provenance only.
- **Regexes must be POSIX-ERE / Rust-regex compatible** (they run under `ripgrep`).
  Test each one before writing it down. Prefer over-matching with
  `confidence: medium` over a clever regex that misses real bugs.

## The confidence contract

`confidence` is not a mood. It is a testable promise about how the rule behaves on
**correct** WordPress code, and `scripts/test_rules.py` enforces it against
`tests/fixtures/safe.php`:

| value    | promise                                                              |
|----------|----------------------------------------------------------------------|
| `high`   | Fires essentially only on real bugs. Must never fire on safe code.    |
| `medium` | May need context to confirm, but must still never fire on safe code.  |
| `low`    | Deliberately broad worklist. Allowed to fire on correct code.         |

The decisive test, learned from two real cases in this repo (`UPLOAD-004`, `RCE-003`):

> **If a rule's own `false_positive_notes` admit that the safe idiom also matches,
> the rule is `low` — not `medium`.**

Both of those rules described the correct pattern they would flag and were still
labelled `medium`. Integration testing caught both firing on `safe.php`. Downgrading
cost no true-positive coverage in either case, because a tighter high-confidence rule
already covered the unambiguous variant (`RCE-002` for `RCE-003`).

That is the shape to aim for: **layer the rules.** Write one narrow `high` rule for
the version of the bug that admits no innocent reading, and one broad `low` rule that
sweeps the rest into a worklist. Do not split the difference with a `medium` rule that
is really a worklist wearing a better label — the whole value of `high` is that an
agent can act on it without reading the surrounding code, and every false positive
spends that credibility.

A `low` rule is not a weak rule. `CSRF-009` matches every nonce call site in the
codebase on purpose, and its notes carry the three-question triage that turns the
worklist into findings. That is a good rule.

## Which CVSS score to record

Use the **NVD Primary** score (`type: "Primary"`, normally `source: nvd@nist.gov`).

NVD often returns several CVSS entries for one CVE: the NVD analyst's Primary score
plus one or more Secondary scores from the reporting CNA (Wordfence, Patchstack).
They frequently disagree, sometimes by more than a point:

| CVE | Primary (nvd@nist.gov) | Secondary (CNA) |
|-----|------------------------|-----------------|
| CVE-2023-5201 | 8.8 | 9.9 (Wordfence) |
| CVE-2024-7854 | 9.8 | 10.0 (Wordfence) |
| CVE-2024-50442 | 7.2 | 6.5 (Patchstack) |

`scripts/harvest_nvd.py:pick_cvss()` already selects Primary, and the whole priority
ranking in `scripts/build_db.py` is computed from those values. A class file that
records a Secondary score is therefore inconsistent with the ranking that cites it.

This is an easy mistake to make in the other direction: reading the API response and
taking `metrics.cvssMetricV31[0]` returns whichever entry NVD happens to list first,
which is often the Secondary one. All four cases in the table above reached this repo
that way and were corrected. If a score here looks "stale" against a quick API check,
verify you compared Primary to Primary before changing it.
