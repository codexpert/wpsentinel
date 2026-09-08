# User guide: auditing your own plugin or theme

This walks through running wpsentinel against a codebase you own, reading what
comes back, and deciding what is actually a bug.

The single most important idea is in the [triage](#3-triage-the-part-that-matters)
section: **the scanner reports shapes, not proofs.** A finding is a place worth
reading, not a vulnerability. Treating raw output as a list of bugs will waste your
time and, worse, teach you to ignore the tool.

---

## 1. Setup

```bash
git clone <your-fork-url> wpsentinel
cd wpsentinel
python3 scripts/wpscan.py --help
```

Requirements: **Python 3.8+**. Nothing else — no pip install, no PHP, no Node, no
ripgrep. If `--help` prints, you are ready.

The rules ship pre-built in `data/classes.json`, so you do not need to run the
harvesters or rebuild the database to scan.

---

## 2. Your first scan

Point it at a plugin or theme directory:

```bash
python3 scripts/wpscan.py /path/to/wp-content/plugins/my-plugin
```

You will get findings grouped by vulnerability class, ordered by priority, each
with the matched line and triage notes.

### What gets scanned

Extensions `.php`, `.phtml`, `.inc`, `.js`. These directories are skipped:

```
node_modules  vendor  .git  .svn  .hg  bower_components
tests  test  __tests__  spec  cypress  e2e
dist  build  .cache  coverage
```

...plus anything starting with `.`.

> **If the file count looks too low, this is usually why.** On a real plugin we
> tested, `find` reported 252 PHP files but the scanner reported far fewer. That was
> correct: 172 were in a `.claude/` cache directory and 38 in `tests/`. Check what
> you are counting before assuming the scanner missed something.

Scanning a vendored dependency you do not maintain is rarely useful — you cannot
patch it, and upstream may already have. Scan your own code.

---

## 3. Triage: the part that matters

Every finding is a **shape** — a line whose form resembles a known bug. Whether it
is a bug depends on code the regex could not see: the line above, the function that
assigns the variable, the hook that registers the handler.

For each finding, answer one question:

> **Can attacker-controlled data reach this line, from an entry point, at a
> privilege the attacker can actually obtain?**

If you cannot name the entry point, you do not have a finding.

### The three-step check

1. **Find the sink.** Read the flagged line and the ~20 lines around it.
2. **Trace the source.** Where does the variable come from? A superglobal, a REST
   parameter, post meta, an option? Or a constant, a `$wpdb` property, a literal?
3. **Check the guard.** Is there a capability check, nonce, escape, or `prepare()`
   between them — including on a *previous line* the rule could not see?

### A real worked example

Auditing a production plugin, we read every high-confidence finding. **Almost all
were false positives** — not because the rules are bad, but because each one's
safety was established on a line the rule could not see:

| Finding | Looked like | Actually was |
|---|---|---|
| `$wpdb->get_var("SHOW TABLES LIKE '$table_name'")` | SQL injection | `$table_name` built from `$wpdb->prefix` + a constant, one line above |
| `$key = 'cache_' . md5($apiKey)` | Hardcoded secret | A transient cache key; the handler above checks nonce *and* `manage_options` |
| `<?php echo $is_contact ? 'a' : 'b'; ?>` | Reflected XSS | Both branches are string literals |
| `'<a href="' . $url . '">'` | Stored XSS | `esc_url()` applied on the preceding line |

That ratio is normal and is not a defect. A scanner that only reported certain bugs
would miss most real ones. Your job is the last mile.

**The corollary:** do not "fix" a false positive. Wrapping a constant in
`esc_html()` adds noise and teaches the next reader that the codebase does not
distinguish trusted from untrusted data.

---

## 4. Reading confidence levels

| Level | Contract | What to do |
|---|---|---|
| `high` | Never fires on correct code (enforced by `scripts/test_rules.py`) | Read it now |
| `medium` | Also never fires on correct code, but needs context to confirm | Read it this pass |
| `low` | **Deliberately broad worklist. Fires on correct code by design.** | Sweep when you have time |

Low-confidence rules are hidden unless you pass `--all`. They are not weak rules —
`CSRF-009` matches *every* nonce call site on purpose, and its notes carry the
three-question triage that turns that list into findings.

On the plugin above: 67 findings by default (24 high, 43 medium), **277 with
`--all`**. Use `--all` for a deliberate sweep of one class, not for a first look.

---

## 5. Useful invocations

```bash
# Act-now items only — good for a pre-release gate
python3 scripts/wpscan.py ./my-plugin --high-only

# One class at a time — the sane way to work through a backlog
python3 scripts/wpscan.py ./my-plugin --class WP-SQLI --class WP-AUTHZ

# Everything, including the low-confidence worklist
python3 scripts/wpscan.py ./my-plugin --all

# Machine-readable, for an agent or a dashboard
python3 scripts/wpscan.py ./my-plugin --quiet --json findings.json

# A single file
python3 scripts/wpscan.py ./my-plugin/includes/ajax.php
```

### Exit codes

`0` = nothing to decide. `1` = findings need a human decision.

```yaml
# .github/workflows/security.yml
- name: Security audit
  run: python3 wpsentinel/scripts/wpscan.py . --high-only
```

Start CI with `--high-only`. Gating on everything on day one produces a red build
nobody trusts, which is worse than no gate.

---

## 6. Using it with a coding agent

The repo ships a skill and three commands. From this repo:

```
/wp-audit ../my-plugin        # scan, triage, and report verified findings only
/wp-fix   <finding>           # apply the WordPress-correct fix
/wp-rule  <pattern>           # add or refine a detection rule
```

The difference from running the scanner yourself is that `/wp-audit` does the
triage: it reads the code behind each finding, traces the entry point, and reports
only what it can substantiate — with the false positives named and dismissed rather
than silently dropped.

The skill's governing instruction is that it may not report a finding without
naming the entry point that carries attacker data to the sink.

To use it on another machine, copy `skills/` and `.claude/commands/` into that
project, or add this repo as a plugin.

---

## 7. Understanding a class

Every finding cites a class file. These are the actual reference material —
root cause, vulnerable and secure code, real CVEs with links to the vulnerable
source, and an audit checklist:

```bash
less kb/classes/WP-SQLI.md
```

Start with `kb/reference/` if you are new to WordPress security:

- `entry-points.md` — every way untrusted data enters. Read the `is_admin()`
  section; that misconception causes a lot of real vulnerabilities.
- `capability-matrix.md` — roles, capabilities, and why Contributor is the
  attacker position that matters most.
- `wp-security-apis.md` — which escaping and sanitizing function is correct where.
- `secure-handler-template.md` — a correct handler to copy.

---

## 8. Adding your own rules

If you find a bug shape the rules miss, add it. Rules live in the frontmatter of
`kb/classes/<CLASS>.md`.

```yaml
  - id: SQLI-010
    description: What this catches, in one line
    regex: 'your\s*pattern'
    confidence: medium
    false_positive_notes: >-
      When this fires on correct code, and what to check.
```

Then:

```bash
python3 scripts/validate_kb.py --strict   # schema, regex safety
python3 scripts/test_rules.py             # no FPs on correct code, no missed bugs
python3 scripts/build_db.py               # rebuild data/classes.json
```

**Three rules that will save you time:**

1. **Never use POSIX bracket expressions** (`[[:space:]]`). ripgrep accepts them;
   Python's `re` silently misparses them into an ordinary character set, so the rule
   compiles and stops matching. The validator rejects them outright.
2. **If your notes admit the safe idiom also matches, the rule is `low`, not
   `medium`.** Enforced by `test_rules.py` against `tests/fixtures/safe.php`.
3. **Layer instead of compromising.** One narrow `high` rule for the shape that
   admits no innocent reading, one broad `low` worklist for the rest. The value of
   `high` is that it can be acted on without reading the surrounding code, and every
   false positive spends that credibility.

For a shape that spans lines, set `multiline: true` — it is matched against a
short joined window. That exists because `permission_callback => function () {
return true; }` written across three lines is exactly as open as `__return_true`,
and formatting must not decide whether a vulnerability is reported.

---

## 9. Troubleshooting

**"Too few files scanned"** — check `SKIP_DIRS` above. Usually correct behaviour.

**"No findings at all"** — try `--all`. A genuinely clean small plugin is possible;
zero findings across a large codebase more often means you pointed at the wrong
directory. Check the file count in the output.

**"A rule is wrong for my codebase"** — use `--class` to exclude it from routine
runs, then fix the rule and send a PR. Local suppression comments are deliberately
not supported: they hide findings from the next reader too.

**"I want to rebuild from source data"** — `scripts/harvest_nvd.py` and
`harvest_patchstack.py` re-fetch the corpora (checkpointed and resumable). The
corpora are not redistributed; see `ATTRIBUTION.md`.

---

## 10. What this does not do

- **No taint analysis.** It does not follow a variable across functions. A bug whose
  source and sink are in different files will be missed.
- **PHP and JS only.** No template-engine or build-output analysis.
- **No runtime testing.** Static patterns only; it cannot confirm exploitability.
- **Not a compliance tool.** A clean run means these known shapes were not found —
  not that the code is secure.

It is a way to bring a decade of real WordPress disclosures to bear on your code in
under a second, and to point you at the twenty lines worth reading.
