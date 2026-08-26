---
name: wp-security-audit
description: Use when auditing, reviewing, or hardening a WordPress plugin or theme for security, or when asked to find or fix vulnerabilities in WordPress PHP/JS code. Covers 25 vulnerability classes (SQLi, XSS, CSRF, missing capability checks, arbitrary upload, LFI, object injection, SSRF, privilege escalation and more) with detection rules and WordPress-correct fixes.
---

# WordPress Security Audit

Audit a WordPress plugin or theme against a knowledge base of 25 vulnerability classes
built from ~37,000 real disclosures, then propose fixes that use WordPress's own APIs.

## The one rule that matters

**The scanner reports shapes. Only reading the code turns a shape into a finding.**

Every rule is a regex over single lines (or a short window). It cannot follow a variable
across an assignment, into a function, or back to its source. On a real plugin audit, every
single high-confidence hit turned out to be safe — and in each case the safety was
established **one line above the match**:

```php
$table_name = $wpdb->prefix . THRIVEDESK_DB_TABLE_CONVERSATION;  // <- safe, constant
$row = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");         // <- rule fires here
```

Report a finding only after reading the surrounding code and being able to state how
attacker-controlled data reaches the sink. Reporting unverified hits destroys the
credibility of the ones that are real.

## Workflow

### 1. Scan

```bash
python3 scripts/wpscan.py <plugin-dir> --json findings.json
```

- default shows `high` + `medium`
- `--high-only` for the act-now set
- `--all` adds the low-confidence worklist (matches correct code by design; use when you
  want an exhaustive inventory of call sites, not a list of bugs)
- `--class WP-SQLI` to focus

If the tool is not present, fall back to reading `kb/classes/*.md` and grepping for the
`regex` values in each file's `detection:` block.

### 2. Triage each finding

For every hit, in this order:

1. **Read the surrounding lines** — at minimum 10 above and 5 below. Most false positives
   die here.
2. **Trace the input.** Name the entry point (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/
   `$_FILES`, a REST param, a shortcode attribute, post meta, an option, an imported file).
   If you cannot name one, it is not a finding.
3. **Check the guards.** Is there a `current_user_can()` for the right capability, and a
   nonce check whose **result is used**? Note which is missing — they are different bugs
   (see the classes below).
4. **Decide who can reach it.** Unauthenticated, Subscriber+, Contributor+, Admin+. This
   drives severity more than the sink does; an Admin-only flaw on a default install is
   usually not a vulnerability, because an administrator can already run code.
5. **Open the class file** `kb/classes/<CLASS>.md` and read `false_positive_notes` for that
   rule id. They are written from real cases and usually name the exact safe idiom.

Read `references/triage.md` for the per-class questions.

### 3. Report

Group by class, ordered by the class's `priority_rank`. For each **confirmed** finding give:

- file:line, and the reachable entry point
- who can reach it (the privilege level)
- what an attacker gets
- the fix, as a diff

State plainly which hits you dismissed and why — that is evidence you checked, and it lets
the maintainer disagree with a specific call rather than the whole report.

Never call a scan "clean" on the basis of a default run. Say what confidence level ran and
what was not checked.

### 4. Fix

Use WordPress's own APIs. Read `references/fixes.md` for the per-class patterns. The
recurring mistakes:

- `esc_*` at **output**, not at input. Sanitising on save does not make a later echo safe.
- `$wpdb->prepare()` must receive the query **with placeholders** — interpolating before
  prepare sees it is the bug. `%s` supplies its own quotes; `'%s'` is wrong. Identifiers
  need `%i` (WP 6.2+).
- A nonce proves **intent**; a capability proves **permission**. Both are needed for a
  privileged state change. Neither substitutes for the other.
- `is_admin()` is not an authorization check. It only reports which screen is loading.
- `wp_safe_remote_get()` blocks private ranges, but did **not** block the cloud metadata
  address `169.254.169.254` until WordPress 7.1.
- `wp_localize_script()` runs `html_entity_decode()` over every scalar, silently undoing
  pre-escaping.

## The 25 classes

Ranked by severity x exploitability x prevalence over the corpus. Full detail, rules,
verified CVEs and fixes are in `kb/classes/<id>.md`.

| # | Class | What it is |
|---|-------|------------|
| 1 | WP-AUTHBYPASS | Login decision itself is wrong (OTP/social/token) |
| 2 | WP-CSRF | Nonce missing, ignored, or used as authorization |
| 3 | WP-PRIVESC | Low-privileged user reaches higher privilege |
| 4 | WP-UPLOAD | Arbitrary file upload to RCE |
| 5 | WP-POI | PHP object injection via `unserialize()` |
| 6 | WP-SQLI | Unprepared `$wpdb` queries |
| 7 | WP-LFI | User-controlled `include`/`require` |
| 8 | WP-RCE | `eval`, dynamic callables, shell execution |
| 9 | WP-FILEREAD | Arbitrary file contents returned |
| 10 | WP-XSS-S | Stored XSS (Contributor+ is the dominant case) |
| 11 | WP-SECRETS | Hardcoded credentials, weak randomness |
| 12 | WP-AUTHZ | Missing/insufficient `current_user_can()` |
| 13 | WP-DELETE | Arbitrary file deletion |
| 14 | WP-IDOR | Action authorized, target ownership never checked |
| 15 | WP-SSRF | Server-side request forgery |
| 16 | WP-INFO | Sensitive information disclosure |
| 17 | WP-AJAX | `wp_ajax_nopriv_` exposing a handler to everyone |
| 18 | WP-REDIRECT | Open redirect |
| 19 | WP-OPTIONS | Option write escalating to site takeover |
| 20 | WP-TRAVERSAL | `../` on write/move/extract |
| 21 | WP-REST | Weak or absent `permission_callback` |
| 22 | WP-XSS-R | Reflected XSS |
| 23 | WP-XSS-DOM | DOM XSS in plugin JavaScript |
| 24 | WP-XXE | XML external entities |
| 25 | WP-CSVINJ | Formula injection in exported CSV |

**Three classes share CWE-862 and must not be conflated:** WP-AUTHZ is the *sink* (the
handler body), WP-AJAX is the *registration* (`wp_ajax_nopriv_`), WP-REST is the
*registration* (`permission_callback`). A handler can be all three at once; say which.

## Confidence

Confidence is a promise about behaviour on **correct** code, enforced by
`scripts/test_rules.py`:

| level | promise |
|-------|---------|
| `high` | Does not fire on correct code. Still verify reachability before reporting. |
| `medium` | Needs context, but should not fire on correct code. |
| `low` | Deliberate worklist. Matches correct code by design; hidden unless `--all`. |

A `low` rule is not a weak rule — `CSRF-009` matches every nonce call site on purpose, and
its notes carry the triage that turns the list into findings.

## Writing new rules

If you add a rule, follow `kb/SCHEMA.md`:

- No POSIX bracket expressions (`[[:space:]]`). Python's `re` silently misparses them into
  an ordinary character set and the rule stops matching — a false negative.
- No lookaround or backreferences; ripgrep's engine cannot run them.
- Use `\s` and `[A-Za-z0-9]`, which work in both engines.
- Set `multiline: true` for shapes that span lines, so formatting cannot hide a bug.
- Then run `validate_kb.py`, `test_rules.py`, and `audit_examples.py`.
