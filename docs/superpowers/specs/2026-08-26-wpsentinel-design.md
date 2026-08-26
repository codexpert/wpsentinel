# wpsentinel — Design Spec

**Date:** 2026-08-26
**Status:** Phase 1 in progress

## Purpose

An open-source, agent-native toolkit for auditing WordPress plugin and theme codebases
against the vulnerability classes that actually get exploited, and for proposing fixes
that use the correct WordPress APIs.

The deliverable is not a vulnerability list. It is a **reusable audit capability**: a
knowledge base, a scanner, and a Claude skill that together let any coding agent find
and fix these bugs in a codebase it has never seen.

## Non-goals

- Not a runtime scanner or WAF. It reads source code; it never touches a live site.
- Not a vulnerability disclosure service. No plugin names, vendor names, or researcher
  credits are recorded — deliberately, per project scope. We catalogue **patterns**,
  not victims. Source URLs are retained only for provenance and verification.
- Not an exploit toolkit. Vulnerable snippets illustrate flaws for remediation;
  weaponized payloads are out of scope.

## Architecture

Three layers, each usable on its own:

```
  kb/          Knowledge base   — what the bug classes are, how to spot them, how to fix them
    |
    v
  scripts/     Scanner          — Python + ripgrep, applies kb detection rules to a codebase
    |
    v
  skills/      Claude skill     — drives the scanner, triages findings, writes the fixes
```

### Layer 1 — Knowledge base (`kb/`)

- `kb/classes/<CLASS_ID>.md` — one file per vulnerability class. YAML frontmatter is
  machine-readable (detection regexes, CWE, severity, verified real-world examples);
  the body is agent-readable (root cause, vulnerable vs secure pattern, audit checklist).
  Format is fixed by `kb/SCHEMA.md`.
- `kb/reference/` — the cross-cutting material every class depends on: the untrusted
  entry-point inventory, the WordPress security API tables, the role/capability severity
  model, and annotated secure-handler templates.
- `data/` — the normalized CVE dataset (Patchstack + NVD), used to rank classes by real
  prevalence and severity rather than by intuition.

**Why class-first rather than CVE-first:** a flat dump of tens of thousands of CVEs
cannot audit anything. Roughly twenty recurring classes explain the overwhelming majority
of them, and a class carries what a CVE row does not — the root cause, the detection
signature, and the fix. The CVE dataset's job is to *rank and evidence* the classes.

### Layer 2 — Scanner (`scripts/`)

Python 3 stdlib only. No PHP, Node, pip, or ripgrep dependency — it must run anywhere a
coding agent runs. Reads detection rules from `kb/classes/*.md` frontmatter, so adding a
class requires no scanner change.

Rules are authored in Rust-regex (ripgrep) syntax and executed through Python's `re`.
Rust-regex is a strict subset of `re` for the constructs we use, so the direction is safe;
authoring against the narrower dialect keeps rules runnable under ripgrep too. We do not
shell out to `rg`: some environments (including the one this was built in) expose it only
as a shell function, so `subprocess` cannot find it and the dependency silently breaks.

Findings carry a confidence level. `high` is reported directly; `medium`/`low` are staged
for agent triage rather than dumped on the user, because the noisy classes (XSS especially)
are precisely where an unreviewed regex hit is worthless.

### Layer 3 — Skill (`skills/`)

A Claude skill that runs the scanner, reads the surrounding code for each finding to
confirm or dismiss it, and proposes a fix drawn from the secure-handler templates.

## Ranking model

Priority is not raw CVSS. It is:

```
priority = severity x exploitability x prevalence
```

where **exploitability** is dominated by required privilege. Unauthenticated RCE and
unauthenticated privilege escalation rank at the top; Admin+ SQL injection ranks low,
because an administrator already holds equivalent-or-greater power on a default install.
This is the WordPress-specific judgement that generic CVSS scoring gets wrong, and it is
encoded in `kb/reference/capability-matrix.md`.

## Data sources

| Source | Access | Role |
|---|---|---|
| Patchstack database | public HTTP | structured backbone |
| NVD REST API | public, rate-limited 5 req/30s | CVSS, CWE, references |
| Wordfence threat intel | bot-protected list; v3 API needs a free key | curated deep-dive cases |
| plugins.trac.wordpress.org | public | code-level root-cause analysis |

Harvesters are polite, resumable, and checkpointed. **Real data only** is a hard rule:
an unverifiable CVE is omitted, never invented. A fabricated example would propagate
false confidence into every audit the tool performs.

## Phasing

1. **Phase 1 — Knowledge base.** Parallel research agents build the class files and
   reference material; harvest agents build the dataset. *Checkpoint with the user.*
2. **Phase 2 — Scanner.** Rule-driven Python/ripgrep engine with fixture-based tests.
3. **Phase 3 — Skill and packaging.** Claude skill, slash commands, README, LICENSE,
   source attribution, and open-source release.

## Verification

The scanner is validated against PHP fixtures containing known-vulnerable and
known-correct code for every class. A rule that cannot flag its own fixture, or that
flags the secure variant, does not ship. Every regex is tested under ripgrep before it
enters the knowledge base — not merely written down and assumed to work.
