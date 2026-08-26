# wpsentinel

**An agent-native security audit toolkit for WordPress plugins and themes.**

wpsentinel encodes how WordPress code actually gets exploited — and how to fix it — into a
form a coding agent can act on. Point it at a plugin or theme codebase and it finds the
vulnerability classes that account for the overwhelming majority of real-world WordPress
CVEs, then proposes fixes that use the correct WordPress APIs.

**25 vulnerability classes · 214 detection rules · 190 verified CVEs · 36,972-record ranked
corpus.** Knowledge base, scanner, and agent skill are all in place.

## Quick start

```bash
python3 scripts/wpscan.py /path/to/plugin          # high + medium confidence
python3 scripts/wpscan.py /path/to/plugin --high-only
python3 scripts/wpscan.py /path/to/plugin --all    # + low-confidence worklist
python3 scripts/wpscan.py /path/to/plugin --class WP-SQLI --json report.json
```

No install step and no dependencies — Python 3.8+ and the repo.

Exit code is `1` when anything at high or medium confidence needs a decision, so it drops
into CI as a gate.

### With a coding agent

The `wp-security-audit` skill in [`skills/`](skills/wp-security-audit/SKILL.md) teaches an
agent to run the scanner and, critically, to **triage the output by reading the code**
before reporting anything. Slash commands for Claude Code live in `.claude/commands/`:

| Command | Does |
|---|---|
| `/wp-audit <path>` | Scan, triage, and report verified findings with fixes |
| `/wp-fix <file:line>` | Apply a WordPress-correct fix for one finding |
| `/wp-rule <class>` | Add or refine a detection rule, with the gates enforced |

## The scanner finds shapes, not proofs

This matters more than any other caveat. Rules are regexes over single lines (or a short
window); they cannot follow a variable across an assignment. On the first real plugin
audited, **every** high-confidence hit turned out to be safe — and in each case the safety
was established one line above the match:

```php
$table_name = $wpdb->prefix . MY_TABLE_CONSTANT;            // safe, constant
$row = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");    // rule fires here
```

Treat output as a worklist for a reviewer, never as a verdict. The skill exists to enforce
exactly that discipline.

## Why this exists

Most WordPress security tooling tells you *that* a site is running a vulnerable version of
something. Almost none of it helps a developer avoid writing the vulnerability in the first
place, or helps a reviewer catch it in a pull request.

The gap is knowledge shaped for the job. A CVE row says a plugin had SQL injection. It does
not say that the root cause was interpolating `$_GET['orderby']` into an `ORDER BY` clause,
that `$wpdb->prepare()` cannot parameterize an identifier, that the fix is an allowlist or
the `%i` placeholder added in WordPress 6.2, or which line to change. wpsentinel captures
that layer.

## Design principles

**Classes, not CVEs.** Roughly two dozen recurring classes explain the bulk of WordPress
vulnerabilities. Each class file carries a root cause, a detection signature, a secure fix
pattern, and verified real-world examples. A flat CVE dump cannot audit anything; a class
can.

**Privilege drives priority.** Priority is `severity × exploitability × prevalence`, and
exploitability is dominated by the privilege an attacker needs. Unauthenticated remote code
execution outranks Admin+ SQL injection by a wide margin — an administrator can already
install plugins, so the flaw grants nothing new. Generic CVSS scoring misses this, and
WordPress auditing lives or dies by it.

**Patterns, not victims.** No plugin names, vendor names, or researcher credits are
recorded. We catalogue the *pattern*. Source links are preserved for verification and
because the data license requires them — follow one to see the researcher's credit in full.

**Real data only.** Every example is a CVE actually retrieved and verified from a public
database. An unverifiable example is omitted rather than invented, because a fabricated
example would propagate false confidence into every audit the tool performs.

**Regexes are tested, not asserted.** Every detection rule is run against PHP fixtures
containing both vulnerable and correct code before it enters the knowledge base. A rule
that cannot flag its own fixture, or that flags the secure variant, does not ship.

## Repository layout

```
kb/
  SCHEMA.md            Format contract for class files
  classes/             One file per vulnerability class (machine-readable frontmatter)
  reference/           Entry points, WP security APIs, capability matrix, secure templates
data/
  raw/                 Harvested source datasets (NDJSON)
scripts/               Harvesters, scanner, and the four QA gates (Python 3 stdlib)
skills/                Agent skill: workflow, triage guide, fix patterns
tests/fixtures/        safe.php and vulnerable.php - the two-directional test corpus
.claude/commands/      Slash commands for Claude Code
docs/                  Design spec
```

## Requirements

Python 3.8 or newer. Nothing else — no PHP, no Node, no pip installs, no ripgrep.

Detection rules are authored in Rust-regex (ripgrep) syntax, which is a strict subset of
Python's `re`, so rules stay portable if you prefer to run them through ripgrep yourself.
The bundled scanner uses `re` directly: several environments expose `rg` only as a shell
function rather than a binary on `PATH`, so shelling out to it is not reliably portable —
and portability is the whole point of a toolkit meant to run wherever an agent runs.

## Data sources and licensing

wpsentinel derives from public vulnerability databases whose licenses permit redistribution
**with attribution**. Those obligations are real and are documented in
[ATTRIBUTION.md](ATTRIBUTION.md) — read it before redistributing.

## Scope

This is a defensive tool. It documents vulnerable and secure patterns so they can be found
and fixed. It does not ship exploit payloads, and it is intended for auditing code you own
or are authorized to review.

## License

Code: MIT (see [LICENSE](LICENSE)). Vulnerability data: see [ATTRIBUTION.md](ATTRIBUTION.md).
