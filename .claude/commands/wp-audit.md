---
description: Security-audit a WordPress plugin or theme and report verified findings
argument-hint: [path-to-plugin] [--high-only|--all]
---

Security-audit the WordPress plugin or theme at: $ARGUMENTS

If no path is given, audit the current working directory.

Use the `wp-security-audit` skill. Follow its workflow exactly:

1. Run `python3 scripts/wpscan.py <path> --json /tmp/wpaudit.json` (add any flags the user
   passed through).
2. **Triage every hit by reading the code.** The scanner reports shapes; only reading turns
   a shape into a finding. Read at least 10 lines above and 5 below each hit — most false
   positives are values that were escaped or validated on the preceding line.
3. For each hit, name the entry point that carries attacker data to the sink. If you cannot
   name one, it is not a finding — dismiss it and say why.
4. Establish who can reach it (unauthenticated / Subscriber+ / Contributor+ / Admin+). This
   drives severity more than the sink does.

Report grouped by class, most severe first. For each confirmed finding give file:line, the
entry point, who can reach it, the impact, and a fix as a diff.

List the hits you dismissed and why, briefly. That shows the work and lets the maintainer
challenge a specific call.

Do not describe the result as "clean" without stating which confidence level ran and what
was not checked.
