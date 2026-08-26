---
description: Apply a WordPress-correct fix for a specific vulnerability finding
argument-hint: [file:line or class id, e.g. src/Admin.php:212 or WP-SQLI]
---

Fix the WordPress security issue at: $ARGUMENTS

Use the `wp-security-audit` skill, and read `references/fixes.md` for the class's pattern.

Before editing:

1. Read the code and confirm the vulnerability is real — that attacker-controlled data
   genuinely reaches the sink. If it does not, say so and change nothing.
2. Open `kb/classes/<CLASS>.md` and read the Secure pattern section and the rule's
   `false_positive_notes`.

When fixing:

- Use WordPress's own APIs rather than a hand-rolled check.
- Escape at output, in the right context; sanitising at input is not a substitute.
- If the handler is missing both a capability check and a nonce check, add both — they are
  different obligations and neither substitutes for the other.
- Preserve the surrounding code's style, naming and indentation.
- Do not widen the change beyond the fix.

Afterwards, re-run the scanner on the file and confirm the finding is gone and no new one
appeared.
