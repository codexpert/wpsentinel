# Triage: turning a scanner hit into a finding, or dismissing it

The scanner matches a line. You decide whether that line is a vulnerability. This file is
the question to ask per class. Every question is phrased so that "I can't answer it from
the code" means **not a finding** — say so and move on.

## Universal first pass

Before the class-specific question, these dismiss most hits:

1. **Is the flagged value a literal or a constant?** A ternary between two string literals
   is not XSS. `$wpdb->prefix . SOME_CONSTANT` is not injection.
2. **Was it escaped or validated on a previous line?** This is the single most common
   false positive. Read up.
3. **Is the file even shipped?** Tests, fixtures, build output and vendored dependencies
   are not your attack surface.
4. **Can an attacker reach the function at all?** Find the `add_action`, `add_shortcode`,
   `register_rest_route`, or direct call. An unreferenced private method is not reachable.

## Privilege is the severity multiplier

Establish who can reach the code before you score it:

| Reachable by | Weight |
|---|---|
| Unauthenticated | Highest. No prerequisites. |
| Subscriber+ | High. Open registration makes this equivalent to unauthenticated. |
| Contributor+/Author+ | Real. The dominant stored-XSS case in the corpus. |
| Editor+ | Lower. Already trusted with content. |
| Admin+ | Usually **not a vulnerability** on a default install — an admin can already install a plugin and run code. Exceptions: multisite (where only Super Admin is fully trusted), and any site that restricts `unfiltered_html` or `DISALLOW_FILE_EDIT`. |

Say which of these applies in the report. A "critical SQLi" that requires an administrator
is not critical, and claiming otherwise costs you the reader's trust on the next finding.

## Per class

**WP-SQLI** — Does the untrusted value enter the string *before* `prepare()` sees it?
`prepare("... $x ...")` is a bug; `prepare("... %s ...", $x)` is correct. `'%s'` in quotes
is a bug (`%s` adds its own). Identifiers can't be bound before WP 6.2; check for `%i` or
an allowlist. `$wpdb->prefix` is trusted.

**WP-XSS-S / WP-XSS-R** — Trace to the *output*. Was `esc_html`/`esc_attr`/`esc_url`/
`wp_kses_post` applied at the echo, matching the context? Escaping at save time does not
count. For attributes, is the value quoted? For `WP-XSS-DOM`, join the source and the sink:
they are routinely 1000+ lines apart and often in different files.

**WP-CSRF** — Three distinct bugs: (a) no nonce at all; (b) a nonce checked but the
**result discarded** — a bare `wp_verify_nonce(...);` statement does nothing, because it
returns rather than dying; (c) a nonce treated as authorization. `check_admin_referer()`
and `check_ajax_referer()` die on their own, so a bare statement is correct for those.

**WP-AUTHZ** — Which capability guards the state change, and is it the right one?
`current_user_can('read')`/`'edit_posts'` on an admin action is not a guard. A role name
(`'administrator'`) is not a capability. `is_admin()` is not an authorization check.

**WP-AJAX** — Is the hook `wp_ajax_nopriv_`? Then it is reachable by the entire internet
and needs its own authorization. Note the registration may go through a loader wrapper
rather than a literal `add_action` — grep for the hook string, not the function.

**WP-REST** — Read the `permission_callback`. `__return_true`, a closure returning `true`,
an omitted callback, or a bare `is_user_logged_in()` on a privileged route are all findings.
A public read route is legitimate if it constrains what it returns — check for
`post_status => 'publish'` and an allowlist of post types.

**WP-UPLOAD** — Is the type decision made on `$_FILES[..]['type']` (attacker-controlled
header) or on real content sniffing (`wp_check_filetype_and_ext`, `finfo`)? Is the stored
filename built from the *verified* extension or from the submitted name? Is it a denylist?
Every denylist is incomplete.

**WP-LFI / WP-FILEREAD / WP-TRAVERSAL / WP-DELETE** — Same question, four sinks: does the
path come from the request, and is it constrained by an allowlist (best) or by
`realpath()` + a strict prefix check? `basename()` alone stops traversal but not
"any file in this directory". Note `path_join()` returns its second argument unchanged when
that argument is absolute.

**WP-POI** — Is `unserialize()` reachable with attacker data? The two-argument form with
`['allowed_classes' => false]` is safe. `maybe_unserialize()` on an option or meta value is
a finding only if an attacker can write that option or meta.

**WP-SSRF** — `wp_remote_get()` does no host validation; `wp_safe_remote_get()` does, but
did not block `169.254.169.254` before WP 7.1. Check for
`http_request_host_is_external` being filtered to true — that disables the check globally.

**WP-PRIVESC / WP-OPTIONS** — Does a role, capability, or meta **key** come from the
request? `update_user_meta($id, $key, $v)` with a variable `$key` lets an attacker name
`wp_capabilities`. For options, the takeover chain is usually
`users_can_register` + `default_role`, or an SMTP setting that redirects password resets.

**WP-IDOR** — The request is authorized; is the **target** checked? Look for an ownership
comparison against `get_current_user_id()` near the lookup.

**WP-SECRETS** — Is the literal an actual credential, or a cache key / prefix / example?
`md5($api_key)` used as a transient key is not a hardcoded secret. Check randomness used
for tokens: `rand`/`mt_rand`/`uniqid` are predictable; use `wp_generate_password()` or
`random_bytes()`.

**WP-XXE** — Is `LIBXML_NOENT` passed? On PHP 8 defaults are safe, so an explicit
`LIBXML_NOENT` or `LIBXML_DTDLOAD` is the bug.

**WP-AUTHBYPASS** — Ask three things: does the code establish an unforgeable fact, is that
fact bound to the identity being logged in, and is the result acted on correctly? Loose
`==` on tokens, and treating "the provider said OK" as "this user is that user", are the
recurring failures.
