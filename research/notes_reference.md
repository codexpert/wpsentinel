# Research Notes — Cross-Cutting Reference Material

Provenance and verification record for the four files in `kb/reference/`:

- `kb/reference/entry-points.md`
- `kb/reference/wp-security-apis.md`
- `kb/reference/capability-matrix.md`
- `kb/reference/secure-handler-template.md`

Research date: **2026-08-26**.

---

## Environment baseline established

| Fact | Value | How verified |
|---|---|---|
| Current WordPress **stable** | **7.1** | `https://api.wordpress.org/core/version-check/1.7/` → `wordpress-7.1.zip` |
| Current **trunk** | `7.2-alpha-63347` | `wp-includes/version.php` on `master` |
| `$wp_db_version` | `61833` | same |
| Required PHP | `7.4` | same |
| Current **WPCS** | **3.4.1** (released 2026-07-27) | GitHub releases |

> ⚠️ This is itself a delta worth recording. Pre-existing assumptions treated
> WordPress 6.x as current. All version-gate statements in the reference files
> (`%i` @ 6.2, `permission_callback` notice @ 5.5, `esc_url_raw` alias @ 6.1,
> `map_meta_cap` object-ID guard @ 6.1, `esc_url` https-prepend @ 6.9) were
> re-checked against trunk rather than recalled.

## Method

Primary evidence was WordPress core source fetched from
`raw.githubusercontent.com/WordPress/WordPress/master/...` via `curl`, because
docblocks and the actual conditional logic are more authoritative than the
handbook prose (and, as recorded in §"Documentation defects" below, the handbook
is wrong in at least two places). Handbook pages were fetched with `WebFetch` for
the canonical *wording* of principles and for the officially recommended patterns.

Files read directly:

- `wp-admin/admin-ajax.php`, `wp-admin/admin-post.php`
- `wp-includes/rest-api.php`, `wp-includes/rest-api/class-wp-rest-server.php`
- `wp-includes/class-wpdb.php`
- `wp-includes/pluggable.php`
- `wp-includes/formatting.php`, `wp-includes/functions.php`, `wp-includes/compat.php`
- `wp-includes/load.php`, `wp-includes/http.php`
- `wp-includes/capabilities.php`, `wp-includes/class-wp-user.php`
- `wp-admin/includes/file.php`, `wp-admin/includes/schema.php`
- `wp-includes/user.php`, `wp-includes/ms-functions.php`
- WPCS ruleset XML: `WordPress/`, `WordPress-Extra/`, `WordPress-Core/`, `WordPress-Docs/`
- WPCS `WordPress/Sniffs/DB/PreparedSQLPlaceholdersSniff.php`

Docs fetched:

- `developer.wordpress.org/apis/security/` (+ `escaping/`, `sanitizing/`, `nonces/`)
- `developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/`
- `developer.wordpress.org/apis/wp-config-php/`
- `developer.wordpress.org/reference/functions/map_meta_cap/`
- `wordpress.org/documentation/article/roles-and-capabilities/`
- WPCS repo, releases, upgrade wikis, security advisory GHSA-3pwp-g2mj-5p3v

`unfiltered_html` logic was additionally cross-checked against the **6.8** and
**6.9** tags and is byte-identical to trunk, so those findings apply to current
stable, not only to trunk.

---

## VERIFIED against primary source (quoted in the reference files)

### Entry points

1. **`admin-ajax.php` fires `admin_init` with no auth check.** Read the file in
   order: `define( 'WP_ADMIN', true )` → `require wp-load.php` →
   `send_origin_headers()` → action presence check → `require admin.php` →
   `do_action( 'admin_init' )` → *only then* `if ( is_user_logged_in() )`.
2. **`admin-post.php` does the same** — `do_action( 'admin_init' )` precedes the
   `is_user_logged_in()` branch.
3. **`admin-ajax.php` dispatch has no nonce or capability logic.**
   `is_user_logged_in()` merely selects `wp_ajax_{action}` vs
   `wp_ajax_nopriv_{action}`; `has_action()` absence yields `wp_die( '0', 400 )`.
4. **`admin-post.php` has bare `admin_post` / `admin_post_nopriv` hooks** for the
   empty-action case — easy to miss when grepping for `admin_post_`.
5. **`is_admin()` returns the `WP_ADMIN` constant** (`wp-includes/load.php`), and
   core's own sibling docblock says *"Does not check if the user is an
   administrator; use `current_user_can()`."*

### REST

6. **`_doing_it_wrong` for a missing `permission_callback` is `@since 5.5.0`** —
   confirmed in `rest-api.php`, including the exact message text.
7. **The notice does not block anything.** `WP_REST_Server::dispatch()` guards the
   check with `! empty( $handler['permission_callback'] )`, so a missing/empty
   callback means **no check runs and the endpoint executes anonymously**.
8. **Rejection is strict:** `false === $permission || null === $permission`.

### Database

9. **`%i` is `@since 6.2.0`**, with `wpdb::has_cap( 'identifier_placeholders' )`
   for runtime detection, and `_escape_identifier_value()` doubling backticks.
10. **`esc_sql()` replaces `%` with a placeholder since 4.8.3** — core warns the
    output is not reusable elsewhere.
11. **`esc_like()` is `addcslashes( $text, '_%\\' )`** and its docblock states
    *"The output is not SQL safe."*

### Nonces

12. **`wp_verify_nonce()` returns `1`, `2`, or `false` — never `true`.**
13. **Anonymous nonces are identical site-wide.** Hash input is
    `$tick|$action|$uid|$token`; for logged-out users `$uid = 0` and the session
    token is empty.
14. **`check_admin_referer( -1 )` passes on Referer alone** —
    `! ( -1 === $action && str_starts_with( $referer, $adminurl ) )`.
15. **`check_ajax_referer()` dies with `wp_die( -1, 403 )`** when `$stop` is true.

### Uploads / filesystem / HTTP

16. **`_wp_handle_upload()` override defaults:** `test_form`, `test_size`,
    `test_type` all default `true`; `test_type => false` disables MIME validation
    entirely.
17. **`unfiltered_upload` requires `ALLOW_UNFILTERED_UPLOADS`** and, on multisite,
    Super Admin — so **nobody has it by default**.
18. **`wp_http_validate_url()`** rejects non-http(s), credentials, hosts with
    `: # ? [ ]`, and private IPv4 ranges — but is **IPv4-only** and **skips the IP
    check entirely when the host equals the site's own host**.
19. **`wp_validate_redirect()`** allows only http/https and only
    `allowed_redirect_hosts`.

### Capabilities

20. **`unfiltered_html` switch block** confirmed verbatim; `edit_css` shares the
    same case (an undocumented alias).
21. **`DISALLOW_FILE_EDIT` strips exactly 3 caps**; `DISALLOW_FILE_MODS` strips 16
    across four `wp_is_file_mod_allowed()` contexts, including
    `capability_edit_themes` — the mechanical proof that it implies
    `DISALLOW_FILE_EDIT`, as the docs claim.
22. **Subscriber has exactly `read` + `level_0`** (`populate_roles_160()`; no later
    `populate_roles_*` touches the role).
23. **Defaults:** `users_can_register => 0`, `default_role => 'subscriber'`
    (`populate_options()`).
24. **`map_meta_cap()` missing-object-ID guard is `@since 6.1.0`.**

---

## DELTAS — where current behavior differed from initial expectation

These are the traps the audit tool must encode. Each was expected one way and
verified to be another.

### D1. `esc_url_raw()` is the alias; `sanitize_url()` is canonical — **reversed**

Expected `sanitize_url()` to be the newer alias of `esc_url_raw()`. Actually:

```php
/** @since 6.1.0 Turned into an alias for sanitize_url(). */
function esc_url_raw( $url, $protocols = null ) { return sanitize_url( $url, $protocols ); }
function sanitize_url( $url, $protocols = null ) { return esc_url( $url, $protocols, 'db' ); }
```

**Impact:** fix suggestions should prefer `sanitize_url()`. Both are correct and
neither is deprecated, but naming matters for idiomatic output.

### D2. `validate_file()` does NOT reject absolute POSIX paths — **fails open**

The most security-significant delta found. Core's own docblock:

> "Note that absolute POSIX paths such as `/etc/passwd` are **not** rejected, and
> never have been. Callers that must reject them are responsible for their own
> check."

Also: `validate_file( '' )` and any non-scalar returns **`0` (OK)**. Return `2`
covers only **Windows** absolute/UNC/device paths, and that widening is
`@since 7.2.0` — **newer than current stable 7.1**.

**Impact:** any WP-LFI fix that recommends `validate_file()` as *the* control is
wrong. The load-bearing control is `realpath()` + a prefix check, or better, an
ID lookup. Encoded in `wp-security-apis.md` §6 and template (d).

### D3. `permission_callback` "required since 5.5" is documentation, not enforcement

Expected WP 5.5 to have closed the missing-`permission_callback` hole. It did not:
the `_doing_it_wrong()` notice is silent without `WP_DEBUG`, the route still
registers, and `dispatch()` skips the check entirely when the key is empty.

**Impact:** never down-rate a missing `permission_callback` on "WP 5.5+ handles
that". Encoded prominently in `entry-points.md` §5.

### D4. `permission_callback` return-value check is strict — falsy values GRANT access

`false === $permission || null === $permission` means `0`, `'0'`, `''`, `array()`,
and `0.0` all **allow** the request. So
`'permission_callback' => fn( $r ) => get_current_user_id()` grants anonymous
access, since that returns `int 0` when logged out.

Also noted: `rest_send_allow_header()` uses `true === $permission`, i.e. stricter
than dispatch. The two are inconsistent; only dispatch controls access.

**Impact:** a detection rule for non-boolean `permission_callback` bodies.

### D5. `admin_init` fires for **anonymous** users, not just logged-in ones

Expected `admin_init` to be reachable by "any logged-in user". It is worse: both
`admin-ajax.php` and `admin-post.php` call `do_action( 'admin_init' )` **before**
any `is_user_logged_in()` branch, so it fires with **no cookie at all**.

**Impact:** `admin_init` handlers must be treated as fully unauthenticated, not
subscriber-gated. Stated loudly in `entry-points.md` §4.

### D6. Site Administrators lose `unfiltered_html` on multisite

Expected multisite to restrict *installation* caps. It also strips
`unfiltered_html` from site Administrators — only Super Admins keep it.

**Impact on the severity model:** "Editor+/Admin+ stored XSS is not a
vulnerability because they have `unfiltered_html`" is **only true on single
site**. On multisite the same finding is a real escalation path. Every
`unfiltered_html`-based down-rating in `capability-matrix.md` now carries an
explicit environment caveat.

### D7. `is_super_admin()` returns true for every single-site Administrator

Expected a multisite-only network-owner check. Actually, off-multisite it is a
`$user->has_cap( 'delete_users' )` test — true for every Administrator *and any
custom role granted `delete_users`*. It also matches on **`user_login` (string),
not user ID**, so renaming a user silently revokes Super Admin. And
`get_super_admins()` falls back to the literal username `'admin'` if the
`site_admins` network option is missing.

**Impact:** `is_super_admin()` is not a reliable "is this the network owner" gate.

### D8. Not all meta caps fail closed without an object ID

Expected the WP 6.1 guard to be universal. Post/page/term/comment/meta caps do
fail closed, but **user-related meta caps have no guard**: `edit_user`,
`delete_user`, `promote_user`, `remove_user`, and the app-password caps fall
through to their **primitive** instead of `do_not_allow`.

Also: on **WP ≤ 6.0** there was no guard at all — `get_post( null )` returns the
**global `$post`**, so a missing-ID `edit_post` check silently evaluated against
whatever post was in the loop. **Severity of this pattern depends on the target's
minimum WP version.**

**Impact:** the genuinely dangerous modern bug is the *inverse* — primitive
`edit_posts` used where meta `edit_post, $id` is required (fail-open WP-IDOR).
That is now the emphasised rule.

### D9. `WordPress-Extra` does NOT include `ValidatedSanitizedInput`

Expected `WordPress-Extra` to carry all `WordPress.Security.*` sniffs. It carries
4 of 5 — `EscapeOutput`, `NonceVerification`, `SafeRedirect`, `PluginMenuSlug` —
but **omits `WordPress.Security.ValidatedSanitizedInput`** and
**`WordPress.DB.DirectDatabaseQuery`**. Those two reach the full `WordPress`
ruleset only via PHPCS auto-registration of the `WordPress/Sniffs/` directory.
`WordPress-Core` contains **zero** `Security.*` sniffs.

**Impact:** any static pre-screen configured with `WordPress-Extra` silently
misses input-sanitization findings. Recorded with the corrected ruleset config in
`wp-security-apis.md` §7.

### D10. WPCS 3.4.1 is a security release — the linter itself was RCE-able

`WordPress.WP.EnqueuedResourceParameters` could achieve **arbitrary command
execution on the scanning host** when run over untrusted PHP (GHSA-3pwp-g2mj-5p3v).
The sniff is reachable from both `WordPress` and `WordPress-Extra`.

**Impact:** wpsentinel lints third-party plugin code by definition. Any bundled or
recommended WPCS must be **≥ 3.4.1**. This is an operational requirement, not a
documentation note.

### D11. `%i` support in WPCS is version-gated on `minimum_wp_version`

`PreparedSQLPlaceholdersSniff` handles `%i` since WPCS 3.0, but raises
`UnsupportedIdentifierPlaceholder` when `minimum_wp_version < 6.2`. The current
WPCS default `minimum_wp_version` is **6.7**, so `%i` passes out of the box —
findings only appear if a lower minimum is configured.

### D12. `esc_url()` behavior changed in WP 6.9

`esc_url()` / `esc_url_raw()` / `sanitize_url()` now **prepend `https://`** when
the URL has no scheme and the first entry in `$protocols` is `https`. Not a
vulnerability, but it changes round-trip behavior for stored URLs.

### D13. `DISALLOW_FILE_MODS` does not do what it is usually assumed to do

- It does **not** block `activate_plugins` / `deactivate_plugins` — a compromised
  admin can still activate an already-installed malicious plugin.
- It **silently disables all background auto-updates** (context
  `automatic_updater`), trading one risk for another.
- Both constants are enforced **only inside `map_meta_cap()`**; plugin code that
  writes files without a capability check is unaffected. They are not a filesystem
  sandbox.
- The `file_mod_allowed` filter (WP 4.8+) lets any plugin re-enable file mods
  per-context, so the constant's presence in `wp-config.php` is not proof the
  restriction is in force.

### D14. On a default multisite network, site Admins cannot activate plugins at all

`activate_plugins` additionally requires `manage_network_plugins` unless the
network option `menu_items['plugins']` is set — and **`menu_items` is absent from
the default `populate_network_meta()` sitemeta**.

### D15. `customize` is not a stored capability on any role

It is a pure meta cap aliasing `edit_theme_options`. Scanning role arrays for it
always returns nothing — a false-negative source for role-array-based tooling.

---

## Documentation defects found in official sources

Recorded because the audit tool should trust source over prose here.

1. **`wordpress.org/documentation/article/roles-and-capabilities/` contains two
   contradictory `unfiltered_html` rows** in its capability-vs-role table — one
   marked "yes (single site)" and one plain "yes". The **"yes (single site)" row is
   correct**; the other contradicts both the page's own prose note *("In WordPress
   Multisite, only Super Admins have the `unfiltered_html` capability")* and
   `capabilities.php`.
2. **Same table lists `delete_site` as unconditionally available to
   Administrators**, but the source is multisite-only
   (`else { $caps[] = 'do_not_allow'; }`).
3. Same table has typos: `delete_others_pos` for `delete_others_posts`, and a
   nonexistent `upload_network` capability.
4. **`developer.wordpress.org/apis/security/sanitizing/`** does not mention
   `absint`, `intval`, `wp_unslash`, or the "sanitize on input / escape on output"
   phrasing — those come from the Security chapter index and from core source.

---

## Deliberately excluded

Per project scope: no plugin, theme, vendor, or researcher names appear in any of
the four reference files. No CVE examples were added — these are cross-cutting
reference documents, not vulnerability-class files, and the class files owned by
other agents carry the curated real-world cases.

## Not fully resolved / open items

- **IPv6 SSRF coverage.** `wp_http_validate_url()` was read closely enough to
  confirm the IPv4-only regex and `gethostbyname()` path, and the private-range
  check that follows. The exact set of reserved IPv4 ranges core enumerates was
  not transcribed line-by-line; the reference states the limitation
  (IPv4-only, same-host bypass, double-resolution) without claiming a specific
  range list.
- **`wp-cron.php` reachability** is stated from core behavior and the
  `DISABLE_WP_CRON` semantics, but the cron file itself was not read line-by-line
  this session. The claims made are limited to what is uncontroversial: the
  endpoint is web-accessible and unauthenticated by default, and `DISABLE_WP_CRON`
  stops only the front-end spawn.
- **XML-RPC.** `xmlrpc.php` was not read directly. Claims are limited to the
  dispatch model (anonymous dispatch; per-method authentication is the method's
  own responsibility) and the fact that `xmlrpc_enabled` gates only authenticated
  core methods. No specific method behavior is asserted.
