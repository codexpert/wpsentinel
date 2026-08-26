# Research notes — access-control vulnerability classes

Covers `WP-ACL`, `WP-AJAX`, `WP-REST`. Scope: disclosures 2023-01-01 → 2026-08-26.

Per project scope these notes name **patterns, not products**. Plugin/theme/vendor names and
researcher credits are deliberately excluded. Where a URL contains a plugin slug it is retained
purely as a provenance pointer to the code that was read.

---

## 1. Method

**Sources used (all actually retrieved, not recalled):**

| Source | How it was queried | What it gave |
| --- | --- | --- |
| NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<term>&resultsPerPage=2000` for the terms `permission_callback`, `wp_ajax_nopriv`, `admin_init`, `admin-post.php`, `current_user_can`, `is_admin`, `__return_true`, `rest_api_init`; plus `cweId=CWE-862 / CWE-863` | CVE IDs, CVSS vectors, CWE mappings, and — critically — the **reference lists containing exact `plugins.trac.wordpress.org/browser/...#L<n>` links** |
| WordPress.org plugin SVN | `plugins.svn.wordpress.org/<slug>/tags/<vulnerable-version>/<file>` | The raw pre-patch source for every trac reference below |
| WordPress core SVN | `core.svn.wordpress.org/tags/6.8.2/...` | Ground truth on `admin-post.php`, `admin-ajax.php`, `admin.php`, `rest-api.php`, `class-wp-rest-server.php` |
| Patchstack whitepapers | `patchstack.com/whitepaper/2025-mid-year-vulnerability-report/`, `.../state-of-wordpress-security-in-2026/` | Ecosystem-level prevalence percentages |
| WordPress developer docs | `developer.wordpress.org/reference/functions/is_admin/`, `.../rest-api/extending-the-rest-api/routes-and-endpoints/`, `make.wordpress.org/core/2020/07/22/rest-api-changes-in-wordpress-5-5/` | Authoritative statements on the correct APIs |

**Not usable:** `patchstack.com/database/...` detail pages and `wordfence.com/threat-intel/...` pages
are client-rendered; plain fetches return an empty shell. The Wordfence advisory *text* is still
available because Wordfence is the CNA for most of these records, so its analysis is embedded
verbatim in the NVD description field. That is what was used.

**Verification rule applied:** every CVE ID written into a class file was located in a JSON payload
downloaded from the NVD API during this session. Candidates that could not be located were dropped
rather than guessed at.

---

## 2. Prevalence

Two different numbers get conflated in the literature; the KB should keep them separate.

- **By disclosure volume (H1 2025, Patchstack):** Broken Access Control = **10.9%** of 6,700 new
  ecosystem vulnerabilities, ranking **4th** behind XSS (34.7%), CSRF (19%) and LFI (12.6%),
  ahead of SQLi (7.2%).
- **By real-world exploitation (2025, Patchstack 2026 report):** Broken Access Control is the
  **single most exploited** category. The report's stated reason is directly relevant to this tool:
  the exploit traffic "look[s] like normal authenticated traffic with no obvious injection
  patterns", so signature-based WAFs cannot see it. A static source audit is one of the only
  practical detections.
- Ecosystem totals for context: 11,334 new WordPress vulnerabilities in 2025 (+42% YoY), 91% in
  plugins, 9% in themes.

`prevalence_rank` values assigned (1 = most common ecosystem-wide, provisional pending synthesis
across all classes): **WP-ACL 3, WP-AJAX 4, WP-REST 6.** Rationale: the Patchstack ordering puts the
access-control family 4th overall; WP-ACL is the broadest of the three sub-classes (it absorbs
`admin_init`, `admin_post_*`, `is_admin()` and ordering bugs), WP-AJAX is the highest-volume single
mechanism, and WP-REST is the fastest-growing but still the smallest of the three by count.

**Trend observed while collecting:** REST authorization findings are essentially absent from
2023–2024 NVD descriptions and become common from mid-2025 onward. This is a *reporting* shift, not
a code shift — from 2025 the CNA began naming the exact route and the exact `permission_callback`
value in the advisory text. Earlier REST bugs exist but are described too vaguely to cite
responsibly, so the WP-REST examples are 2025–2026 only.

---

## 3. Root-cause findings from WordPress core source

These are the facts that make the three classes possible. All read from core 6.8.2.

### 3.1 `admin_init` fires before authentication on two endpoints

`wp-admin/admin-post.php` bootstraps and then:

```php
require_once ABSPATH . 'wp-admin/includes/admin.php';
nocache_headers();
/** This action is documented in wp-admin/admin.php */
do_action( 'admin_init' );

$action = ! empty( $_REQUEST['action'] ) ? sanitize_text_field( $_REQUEST['action'] ) : '';
...
if ( ! is_user_logged_in() ) {
```

`do_action('admin_init')` runs **before** the `is_user_logged_in()` branch. `wp-admin/admin-ajax.php`
does the same thing and never checks login at all before firing it. By contrast
`wp-admin/admin.php` calls `auth_redirect()` at L100 and only reaches `do_action('admin_init')` at
L176 — which is why developers who only ever load their settings screen through the menu never
observe the unauthenticated path.

Net effect: **`add_action('admin_init', ...)` is an unauthenticated entry point.** `POST /wp-admin/admin-post.php`
with no cookies executes every `admin_init` callback on the site.

### 3.2 `admin_post_*` is authenticated but not authorized

Same file, after the branch: `do_action( "admin_post_{$action}" )` fires for any logged-in user.
There is no capability filtering — Subscriber is enough. `admin_post_nopriv_*` drops even that.

### 3.3 `admin-ajax.php` dispatch is a pure login test

```php
if ( is_user_logged_in() ) {
    if ( ! has_action( "wp_ajax_{$action}" ) ) { wp_die( '0', 400 ); }
    do_action( "wp_ajax_{$action}" );
} else {
    if ( ! has_action( "wp_ajax_nopriv_{$action}" ) ) { wp_die( '0', 400 ); }
    do_action( "wp_ajax_nopriv_{$action}" );
}
```

Two consequences: `wp_ajax_nopriv_*` = fully public, and `wp_ajax_*` = *any* authenticated role.
Core supplies no capability layer in either branch.

### 3.4 `is_admin()` is true on `admin-ajax.php`

`admin-ajax.php` and `admin-post.php` both `define('WP_ADMIN', true)`, so `is_admin()` returns
`true` for an unauthenticated request to either. Official docs state it plainly:

> "Does not check if the user is an administrator; use current_user_can() for checking roles and capabilities."

### 3.5 WordPress 5.5 warns about a missing `permission_callback`; it does not block

`wp-includes/rest-api.php` L122 emits `_doing_it_wrong()` when the key is absent. The dispatcher in
`wp-includes/rest-api/class-wp-rest-server.php` L1258 is the part that matters:

```php
// Check permission specified on the route.
if ( ! is_wp_error( $response ) && ! empty( $handler['permission_callback'] ) ) {
```

An absent `permission_callback` fails `! empty(...)`, so the whole permission block is **skipped**
and the route is public. The 5.5 dev note confirms the intent: a `_doing_it_wrong` notice, "a
warning, not a blocking error". Any belief that "5.5 made permission_callback mandatory" is wrong
and will cause an auditor to under-report.

Also note `false === $permission || null === $permission` → 403. A callback that returns a
truthy non-`true` value, or that returns nothing on some branch, behaves as **allow** unless it
returns exactly `false`/`null`/`WP_Error`.

---

## 4. Code read at plugins.trac / plugins.svn

19 pre-patch plugin files plus 5 core files were read in full or in the relevant region. The exact
line evidence is reproduced in each class file. Summary of what each demonstrated:

**WP-ACL**
1. `admin_post_delete_db_table` → `$wpdb->query("DROP TABLE IF EXISTS $db_table")` with no
   capability check and no nonce. Two `admin_post_*` registrations, zero guards in the file.
2. `admin_init` callback whose only guard is `isset($_GET['page']) && $_GET['page'] == $this->page_name`
   — an attacker-controlled query string used as an authorization decision.
3. `admin_init` **anonymous closure** whose only guard is `isset($_POST['permalink_structure'])`,
   then `update_option()`. Closure form defeats any "find the named callback then inspect it" tool.
4. `if(!is_admin() AND $settings['AllowFrontManage'] != 'YES') { return; }` — because `is_admin()`
   is true under `admin-ajax.php`, the operator short-circuits and the *actual* setting is never
   evaluated. Same file also contains `if (!current_user_can('manage_options') && !is_admin())`
   twice, under a comment reading "Verify admin permissions" — a clear demonstration that
   `is_admin()` is being used as an authorization primitive.
5. `Plugin_Upgrader::install()` executed at L233, `current_user_can('activate_plugins')` gate at
   L235. The check exists; it is simply two lines too late.
6. `if (!current_user_can('install_plugins')) $error = esc_html__('Sorry, ...');` with **no
   `return`** — execution falls through to `$upgrader->install()` and `activate_plugin()`, and the
   error is only emitted at the end via `wp_send_json_error()`.

**WP-AJAX**
7. `wp_ajax_nopriv_*` → handler reading `$_POST['user_id']` / `$_POST['user_email']` straight into
   `wp_update_user()`. Inputs are `sanitize_text_field()`-ed, which is the classic false comfort:
   sanitization is not authorization.
8. `wp_ajax_nopriv_*` → handler calling `wp_set_current_user()` then `wp_set_auth_cookie($user->ID, true)`
   on a user resolved from an attacker-supplied e-mail. Full authentication bypass. The registration
   is **split across three lines**, which breaks single-line regexes.
9. `wp_ajax_*`-only registration → `updateOptions()` with no `current_user_can()` and no
   `check_ajax_referer()`, writing `update_option()` directly. Textbook "authenticated but not
   authorized".
10. Handler that *does* `check_ajax_referer('..._nonce', 'nonce')` then runs four `$wpdb->delete()`
    calls with no capability check. Nonce proves intent, never permission — and this plugin's nonce
    is enqueued on every wp-admin page, including `profile.php`, which Subscribers can load.
11. **The worst case for regex detection:** a module base class exposes
    `_addAjaxAction($tag, $method)` which internally does `$this->_addAction('wp_ajax_' . $tag, ...)`.
    The file containing the vulnerable handlers registers via
    `$this->_addAjaxAction( Visualizer_Plugin::ACTION_CREATE_CHART, 'renderChartPages' )`.
    `rg 'wp_ajax' <that file>` returns **zero matches**. Verified.

**WP-REST**
12. One route array with `'permission_callback' => function () { return true; }` and, ten lines
    below, a sibling route registered with **no `permission_callback` key at all** whose callback
    performs a `$wpdb->update()` delete. Both variants, same file. `__return_true`-only regexes miss
    both.
13. ~74 `register_rest_route()` calls in a single file with no `permission_callback` on any of them,
    one of which reaches `wp_delete_user( $user_id )` in a loop over a request array.
14. `'permission_callback' => '__return_true'` on GET routes whose callbacks
    `get_option('<plugin>_settings_list')` and proxy a third-party API key's data back to the caller.
15. A route table where **four** admin-tools routes use `'__return_true'` and **five** siblings in
    the same array literal correctly use `array( $this, 'check_permission' )` →
    `current_user_can( ADMIN_ROLE )`. Inconsistency inside one array is a strong audit signal. The
    correct callback also runs its result through `apply_filters(...)`, meaning a third party can
    flip the authorization decision — a secondary finding worth flagging.
16. A `permission_callback` that is a real named method — so not `__return_true`, not missing —
    whose entire body is `if ( ! is_user_logged_in() ) { return WP_Error; } ... return true;`.
    Reused as the permission callback for state-changing reaction routes. Authentication substituted
    for authorization.

---

## 5. Regex testing

Fixtures: `/tmp/wpsentinel-fixtures/vuln.php` (patterns that must match) and
`/tmp/wpsentinel-fixtures/safe.php` (correctly-guarded equivalents that must not). Every published
regex was additionally run against the **real pre-patch plugin files** downloaded above and confirmed
to fire on the exact line cited in the CVE reference.

Engine: ripgrep 14.1.1, default Rust regex engine. **No lookahead/lookbehind is used anywhere** —
that constraint is what forces the two-stage recipe for "missing `permission_callback`", since
"a block that does *not* contain X" is not expressible as a Rust regex.

Confirmed behaviours worth carrying into the audit skill:

| Finding | Evidence |
| --- | --- |
| Anchoring on `add_action\s*\(\s*['"]hook` **misses multi-line registrations** | Real file registers `'wp_ajax_nopriv_...'` on its own line, 2 lines below `add_action(`. Same-line regex: no match. Bare-hook-string regex: match. |
| Bare hook-string regexes also catch string concatenation | `add_action( 'wp_ajax_nopriv_' . $slug . '_go', ... )` matched. |
| Bare hook-string regexes also catch commented-out code | A `// add_action('wp_ajax_nopriv_...')` line matched. Documented FP. |
| `is_admin()` guard regex flags legitimate context routing | `if ( is_admin() ) { require admin class } else { require public class }` matched. Unavoidable; needs human triage. |
| `__return_true` on a genuinely public read-only route is correct | `safe.php` control matched. Severity depends entirely on what the callback does. |
| The +20-line window for "missing `permission_callback`" produces **false negatives** when route registrations are adjacent or when commented-out route blocks sit nearby | Fixture route at L107 was missed with a fixed +20 window; bounding the window at the *next* `register_rest_route` fixed it, giving 2/2 true positives and 0 false positives on fixtures, and correctly flagging both real CVE lines. |

---

## 6. Cross-class overlaps to keep in mind during synthesis

- One real advisory in this set is simultaneously a `wp_ajax_nopriv_` exposure (WP-AJAX) and an
  `is_admin()` misuse (WP-ACL). The three classes are facets of CWE-862, not disjoint sets. An audit
  finding should be allowed to carry more than one class ID.
- Several examples are also CSRF (CWE-352) because the missing control is *both* the capability
  check and the nonce. WP-CSRF, if another agent owns it, will legitimately overlap here. The
  distinction to preserve: **a nonce proves intent, a capability proves permission**; a handler
  needs both, and having one never substitutes for the other.
- IDOR / broken object-level authorization (checking *a* capability but not *for the target object*)
  appears repeatedly. It is called out inside WP-REST and WP-AJAX rather than being split out,
  because in WordPress the fix is the same API — `current_user_can( 'edit_post', $post_id )` with
  the object ID passed as the second argument.
