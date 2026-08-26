---
class_id: WP-AUTHZ
title: Missing or Insufficient Capability Check on a Privileged Handler
cwe: [CWE-862, CWE-863, CWE-285]
owasp: A01:2021-Broken Access Control
severity_typical: medium
auth_required_typical: subscriber+
prevalence_rank: 2
detection:
  - id: AUTHZ-001
    description: A role name passed to current_user_can() where a capability belongs
    regex: 'current_user_can\s*\(\s*[''"](administrator|editor|author|contributor|subscriber|super_?admin)[''"]'
    confidence: high
    false_positive_notes: >-
      Almost never intentional. It happens to work on a default install because the
      wp_capabilities usermeta array literally contains administrator => true, so that key
      lands in $user->allcaps. It breaks the moment a membership, LMS or e-commerce plugin
      renames the role, clones it, or grants the same powers to a different role — and it is
      silently false for a Super Admin on multisite who holds no site role at all. WPCS flags
      this as WordPress.WP.Capabilities RoleFound. Fix by naming the capability the action
      actually needs.
  - id: AUTHZ-002
    description: Meta capability checked with no object ID — fail-closed on WP 6.1+, wrong-object below
    regex: 'current_user_can\s*\(\s*[''"](edit_post|delete_post|read_post|edit_page|delete_page|read_page|publish_post|edit_comment|edit_term|delete_term|assign_term|edit_user|delete_user|promote_user|remove_user)[''"]\s*\)'
    confidence: high
    false_positive_notes: >-
      The closing paren immediately after the string is the whole signal, so this does not
      match the correct current_user_can( 'edit_post', $post_id ) form. Two different bugs
      share the shape. For post/term/comment caps, WP >= 6.1 appends do_not_allow and the
      check returns false for everyone including Super Admins — a broken feature, not an
      escalation, and invisible in production because _doing_it_wrong() is silent without
      WP_DEBUG. For the USER caps (edit_user, delete_user, promote_user, remove_user) there
      is no such guard: they fall through to the primitive (edit_users, delete_users,
      promote_users, remove_users), which silently drops the per-object protections — that
      variant IS an escalation. Read capability-matrix.md §4 before rating.
  - id: AUTHZ-003
    description: Role membership or legacy user level tested instead of a capability
    regex: '(in_array\s*\(\s*[''"](administrator|editor|author|contributor|subscriber)[''"]|->\s*user_level|[''"]level_(10|[0-9])[''"])'
    confidence: high
    false_positive_notes: >-
      Matches role names used in non-authorization contexts too — a label array, a
      get_users( array( 'role__in' => ... ) ) query, a settings dropdown. Read the line. It is
      a finding when the result gates an action. user_level and level_N have been deprecated
      since WP 3.0 and are not maintained; a plugin that adds capabilities to a role does not
      change its level, so a level check is stale by construction.
  - id: AUTHZ-004
    description: A non-authorization predicate used as the guard on a state change
    regex: '\bif\s*\(\s*[!\s]*(is_admin|is_user_logged_in|wp_doing_ajax|is_user_admin|is_network_admin)\s*\(\s*\)|\bif\s*\(\s*defined\s*\(\s*[''"]DOING_AJAX[''"]'
    confidence: medium
    false_positive_notes: >-
      is_admin() is legitimate for deciding WHAT TO LOAD ("only register this menu on admin
      screens") and that use is common, so expect benign hits. It is never an authorization
      check: admin-ajax.php and admin-post.php both define WP_ADMIN = true before any login
      check, so is_admin() is true for a fully anonymous request (see entry-points.md §1).
      is_user_logged_in() is a real but very weak gate — it admits every Subscriber, and on a
      site with open registration or WooCommerce customers that is effectively the whole
      internet plus one signup. Rule: if the guarded block writes anything, this is a finding.
  - id: AUTHZ-005
    description: Capability supplied as a variable, filter, option or constant rather than a literal
    regex: 'current_user_can\s*\(\s*(\$|apply_filters|get_option|constant)'
    confidence: medium
    false_positive_notes: >-
      Legitimate in generic framework code that receives the capability from a caller which
      hard-codes it. It becomes a finding when the value is reachable from configuration —
      $this->capability defaulting to 'read', a settings field, or an apply_filters() hook any
      other plugin can lower. Trace the default. A default of 'read', 'exist' or 'level_0'
      means every logged-in user passes.
  - id: AUTHZ-006
    description: A site-takeover-critical option written from plugin code
    regex: '\b(update_option|add_option|update_site_option|update_network_option)\s*\(\s*[''"](default_role|users_can_register|siteurl|home|admin_email|wp_user_roles|active_plugins|template|stylesheet|new_admin_email)[''"]'
    confidence: high
    false_positive_notes: >-
      A plugin has almost no legitimate reason to write these. default_role plus
      users_can_register is the anonymous-administrator pair (capability-matrix.md §6.8);
      wp_user_roles rewrites the whole role table; siteurl/home enable a persistent redirect
      and script-source hijack; admin_email/new_admin_email redirect password recovery. If any
      of these is written, the handler needs manage_options AND a nonce, with no exceptions.
  - id: AUTHZ-007
    description: Option or metadata write whose KEY is not a literal — an arbitrary-write primitive
    regex: '(\b(update_option|add_option|delete_option|update_site_option|update_network_option)\s*\(\s*[^''"\s)]|\b(update_user_meta|add_user_meta|delete_user_meta|update_post_meta|update_term_meta)\s*\(\s*[^,]+,\s*\$)'
    confidence: medium
    false_positive_notes: >-
      High volume: a computed key like $this->prefix . '_settings' matches and is usually
      fine. The question to answer for each hit is whether the key can be influenced by the
      request. If it can, the handler is an arbitrary-option-write or arbitrary-usermeta-write
      primitive, and per capability-matrix.md §6.8 that is Critical regardless of what the
      developer thought they were storing — because default_role, users_can_register and
      wp_capabilities are reachable through it.
  - id: AUTHZ-008
    description: State-changing sink fed directly by a request superglobal on the same statement
    regex: '\b(update_option|add_option|delete_option|update_user_meta|add_user_meta|delete_user_meta|update_post_meta|wp_insert_user|wp_update_user|wp_delete_user|wp_insert_post|wp_update_post|wp_delete_post|wp_set_password|wp_mail)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE|FILES)|->\s*(insert|update|delete|replace|query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: medium
    false_positive_notes: >-
      This is the closest a line-oriented rule gets to the actual bug, because a write driven
      straight off a superglobal is a request handler by definition — so the enclosing
      function is exactly the one that must contain a capability check. A hit is NOT itself a
      finding: read upward to the top of the function and to the add_action() that registers
      it. Misses every multi-line case ($x = $_POST['x']; ... update_option( 'k', $x );),
      which is the majority; pair it with AUTHZ-007 and AUTHZ-009.
  - id: AUTHZ-009
    description: Privilege-granting sinks — the worklist that must never be reachable without a capability check
    regex: '(->\s*(set_role|add_role|add_cap|remove_cap|remove_role)\s*\(|\b(wp_insert_user|wp_create_user|wp_update_user|grant_super_admin|add_user_to_blog|wp_set_auth_cookie|wp_set_current_user|wp_set_password)\s*\()'
    confidence: low
    false_positive_notes: >-
      Deliberately a worklist, not a verdict. Registration plugins call wp_insert_user()
      legitimately; membership plugins call set_role() legitimately. The rule's value is
      completeness: every one of these sinks grants privilege, so for each hit the auditor
      must answer three questions — which hook reaches this function, does that function call
      current_user_can() before the sink, and does the failure branch actually terminate.
      wp_set_auth_cookie() and wp_set_current_user() deserve special attention: they issue or
      assume an identity, so reaching either from a request-controlled user ID is
      authentication bypass, not merely missing authorization.
fix_apis:
  - current_user_can()
  - current_user_can( $meta_cap, $object_id )
  - user_can()
  - map_meta_cap()
  - wp_die()
  - wp_send_json_error()
  - check_admin_referer()
  - check_ajax_referer()
  - rest_authorization_required_code()
examples:
  - cve: CVE-2025-5486
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A settings handler registered on admin_init read $_POST and wrote plugin options with no capability check and no nonce, letting an anonymous request redirect all outgoing site mail to an attacker address.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-5486
    code_ref: https://plugins.trac.wordpress.org/browser/wp-email-debug/tags/1.0/hooks.php#L41
    root_cause: admin_init fires unauthenticated via admin-post.php and admin-ajax.php; the handler contained neither current_user_can() nor a nonce check.
  - cve: CVE-2025-5304
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: An AJAX handler verified a nonce, then copied every administrator capability onto a user ID taken from the request, with no capability check anywhere in the function.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-5304
    code_ref: https://plugins.trac.wordpress.org/browser/project-notebooks/tags/1.1.3/includes/structure/admin/pto_admin_settings.php#L233
    root_cause: A nonce was mistaken for authorization; wp_verify_nonce() answers "did this request come from our UI", never "may this user do this".
  - cve: CVE-2025-2266
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: Two option-writing AJAX handlers sat in the same 49-line file, both registered for logged-out users; the first checked manage_options and the second checked nothing, giving anonymous callers an arbitrary-option write.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2266
    code_ref: https://plugins.trac.wordpress.org/browser/checkout-mestres-wp/tags/8.7.5/backend/core/base/ajax.php#L31
    root_cause: The capability check was omitted on one of two sibling handlers; the option name came from the request, making it an arbitrary-option-write primitive.
  - cve: CVE-2026-19598
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: An AJAX router expressed every guard — method allowlist, login test, nonce and capability gate — as a call to a helper that, on one request-selectable error mode, only wrote to the PHP error log and returned, so execution continued past each failed check.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-19598
    code_ref: https://plugins.trac.wordpress.org/browser/pods/tags/3.3.9/includes/general.php#L400
    root_cause: The capability check was present and correct but did not terminate the request; a guard that returns instead of dying is not a guard.
  - cve: CVE-2026-4119
    year: 2026
    severity: 9.1
    auth: subscriber+
    summary: Table-creation and table-deletion handlers were registered on admin_post_ hooks with no capability check and no nonce, so any account on the site could drop an arbitrary database table.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4119
    code_ref: https://plugins.trac.wordpress.org/browser/create-db-tables/tags/1.2.1/create-db-tables.php#L368
    root_cause: admin_post_{action} authenticates but does not authorize; the menu page's capability argument protects only the screen, not the form target.
  - cve: CVE-2026-18316
    year: 2026
    severity: 9.1
    auth: subscriber+
    summary: An import handler registered on both the logged-in and logged-out AJAX hooks verified a nonce that was emitted into every admin page via wp_localize_script, and performed no capability check at all.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-18316
    code_ref: https://plugins.trac.wordpress.org/browser/solace-extra/tags/1.6.0/includes/class-solace-extra.php#L336
    root_cause: A nonce that every logged-in user can read is not an access control; the missing control was current_user_can().
  - cve: CVE-2025-4672
    year: 2025
    severity: 8.8
    auth: contributor+
    summary: A REST route that writes arbitrary user meta for an arbitrary user ID was gated on edit_posts, a primitive capability held by Contributors, allowing any Contributor to overwrite their own wp_capabilities and become an administrator.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-4672
    code_ref: https://plugins.trac.wordpress.org/browser/offsprout-page-builder/tags/2.15.2/api/class-offsprout-api-extensions.php#L514
    root_cause: The capability check existed but did not match the impact — a user-meta write needs edit_users, not edit_posts, and needs an ownership check on the target ID.
  - cve: CVE-2026-4003
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A public form-save handler blocked logged-out callers only when the submitted user ID was empty; supplying a non-empty user ID skipped the branch entirely and reached update_user_meta() for any account.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4003
    code_ref: https://plugins.trac.wordpress.org/browser/userspn/tags/1.0.31/includes/class-userspn-ajax-nopriv.php#L190
    root_cause: The authorization condition was tangled into an input-validation condition, so attacker-controlled input selected which branch ran and therefore whether the check applied.
  - cve: CVE-2024-3750
    year: 2024
    severity: 8.8
    auth: subscriber+
    summary: A chart data-source handler reachable by any logged-in user ran caller-supplied SQL without a capability check, giving Subscribers arbitrary read and write against the database.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-3750
    root_cause: The handler was registered on the logged-in AJAX hook only, and the developer treated "logged in" as the authorization boundary for an administrative feature.
---

## What it is

A request reaches a handler that performs a privileged action — writing an option, granting
a role, deleting a row, reading someone else's data — and nothing on the path asked whether
*this* user is allowed to do it. The handler may be perfectly written in every other
respect: input sanitised, output escaped, SQL prepared, nonce verified. The one call that is
missing is `current_user_can()`.

This is the **sink side** of broken access control. The two sibling classes cover the
*registration* side of the same CWE: **WP-AJAX** for `wp_ajax_nopriv_` handlers exposed to
the whole internet, and **WP-REST** for routes whose `permission_callback` does not
authorise. Those classes are about *who can reach the function*. This class is about *what
the function fails to check once reached*, and it applies identically to a handler reached
by AJAX, by `admin_post`, by `admin_init`, by a shortcode, by `template_redirect`, or by a
REST route that has a perfectly good `permission_callback` on a *different* route in the
same file.

At 911 records it is the second-largest class in the corpus. Across the 2,718 records
carrying CWE-862, CWE-863 or CWE-285 the mean CVSS is 6.12 and the median 5.3, but the
distribution is bimodal: about 59 % are reachable by any logged-in account and cluster
around 4.3, while about 40 % are unauthenticated and cluster at 8.8–9.8. The class itself
has **no intrinsic severity** — rate it as the action it exposes, at the tier that reaches
it (capability-matrix.md §6.7).

## Why it happens in WordPress

- **Hooks dispatch; they do not authorise.** `add_action()` is a routing table. Every hook
  in `entry-points.md` will invoke plugin code for an anonymous attacker. Nothing in core
  checks a capability on the plugin's behalf, ever.
- **`is_admin()` is the single most damaging misconception.** It returns the `WP_ADMIN`
  constant, which `admin-ajax.php` and `admin-post.php` both define as `true` *before* any
  login check. `is_admin()` is therefore `true` for a completely anonymous
  `POST /wp-admin/admin-ajax.php`. Core's own docblock says it: it does not check whether
  the user is an administrator. It answers *where am I*, not *who are you*.
- **`admin_init` is not an administrator hook.** It fires from `wp-admin/admin.php` (behind
  `auth_redirect()`), and from `admin-ajax.php` and `admin-post.php` (behind **nothing**).
  A settings handler on `admin_init` is an unauthenticated endpoint. This is CVE-2025-5486
  exactly.
- **A capability on `add_menu_page()` protects the screen, not the handler.** It gates
  `/wp-admin/admin.php?page={slug}`. If the same code also processes `$_POST` from
  `admin_init`, or the form posts to `admin-post.php`, that second path has no capability
  anywhere. CVE-2026-4119 is this shape.
- **Nonces get mistaken for authorization.** `wp_verify_nonce()` answers "did this request
  originate from our UI, in this user's session". It says nothing about privilege. Worse, a
  nonce printed by `wp_localize_script()` on an unrestricted `admin_enqueue_scripts` or
  `wp_enqueue_scripts` hook is readable by every logged-in user — or by every visitor. Two
  of the case studies below turn on exactly this.
- **`edit_posts` is a primitive with no ownership logic.** Contributor and up hold it. It
  answers "may this user edit posts in general", never "may this user edit *this* object".
  Using it to gate an operation on a request-supplied ID is the canonical fail-open
  (capability-matrix.md §4).
- **Guards that do not terminate.** `return;` inside a `foreach`, inside a filter callback,
  or inside a helper that the caller ignores, leaves execution running. CVE-2026-19598 is a
  whole plugin's authorization layer defeated this way.
- **Copy-paste asymmetry.** Handlers are written by copying the one above and editing it.
  The check is present on three of four siblings. Grep counts (`current_user_can` vs
  entry-point count) find this; reading one handler does not.

## Vulnerable pattern

```php
// wp-content/plugins/example/hooks.php
//
// The developer's mental model: "this is the settings screen, only admins see it."
// The actual reachability: admin_init fires on admin-post.php and admin-ajax.php with
// no authentication in front of it, so this runs for an anonymous POST.
add_action( 'admin_menu', 'example_settings_menu' );
add_action( 'admin_init', 'example_handle_settings' );

function example_settings_menu() {
    // This capability protects the SCREEN. It does not protect the handler below.
    add_options_page( 'Example', 'Example', 'manage_options', 'example', 'example_page' );
}

function example_handle_settings() {
    if ( isset( $_POST['example_submit'] ) ) {          // no capability, no nonce
        update_option( 'example_enabled', true );
        update_option( 'example_email', $_POST['example_sendto'] );
    }
}
```

```
POST /wp-admin/admin-post.php?action=anything_registered
Cookie: (none)

example_submit=1&example_sendto=attacker@example.com
```

The second family is worse, because it looks defended:

```php
add_action( 'wp_ajax_example_grant',        'example_grant' );
add_action( 'wp_ajax_nopriv_example_grant', 'example_grant' );

function example_grant() {
    // A nonce IS checked. There is still no authorization.
    if ( ! wp_verify_nonce( $_POST['nonce'], 'example-nonce' ) ) {
        wp_die( 'Busted!' );
    }

    $user = get_user_by( 'id', (int) $_POST['user_id'] );   // any user, chosen by attacker
    $role = get_role( 'administrator' );
    foreach ( $role->capabilities as $cap => $_ ) {
        $user->add_cap( $cap );                             // ...including this one
    }
}
```

…and the nonce is published to everyone:

```php
wp_localize_script( 'example-js', 'exampleVars', array(
    'ajaxurl' => admin_url( 'admin-ajax.php' ),
    'nonce'   => wp_create_nonce( 'example-nonce' ),   // readable by every visitor
) );
```

The third family is the one that survives review, because `current_user_can()` is right
there:

```php
function example_delete() {
    // edit_posts is a PRIMITIVE. Contributor holds it. It carries no ownership check.
    if ( current_user_can( 'edit_posts' ) ) {
        wp_delete_post( (int) $_POST['post_id'], true );   // anyone's post, published or not
    }
}
```

## Secure pattern

The correct shape is four ordered steps, and the order matters: **authorise, then verify
intent, then validate input, then act.**

```php
add_action( 'wp_ajax_example_grant', 'example_grant' );   // note: NO _nopriv_ twin

function example_grant() {
    // 1. AUTHORIZE. Name the capability the action actually needs, not the one the
    //    current UI happens to be behind. Granting capabilities needs promote_users.
    if ( ! current_user_can( 'promote_users' ) ) {
        // The failure branch MUST terminate. wp_send_json_* call wp_die() internally.
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    // 2. VERIFY INTENT. check_ajax_referer() dies on failure by default; the explicit
    //    third argument is there so a future edit cannot silently turn it into a no-op.
    check_ajax_referer( 'example-grant', 'nonce', true );

    // 3. VALIDATE INPUT, including the OBJECT the caller named.
    $user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
    $user    = $user_id ? get_userdata( $user_id ) : false;
    if ( ! $user ) {
        wp_send_json_error( array( 'message' => 'unknown user' ), 400 );
    }

    // 4. RE-AUTHORIZE AGAINST THE OBJECT. The primitive above said "may grant roles at
    //    all"; this says "may act on THIS user". Note the object ID argument.
    if ( ! current_user_can( 'edit_user', $user_id ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    $user->add_role( 'editor' );
    wp_send_json_success();
}
```

For a post-scoped operation, the meta capability with the object ID is the entire fix:

```php
$post_id = absint( $_POST['post_id'] );

// WRONG: primitive, no ownership, no status, no post-type logic. Contributor passes.
if ( current_user_can( 'edit_posts' ) ) { ... }

// RIGHT: map_meta_cap() resolves author vs. others, published vs. draft, and post type.
if ( ! current_user_can( 'delete_post', $post_id ) ) {
    wp_die( '', 403 );
}
wp_delete_post( $post_id, true );
```

Three rules that prevent most of this class:

1. **Every handler authorises itself.** Do not rely on the capability passed to
   `add_menu_page()`, on the hook's name, on `is_admin()`, or on a check performed by the
   function that *usually* calls this one. A handler is reachable by every path that can
   reach any of its hooks.
2. **The failure branch terminates.** `wp_die()`, `wp_send_json_error()`, or a `return`
   from the *outermost* handler. A `return` inside a loop or a helper is not a guard. If
   authorization is centralised in a helper, that helper must `exit`, not report.
3. **Choose the capability from the impact, not from the UI.** Use the
   "Choosing the right capability for a handler" table in capability-matrix.md §2. If the
   action writes a site-wide option, it is `manage_options`, even if the button lives on a
   page that Editors can see.

## Real-world case studies

### `admin_init` is an unauthenticated hook (CVE-2025-5486, 9.8, unauthenticated)

The whole plugin is five hooks and four functions:

```php
add_action('admin_menu', 'WPMDBUG_settings_menu');
add_action('admin_init', 'WPMDBUG_handle_settings');
add_action('admin_notices', 'WPMDBUG_admin_notices');
```
`https://plugins.trac.wordpress.org/browser/wp-email-debug/tags/1.0/hooks.php#L7`

`WPMDBUG_settings_menu()` registers the screen with `'manage_options'`, which is correct and
which is what a reviewer sees first. The handler does not inherit it:

```php
function WPMDBUG_handle_settings() {
  global $WPMDBUGerror;
  if (isset($_POST['wpmdbug_submit'])) {
    if (isset($_POST['wpmdbug_enabled'])) {
      update_option('WPMDBUG_enabled', TRUE);
    ...
      update_option('WPMDBUG_email', $newEmail);
```
`https://plugins.trac.wordpress.org/browser/wp-email-debug/tags/1.0/hooks.php#L41`

**Root cause at that line:** `admin_init` fires from `admin-ajax.php` and `admin-post.php`
before either file inspects `is_user_logged_in()`. An anonymous `POST` to
`/wp-admin/admin-post.php?action=<any registered action>` runs this function. The plugin
redirects all `wp_mail()` output to `WPMDBUG_email`; set it to an attacker address, trigger
an administrator password reset, and the reset link arrives in the attacker's inbox. Two
option writes, no shell, full takeover.

Note what a naive `current_user_can` count would say about this plugin: it appears once, on
line 34, in `add_options_page()`. The count is non-zero. The handler is still naked. **Count
capability checks per *entry point*, never per file.**

### A nonce is not an authorization check (CVE-2025-5304, 9.8, unauthenticated)

Ten registrations, five actions, every one of them exposed to logged-out callers:

```php
/* remove user */
add_action('wp_ajax_nopriv_wpnb_pto_users_deletd', array($this, 'wpnb_pto_users_deletd'));
add_action('wp_ajax_wpnb_pto_users_deletd', array($this, 'wpnb_pto_users_deletd'));

/* add new users */
add_action('wp_ajax_nopriv_wpnb_pto_new_users_add', array($this, 'wpnb_pto_new_users_add'));
add_action('wp_ajax_wpnb_pto_new_users_add', array($this, 'wpnb_pto_new_users_add'));
```
`https://plugins.trac.wordpress.org/browser/project-notebooks/tags/1.1.3/includes/structure/admin/pto_admin_settings.php#L32`

The handler *does* check something — and then hands out administrator capabilities:

```php
public function wpnb_pto_new_users_add(){
    if (!wp_verify_nonce($_POST['nonce'], 'ajax-nonce')) {
        die('Busted!');
    }
    ...
    $user_ids = explode(",", $ids);
    $user_type = sanitize_text_field($_POST['user_type']);
    if ($user_type == 2) {
        foreach ($user_ids as $users) {
            $user = get_user_by('id', $users);
            $user->add_role('project_plugin_administrators'); // admin rol
            $role = get_role('administrator');
            foreach ($role->capabilities as $key => $caps) {
                $user->add_cap($key); // admin cpability add
            }
```
`https://plugins.trac.wordpress.org/browser/project-notebooks/tags/1.1.3/includes/structure/admin/pto_admin_settings.php#L233`

**Root cause at that line:** the *only* gate is `wp_verify_nonce`, which answers a question
about request provenance, not about privilege. The user IDs come from `$_POST['ids']`. The
loop copies **every** capability of the administrator role onto them — including
`edit_plugins`, `install_plugins` and `promote_users`. There is no `current_user_can()`
anywhere in the function.

This is the highest-value shape to grep for in the whole class: **a handler that verifies a
nonce and nothing else.** A reviewer's eye reads "security check present" and moves on.
Cross-check every `wp_verify_nonce` / `check_ajax_referer` against a `current_user_can` in
the same function body.

### The check exists on the handler above (CVE-2025-2266, 9.8, unauthenticated)

The entire file is 49 lines and contains two handlers. Both are registered for logged-out
callers. The first is guarded:

```php
add_action( 'wp_ajax_cwmpChangeFuncionalidade', 'cwmpChangeFuncionalidade' );
add_action( 'wp_ajax_nopriv_cwmpChangeFuncionalidade', 'cwmpChangeFuncionalidade' );
function cwmpChangeFuncionalidade(){
	if(current_user_can('manage_options')){
```

The second, twenty-five lines later, is not:

```php
add_action( 'wp_ajax_cwmpUpdateOptions', 'cwmpUpdateOptions' );
add_action( 'wp_ajax_nopriv_cwmpUpdateOptions', 'cwmpUpdateOptions' );
function cwmpUpdateOptions() {
    if (isset($_POST['data'])) {
        parse_str($_POST['data'], $parsed_data);
        ...
            update_option(sanitize_text_field($campo), $safe_value);
```
`https://plugins.trac.wordpress.org/browser/checkout-mestres-wp/tags/8.7.5/backend/core/base/ajax.php#L31`

**Root cause at that line:** the option *name* is `$campo`, a key from `parse_str()` over a
request string. `sanitize_text_field()` sanitises it as text; it does not restrict it to the
plugin's own namespace. That makes this an **arbitrary-option write** for an anonymous
caller — set `default_role=administrator`, set `users_can_register=1`, register, log in as
an administrator (capability-matrix.md §6.8).

Three lessons. First, this is precisely why WP-AJAX (registration) and WP-AUTHZ (sink) are
separate classes: a `wp_ajax_nopriv_` grep flags **both** functions here and cannot tell
them apart; only reading the body distinguishes the safe one from the fatal one. Second,
`sanitize_*` on an option *key* is not an authorization control and is not a namespace
control. Third, when you find one handler with a check, do not generalise — enumerate the
siblings and check each.

### A guard that does not terminate (CVE-2026-19598, 9.8, unauthenticated)

The AJAX router is written carefully. It has a method allowlist, a login test, a nonce test
and a capability gate:

```php
if ( ! isset( $params->method ) || ! isset( $methods[ $params->method ] ) ) {
    pods_error( __( 'Invalid AJAX request', 'pods' ), $this );
}
...
if ( true !== $method->custom_nonce
     && ( ! is_user_logged_in()
          || ! isset( $params->_wpnonce )
          || false === wp_verify_nonce( $params->_wpnonce, 'pods-' . $params->method ) ) ) {
    pods_error( __( 'Unauthorized request', 'pods' ), $this );
}
...
if ( ! empty( $method->priv ) && ! pods_is_admin( [ 'pods' ] ) ) {
    if ( true !== $method->priv && pods_is_admin( $method->priv ) ) {
        // They have access to the custom priv.
    } else {
        pods_error( __( 'Access denied', 'pods' ), $this );
    }
}
```

Every guard delegates termination to `pods_error()`. In one error mode, selected by a
request parameter, that function does this:

```php
} elseif ( 'json' === $error_mode ) {
    $meta_box_loader_compat = (int) pods_v( 'meta-box-loader', 'request', 0 );

    // Check if this is a back-compat meta box save request.
    if ( 1 === $meta_box_loader_compat ) {
        // Do not block this page.
        error_log( 'Pods Meta Save Error:' . $error );
    } else {
        wp_send_json( [ 'message' => $error ], 500 );
    }
}
...
return false;
```
`https://plugins.trac.wordpress.org/browser/pods/tags/3.3.9/includes/general.php#L400`

**Root cause at that line:** with `meta-box-loader=1` in the request, `pods_error()` writes
a log line and **returns `false`**. None of the four call sites checks the return value, so
control falls straight through to the dispatch below — past the allowlist, past the login
test, past the nonce, past the capability check. NVD classifies this as CWE-863 (incorrect
authorization) rather than CWE-862 (missing authorization), and the distinction is exactly
the point: the checks are *there*.

**Detection consequence:** presence of `current_user_can()` proves nothing. For every check
you find, follow the failure path and confirm it reaches `wp_die()`, `exit`, `die`, a
`wp_send_json_*` (which calls `wp_die()` internally), or a `return` from the outermost
handler. A guard whose failure branch is a function call is only as good as that function.

### The menu capability does not protect the form target (CVE-2026-4119, 9.1, any logged-in user)

```php
function cdbt_delete_db_table() {

    $db_table = sanitize_text_field($_POST['db_table']);

	if($db_table != null) {

        global $wpdb;

        $delete_table_statement = $wpdb->query("DROP TABLE IF EXISTS $db_table");
```
`https://plugins.trac.wordpress.org/browser/create-db-tables/tags/1.2.1/create-db-tables.php#L368`

and the registration, at the bottom of the same file:

```php
// Create Database Table
add_action( 'admin_post_add_table', 'cdbt_create_new_table' );

// Delete Database Table
add_action( 'admin_post_delete_db_table', 'cdbt_delete_db_table' );
```
`https://plugins.trac.wordpress.org/browser/create-db-tables/tags/1.2.1/create-db-tables.php#L405`

**Root cause at that line:** `add_action('admin_menu', 'cdbt_create_db_tables_create_menu')`
on line 38 registers the screen with an administrative capability, and the developer stopped
there. `admin_post_{action}` requires only that the caller be logged in — it authenticates,
it does not authorise. Every Subscriber, WooCommerce customer and LMS student on the site
can `POST /wp-admin/admin-post.php?action=delete_db_table` with any table name. There is no
nonce either, so the same request works as CSRF against an administrator.

Note the second bug on the same line: `$db_table` is interpolated into the query
(`sanitize_text_field()` does nothing to SQL metacharacters), so this is also WP-SQLI. That
pairing is typical — a handler that skipped the capability check usually skipped the rest.

### A nonce every logged-in user can read (CVE-2026-18316, 9.1, subscriber+)

```php
// Import Zip Elementor
$this->loader->add_action( 'wp_ajax_action-import-zip', $plugin_admin, 'import_zip' );
$this->loader->add_action( 'wp_ajax_nopriv_action-import-zip', $plugin_admin, 'import_zip' );
```
`https://plugins.trac.wordpress.org/browser/solace-extra/tags/1.6.0/includes/class-solace-extra.php#L336`

**Root cause:** `import_zip()` verifies the `ajax-nonce` nonce and performs no capability
check. That nonce is emitted on **every** admin page through `wp_localize_script()` on an
unrestricted `admin_enqueue_scripts` hook, so any authenticated user — Subscriber
included — can read it out of the page source and replay it.

Two things to carry away. First, the registration goes through
`$this->loader->add_action(...)`, the WordPress Plugin Boilerplate indirection: a detection
rule must therefore **not** anchor on `^\s*add_action` (AJAX-001 in WP-AJAX matches the
quoted hook string wherever it appears, which is why it still fires here). Second, when a
handler's only control is a nonce, the real question is *who can obtain that nonce*. Trace
every `wp_create_nonce()` to the script it is localised into and to the hook that enqueues
it.

### The check is present but does not match the impact (CVE-2025-4672, 8.8, contributor+)

Every route in this controller has a `permission_callback`, so the WP-REST rules report it
as protected:

```php
register_rest_route( $namespace . $version, '/usermeta/(?P<metaKey>[\S]+)/(?P<userId>[\d]+)', array(
    array(
        'methods'         => WP_REST_Server::CREATABLE,
        'callback'        => array( $this, 'create_usermeta' ),
        'permission_callback' => array( $this, 'create_meta_permissions_check' )
    ),
```

The callback:

```php
public function create_meta_permissions_check( $request ) {
    return current_user_can( 'edit_posts' );
}
```

The handler:

```php
public function create_usermeta( $request ) {
    $user_id = (int) $request->get_param( 'userId' );
    $meta_key = (string) $request->get_param( 'metaKey' );
    $json_payload = $request->get_json_params();

    $data = update_user_meta( $user_id, $meta_key, $json_payload );
```
`https://plugins.trac.wordpress.org/browser/offsprout-page-builder/tags/2.15.2/api/class-offsprout-api-extensions.php#L514`

**Root cause at that line:** the route writes **any meta key** on **any user**, and it is
gated on `edit_posts` — a primitive held by Contributor and above with no ownership logic at
all (capability-matrix.md §4). A Contributor sets `metaKey=wp_capabilities` and `userId` to
their own ID, posts `{"administrator":true}`, and is an administrator. The correct gate is
`edit_users` plus `current_user_can( 'edit_user', $user_id )` plus a key allowlist.

This is CWE-863 rather than CWE-862: authorization was performed *incorrectly*, not omitted.
Grep-based tooling scores this file as clean on every rule that looks for the *presence* of
a check. **The audit question is never "is there a capability check" — it is "does the
capability match the worst thing this handler can do".**

### Authorization tangled into input validation (CVE-2026-4003, 9.8, unauthenticated)

```php
$user_id = !empty($_POST['userspn_form_user_id']) ? USERSPN_Forms::userspn_sanitizer(wp_unslash($_POST['userspn_form_user_id'])) : 0;
...
if (($userspn_form_type == 'user' && empty($user_id) && !in_array($userspn_form_subtype, ['user_alt_new']))
    || ($userspn_form_type == 'post' && (...))
    || ($userspn_form_type == 'option' && !is_user_logged_in())) {
    ...
    echo wp_json_encode(['error_key' => 'userspn_form_save_error_unlogged', ]);exit;
}else{
    // reaches update_user_meta($user_id, $userspn_key, $userspn_value) for any $user_id
```
`https://plugins.trac.wordpress.org/browser/userspn/tags/1.0.31/includes/class-userspn-ajax-nopriv.php#L190`

**Root cause at that line:** the branch that rejects unauthenticated callers requires
`empty($user_id)`. Supply a non-empty `userspn_form_user_id` and the condition is false, so
the `else` runs and `update_user_meta()` is reached for an arbitrary account. The nonce
that guards the endpoint is published to every visitor by `wp_localize_script()` on
`wp_enqueue_scripts`.

**The generalisable defect:** authorization was expressed as one disjunct inside a
multi-clause condition that also does input validation, so *attacker-controlled input
selects whether the authorization clause is evaluated at all*. Authorization must be its own
statement, at the top of the handler, with its own terminating failure branch. Any `if`
whose condition mixes `is_user_logged_in()` / `current_user_can()` with `empty()`,
`isset()`, or a comparison against request data is a finding on sight.

### "Logged in" as the boundary for an administrative feature (CVE-2024-3750, 8.8, subscriber+)

A charting plugin exposed a data-source handler that executes caller-supplied SQL. It was
registered only on the logged-in AJAX hook — no `_nopriv_` twin — and the author appears to
have treated that as the access control. It is not: `wp_ajax_{action}` admits every
Subscriber, and Subscriber is the default role for open registration, WooCommerce customers,
membership sites and LMS students.

**Root cause:** the handler performs an administrative action (arbitrary SQL) and never calls
`current_user_can()`. Omitting `_nopriv_` narrows the audience from "the internet" to
"anyone with an account", which on most real sites is a distinction without a difference.
`source_url`: `https://nvd.nist.gov/vuln/detail/CVE-2024-3750`.

## Detection guidance

**What the regexes catch reliably**

- `AUTHZ-001`, `AUTHZ-002` and `AUTHZ-003` catch *wrong* checks with near-zero false
  positives, because each has a syntactic signature: a role name where a capability belongs,
  a meta capability with no object ID, a role-membership test.
- `AUTHZ-006` catches the escalation-critical option writes. Any hit is a finding unless the
  handler is gated on `manage_options` **and** a nonce.
- `AUTHZ-008` is the closest a line rule gets to the real bug: a write driven straight off a
  superglobal marks the enclosing function as a request handler, which is exactly the
  function that must contain the check.
- `AUTHZ-007` and `AUTHZ-009` are worklists. Their value is completeness, not precision.

**What the regexes CANNOT catch — read the code**

1. **Absence.** This is the defining limitation of the class and it cannot be engineered
   around with a line-oriented rule: you cannot grep for a call that is not there. Every rule
   above is a *proxy* — it flags a registration or a sink and tells you which function body
   to read. The finding is always produced by reading, never by matching. Budget the audit
   accordingly.
2. **The correct unit of analysis is the entry point, not the file.** Build the entry-point
   inventory first (entry-points.md §12), then for each entry point answer: which capability
   is checked, does it match the impact, and does the failure branch terminate. A file with
   twelve `current_user_can()` calls and thirteen entry points has a hole.
3. **Whether an existing check terminates.** CVE-2026-19598. Follow every failure branch to
   `wp_die` / `exit` / `wp_send_json_*` / a `return` from the outermost handler. A `return`
   inside a loop, a filter callback, or a helper whose result is discarded is not a guard.
4. **Whether the capability matches the impact.** CVE-2025-4672. `edit_posts` guarding a
   user-meta write, `read` guarding an option write, `upload_files` guarding a file delete.
   Use the capability-selection table in capability-matrix.md §2 and rate against the *worst*
   reachable outcome, not the intended one.
5. **Multi-hop reachability.** The registration, the dispatcher and the sink are routinely in
   three different files, connected by a variable method name (`->$task()`), a
   `call_user_func()`, a `switch` on `$_POST['method']`, or a framework's route table. See
   WP-AJAX and WP-REST for the registration-side rules that anchor these chains.
6. **Object-level authorization (IDOR).** A correct primitive check plus a request-supplied
   object ID is still broken. Every `$_POST['id']`, `user_id`, `post_id`, `order_id`,
   `booking_id` needs `current_user_can( $meta_cap, $id )` or an explicit ownership
   comparison. This is the boundary with WP-IDOR; findings usually belong to both.
7. **Where the nonce comes from.** A nonce is not authorization, and a nonce localised to a
   front-end script is not even a CSRF control against an authenticated attacker. Trace every
   `wp_create_nonce()` to its `wp_localize_script()` and to the enqueue hook.
8. **Capabilities the plugin itself grants.** `add_cap()`, `add_role()`, and `user_has_cap` /
   `map_meta_cap` filters can hand a takeover-equivalent capability to a low role, which
   lowers the effective tier of *every other finding in the plugin*. Check these before
   rating anything (capability-matrix.md §8.7).
9. **`'map_meta_cap' => false` on a custom post type.** Ownership and status logic is bypassed
   entirely; `edit_post` degrades to the raw primitive. High-signal, invisible to any rule
   here.
10. **Cron and CLI contexts.** `current_user_can()` is meaningless with no current user, so a
    capability check inside a cron callback either always fails or is dead code — validate at
    scheduling time instead. Missing capability checks in `WP_CLI::add_command()` handlers are
    **not** vulnerabilities (entry-points.md §10).

## Audit checklist

- [ ] Build the entry-point inventory first (entry-points.md §12). Record the minimum
      privilege that reaches each one. Nothing else in this checklist is meaningful without it.
- [ ] For every entry point, locate the capability check **inside the callback**. Missing →
      finding, rated as the action it exposes at the tier that reaches it.
- [ ] Compare the count of entry points against the count of `current_user_can` calls. A
      deficit names the handlers to read first.
- [ ] Run `AUTHZ-001`, `AUTHZ-002`, `AUTHZ-003`; treat every hit as a finding until the line
      is shown to be non-authorizing.
- [ ] Run `AUTHZ-004`. For each hit, decide whether the predicate is deciding *what to load*
      (benign) or *whether to act* (finding).
- [ ] Run `AUTHZ-006`. Any write to `default_role`, `users_can_register`, `siteurl`, `home`,
      `admin_email` or `wp_user_roles` must be behind `manage_options` plus a nonce.
- [ ] Run `AUTHZ-007`; for each hit, determine whether the option/meta **key** can be
      influenced by the request. If yes, rate as arbitrary-write → privilege escalation
      (Critical), not as a settings bug.
- [ ] Run `AUTHZ-008` and `AUTHZ-009` to build the sink worklist, then read each enclosing
      function top-to-bottom.
- [ ] For every `current_user_can()` found, verify all three of: the capability matches the
      worst reachable impact; a meta capability is passed its object ID; the failure branch
      terminates.
- [ ] Grep `wp_verify_nonce|check_ajax_referer|check_admin_referer` and diff against
      `current_user_can` per function. A nonce-only handler is the highest-yield shape in the
      class.
- [ ] Trace every `wp_create_nonce()` to its `wp_localize_script()` and enqueue hook; record
      who can read it.
- [ ] For every request-supplied object ID reaching a write, confirm an object-level check
      (`current_user_can( $meta_cap, $id )` or an explicit owner comparison).
- [ ] Grep `add_cap|add_role|user_has_cap|map_meta_cap` for capabilities the plugin grants to
      low roles, and `'map_meta_cap'\s*=>\s*false` on registered post types.
- [ ] Check whether any authorization condition is combined with input validation in a single
      `if` (CVE-2026-4003). Authorization gets its own statement.
- [ ] Cross-check the registration side: see **WP-AJAX** for `wp_ajax_nopriv_` /
      `admin_post_nopriv_` exposure and **WP-REST** for `permission_callback`. A handler can
      be a finding in this class and in one of those simultaneously; report the registration
      and the sink together.
