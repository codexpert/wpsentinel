---
class_id: WP-CSRF
title: Missing or incorrect nonce verification (Cross-Site Request Forgery)
cwe: [CWE-352]
owasp: A01:2021-Broken Access Control
severity_typical: medium
auth_required_typical: unauthenticated
prevalence_rank: 11
detection:
  - id: CSRF-001
    description: Nonce verification gated on the presence of the nonce field — omit the field and the check is skipped
    regex: 'if\s*\(\s*(isset|!\s*empty)\s*\(\s*\$_(POST|GET|REQUEST)\s*\[\s*[''"][^''"]*(nonce|referer|security|token)[^''"]*[''"]'
    confidence: high
    false_positive_notes: >-
      The safe idiom is negated — `if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( ... ) )`
      — and this rule deliberately does not match it, because the leading `!` is what makes the
      absent-nonce case fail closed. A positive `isset()` wrapping the verification means the
      attacker chooses whether the check runs at all. The residual false positive is
      `if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( ... ) ) { ...work... }` where the work
      is inside the block; read the block boundary before dismissing a hit.
  - id: CSRF-002
    description: Bare wp_verify_nonce() statement — the boolean result is computed and thrown away
    regex: '^\s*@?wp_verify_nonce\s*\('
    confidence: high
    false_positive_notes: >-
      Essentially always a finding. wp_verify_nonce() is the only one of the three verification
      helpers that RETURNS instead of terminating, so a statement-position call does nothing at all.
      check_admin_referer() and check_ajax_referer() call wp_die() themselves, so a bare statement
      is their correct usage — that is why they are excluded here and handled by CSRF-003/CSRF-009.
      The `@?` prefix is present for the same reason as in WP-DELETE: suppressed calls occur.
  - id: CSRF-003
    description: check_ajax_referer() with $die=false whose boolean result is discarded
    regex: 'check_ajax_referer\s*\([^;]*,\s*false\s*\)\s*;'
    confidence: high
    false_positive_notes: >-
      Passing false as the third argument converts check_ajax_referer() from a terminating guard
      into a predicate. Ending the statement there discards the predicate. Rare but unambiguous;
      the only benign shape is `$ok = check_ajax_referer( 'a', 'n', false );` which this does not
      match because of the trailing `;` immediately after the closing paren.
  - id: CSRF-004
    description: wp_verify_nonce() called with a single argument — no $action, so it verifies against -1
    regex: 'wp_verify_nonce\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[''"][^''"]+[''"]\s*\]\s*\)'
    confidence: high
    false_positive_notes: >-
      $action defaults to -1, so the token is verified against a generic action any page on the
      site can mint. Deliberately narrowed to a bare superglobal argument so that the balanced-paren
      case `wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['n'] ) ), 'act' )` cannot be
      mistaken for a one-argument call; the cost is that a single-argument call through an
      intermediate variable is missed. Pair with CSRF-009 when auditing exhaustively.
  - id: CSRF-005
    description: Inverted nonce guard on one line — a VALID nonce takes the early-return branch
    regex: 'if\s*\(\s*(wp_verify_nonce|check_ajax_referer)\s*\([^;]*\)\s*\)\s*\{?\s*(return|die|exit|wp_die)'
    confidence: high
    false_positive_notes: >-
      Only matches the non-negated form, so the correct `if ( ! wp_verify_nonce( ... ) ) { return; }`
      never fires. Line-oriented: it misses the (more common) shape where the brace opens on the
      `if` line and `return false;` sits on the next line. When triaging a hit from CSRF-004 or
      CSRF-009, read two lines further and check the polarity by hand.
  - id: CSRF-006
    description: REST route registered with no intent check — permission_callback always returns true
    regex: '[''"]permission_callback[''"]\s*=>\s*([''"]__return_true[''"]|function[^;]*\{\s*return\s+true)'
    confidence: high
    false_positive_notes: >-
      Legitimate on a genuinely public read-only route (a public search endpoint). On anything
      that writes, it is a finding: `permission_callback` is the ONLY place a REST route can
      express an authorization decision, and returning true unconditionally also removes the
      route from the set of things core will refuse. Grade by the HTTP method and by what the
      callback does, not by whether the callback contains a `current_user_can()`.
  - id: CSRF-007
    description: Nonce minted into front-end JavaScript, making it obtainable by any anonymous visitor
    regex: '[''"]nonce[''"]\s*=>\s*wp_create_nonce\s*\('
    confidence: medium
    false_positive_notes: >-
      Not a vulnerability by itself — this is how every legitimate AJAX form works. It matters as
      the second half of a pair: when a handler's only control is a nonce, this rule tells you
      whether an attacker can simply fetch the nonce. Check which enqueue hook the surrounding
      wp_localize_script()/wp_add_inline_script() runs on. `wp_enqueue_scripts` (front end) means
      anonymous; `admin_enqueue_scripts` means logged-in-with-that-screen.
  - id: CSRF-008
    description: HTTP Referer used as the CSRF control
    regex: '\$_SERVER\s*\[\s*[''"]HTTP_REFERER[''"]\s*\]'
    confidence: medium
    false_positive_notes: >-
      Often benign (redirect-back-to-previous-page). It is a finding when the value gates a
      state-changing branch: Referer is attacker-influenced, frequently absent under privacy
      settings and referrer-policy headers, and the "absent" case is usually coded as allow.
      Distinguish from core's wp_get_referer()/check_admin_referer(), which combine the referer
      with a real nonce.
  - id: CSRF-009
    description: Every nonce verification site — the exhaustive worklist
    regex: '\b(wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\('
    confidence: low
    false_positive_notes: >-
      Matches correct code by design; the point is completeness. Most plugins have few enough
      of these to triage by hand. For each hit ask three questions in order: (1) is the result
      acted on, (2) is the $action string specific to this operation rather than shared across
      the plugin, (3) is there a current_user_can() alongside it. A "no" to (3) is not a CSRF
      finding — it is a WP-AUTHZ finding, and the two are frequently present together.
fix_apis:
  - wp_nonce_field()
  - wp_nonce_url()
  - wp_create_nonce()
  - wp_verify_nonce()
  - check_admin_referer()
  - check_ajax_referer()
  - current_user_can()
  - register_rest_route() permission_callback
examples:
  - cve: CVE-2026-6292
    year: 2026
    severity: 4.3
    auth: unauthenticated
    summary: A settings handler verified a nonce and then returned early when the nonce was VALID, so only forged requests reached the option writes.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6292
    code_ref: https://plugins.trac.wordpress.org/browser/mp-customize-login-page/trunk/class.mp-customize-login-page.php#L103
    root_cause: Inverted guard — `if ( wp_verify_nonce( $_POST['_wpnonce'] ) ) { return false; }` — compounded by the missing $action argument, which makes the token verify against the generic -1 action.
  - cve: CVE-2026-6455
    year: 2026
    severity: 8.1
    auth: unauthenticated
    summary: A bulk-action handler wrapped its nonce verification in an isset() test on the nonce field itself, so omitting the field skipped verification entirely and reached an unparameterised SQL sink and an unserialize().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6455
    code_ref: https://plugins.trac.wordpress.org/browser/wp-contact-form-7-db-handler/tags/3.0/include/form-inner-page-class.php#L589
    root_cause: The nonce check was conditional on the attacker supplying a nonce; the absent-nonce path fell through to the privileged work.
  - cve: CVE-2026-15212
    year: 2026
    severity: 8.8
    auth: unauthenticated
    summary: A shared AJAX guard performed its capability check unconditionally but gated its nonce check behind a boolean plugin option that was absent from the defaults and therefore false, leaving every settings-writing AJAX action forgeable.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15212
    code_ref: https://plugins.trac.wordpress.org/browser/wpo365-login/tags/43.2/Services/Ajax_Service.php#L805
    root_cause: CSRF protection made opt-in by configuration and defaulted off; the handler's own capability check confirmed the victim administrator's permission and so actively helped the attack.
  - cve: CVE-2026-4275
    year: 2026
    severity: 8.8
    auth: unauthenticated
    summary: Plugin-install and plugin-activate REST routes declared permission_callback as __return_true while performing their capability check inside the callback body.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4275
    code_ref: https://plugins.trac.wordpress.org/browser/addons-for-divi/tags/4.2.2/includes/rest-api.php#L81
    root_cause: permission_callback is the only place a REST route can declare an authorization requirement; replacing it with __return_true removes the route's declared boundary, leaving an internal current_user_can() that answers "may this user" but never "did this user ask".
  - cve: CVE-2026-15070
    year: 2026
    severity: 8.8
    auth: unauthenticated
    summary: An AJAX action guarded only by current_user_can('manage_options') wrote a request-supplied value into a PHP file inside the plugin directory, turning a forged administrator request into remote code execution.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15070
    code_ref: https://plugins.trac.wordpress.org/browser/salon-booking-system/tags/10.30.32/src/SLN/Action/Ajax/SetCustomText.php#L17
    root_cause: Permission proven, intent never proven — no nonce anywhere in the handler — and sanitize_text_field() left the quotes, parentheses and semicolons needed to break out of the generated PHP string literal.
  - cve: CVE-2026-17608
    year: 2026
    severity: 6.5
    auth: unauthenticated
    summary: A debug/maintenance screen deleted options named by the request with no nonce, allowing siteurl, home, active_plugins, template and stylesheet to be removed.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-17608
    code_ref: https://plugins.trac.wordpress.org/browser/wp-compress-image-optimizer/tags/7.10.03/templates/admin/debug_tool.php#L550
    root_cause: Top-level template code executed a delete_option() branch on the presence of a request parameter; being inside wp-admin was treated as sufficient proof of intent.
  - cve: CVE-2026-4068
    year: 2026
    severity: 4.3
    auth: unauthenticated
    summary: The same admin template verified a nonce for its add-field branch and omitted verification entirely for its delete-field branch.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4068
    code_ref: https://plugins.trac.wordpress.org/browser/add-custom-fields-to-media/tags/2.0.3/admin/partials/add-custom-fields-to-media-admin-display.php#L38
    root_cause: Partial nonce coverage — the presence of a correct wp_verify_nonce() a few lines above made the unprotected branch read as protected.
  - cve: CVE-2023-1023
    year: 2023
    severity: 4.3
    auth: subscriber+
    summary: A settings-save AJAX handler verified a nonce and performed no capability check, and the nonce it required was issued to every authenticated user regardless of role.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-1023
    code_ref: https://plugins.trac.wordpress.org/changeset/2870465/wp-meta-seo/trunk?contextall=1&old=2869205&old_path=%2Fwp-meta-seo%2Ftrunk#file2
    root_cause: A nonce was used as the access-control mechanism. Nonces prove intent, not permission; the fix was to add current_user_can(), not to change the nonce.
---

## What it is

A state-changing endpoint acts on a request without proving that the *user* meant to make it.
WordPress's answer to this is the nonce: a token derived from the user's session, an action
string and the current time slice, which a cross-origin page cannot compute. Cross-Site
Request Forgery is what happens when that token is absent, when it is verified but the answer
is ignored, or when it is treated as an authorization decision it was never designed to make.

The class is large — 531 records in the sampled corpus, 9.45% of everything — and its average
CVSS is deceptively low at 4.65, because most instances change a cosmetic setting. The tail is
not low: the same defect on a handler that writes a PHP file, deletes `active_plugins`, or
merges arbitrary keys into a plugin option is scored 8.8 and converts to full site takeover.

## The distinction this class exists to enforce

> **A nonce proves intent. A capability proves permission. They are different questions and a
> state-changing handler must answer both.**

| Control | Question it answers | What it stops |
|---|---|---|
| `wp_verify_nonce()` / `check_admin_referer()` / `check_ajax_referer()` | *Did this user deliberately ask for this, from our UI?* | CSRF |
| `current_user_can( $cap )` | *Is this user allowed to do this at all?* | WP-AUTHZ, WP-PRIVESC, WP-IDOR |

Every combination of the two produces a different, named defect:

- **Neither** — the handler is reachable by anyone. That is WP-AUTHZ (and usually also
  WP-PRIVESC or WP-OPTIONS depending on the sink), not primarily CSRF.
- **Nonce only** — the handler is CSRF-proof but has no permission boundary. Any user who can
  obtain the nonce can call it. If the nonce is printed into a public page (CSRF-007), that is
  every anonymous visitor. This is the CVE-2023-1023 shape, and it is why "there is a nonce"
  is never an answer to "is this authorized".
- **Capability only** — the handler cannot be reached by an attacker directly, so the attacker
  reaches it *through the victim's browser*. This is classic CSRF and the capability check
  actively helps: the request carries the administrator's cookies, so the capability check
  passes. CVE-2026-15070 (capability check present, no nonce, writes PHP to disk) and
  CVE-2026-15212 (capability check present, nonce optional by configuration) are both this shape.
- **Both, but the nonce is mishandled** — the largest and most interesting group, covered below.

Because a nonce is bound to the *user session*, one further consequence follows: a nonce
protects a logged-in victim from a forged request, but it says nothing about which logged-in
victim. A Subscriber holding a valid nonce for a settings action is exactly as authorized as
an Administrator holding the same nonce, unless a capability check separates them.

## Why it happens in WordPress

- **`wp_verify_nonce()` returns; the other two die.** `check_admin_referer()` and
  `check_ajax_referer()` call `wp_die()` internally, so writing them as a bare statement is
  correct. `wp_verify_nonce()` does not. Developers move between the three and carry the calling
  convention with them, producing a statement whose entire effect is to compute a boolean and
  discard it. This is CSRF-002 and it is the single most greppable bug in the class.
- **`check_ajax_referer( $action, $q, false )` silently changes contract.** The third argument
  is `$die`. Passing `false` turns a guard into a predicate. If the call site was not also
  changed to test the return value, protection disappears with no visible diff at the call.
- **The `$action` argument is optional.** `wp_verify_nonce( $token )` verifies against `-1`.
  Any nonce created anywhere on the site with the default action satisfies it, including one
  a public page handed the attacker. The signature makes the dangerous form the shorter one.
- **`isset()` around the check.** Written defensively — "only verify if they sent one" — it
  inverts the failure mode: the attacker decides whether verification happens by choosing not
  to send the field. CVE-2026-6455 is exactly this.
- **`permission_callback` is easy to switch off.** REST routes have a mandatory
  `permission_callback`; setting it to `__return_true` satisfies the requirement while removing
  the boundary. Developers do this to "fix" a 401 during development and it ships.
- **`is_admin()` is not a boundary.** Handlers hooked to `admin_init`, or top-level code in an
  admin template, are frequently written as if reaching them proved anything. `is_admin()`
  returns the value of the `WP_ADMIN` constant — see `kb/reference/entry-points.md` §1 — and
  `admin-ajax.php` sets it for unauthenticated requests too.
- **Nonces are public by construction on the front end.** Any AJAX-driven front-end feature must
  hand its nonce to JavaScript, and that JavaScript is served to anonymous visitors. A front-end
  nonce is a shared secret with the entire internet.
- **Nonces expire but are not single-use.** Default lifetime is 24 hours (two 12-hour ticks).
  A nonce leaked through a cache, a log, or a Referer header stays valid for up to a day.

## Vulnerable pattern

The four shapes, smallest first. All are real; all read as protected code.

```php
// 1. The result is computed and discarded. This is a no-op.
function example_save_settings() {
    wp_verify_nonce( $_POST['nonce'], 'example_save' );   // <- returns; nothing tests it
    update_option( 'example_settings', wp_unslash( $_POST['settings'] ) );
    wp_send_json_success();
}

// 2. Verification is conditional on the attacker supplying a nonce.
function example_bulk_action() {
    if ( isset( $_POST['_wpnonce'] ) && ! empty( $_POST['_wpnonce'] ) ) {
        if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'bulk-example' ) ) {
            wp_die( 'Not valid..!!' );
        }
    }
    // Omit _wpnonce entirely and execution simply arrives here.
    example_delete_rows( $_POST['ids'] );
}

// 3. Inverted polarity, and no $action so the token verifies against -1.
public static function enter_example_options() {
    if ( wp_verify_nonce( $_POST['_wpnonce'] ) ) {   // TRUE means the nonce was GOOD
        return false;                                 // ... and we bail out
    }
    update_option( 'example_logo', esc_url_raw( $_POST['example-logo'] ) );
}

// 4. Permission proven, intent never proven.
public function execute() {
    if ( current_user_can( 'manage_options' ) ) {     // the victim IS an administrator
        $this->settings->setCustomText(
            sanitize_text_field( wp_unslash( $_POST['key'] ) ),
            sanitize_text_field( wp_unslash( $_POST['value'] ) )
        );
        $this->settings->save();                      // ... and the value is written to a PHP file
    }
}
```

Shape 4 is the one that most often survives review, because a reviewer scanning for
`current_user_can()` finds it and stops. The capability check is not merely insufficient here —
under CSRF it is the mechanism by which the attack succeeds, since the forged request travels
with the administrator's cookies and therefore satisfies it.

And the REST variant:

```php
register_rest_route( $ns, '/install_plugin', array(
    'methods'             => WP_REST_Server::EDITABLE,
    'callback'            => array( $this, 'install_plugin' ),
    'permission_callback' => '__return_true',        // no declared boundary
) );

public function install_plugin( WP_REST_Request $request ) {
    $slug = sanitize_key( wp_unslash( $request->get_param( 'slug' ) ) );
    if ( ! current_user_can( 'install_plugins' ) ) {  // permission, not intent
        return new WP_Error( 'insufficient_permissions', __( 'Sorry, ...' ), array( 'status' => 403 ) );
    }
    // ... installs the plugin
}
```

## Secure pattern

Order matters: cheapest rejection first, and never let a missing field skip a check.

```php
add_action( 'wp_ajax_example_save_settings', 'example_save_settings' );
// Note the deliberate absence of wp_ajax_nopriv_ — an anonymous caller has no business here.

function example_save_settings() {
    // 1. INTENT. check_ajax_referer() dies on failure, and a MISSING nonce is a failure
    //    because the guard is not wrapped in isset(). Never pass $die=false unless you
    //    are testing the return value on the same expression.
    check_ajax_referer( 'example_save_settings', 'nonce' );

    // 2. PERMISSION. Separate question, separate check, and the capability must be the one
    //    the operation actually needs (see kb/reference/capability-matrix.md).
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    // 3. Only now touch state, and only through an allowlist (see WP-OPTIONS).
    $allowed = array( 'example_layout', 'example_colour' );
    foreach ( $allowed as $key ) {
        if ( isset( $_POST[ $key ] ) ) {
            update_option( $key, sanitize_key( wp_unslash( $_POST[ $key ] ) ) );
        }
    }
    wp_send_json_success();
}
```

The admin-form equivalent, with the nonce emitted by core so the action strings cannot drift:

```php
// Rendering side.
echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
wp_nonce_field( 'example_save_settings', 'example_nonce' );
// ...

// Handling side. check_admin_referer() wp_die()s on failure; a bare statement is correct here.
add_action( 'admin_post_example_save', function () {
    check_admin_referer( 'example_save_settings', 'example_nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Insufficient permissions.', 'example' ), 403 );
    }
    // ...
} );
```

And REST, where `permission_callback` is the boundary and must carry the capability:

```php
register_rest_route( 'example/v1', '/settings', array(
    'methods'             => WP_REST_Server::EDITABLE,
    'callback'            => 'example_rest_update_settings',
    'permission_callback' => function () {
        return current_user_can( 'manage_options' );
    },
    'args'                => array(
        'layout' => array(
            'required'          => true,
            'validate_callback' => function ( $v ) { return in_array( $v, array( 'grid', 'list' ), true ); },
        ),
    ),
) );
```

Core supplies the intent half for REST automatically: `rest_cookie_check_errors()` requires an
`X-WP-Nonce` (or `_wpnonce`) for cookie-authenticated requests. That protection only functions
if `permission_callback` still expresses a real requirement — see the detection note below for
exactly how core behaves when the nonce is missing.

Non-negotiables: the verification is unconditional; its result terminates or is tested; the
`$action` string is specific to this one operation; a `current_user_can()` sits beside it; and
for REST, the capability lives in `permission_callback`, not only in the callback body.

## Real-world case studies

### Inverted guard, and no action string (CVE-2026-6292, 4.3, unauthenticated)

```php
public static function enter_mpclp_login_options() {
    if ( wp_verify_nonce( $_POST['_wpnonce'] ) ){
        return false;
    }

    update_option( 'mpclp_login_image', esc_url_raw($_POST['mpclp-login-image']) );
    ...
}
```
`https://plugins.trac.wordpress.org/browser/mp-customize-login-page/trunk/class.mp-customize-login-page.php#L103`

**Root cause at that line:** two independent defects stacked. The condition is inverted — a
*valid* nonce takes the early return, an invalid or absent one falls through to the option
writes. And `wp_verify_nonce()` is called with one argument, so `$action` defaults to `-1`; even
with correct polarity the token would verify against a generic action rather than this operation.

The dispatcher is `add_action`-free: `init()` runs on every request and calls the handler
whenever `$_POST['mpclp-options'] === 'update'`, with no capability check anywhere. What makes
this case pedagogically valuable is that two sibling functions **in the same file** get the
polarity right:

```php
public static function delete_mpclp_login_image() {
    if ( !wp_verify_nonce( $_POST['_wpnonce'], self::NONCE ) )
        return false;
    delete_option( 'mpclp_login_image' );
}
```

A reviewer who greps for `wp_verify_nonce` in this file sees three hits and moves on. The defect
is visible only to a check on the *polarity and arity* of each call — which is precisely the
gap between CSRF-009 (finds all three) and CSRF-004/CSRF-005 (finds the broken one).

### The nonce check the attacker opts out of (CVE-2026-6455, 8.1, unauthenticated)

```php
public function process_bulk_action()
{
    ...
    if (isset($_POST['_wpnonce']) && ! empty($_POST['_wpnonce'])) {
        $nonce        = filter_input(INPUT_POST, '_wpnonce', FILTER_SANITIZE_STRING);
        $nonce_action = 'bulk-' . $this->_args['plural'];

        if (!wp_verify_nonce($nonce, $nonce_action)) {
            wp_die('Not valid..!!');
        }
    }

    if ('delete' === $action) {
        ...
            $results = $wpdb->get_results("SELECT * FROM $table_name WHERE ID = $ID AND post_type = 'ys_cfdbh' LIMIT 1", OBJECT);
            $result_values = unserialize($result_value);
```
`https://plugins.trac.wordpress.org/browser/wp-contact-form-7-db-handler/tags/3.0/include/form-inner-page-class.php#L589`

**Root cause at that line:** the *inner* check is correct — it verifies, and it `wp_die()`s on
failure. The *outer* `isset()` hands the attacker the decision of whether the inner check runs.
Sending no `_wpnonce` field at all skips straight to the work.

The impact stacks: `WHERE ID = $ID` is unparameterised (WP-SQLI), the query result is passed to
`unserialize()` (WP-POI), and the deserialised array's file-path values reach `wp_delete_file()`
(WP-DELETE). One forged administrator click chains three classes. **A CSRF finding's severity is
the severity of the sink it unlocks**, which is why this class's average CVSS is a poor guide to
any individual instance.

### CSRF protection as an opt-in feature flag (CVE-2026-15212, 8.8, unauthenticated)

```php
public static function verify_ajax_request( $error_message_fragment ) {
    $error_message = '';

    if ( ! is_user_logged_in() ) {
        $error_message = 'Attempt ' . $error_message_fragment . ' by a user that is not logged on';
    }

    if (
        Options_Service::get_global_boolean_var( 'enable_nonce_check' )
        && ( ! isset( $_POST['nonce'] )
            || ! wp_verify_nonce( $_POST['nonce'], 'wpo365_fx_nonce' ) )
    ) {
        $error_message = 'Request ' . $error_message_fragment . ' has been tampered with (invalid nonce)';
    }
    ...
}
```
`https://plugins.trac.wordpress.org/browser/wpo365-login/tags/43.2/Services/Ajax_Service.php#L805`

**Root cause at that line:** the nonce clause is `&&`-guarded by a boolean option that is absent
from the plugin's default options array, so `get_global_boolean_var()` returns false and the
entire second operand short-circuits away. The verification is written correctly — negated,
handles the missing field — and never executes.

The caller then does everything right by the WP-AUTHZ playbook:

```php
public static function update_settings() {
    $current_user = self::verify_ajax_request( 'to update the wpo365-login settings' );

    if ( Permissions_Helpers::user_is_admin( $current_user ) === false ) {
        ...
        wp_die();
    }

    self::verify_posted_data( array( 'settings' ) );
    $updated = Options_Service::update_options( $_POST['settings'], false, $reset );
}
```

The capability check is present and correct — and it is what makes the attack work, because the
forged request rides the administrator's cookies. `update_options()` merges every key of the
attacker's base64/JSON payload into the plugin's option with no allowlist, so the payload can
set the plugin's `new_usr_default_role` to `administrator` and plant a known SCIM token: a
cross-reference into **WP-OPTIONS**. **This is the archetype of the class: capability yes, intent
no, arbitrary option merge as the sink.**

### permission_callback => '__return_true' on a plugin installer (CVE-2026-4275, 8.8, unauthenticated)

```php
'/activate_plugin' => [
    'methods' => \WP_REST_Server::EDITABLE,
    'callback' => [$this, 'activate_plugin'],
    'permission_callback' => '__return_true',
    'args' => $this->get_plugin_args(),
],
'/install_plugin' => [
    'methods' => \WP_REST_Server::EDITABLE,
    'callback' => [$this, 'install_plugin'],
    'permission_callback' => '__return_true',
    ...
```
`https://plugins.trac.wordpress.org/browser/addons-for-divi/tags/4.2.2/includes/rest-api.php#L81`

with the capability check moved inside the callback:

```php
public function install_plugin(WP_REST_Request $request)
{
    $slug = sanitize_key(wp_unslash($request->get_param('slug')));
    ...
    if (!current_user_can('install_plugins')) {
        return new WP_Error('insufficient_permissions', ...);
    }
```

**Root cause:** `permission_callback` is the only place a REST route declares an authorization
requirement, and `__return_true` erases it. A `current_user_can()` in the callback body answers a
different question and answers it later.

**A correctness note worth carrying into triage, because it changes how you grade these hits.**
Core's `rest_cookie_check_errors()` (`wp-includes/rest-api.php`) handles the nonce for
cookie-authenticated REST requests:

```php
	if ( true !== $wp_rest_auth_cookie && is_user_logged_in() ) {
		return $result;
	}
	...
	if ( null === $nonce ) {
		// No nonce at all, so act as if it's an unauthenticated request.
		wp_set_current_user( 0 );
		return true;
	}
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/rest-api.php` (lines 1130–1172)

So for a plain browser session, a nonce-less REST request is *demoted to user 0*, and an internal
`current_user_can()` then fails. But note the early return two blocks above: if the request was
authenticated by anything other than the login cookie — an application password, a JWT/SSO plugin,
any `determine_current_user` filter — `$wp_rest_auth_cookie` is not `true`, the function returns
before reaching the nonce logic, and **no nonce is checked at all**. On such a site a
`__return_true` route with an internal capability check is reachable with a stolen or replayed
credential and no token. Treat `__return_true` on a writing route as a finding in every case; the
severity depends on how the site authenticates, and the demotion behaviour is the reason a hit
can look unexploitable in one environment and be trivially exploitable in another.

### Permission without intent, ending in RCE (CVE-2026-15070, 8.8, unauthenticated)

```php
public function execute()
{
    if (!is_user_logged_in()) {
        return array( 'redirect' => wp_login_url());
    }

    $plugin = SLN_Plugin::getInstance();

    if(current_user_can('manage_options')) {
        $plugin->getSettings()->setCustomText(sanitize_text_field(wp_unslash($_POST['key'])), sanitize_text_field(wp_unslash($_POST['value'])));
        $plugin->getSettings()->save();
    } else {
        $this->addError(__("You don't have permissions", 'salon-booking-system'));
    }
```
`https://plugins.trac.wordpress.org/browser/salon-booking-system/tags/10.30.32/src/SLN/Action/Ajax/SetCustomText.php#L17`

**Root cause:** there is no nonce in the handler, in the abstract base, or in the dispatcher.
Two checks are present — `is_user_logged_in()` and `current_user_can( 'manage_options' )` — and
both are satisfied by the victim's own session under a forged request. The saved value is later
interpolated into a PHP string literal and written to `translate-constants.php` inside the plugin
directory with `file_put_contents()`; `sanitize_text_field()` strips tags and control characters
but leaves `'`, `(`, `)`, `;`, `$` and `[]` — everything needed to close the literal and append
code. One administrator visiting an attacker's page yields RCE.

### Partial coverage: right branch protected, wrong branch not (CVE-2026-4068, 4.3, unauthenticated)

The add-field branch of an admin template validated a nonce properly; the delete-field branch
a dozen lines below processed `$_GET['delete']` and called `update_option()` with no verification.
`https://plugins.trac.wordpress.org/browser/add-custom-fields-to-media/tags/2.0.3/admin/partials/add-custom-fields-to-media-admin-display.php#L38`

**Root cause:** nonce coverage is per-branch, not per-file. A correct `wp_verify_nonce()` a few
lines earlier is what makes the unprotected branch invisible to review and to any rule that asks
"does this file check nonces". CSRF-009's exhaustive worklist exists for this: the question is
never *whether* a file verifies nonces but *whether every state-changing branch does*.
`$_GET`-triggered deletes are especially exposed because they need no form at all — a bare
`<img src="...">` on any page the administrator visits is enough.

### The nonce used as access control (CVE-2023-1023, 4.3, subscriber+)

A settings-save AJAX handler verified a nonce, correctly, and performed no capability check. The
advisory records the decisive detail: the required nonce was *accessible to all authenticated
users regardless of role*.
`https://plugins.trac.wordpress.org/changeset/2870465/wp-meta-seo/trunk?contextall=1&old=2869205&old_path=%2Fwp-meta-seo%2Ftrunk#file2`

**Root cause:** the plugin relied on nonce checks as a means of access control. A nonce is bound
to the session and the action; it is not bound to a role. Any Subscriber who can load a page that
prints that nonce holds a token indistinguishable from an Administrator's. The vendor fix added
`current_user_can()`; nothing about the nonce needed to change.

Five related CVE ids were assigned to five different handlers in the same release, which is the
usual pattern for this defect — a shared helper that verifies a nonce and returns is applied
across every AJAX action in the plugin, so the missing capability check is missing everywhere at
once. When you find one, enumerate the helper's callers rather than reporting a single handler.

### Option deletion from an admin screen with no nonce (CVE-2026-17608, 6.5, unauthenticated)

A debug/maintenance template executed a `delete_option()` branch keyed on a request parameter
with no verification, reachable for `siteurl`, `home`, `active_plugins`, `template` and
`stylesheet`.
`https://plugins.trac.wordpress.org/browser/wp-compress-image-optimizer/tags/7.10.03/templates/admin/debug_tool.php#L550`

**Root cause:** top-level code in an admin template treated "we are inside wp-admin" as proof of
intent. Deleting `siteurl`/`home` takes the site offline; deleting `active_plugins`,
`template` and `stylesheet` resets the site to a default theme with every plugin disabled —
including any security plugin. Availability-only CSRF still merits urgent triage when the options
in reach are core ones; see **WP-OPTIONS** for why the option name determines the severity.

## Detection guidance

**What the regexes catch reliably**

- `CSRF-002` is the highest-value single rule in this class: a statement-position
  `wp_verify_nonce()` is a no-op with essentially no benign form, and it is invisible to review
  because the line reads exactly like the correct `check_admin_referer()` idiom.
- `CSRF-001` catches the opt-out shape and deliberately does not fire on the correct negated
  guard, so its hits are close to pure.
- `CSRF-004` catches the missing-`$action` form, which is both a bug in itself and a strong
  signal that the surrounding guard was written carelessly.
- `CSRF-006` produces a short, complete list of REST routes with no declared boundary; combine
  it with the route's `methods` value and triage every non-read route.
- `CSRF-009` is small enough in most plugins to triage exhaustively, and exhaustive triage is
  the recommended workflow because the interesting defects are all *near* a correct check.

**What the regexes CANNOT catch — read the code**

1. **The absent check.** No regex finds a nonce that was never written. Enumerate handlers
   first — `wp_ajax_*`, `admin_post_*`, `register_rest_route`, `add_action('admin_init')`,
   `add_action('init')`, `add_action('plugins_loaded')`, shortcodes, and the plugin's own
   `$_GET['action']`/`task=` router (see `kb/reference/entry-points.md`) — then ask of each
   whether it changes state and whether it verifies anything. This is the majority of the class.
2. **Multi-line polarity.** `CSRF-005` is line-oriented. The common inverted form opens a brace
   on the `if` line and returns on the next. When any rule points at a `wp_verify_nonce()`, read
   the following two lines by hand.
3. **Verification in a shared helper.** `verify_ajax_request()`, `check_permissions()`,
   `is_valid_request()` — the call sites look protected and the defect lives one level down, in
   a feature flag, an early `return true`, or a branch that only warns. Follow every helper to
   its `wp_verify_nonce()` and check what happens on the false path.
4. **Whether the `$action` string is specific.** A plugin that uses one nonce action for every
   operation lets a nonce obtained for a harmless action authorise a destructive one. Collect all
   `wp_create_nonce()` / `wp_nonce_field()` action strings and compare against the verification
   strings; a single shared constant is a finding.
5. **Whether the nonce is obtainable.** Static analysis sees `check_ajax_referer()` and scores
   the handler protected. Determine whether the nonce is rendered into a public page
   (`CSRF-007` on a `wp_enqueue_scripts` enqueue), issued by a separate public endpoint, or
   printed into an HTML comment or data attribute. See WP-DELETE (CVE-2026-14487) for a public
   endpoint that handed out valid nonces to anonymous callers on request.
6. **Whether a capability check accompanies it.** This is the WP-AUTHZ question and it must be
   asked of every CSRF-009 hit. Nonce-only handlers are a distinct, common and separately
   scored defect.
7. **GET-triggered state change.** A handler that acts on `$_GET` is exploitable with an
   `<img>` tag and needs no form, no JavaScript and no user interaction beyond loading a page.
   Grep for `$_GET` inside anything named `*_delete*`, `*_save*`, `*_reset*`, `*_activate*`.
8. **The sink.** CSRF severity is the severity of what the forged request reaches. Cross-check
   every CSRF finding against WP-OPTIONS (option writes/deletes), WP-UPLOAD, WP-DELETE,
   WP-PRIVESC (user creation/role change) and WP-RCE (writes into a `.php` path). A "settings
   change" finding that can set `default_role` is a 9.8, not a 4.3.
9. **Non-REST routes that bypass core's nonce handling.** Custom `?rest_route=` handling,
   `template_redirect` dispatchers and `parse_request` hooks never reach
   `rest_cookie_check_errors()`, so none of core's automatic REST protection applies.
10. **`?_method=` / `X-HTTP-Method-Override`.** Core honours these on REST requests, so a
    top-level GET navigation can be converted into a POST. A route that assumed "POST only means
    a form we rendered" is wrong.

## Audit checklist

- [ ] Run `CSRF-002` and `CSRF-003` first. Every hit is a broken check standing where a working
      one is supposed to be; they are the cheapest true positives in the class.
- [ ] Run `CSRF-001` and treat each hit as a finding unless the state change is provably inside
      the `isset()` block.
- [ ] Run `CSRF-009` to build the complete list of verification sites, then for each one confirm:
      the result terminates or is tested; the `$action` is specific to this operation; a
      `current_user_can()` with the *right* capability sits alongside.
- [ ] Read two lines past every `wp_verify_nonce()` hit and check the polarity by hand —
      `CSRF-005` only sees the single-line form.
- [ ] Enumerate every state-changing entry point (`wp_ajax_*`, `admin_post_*`,
      `register_rest_route`, `admin_init`, `init`, `plugins_loaded`, shortcodes, custom routers)
      and diff that list against the `CSRF-009` list. Everything in the first list and not the
      second is an unprotected handler.
- [ ] Run `CSRF-006`; for each `__return_true` route, record the `methods` value. Every
      non-`READABLE` route is a finding.
- [ ] For each nonce action string, find where it is created. Run `CSRF-007` and check which
      enqueue hook the localisation runs on — `wp_enqueue_scripts` means the nonce is public.
- [ ] Grep for shared verification helpers (`verify_*`, `check_*`, `*_permission*`) and follow
      each to the actual `wp_verify_nonce()`; look for feature flags, early `return true`, and
      false paths that only log.
- [ ] Grep for `$_GET` inside delete/save/reset/activate handlers — those are exploitable with a
      bare `<img>` tag.
- [ ] Run `CSRF-008` and check whether any Referer test gates a state change, and what the code
      does when the header is absent.
- [ ] For every confirmed CSRF, follow the sink and re-score: option write (WP-OPTIONS), user
      creation or role change (WP-PRIVESC), file write (WP-RCE/WP-UPLOAD), file delete
      (WP-DELETE), SQL (WP-SQLI), `unserialize()` (WP-POI).
- [ ] Verify the fix uses `check_admin_referer()`/`check_ajax_referer()` (which terminate) or
      tests `wp_verify_nonce()`'s return value, unconditionally, with an operation-specific
      action string — and that a capability check was added rather than the nonce being relied
      on as one.
