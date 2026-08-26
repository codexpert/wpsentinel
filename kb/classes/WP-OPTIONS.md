---
class_id: WP-OPTIONS
title: Arbitrary option / settings update leading to site takeover
cwe: [CWE-862, CWE-269, CWE-15]
owasp: A01:2021-Broken Access Control
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 18
detection:
  - id: OPTIONS-001
    description: Option NAME taken from the request — the attacker chooses which option is written or deleted
    regex: '\b(update_option|update_site_option|update_network_option|add_option|delete_option|delete_site_option)\s*\(\s*[^,;]*(\$_(POST|GET|REQUEST|COOKIE)|->get_param\s*\()'
    confidence: high
    false_positive_notes: >-
      Essentially always a finding, and always Critical regardless of what the plugin intended
      the feature to do, because the reachable set includes default_role, users_can_register,
      siteurl, active_plugins and upload_path. The [^,;]* is deliberately unable to cross a comma,
      so the common and safe update_option( 'literal_name', $_POST['value'] ) does not match — the
      value being attacker-controlled is a different, far less severe problem.
  - id: OPTIONS-002
    description: Option name supplied by a variable rather than a literal or constant
    regex: '\b(update_option|update_site_option|update_network_option|add_option|delete_option|delete_site_option)\s*\(\s*\$[A-Za-z_]'
    confidence: medium
    false_positive_notes: >-
      Fires on the correct allowlisted form `foreach ( $allowed as $key ) { update_option( $key,
      ... ) }` as well as on the vulnerable one, because the difference is the provenance of the
      variable and a regex cannot see it. Triage by walking back to where the variable is set: a
      hardcoded array is safe, a request value or a stored configuration list is not. Catches the
      static-wrapper form (`Option::update_option( $k, $v )`) that OPTIONS-001 misses.
  - id: OPTIONS-003
    description: Settings import / restore / migrate entry point — bulk option writes with a single authorization decision
    regex: '\b[A-Za-z0-9_]*(import|restore|reset|backup|migrate|sync)_(settings|options|config|configuration)\s*\('
    confidence: medium
    false_positive_notes: >-
      Names a function, not a defect. These handlers are over-represented in this class because
      one weak check governs an unbounded number of option writes, and because the payload is
      usually a JSON or serialized blob whose keys nobody enumerates. For each hit, find the
      authorization check and then find the key allowlist; the allowlist is usually absent.
  - id: OPTIONS-004
    description: Option names that convert an arbitrary write into full takeover — use to grade an OPTIONS-001/002 hit
    regex: '[''"](users_can_register|default_role|default_user_role|admin_email|new_admin_email|siteurl|home|active_plugins|template|stylesheet|mailserver_url|mailserver_login|mailserver_pass|upload_path|upload_url_path)[''"]'
    confidence: medium
    false_positive_notes: >-
      Matches reads as well as writes, and legitimate plugins do read siteurl/admin_email/
      active_plugins. The rule is a severity oracle, not a vulnerability detector: when an
      OPTIONS-001 or OPTIONS-002 hit has no key allowlist, every name on this list is reachable
      and the finding is Critical. A hit in isolation only tells you the plugin touches a
      security-relevant option — check whether it also WRITES it and under what guard.
  - id: OPTIONS-005
    description: Anonymous AJAX route on a settings-shaped action name
    regex: 'wp_ajax_nopriv_[A-Za-z0-9_]*(option|setting|config|save|update|import|install|connect|restore)'
    confidence: medium
    false_positive_notes: >-
      A settings writer registered for anonymous callers is the 9.8 shape. Some hits are benign
      (a nopriv 'save_contact_form' that writes a post, not an option). Cross-reference with
      OPTIONS-007 to see whether an option sink is reachable from the handler, and remember the
      inverse case: a handler registered ONLY on wp_ajax_ is still reachable by every Subscriber.
  - id: OPTIONS-006
    description: Authentication standing in for authorization — credentials verified, capability never checked
    regex: '(->\s*login\s*\(\s*\$|\bwp_authenticate\s*\(|\bwp_check_password\s*\()'
    confidence: medium
    false_positive_notes: >-
      $wp_xmlrpc_server->login() and wp_authenticate() answer "are these credentials valid",
      which every Subscriber's credentials are. XML-RPC method handlers are the classic case
      because the login() call at the top of every method reads like a gate. Legitimate hits
      exist in genuine login flows; the finding is a login() call followed by a privileged
      operation with no current_user_can() between them.
  - id: OPTIONS-007
    description: Every option write or delete — the exhaustive worklist
    regex: '\b(update_option|update_site_option|update_network_option|add_option|delete_option|delete_site_option)\s*\('
    confidence: low
    false_positive_notes: >-
      Matches correct code by design. Most plugins have a manageable number of these. For each
      hit answer: is the option NAME fixed in code; is there a current_user_can( 'manage_options' )
      on the path; and is there a nonce. Note that this rule cannot see plugin-level wrappers
      (Options_Service::update_options(), $this->settings->save(), Carbon Fields, CMB2, ACF
      option pages) — find those wrappers by name and re-run the same three questions.
  - id: OPTIONS-008
    description: Option written from a decoded blob, so the key set is defined by the attacker's payload
    regex: '\b(update_option|update_site_option|add_option)\s*\([^;]*\b(json_decode|maybe_unserialize|unserialize|base64_decode)\s*\('
    confidence: medium
    false_positive_notes: >-
      Round-tripping a plugin's own stored JSON is legitimate; decoding a request body into an
      option is not. Where the blob is unserialize()d rather than json_decode()d the finding is
      also a WP-POI candidate. base64 in this position is a strong signal the payload was shaped
      to survive transport, i.e. that it is externally supplied.
fix_apis:
  - current_user_can( 'manage_options' )
  - register_setting() with sanitize_callback
  - check_admin_referer()
  - check_ajax_referer()
  - update_option()
  - rest_ensure_response()
  - sanitize_key()
  - wp_parse_args()
examples:
  - cve: CVE-2025-2907
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A settings-import handler had neither an authorization check nor a nonce and did not restrict imported keys to the plugin's own options, so an anonymous request could set default_user_role to administrator and enable open registration.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2907
    root_cause: Three independent controls absent at once — capability, nonce and key allowlist — on a handler whose payload is an arbitrary key/value map.
  - cve: CVE-2024-4898
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A REST configuration route declared permission_callback as __return_true and looped every key of a request-supplied options map into update_option(), then created users from the same payload.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-4898
    code_ref: https://plugins.trac.wordpress.org/browser/instawp-connect/tags/0.1.0.38/includes/class-instawp-rest-api.php#L926
    root_cause: An unauthenticated REST route whose only gate was an API key the attacker supplies themselves, writing an unbounded set of option names with no allowlist.
  - cve: CVE-2025-13342
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A front-end form builder's option-saving action accepted crafted form data from public pages and wrote users_can_register, default_role and admin_email.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-13342
    code_ref: https://plugins.trac.wordpress.org/changeset/3400432/acf-frontend-form-element
    root_cause: A generic "this form field maps to an option" feature with insufficient capability checks and no restriction on which option a field may target.
  - cve: CVE-2026-2446
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: An AJAX action with neither authorization nor CSRF checks allowed arbitrary WordPress options to be updated, and was reported specifically as a route to default_role and administrator creation.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-2446
    root_cause: Missing capability check on an option writer whose option name was not constrained.
  - cve: CVE-2026-12736
    year: 2026
    severity: 8.0
    auth: admin+
    summary: A REST route passed the request's option and data parameters straight to update_option() behind a permission_callback that checked only a shop-management capability, letting a non-administrator role write default_role and active_plugins.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12736
    code_ref: https://plugins.trac.wordpress.org/browser/wpify-woo/tags/5.4.10/src/Api/SettingsApi.php#L67
    root_cause: The permission_callback checked a capability appropriate to the plugin's own settings, while the sink could write every option on the site — capability scope and sink scope did not match.
  - cve: CVE-2026-4297
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: An XML-RPC method verified the caller's username and password and then wrote an arbitrary option name and value with no capability check at all.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4297
    code_ref: https://plugins.trac.wordpress.org/browser/newscred-publishing/tags/0.0.31/newscred.php#L272
    root_cause: Authentication treated as authorization. A Subscriber's credentials are valid credentials, so login() succeeds and nothing further is asked.
  - cve: CVE-2026-15212
    year: 2026
    severity: 8.8
    auth: unauthenticated
    summary: A settings AJAX handler merged every key of an attacker-supplied base64/JSON payload into the plugin's own option array with no key allowlist, letting the plugin's default-role setting be set to administrator and an attacker-known API token be planted.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15212
    code_ref: https://plugins.trac.wordpress.org/browser/wpo365-login/tags/43.2/Services/Ajax_Service.php#L805
    root_cause: A plugin-scoped option is sufficient for takeover when the plugin itself creates users — the write does not have to reach a core option name.
  - cve: CVE-2026-17608
    year: 2026
    severity: 6.5
    auth: unauthenticated
    summary: A debug template deleted whichever option a GET parameter named, with no nonce and no capability check, reaching siteurl, home, active_plugins, template and stylesheet.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-17608
    code_ref: https://plugins.trac.wordpress.org/browser/wp-compress-image-optimizer/tags/7.10.03/templates/admin/debug_tool.php#L550
    root_cause: delete_option() with a request-supplied name; deleting rather than writing an option is an equally complete primitive for disabling security plugins and resetting the theme.
  - cve: CVE-2024-4875
    year: 2024
    severity: 4.3
    auth: subscriber+
    summary: A dismiss-admin-notice AJAX handler had no capability check and did not constrain the option name it wrote, so a Subscriber could enable open registration through it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-4875
    code_ref: https://plugins.trac.wordpress.org/browser/ht-mega-for-elementor/trunk/admin/include/class.dynamic-notice.php#L52
    root_cause: A cosmetic feature reached the same sink as a settings screen; the option name came from the request rather than from the notice definition.
  - cve: CVE-2019-25141
    year: 2019
    severity: 9.8
    auth: unauthenticated
    summary: A mail-configuration plugin processed its settings form from admin_init with no capability check and no validation of which options were being written, allowing arbitrary options to be set and administrative accounts to be created.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2019-25141
    code_ref: https://plugins.trac.wordpress.org/changeset?old_path=%2Feasy-wp-smtp&old=2052057&new_path=%2Feasy-wp-smtp&new=2052058&sfp_email=&sfph_mail=
    root_cause: A settings handler on admin_init, which runs for unauthenticated requests to admin-ajax.php and admin-post.php, combined with no restriction on the option names accepted.
---

## What it is

A handler writes (or deletes) a WordPress option whose **name** the attacker controls, or writes
a fixed option whose contents are security-relevant, without a `manage_options` check. WordPress
stores nearly all of its own configuration in the `wp_options` table, so "arbitrary option write"
is not a settings-tampering bug — it is a site-takeover primitive with several independent paths
to administrator, at least one of which works on every install.

This class has no Wordfence category of its own, which is exactly why it is named here: the same
underlying defect is filed as *Missing Authorization*, *CSRF*, *Privilege Escalation* or
*Unauthorized Modification of Data* depending on which control was missing. Naming it separately
makes the escalation explicit, so an auditor grading "attacker can update an arbitrary option"
reaches Critical rather than Medium.

## Why an option write is takeover

Five chains, in rough order of how often they are used. **Chain 1 is the one to assume.**

### 1. `users_can_register` + `default_role` — anonymous self-service administrator

Defaults are `users_can_register => 0` and `default_role => 'subscriber'`. `default_role` is a
plain, unvalidated option: nothing in core restricts it to a low-privilege role. From
`wp_insert_user()`:

```php
	if ( isset( $userdata['role'] ) ) {
		$user->set_role( $userdata['role'] );
	} elseif ( ! $update ) {
		$user->set_role( get_option( 'default_role' ) );
	}
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/user.php` (lines 2658–2662)

So the sequence is:

1. `update_option( 'users_can_register', 1 )` — `/wp-login.php?action=register` now serves a form.
2. `update_option( 'default_role', 'administrator' )` — every account created without an
   explicit role gets `administrator`.
3. Register normally through core's own form. No exploit code, no second request against the
   vulnerable endpoint, nothing anomalous in the access log beyond a registration.
4. As administrator on a single site: `edit_plugins` / `install_plugins` / `activate_plugins`,
   i.e. arbitrary PHP.

Both writes are individually innocuous-looking, which is why an auditor must flag them as a pair.
This is `kb/reference/capability-matrix.md` §6.8, and it is the reason **any** arbitrary-option
write is Critical.

### 2. `siteurl` / `home` — JavaScript execution in the administrator's browser

`site_url()` reads the `siteurl` option and is what core uses to build the URLs of every script
it enqueues, including in `wp-admin`. Repointing `siteurl` at an attacker host makes the next
administrator page load fetch core's own JavaScript from that host. The attacker then executes
script in an authenticated admin context and can drive the plugin/theme editor directly.
Changing `home` alone is a defacement/availability issue; `siteurl` is code execution by proxy.

### 3. `active_plugins`, `template`, `stylesheet` — disable the defences

`active_plugins` is a plain array of `dir/file.php` strings. Core validates entries at load time:

```php
	foreach ( $active_plugins as $plugin ) {
		if ( ! validate_file( $plugin )                     // $plugin must validate as file.
			&& str_ends_with( $plugin, '.php' )             // $plugin must end with '.php'.
			&& file_exists( WP_PLUGIN_DIR . '/' . $plugin ) // $plugin must exist.
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/load.php` (lines 1029–1032)

The validation blocks traversal and requires the file to exist under `WP_PLUGIN_DIR` with a
`.php` extension — so this is **not** a direct arbitrary-include primitive. What it is:

- **Removing** entries deactivates plugins silently, including a security plugin or WAF, with no
  deactivation hooks fired and no admin notice. Every subsequent finding in the audit becomes
  easier to exploit.
- **Adding** an entry activates any `.php` file already inside `wp-content/plugins/` — including
  a vendored or example file that was never meant to be loaded, and including anything a separate
  WP-UPLOAD finding put there.

`template` and `stylesheet` switch the active theme; combined with a bundled theme that has its
own weaknesses, or simply to knock the site into an unstyled state, this is an integrity and
availability primitive. Deleting them (as an arbitrary `delete_option()` can) resets the site to
the default theme.

### 4. Outgoing-mail settings — intercept password resets

Core has no built-in SMTP option, so this chain runs through a plugin's own settings: SMTP host,
port, username and password consumed on `phpmailer_init`. Point them at a mail server the attacker
controls and every outgoing message — critically, the `wp-login.php?action=lostpassword` reset
link for the administrator — is delivered to the attacker. This needs no role change and no
registration, and it is precisely why mail-configuration plugins appear repeatedly in this class.

Do not confuse this with core's `mailserver_url` / `mailserver_login` / `mailserver_pass`: those
are the **POP3** settings for the legacy Post-via-e-mail feature, i.e. *incoming* mail. Writing
them does not intercept anything, but it does point a scheduled fetch at an attacker-controlled
mailbox whose contents become published posts, and it exposes whatever credentials were stored
there to anyone who can read the option.

### 5. `upload_path` / `upload_url_path` — relocate the uploads directory

Both are plain options consumed by `wp_upload_dir()`. Moving uploads out from under
`wp-content/uploads/` moves them out from under the `.htaccess` hardening and out-of-webroot
arrangements that assume that path, and can place attacker-uploaded files somewhere PHP executes.
This turns a benign "authenticated user can upload an image" feature into WP-UPLOAD.

### And: the plugin's own options are often enough

The write does not have to reach a core option name. A plugin that creates users has its own
"default role for new users" setting; a plugin with an API integration has its own shared-secret
option. CVE-2026-15212 is exactly this: the merge only touched the plugin's own option array, and
setting that plugin's `new_usr_default_role` to `administrator` plus planting a known API token
was full takeover. **Never dismiss an arbitrary-write finding because the option is namespaced.**

## Why it happens in WordPress

- **`update_option()` is a two-argument function with no ACL.** There is no capability layer,
  no allowlist, no protected-option concept. Anything that can call it can write anything.
- **Options are the generic key-value store, so plugins build generic endpoints on top.** A
  "save setting" AJAX action that takes `option` and `value` is the natural design and the
  vulnerable one.
- **`admin_init` is not an authorization boundary.** It fires on `admin-ajax.php` and
  `admin-post.php`, both of which serve unauthenticated requests, and `is_admin()` merely returns
  the `WP_ADMIN` constant — see `kb/reference/entry-points.md` §1. A settings handler hooked
  there and keyed on the presence of a POST field runs for anonymous callers.
- **Import/restore/migrate features are one check governing unbounded writes.** The payload is a
  blob; nobody enumerates its keys; the authorization decision happens once, at the top.
- **The capability chosen matches the plugin, not the sink.** `manage_woocommerce`,
  `edit_theme_options`, a plugin-defined `manage_x_settings` — each is a sensible gate for that
  plugin's own settings and a catastrophic one for a sink that can write `default_role`.
- **Authentication is mistaken for authorization.** XML-RPC handlers begin with
  `$wp_xmlrpc_server->login( $user, $pass )`, which returns a `WP_User` for *any* valid
  credentials. Subscriber credentials are valid credentials.
- **Nonces are mistaken for authorization.** A settings writer whose only control is a nonce is
  callable by every user who can obtain that nonce; see **WP-CSRF**.
- **Cosmetic handlers reach the same sink.** "Dismiss this notice", "set my preferred view",
  "mark onboarding complete" all call `update_option()` and receive a fraction of the scrutiny a
  settings screen gets. CVE-2024-4875 is a dismiss-notice handler that could set
  `users_can_register`.

## Vulnerable pattern

```php
// 1. The generic settings writer. The option NAME is a request parameter.
add_action( 'wp_ajax_example_save_option', 'example_save_option' );
add_action( 'wp_ajax_nopriv_example_save_option', 'example_save_option' );

function example_save_option() {
    update_option( $_POST['option'], $_POST['value'] );   // default_role = administrator
    wp_send_json_success();
}

// 2. The REST version, with a capability that fits the plugin and not the sink.
register_rest_route( 'example/v1', 'option', array(
    'methods'             => WP_REST_Server::CREATABLE,
    'callback'            => array( $this, 'save_option' ),
    'permission_callback' => function () {
        return current_user_can( 'manage_woocommerce' );  // Shop Manager, not Administrator
    },
) );
public function save_option( $request ) {
    update_option( $request->get_param( 'option' ), $request->get_param( 'data' ) );
}

// 3. The import handler: one authorization decision, unbounded writes.
function example_import_settings() {
    $settings = json_decode( base64_decode( $_POST['settings'] ), true );
    foreach ( $settings as $key => $value ) {
        update_option( $key, $value );        // every key the payload contains
    }
}

// 4. Authentication where authorization belongs (XML-RPC).
function example_setOption( $args ) {
    global $wp_xmlrpc_server;
    $wp_xmlrpc_server->escape( $args );
    if ( ! $wp_xmlrpc_server->login( $args[1], $args[2] ) ) {   // valid credentials != permission
        return $wp_xmlrpc_server->error;
    }
    update_option( $args[3], $args[4] );
}

// 5. Deletion is an equally complete primitive.
if ( ! empty( $_GET['delete_option'] ) ) {
    delete_option( $_GET['delete_option'] );   // active_plugins, siteurl, stylesheet
}
```

Shape 2 is the one that survives review: there is a `permission_callback`, it contains a real
capability, and a reviewer checking "does this route have authorization" answers yes. The defect
is that the capability's scope (this plugin's settings) is narrower than the sink's scope (every
option on the site).

## Secure pattern

Three obligations, and the key allowlist is the one that is usually skipped.

```php
add_action( 'wp_ajax_example_save_settings', 'example_save_settings' );
// No nopriv counterpart. Option writes are never anonymous.

function example_save_settings() {
    // 1. INTENT.
    check_ajax_referer( 'example_save_settings', 'nonce' );

    // 2. PERMISSION -- the capability the SINK needs. An option write is manage_options,
    //    whatever the plugin's own admin menu happens to be gated on.
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    // 3. ALLOWLIST OF KEYS, defined in code. The request may choose a VALUE from this map;
    //    it may never choose a NAME. This is what makes default_role unreachable.
    $schema = array(
        'example_layout'   => 'sanitize_key',
        'example_per_page' => 'absint',
        'example_notice'   => 'sanitize_text_field',
    );

    foreach ( $schema as $option => $sanitizer ) {
        if ( ! isset( $_POST[ $option ] ) ) {
            continue;
        }
        update_option( $option, call_user_func( $sanitizer, wp_unslash( $_POST[ $option ] ) ) );
    }

    wp_send_json_success();
}
```

For an import/restore feature, intersect the payload with the allowlist rather than iterating it:

```php
function example_import_settings() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Denied', 'example' ), 403 );
    }
    check_admin_referer( 'example_import_settings' );

    $payload = json_decode( file_get_contents( $_FILES['file']['tmp_name'] ), true );
    if ( ! is_array( $payload ) ) {
        wp_die( esc_html__( 'Malformed import.', 'example' ), 400 );
    }

    // Only keys this plugin owns survive. array_intersect_key() is the whole fix.
    $owned = array( 'example_layout', 'example_per_page', 'example_notice' );
    $safe  = array_intersect_key( $payload, array_flip( $owned ) );

    foreach ( $safe as $option => $value ) {
        update_option( $option, sanitize_text_field( is_scalar( $value ) ? $value : '' ) );
    }
}
```

And for admin settings screens, let core own the plumbing — `register_setting()` gives you a
per-option sanitiser and the Settings API supplies the nonce and the capability check:

```php
add_action( 'admin_init', function () {
    register_setting( 'example_group', 'example_layout', array(
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_key',
        'default'           => 'grid',
    ) );
} );
```

Non-negotiables: the option name is chosen by code, never by the request; the capability is
`manage_options` (or `manage_network_options` on a network) regardless of what the plugin's menu
uses; a nonce accompanies it; import payloads are intersected with an owned-key list; and there
is no `wp_ajax_nopriv_` registration on anything that writes an option.

## Real-world case studies

### An unauthenticated REST route that writes any option and then creates users (CVE-2024-4898, 9.8)

```php
	public function add_api_routes() {
		register_rest_route( $this->namespace . '/' . $this->version, '/config', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'config' ),
			'permission_callback' => '__return_true',
		) );
```

and, inside that callback:

```php
		// if any wp_option is passed, then store it
		if ( isset( $parameters['wp'] ) && isset( $parameters['wp']['options'] ) && is_array( $parameters['wp']['options'] ) ) {
			foreach ( $parameters['wp']['options'] as $option_key => $option_value ) {
				Option::update_option( $option_key, $option_value );
			}
		}

		// if any user is passed, then create it
		if ( isset( $parameters['wp'] ) && isset( $parameters['wp']['users'] ) ) {
			InstaWP_Tools::create_user( $parameters['wp']['users'] );
		}
```
`https://plugins.trac.wordpress.org/browser/instawp-connect/tags/0.1.0.38/includes/class-instawp-rest-api.php#L926`

**Root cause at that line:** `permission_callback => '__return_true'` on a POST route, and the
option loop has no allowlist — `$option_key` is whatever the JSON body contains. The only thing
resembling a gate earlier in the function is a check that an `api_key` parameter is present and
accepted by the vendor's key-generation call, and the attacker supplies their own key.

Note the shape of the write: `Option::update_option( $option_key, $option_value )` is a **static
wrapper**, so a rule anchored on `update_option\s*\(\s*\$_POST` finds nothing. OPTIONS-002 catches
it because the first argument is a variable; OPTIONS-007 catches it because the function name
survives the wrapper. **Plugin-level option wrappers are the main reason this class needs a
worklist rule rather than a precise one.** The same file shows why the class is Critical
regardless of intent: the very next block creates users from the same payload.

### The capability fits the plugin, not the sink (CVE-2026-12736, 8.0, non-administrator)

```php
			'option',
			array(
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'save_option' ),
					'permission_callback' => function () {
						return current_user_can( 'manage_woocommerce' );
					},
				),
			)
...
	public function save_option( $request ) {
		update_option( $request->get_param( 'option' ), $request->get_param( 'data' ), isset( $request->get_params()['autoload'] ) ? $request->get_param( 'autoload' ) : true );

		return new WP_REST_Response( array(), 201 );
	}
```
`https://plugins.trac.wordpress.org/browser/wpify-woo/tags/5.4.10/src/Api/SettingsApi.php#L67`

**Root cause at that line:** every control a reviewer looks for is present. There is a
`permission_callback`, it is not `__return_true`, and it contains a genuine `current_user_can()`.
`manage_woocommerce` is held by the Shop Manager role — a role that exists precisely so a
non-administrator can run a store — and the sink it guards can write `default_role`,
`users_can_register` and `active_plugins`.

**The audit question is not "is there a capability check" but "is the checked capability at least
as strong as the strongest thing the sink can do".** An option writer with no name allowlist can
do everything an administrator can do, so the only correct capability is `manage_options`. This
generalises to every plugin-defined capability: `manage_x_settings`, `edit_theme_options`,
`manage_woocommerce`, `edit_pages` — see `kb/reference/capability-matrix.md` §2 for who really
holds each one.

### Authentication is not authorization (CVE-2026-4297, 8.8, subscriber+)

```php
function nc_setOption( $args ) {
    global $wp_xmlrpc_server;
    $wp_xmlrpc_server->escape( $args );

    $username = $args[1];
    $password = $args[2];
    $option_name = $args[3];
    $option_value = $args[4];

    $decoded_value = str_replace("\\\"", "\"", $option_value, $count);

    if ( ! $wp_xmlrpc_server->login( $username, $password ) )
        return $wp_xmlrpc_server->error;

    update_option($option_name, $decoded_value);

    return true;
}
```
`https://plugins.trac.wordpress.org/browser/newscred-publishing/tags/0.0.31/newscred.php#L272`

**Root cause at that line:** `login()` verifies that the credentials are valid and returns the
`WP_User`. It does not ask what that user may do. A Subscriber's credentials are valid, so a
Subscriber reaches `update_option( $option_name, ... )` with both arguments under their control,
sets `default_role` to `administrator`, and registers a second account.

`$wp_xmlrpc_server->escape( $args )` at the top is SQL escaping and reads, at a glance, like
input handling — a second reason this function looks defended. **XML-RPC method handlers are a
systematically under-audited entry point** (`kb/reference/entry-points.md`): they do not appear
in a `wp_ajax_` or `register_rest_route` inventory, they are reachable at `/xmlrpc.php` on most
installs, and the `login()`-at-the-top convention makes the missing capability check look like a
present one. Enumerate `add_filter( 'xmlrpc_methods', ... )` explicitly.

### Deleting options is the same primitive (CVE-2026-17608, 6.5, unauthenticated)

```php
if (!empty($_GET['delete_option'])) {
    delete_option($_GET['delete_option']);
}
```
`https://plugins.trac.wordpress.org/browser/wp-compress-image-optimizer/tags/7.10.03/templates/admin/debug_tool.php#L550`

**Root cause at that line:** top-level template code, triggered by a `$_GET` parameter, with no
nonce and no capability check of its own beyond the plugin-defined capability on the admin page.
`$_GET`-triggering means a bare `<img src="...">` on any page an administrator visits is a
complete exploit.

Deleting is not a lesser primitive than writing. Removing `siteurl` and `home` takes the site
offline; removing `active_plugins` deactivates every plugin including the security stack;
removing `template` and `stylesheet` drops the site to a default theme. The CVSS here is 6.5
because the assessed impact is integrity/availability only — but on a site where the next step of
the attack is blocked by a security plugin, "deactivate everything" is the enabling step for a
9.8. Grade delete primitives by what they *unblock*, not only by what they break.

### The cosmetic handler that reaches the settings sink (CVE-2024-4875, 4.3, subscriber+)

A "dismiss this admin notice" AJAX handler had no capability check and did not constrain which
option it wrote, so a Subscriber could set `users_can_register`.
`https://plugins.trac.wordpress.org/browser/ht-mega-for-elementor/trunk/admin/include/class.dynamic-notice.php#L52`

**Root cause:** the option name came from the request (the notice identifier) rather than from a
server-side registry of known notices, and the handler carried no capability check because
"dismissing a notice" felt harmless. The vendor fix resolves the notice through
`get_notice_by_id()` and checks the capability recorded against that notice definition — i.e. it
converts the attacker-chosen name into a server-chosen one, which is the correct shape.

Two things generalise. First, **any handler whose job is a UI preference is an option writer**:
dismiss, hide, collapse, "don't show again", "set my columns", onboarding-step trackers. Second,
this CVE is scored 4.3 (`C:N/I:L/A:N`) and the same defect scored 9.8 elsewhere; the difference
is whether the scorer traced the option name to `users_can_register`. **Do that trace yourself.**

### One weak check, unbounded writes (CVE-2025-2907, 9.8 and CVE-2019-25141, 9.8)

Two settings-import defects a decade apart, with the same three-part failure:

- A settings-import routine with no authorization check and no CSRF check, and no restriction
  limiting the imported keys to the plugin's own options. The advisory names the outcome
  precisely: `default_user_role` set to `administrator` plus `users_can_register`, then register
  as an administrator.
- A mail-configuration plugin whose settings handler ran on `admin_init` with no capability check
  and insufficient input validation, allowing arbitrary options to be modified and administrative
  accounts to be injected.
  `https://plugins.trac.wordpress.org/changeset?old_path=%2Feasy-wp-smtp&old=2052057&new_path=%2Feasy-wp-smtp&new=2052058&sfp_email=&sfph_mail=`

**Root cause in both:** the payload is an arbitrary key/value map and the code iterates it. An
import feature makes a single authorization decision and then performs an unbounded number of
writes, so a missing check there is worth more than a missing check anywhere else in the plugin.

The second case also illustrates the `admin_init` trap that
`kb/reference/entry-points.md` §1 documents: `admin_init` fires on `admin-ajax.php` and
`admin-post.php`, which serve unauthenticated requests, so a handler registered there and keyed
only on the presence of a POST field is anonymous-reachable. **`is_admin()` and "hooked to
admin_init" are not authorization.**

### The plugin's own option was enough (CVE-2026-15212, 8.8, unauthenticated)

The CSRF-enabled settings merge analysed under **WP-CSRF** never touched a core option name.
`Options_Service::update_options()` merged every key of the attacker's base64/JSON payload into
the plugin's single `wpo365_options` array with no allowlist, and the advisory records the payload
that matters: enable the plugin's SCIM endpoint, plant a known `scim_secret_token`, and set the
plugin's `new_usr_default_role` to `administrator`.
`https://plugins.trac.wordpress.org/browser/wpo365-login/tags/43.2/Services/Ajax_Service.php#L805`

**Root cause:** namespacing an option does not namespace its consequences. Any plugin that
provisions users, authenticates users, or executes anything based on configuration has an option
whose value is equivalent to `default_role`. When you find an unrestricted merge into a plugin's
own option array, read that plugin's option consumers and look for: a default-role setting, a
shared secret, a webhook or callback URL, a file path, a "debug mode" that dumps credentials, and
any option consulted before an authentication decision.

## Detection guidance

**What the regexes catch reliably**

- `OPTIONS-001` is the highest-value rule: a request-named option is a Critical finding with
  essentially no benign form, and it is deliberately narrowed so the common
  `update_option( 'literal', $_POST['v'] )` does not dilute it.
- `OPTIONS-002` catches the wrapper and loop forms `OPTIONS-001` cannot see, at the cost of
  matching correct allowlisted code. Triage is a single backwards walk to the variable's source.
- `OPTIONS-004` is a severity oracle rather than a detector — use it to answer "how bad is this
  OPTIONS-001 hit" and to find code that already reads security-relevant options.
- `OPTIONS-006` reliably finds the XML-RPC `login()`-as-authorization shape, which no
  capability-focused rule finds because there is no `current_user_can()` to inspect.

**What the regexes CANNOT catch — read the code**

1. **Plugin-level option wrappers.** `Options_Service::update_options()`, `$this->settings->save()`,
   `Carbon_Fields`, `CMB2`, ACF option pages, and any `class Settings { public function set() }`.
   Find the wrapper by grepping for `update_option` once, note the class it lives in, then grep
   for that class's method names. This is where the highest-severity findings hide.
2. **Whether a variable option name is allowlisted.** `OPTIONS-002` gives candidates. The
   question is where the variable came from: hardcoded array (safe), request (Critical), stored
   configuration an attacker can write (Critical, two-step).
3. **Whether the capability matches the sink.** No regex decides that
   `manage_woocommerce` is too weak for `update_option()`. Take every capability guarding an
   option write to `kb/reference/capability-matrix.md` §2 and ask which roles hold it.
4. **Whether the handler is reachable anonymously.** `admin_init`, `init`, `plugins_loaded`,
   `template_redirect`, `wp_loaded`, XML-RPC methods, custom `?action=` routers and REST routes
   registered in a loop. Enumerate entry points separately and join against the option-sink list.
5. **Import payload shape.** A `foreach` over a decoded blob is a loop over attacker-chosen keys;
   whether an `array_intersect_key()` guards it is a semantic question.
6. **Two-step writes.** Handler A stores a value in post meta or a transient; handler B reads it
   and calls `update_option()`. Nothing near the sink is tainted. Same working method as
   WP-DELETE's DELETE-008: find the sink, identify the storage key, audit every writer.
7. **Serialised option contents.** Many plugin options are arrays; a partial write that changes
   one nested key can flip a security setting without the option name looking dangerous.
   Read what consumes the option, not only what writes it.
8. **The consequence of the specific option.** A plugin option named `default_user_role`,
   `auto_login`, `api_secret`, `webhook_url`, `debug_log_path` or `allowed_origins` is a takeover
   primitive with a harmless name. Grep the plugin's own option keys and read their consumers.
9. **Multisite.** `update_site_option()` / `update_network_option()` write network-wide settings
   and require `manage_network_options`, which even a site Administrator does not hold. A plugin
   that checks `manage_options` before a network write is an escalation on every network.
10. **`register_setting()` without `sanitize_callback`.** Core will store whatever the Settings
    API receives; the capability is handled but the value is not.

## Audit checklist

- [ ] Run `OPTIONS-001` first. Every hit is Critical — confirm the reachable option set is
      unbounded, then stop looking for mitigations.
- [ ] Run `OPTIONS-007` to build the complete option-sink worklist, and separately grep for the
      plugin's own settings wrapper class; add its methods to the worklist.
- [ ] For each sink, answer three questions: is the option NAME fixed in code; is there a
      `current_user_can( 'manage_options' )` on every path to it; is there a nonce.
- [ ] Run `OPTIONS-002` and walk each variable back to its origin — hardcoded array, request, or
      stored configuration. Treat stored configuration as attacker-controlled until you have
      audited every writer of it.
- [ ] Run `OPTIONS-004` and cross-reference with the sink list; anything that can write a name on
      that list is Critical regardless of the plugin's intent.
- [ ] Run `OPTIONS-003` and `OPTIONS-008`; for every import/restore handler, look specifically
      for `array_intersect_key()` or an equivalent key filter. Its absence is the finding.
- [ ] Run `OPTIONS-005`, and separately check every `wp_ajax_` (non-nopriv) option writer — those
      are reachable by every Subscriber.
- [ ] Run `OPTIONS-006` and, for each `login()` / `wp_authenticate()` hit, check whether a
      `current_user_can()` stands between it and the privileged operation.
- [ ] Enumerate `add_filter( 'xmlrpc_methods', ... )` and audit each method as its own endpoint.
- [ ] Grep for `add_action( 'admin_init'` and `add_action( 'init'` handlers that key on the
      presence of a `$_POST`/`$_GET` field — those run for anonymous requests.
- [ ] Identify UI-preference handlers (`*dismiss*`, `*hide*`, `*_notice*`, `*onboarding*`,
      `*_seen*`) and check whether the option name is request-supplied.
- [ ] List the plugin's own option keys and read their consumers; flag any that set a role,
      hold a secret, name a URL or path, or are consulted before an authentication decision.
- [ ] On multisite, check that any `update_site_option()` / `update_network_option()` is guarded
      by `manage_network_options`, not `manage_options`.
- [ ] Verify each fix constrains the option NAME in code — a fix that only sanitises the value,
      or that only adds a nonce, leaves the class intact.
