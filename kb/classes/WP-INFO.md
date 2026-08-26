---
class_id: WP-INFO
title: Sensitive Information Disclosure
cwe: [CWE-200, CWE-201, CWE-209, CWE-532, CWE-538, CWE-552, CWE-359]
owasp: A01:2021-Broken Access Control
severity_typical: medium
auth_required_typical: unauthenticated
prevalence_rank: 15
detection:
  - id: INFO-001
    description: Log, backup, dump or export file written to a path under the document root
    regex: '(wp_upload_dir\s*\(|[''"]basedir[''"]|WP_CONTENT_DIR|ABSPATH|plugin_dir_path\s*\()[^;]*[''"][^''"]*\.(log|sql|bak|zip|tar|gz|csv|txt|json)[''"]'
    confidence: medium
    false_positive_notes: >-
      Matches any literal filename with a data extension joined to a webroot-relative base.
      Many hits are legitimate assets (a bundled .json or .txt). The finding is a file whose
      CONTENT is sensitive — a debug/payment/API log, a database dump, a backup archive, a
      CSV export of form entries — sitting anywhere the web server will serve it. The base
      being wp_upload_dir()['basedir'] is the worst case, because uploads/ is served with
      directory indexes on many hosts and is never protected by core. Note the regex only
      sees a literal filename; a name built from variables (the W3TC case study) is missed.
  - id: INFO-002
    description: Request data dumped with var_dump/print_r/var_export
    regex: '\b(var_dump|print_r|var_export|debug_zval_dump)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|SESSION|ENV)'
    confidence: high
    false_positive_notes: >-
      Debug scaffolding left in shipped code. A hit dumps the whole superglobal into the
      response, which for $_SERVER includes internal paths, and for $_COOKIE includes the
      victim's session cookies when the handler output is reflected. Practically always a
      finding; the only benign form is print_r($x, true) captured into a variable that is
      then discarded, which this regex cannot distinguish — read the surrounding lines.
  - id: INFO-003
    description: Plugin turns on error display or debug logging
    regex: '(ini_set\s*\(\s*[''"](display_errors|error_reporting)[''"]\s*,\s*[''"]?(1|on|On|true)|define\s*\(\s*[''"]WP_DEBUG(_DISPLAY|_LOG)?[''"]\s*,\s*true)'
    confidence: high
    false_positive_notes: >-
      A plugin must never enable display_errors or WP_DEBUG_DISPLAY: PHP warnings carry
      absolute filesystem paths, and a warning raised inside $wpdb can echo the query.
      WP_DEBUG_LOG=true writes wp-content/debug.log, which is world-readable by default.
      Occasionally guarded by a "development mode" option, which is a mitigating factor and
      not a fix — check whether the option is writable from a request.
  - id: INFO-004
    description: Hardcoded API key, token or secret literal in source
    regex: '[''"]?(api[_-]?key|apikey|secret|client_secret|access_token|auth_token|private_key|app_password|bearer)[''"]?\s*(=>|=|:)\s*[''"][A-Za-z0-9_\-\.]{16,}[''"]'
    confidence: medium
    false_positive_notes: >-
      Matches OAuth client IDs and public/publishable keys as well as genuine secrets, and
      matches placeholder strings in documentation blocks. Triage by asking what the value
      authorises. Remember that anything in a plugin file is readable by every WordPress
      installation of that plugin, so a "shared" secret compiled into the source is public —
      this is the CVE-2026-14487 shape referenced in WP-DELETE, where a hardcoded salt made
      a keyed hash forgeable offline.
  - id: INFO-005
    description: User records or user meta returned in a JSON response
    regex: 'wp_send_json[a-z_]*\s*\([^;]*\b(get_users|get_userdata|WP_User_Query|get_user_meta|user_email|user_pass|user_login)\b'
    confidence: medium
    false_positive_notes: >-
      A hit is a finding only if the endpoint is reachable below the privilege that
      list_users would require, or if it returns fields the caller should not see
      (user_email, user_login, user_pass hash, user_activation_key). Confirm the
      registration site: wp_ajax_nopriv_, permission_callback => __return_true, or a
      shortcode all put this on an anonymous route. Multi-line array construction is
      common, so this single-line regex misses many real cases.
  - id: INFO-006
    description: Whole option value returned in a JSON response
    regex: 'wp_send_json[a-z_]*\s*\([^;]*\bget_option\s*\('
    confidence: medium
    false_positive_notes: >-
      Settings-dump endpoints are the standard way plugin admin screens hydrate their UI,
      and the standard way API keys leak: the settings array usually contains the
      integration credentials next to the display preferences. A hit is a finding if the
      route is reachable below Administrator, or if no field allowlist is applied before
      the response is built.
  - id: INFO-007
    description: Directory listing built from a request-controlled path
    regex: '\b(scandir|glob|opendir|readdir|DirectoryIterator|RecursiveDirectoryIterator|FilesystemIterator)\s*\(\s*[^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      Enumeration of an arbitrary directory reveals backup names, .sql dumps, private
      uploads and the plugin/theme inventory used to pick the next exploit. Note this only
      fires when the superglobal is on the same statement; the common real shape is
      scandir($path) with $path assigned from $_POST several lines earlier — see the
      directory-listing case study. Sweep for bare scandir/glob calls separately and trace
      each argument.
  - id: INFO-008
    description: Every nonce mint site — determine who can obtain each nonce
    regex: '\bwp_create_nonce\s*\('
    confidence: low
    false_positive_notes: >-
      Deliberately broad and cheap: most plugins have a handful. The question for each hit
      is which template, hook or endpoint renders it. A nonce minted inside a wp_head,
      wp_footer, wp_enqueue_scripts or shortcode callback is handed to every anonymous
      visitor, which means every handler protected only by check_ajax_referer() against
      that nonce is effectively unauthenticated. This rule exists to feed that question,
      not to produce findings on its own.
  - id: INFO-009
    description: Exception text or database error echoed to the response
    regex: '(wp_send_json[a-z_]*\s*\(|\becho\s|\bprint\s|\bprint_r\s*\(|\bwp_die\s*\()[^;]*(->getMessage\s*\(|->last_error|mysqli_error\s*\(|error_get_last\s*\()'
    confidence: medium
    false_positive_notes: >-
      $wpdb->last_error and mysqli_error() disclose table names, column names and prefix —
      the reconnaissance a blind SQLi needs. Exception messages from file operations
      disclose absolute paths. Benign when the message is a plugin-authored string, so read
      what the exception actually is. error_get_last() after a failed file read reports the
      open failure including the resolved path, which turns a "no output" arbitrary-read
      bug into a filesystem oracle.
  - id: INFO-010
    description: Any debug-dump primitive — worklist
    regex: '\b(var_dump|print_r|var_export|debug_print_backtrace|phpinfo)\s*\('
    confidence: low
    false_positive_notes: >-
      Noisy: print_r($x, true) is a legitimate idiom for building log strings. Use it to
      enumerate, then keep the hits whose output reaches echo/print/wp_send_json or a
      file under the webroot. phpinfo() is never acceptable in shipped plugin code and any
      hit on it should be promoted immediately.
  - id: INFO-011
    description: Superglobal read with an attacker-named key
    regex: '\$_(COOKIE|SERVER|SESSION|ENV)\s*\[\s*\$'
    confidence: high
    false_positive_notes: >-
      The index is a variable, so the caller chooses WHICH cookie, header, session key or
      environment variable is read. If that value is then returned or rendered, the endpoint
      is a universal read primitive over the victim's cookie jar and the server environment
      — including wordpress_logged_in_* and any secret placed in $_ENV. Benign only when the
      variable is provably drawn from a hard-coded allowlist on a nearby line.
fix_apis:
  - current_user_can()
  - wp_upload_dir()
  - wp_mkdir_p()
  - is_user_logged_in()
  - rest_ensure_response()
  - wp_send_json_error()
  - map_meta_cap()
  - wp_generate_password()
examples:
  - cve: CVE-2024-13818
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: A payment log containing transaction data was written to a fixed, guessable path inside the publicly served uploads directory, so it could be fetched by URL with no authentication.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13818
    code_ref: https://plugins.trac.wordpress.org/browser/pie-register/trunk/classes/base_variables.php#L76
    root_cause: A log file was placed under wp-content/uploads/, which the web server serves directly and which core never protects.
  - cve: CVE-2024-12008
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: Debug logging wrote module log files to a deterministic path under the cache directory in the document root, retrievable by anyone who could guess or derive the module name.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-12008
    code_ref: https://plugins.trac.wordpress.org/browser/w3-total-cache/tags/2.8.0/Util_Debug.php#L45
    root_cause: The log path is composed of a webroot-relative directory, a zero-padded blog id and a fixed module name, so it is fully predictable and no access control stands in front of it.
  - cve: CVE-2025-7654
    year: 2025
    severity: 8.8
    auth: contributor+
    summary: A shortcode returned the value of any cookie named in one of its attributes, so a low-privileged author could publish a page that echoed a viewing administrator's session cookies.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-7654
    code_ref: https://plugins.trac.wordpress.org/browser/funnel-builder/tags/3.11.0.2/woofunnels/includes/class-bwf-data-tags.php#L52
    root_cause: $_COOKIE was indexed by an attacker-chosen key with no allowlist, turning a personalisation tag into an arbitrary cookie reader.
  - cve: CVE-2024-9821
    year: 2024
    severity: 8.8
    auth: subscriber+
    summary: An AJAX endpoint returned the plugin's complete settings map, including third-party API credentials, behind a nonce that the plugin printed into the head of every front-end page.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9821
    code_ref: https://plugins.trac.wordpress.org/browser/bot-for-telegram-on-woocommerce/trunk/nuxy/helpers/helpers.php#L53
    root_cause: No capability check on a settings-dump handler, and the nonce that stood in for one was minted on wp_head for every visitor.
  - cve: CVE-2025-13891
    year: 2025
    severity: 6.5
    auth: author+
    summary: A media-browser AJAX action listed the contents of any directory named in the request, with sanitize_text_field() as the only processing applied to the path.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-13891
    code_ref: https://plugins.trac.wordpress.org/browser/modula-best-grid-gallery/tags/2.12.26/includes/admin/class-modula-gallery-upload.php#L247
    root_cause: sanitize_text_field() leaves ../ intact and the containment helper only checked is_dir(), so scandir() ran against any directory on the filesystem.
  - cve: CVE-2023-6266
    year: 2024
    severity: 7.5
    auth: unauthenticated
    summary: A front-end download route streamed backup archives when a plugin configuration flag was set, treating that flag as if it were an authorization decision.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-6266
    code_ref: https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.5/includes/initializer.php#L1049
    root_cause: A stored setting was ORed with the capability check, so enabling "direct download" removed authentication from an endpoint that hands out a full site backup.
  - cve: CVE-2024-13622
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: Customer-submitted order attachments were stored in a web-served directory with predictable names and no deny rules, so anyone who guessed a filename could retrieve another customer's file.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13622
    code_ref: https://plugins.trac.wordpress.org/browser/woo-addon-uploads/trunk/includes/class-wau-front-end.php#L110
    root_cause: Private user uploads were written into the publicly served uploads tree with no .htaccess/web.config deny rules and no unguessable component in the filename.
---

## What it is

Data that should not be readable is returned to someone who should not have it. There is no
injection and often no traversal: the file is simply in a directory the web server serves,
the endpoint simply answers everybody, or the response simply contains more fields than the
caller was entitled to. The disclosed material ranges from an absolute filesystem path in a
PHP warning to a full database dump, an API key, or another user's email address.

Rated on its own, information disclosure is usually Low or Medium (see
`kb/reference/capability-matrix.md` §6.3). Its real importance is as a **pivot**: a leaked
nonce converts a CSRF-protected handler into an open one, a leaked user list converts a
password-spray into a targeted attack, a leaked `wp-config.php` path makes a traversal
payload reliable, and leaked SQL error text is exactly what turns blind SQL injection into
extraction. Always rate the chain, not the link.

## Why it happens in WordPress

- **`wp-content/uploads/` is a public directory with no access control.** Core protects
  nothing in it. Plugins that need "somewhere to write" reach for
  `wp_upload_dir()['basedir']` because it is the one directory guaranteed to be writable —
  and it is also the one directory guaranteed to be *served*. Logs, CSV exports, generated
  PDFs, invoices, form attachments and database dumps all end up there.
- **Directory indexes.** Apache without `Options -Indexes`, and nginx with `autoindex on`,
  will list `wp-content/uploads/my-plugin/` for anyone. Core ships an empty `index.php` in
  each uploads subdirectory it creates; plugins that create their own subdirectories with
  `wp_mkdir_p()` usually do not.
- **A nonce is not a secret.** `wp_create_nonce()` is deterministic given the action, the
  user and the session token, and it is *designed* to be published in the page. Any nonce
  rendered by a `wp_head`, `wp_footer`, `wp_enqueue_scripts` or shortcode callback is
  handed to anonymous visitors. Handlers "protected" by `check_ajax_referer()` against such
  a nonce are unauthenticated endpoints. This is the same observation that makes several
  WP-DELETE cases 9.1.
- **`WP_DEBUG_LOG` writes into the webroot.** `wp-content/debug.log` is served by default.
  A plugin that flips `WP_DEBUG_LOG` on, or that writes its own log next to it, publishes
  every warning — including the ones containing absolute paths and query fragments.
- **The REST API is public infrastructure.** `permission_callback => '__return_true'` is
  the documented way to say "public", and it is used on routes that return orders, form
  entries and user profiles. Core's own `/wp-json/wp/v2/users` also enumerates any user who
  has authored a published post — expected behaviour, but it is the baseline an audit
  should assume the attacker already has.
- **`$_COOKIE` and `$_SERVER` are read with variable keys.** Personalisation features
  ("show the value of cookie X in this shortcode") are written generically, and the generic
  version reads the session cookie just as happily as the UTM cookie.
- **Options are dumped wholesale.** Admin screens hydrate from `get_option()` through an
  AJAX call; the option array holds the display settings *and* the integration credentials,
  and nobody adds a field allowlist.

## Vulnerable pattern

```php
// 1. A log in the one directory the web server is guaranteed to serve.
$upload = wp_upload_dir();
$log    = $upload['basedir'] . '/example-logs/payments.log';   // .../uploads/example-logs/payments.log
file_put_contents( $log, $entry, FILE_APPEND );                // fetchable by URL, forever

// 2. A settings dump whose only gate is a nonce that every visitor is given.
add_action( 'wp_head', 'example_print_nonce' );                // <-- anonymous visitors too
function example_print_nonce() {
    echo '<script>var example_nonce = "' . wp_create_nonce( 'example_settings' ) . '";</script>';
}

add_action( 'wp_ajax_example_get_settings', 'example_get_settings' );
function example_get_settings() {
    check_ajax_referer( 'example_settings', 'nonce' );          // NOT an authorization check
    wp_send_json( get_option( 'example_settings' ) );           // includes the API key
}

// 3. A personalisation tag that reads whichever cookie it is told to.
add_shortcode( 'example_cookie', function ( $atts ) {
    return isset( $_COOKIE[ $atts['key'] ] ) ? esc_html( $_COOKIE[ $atts['key'] ] ) : '';
} );

// 4. Debug scaffolding and raw error text.
function example_ajax() {
    var_dump( $_POST );                                        // dumps everything, including cookies echoed back
    global $wpdb;
    $wpdb->get_results( $sql );
    if ( $wpdb->last_error ) {
        wp_send_json_error( $wpdb->last_error );                // table names, column names, prefix
    }
}
```

Each of these is reachable with a plain `curl`. None of them involves traversal, injection
or a race.

## Secure pattern

```php
/**
 * 1. Private storage. Two independent controls: put the file outside the served tree if the
 *    host allows it, and make the name unguessable either way.
 */
function example_private_dir() {
    $base = wp_upload_dir();
    $dir  = trailingslashit( $base['basedir'] ) . 'example-private';

    if ( ! is_dir( $dir ) ) {
        wp_mkdir_p( $dir );
    }

    // Deny rules for both server families, plus an index file for hosts that ignore both.
    if ( ! file_exists( $dir . '/.htaccess' ) ) {
        file_put_contents( $dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
    }
    if ( ! file_exists( $dir . '/web.config' ) ) {
        file_put_contents( $dir . '/web.config', '<configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>' );
    }
    if ( ! file_exists( $dir . '/index.php' ) ) {
        file_put_contents( $dir . '/index.php', '<?php // Silence is golden' );
    }

    return $dir;
}

// Unguessable filename, so the file is safe even where the deny rules are ignored.
$name = wp_generate_password( 32, false, false ) . '-invoice.pdf';
file_put_contents( trailingslashit( example_private_dir() ) . $name, $pdf );
```

```php
/**
 * 2. Capability first, nonce second, allowlist third. All three, in that order.
 */
add_action( 'wp_ajax_example_get_settings', 'example_get_settings' );   // note: no _nopriv_
function example_get_settings() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => __( 'Forbidden', 'example' ) ), 403 );
    }
    check_ajax_referer( 'example_settings', 'nonce' );

    $settings = get_option( 'example_settings', array() );

    // Return only what the screen needs. Never the whole option.
    $public = array(
        'layout'   => isset( $settings['layout'] ) ? $settings['layout'] : 'grid',
        'per_page' => isset( $settings['per_page'] ) ? (int) $settings['per_page'] : 10,
        // Prove the key is configured without disclosing it.
        'api_key_set' => ! empty( $settings['api_key'] ),
    );

    wp_send_json_success( $public );
}
```

```php
/**
 * 3. Never index a superglobal with a caller-supplied key.
 */
add_shortcode( 'example_cookie', function ( $atts ) {
    $allowed = array( 'example_utm_source', 'example_campaign' );
    $key     = isset( $atts['key'] ) ? sanitize_key( $atts['key'] ) : '';

    if ( ! in_array( $key, $allowed, true ) ) {
        return '';
    }
    return isset( $_COOKIE[ $key ] ) ? esc_html( wp_unslash( $_COOKIE[ $key ] ) ) : '';
} );
```

```php
/**
 * 4. Log to the error log, respond with a generic message.
 */
if ( $wpdb->last_error ) {
    error_log( '[example] query failed: ' . $wpdb->last_error );   // server-side only
    wp_send_json_error( array( 'message' => __( 'Request failed', 'example' ) ), 500 );
}
```

Two rules worth stating flatly:

- **A plugin must never enable `display_errors`, `WP_DEBUG`, or `WP_DEBUG_DISPLAY`.**
  Those are site-owner decisions taken in `wp-config.php`, and a plugin that sets them
  publishes filesystem paths to every visitor.
- **A deny file is a second line of defence, not the first.** Hosts run nginx configurations
  that ignore `.htaccess` entirely. Unguessable filenames and out-of-webroot storage are the
  controls that survive that; deny rules are the belt on top of the braces.

## Real-world case studies

### The log in the uploads directory (CVE-2024-13818, 7.5, unauthenticated)

The remediated code documents the original path while cleaning it up:

```php
// delete payment logs file - temperorly
$upload_dir = wp_upload_dir();
$temp_dir = $upload_dir['basedir'] . "/pie-logs/payment-log.log";

if ( file_exists($temp_dir) ) { // Check if file exists
    ...
    $wp_filesystem->delete( $temp_dir );
}

$secure_log_dir = WP_CONTENT_DIR . "/pie-logs"; // Secure directory
```
`https://plugins.trac.wordpress.org/browser/pie-register/trunk/classes/base_variables.php#L76`

**Root cause at that line:** `wp_upload_dir()['basedir']` resolves to
`wp-content/uploads/`, which every web server serves and no core rule protects. The path
had no random component, so `https://target/wp-content/uploads/pie-logs/payment-log.log`
retrieved the transaction log directly. The fix moves the directory up one level to
`WP_CONTENT_DIR` — note that this is *also* inside the webroot, and is only safer because
plugin authors then add deny rules; the durable control is the one in the secure pattern
above. When auditing, treat every `wp_upload_dir()` join whose filename ends in `.log`,
`.sql`, `.csv`, `.txt` or `.zip` as a finding until the deny rules and the filename entropy
are both confirmed.

### A predictable log path, built from variables (CVE-2024-12008, 7.5, unauthenticated)

```php
$from_dir = W3TC_CACHE_DIR;
if ( defined( 'W3TC_DEBUG_DIR' ) && W3TC_DEBUG_DIR ) {
    $dir_path = W3TC_DEBUG_DIR;
    ...
} else
    $dir_path = Util_Environment::cache_dir( 'log' );
$filename = $dir_path . '/' . $postfix . '/' . $module . '.log';
```
`https://plugins.trac.wordpress.org/browser/w3-total-cache/tags/2.8.0/Util_Debug.php#L45`

**Root cause at that line:** the three components are a webroot-relative cache directory, a
`sprintf( '%06d', $blog_id )` blog identifier, and a fixed module name from a small known
set. Nothing in the path is secret, so an attacker enumerates the module names and fetches
each log. **Detection lesson:** `INFO-001` cannot see this — there is no literal filename on
the line, only `$module . '.log'`. Any sweep for exposed logs must also grep for `'.log'`,
`'.sql'`, `'.csv'` as *fragments* and trace the variables around them.

### A shortcode that reads any cookie (CVE-2025-7654, 8.8, contributor+)

```php
public function get_cookie( $attr ) {
    $attr = shortcode_atts( array(
        'key' => '',
    ), $attr );

    if ( empty( $attr['key'] ) ) {
        return '';
    }

    $data = isset( $_COOKIE[ $attr['key'] ] ) ? bwf_clean( $_COOKIE[ $attr['key'] ] ) : '';
```
`https://plugins.trac.wordpress.org/browser/funnel-builder/tags/3.11.0.2/woofunnels/includes/class-bwf-data-tags.php#L52`

**Root cause at that line:** `$_COOKIE` is indexed by a shortcode attribute. `bwf_clean()`
is an output sanitiser; it does not restrict *which* cookie is read. Anyone who can place a
shortcode — Contributor on a normal site — can publish content that renders the cookie jar
of whoever views it. Because Contributor drafts are reviewed by an Editor or Administrator
by design (see `kb/reference/capability-matrix.md` §6.4), the realistic victim is a
privileged user and the realistic payload is `wordpress_logged_in_<hash>`. Note this is a
disclosure to the *page*, not to the attacker, so it needs a second step to exfiltrate —
usually the same shortcode inside an attribute the attacker also controls, or a companion
XSS. Rate the chain.

### A settings dump behind a public nonce (CVE-2024-9821, 8.8, subscriber+)

The nonce factory runs on the front end:

```php
$nonces_list = array();

foreach ( $nonces as $nonce_name ) {
    $nonces_list[ $nonce_name ] = wp_create_nonce( $nonce_name );
}
?>
<script>
    var stm_wpcfto_nonces = <?php echo wp_json_encode( $nonces_list ); ?>;
</script>
<?php
}

add_action( 'admin_head', 'stm_wpcfto_nonces' );
add_action( 'wp_head', 'stm_wpcfto_nonces' );
```

and the settings endpoint consumed one of them:

```php
add_action( 'wp_ajax_stm_wpcfto_get_settings', 'stm_wpcfto_get_settings_callback' );

function stm_wpcfto_get_settings_callback() {
    check_ajax_referer( 'stm_wpcfto_get_settings_nonce', 'nonce' );

    if(!current_user_can( 'edit_posts' )) {      // <-- added by the fix
        wp_send_json_error();
    }
    $source = ( isset( $_GET['source'] ) ) ? sanitize_text_field( $_GET['source'] ) : '';
    $name   = ( isset( $_GET['name'] ) ) ? sanitize_text_field( $_GET['name'] ) : '';
    wp_send_json( wpcfto_get_settings_map( $source, $name ) );
}
```
`https://plugins.trac.wordpress.org/browser/bot-for-telegram-on-woocommerce/trunk/nuxy/helpers/helpers.php#L53`

**Root cause:** before the fix, `check_ajax_referer()` was the *entire* gate on an endpoint
that returns the plugin's settings map — which for this plugin includes the messaging bot
API token. The `wp_head` registration on line 53 means the required nonce is printed into
every front-end page, so any logged-in user (and, for the `_nopriv_`-registered siblings,
anyone at all) already holds it. **This is the single most transferable lesson in the
class:** when a handler's only guard is a nonce, find the `wp_create_nonce()` that mints it
and check which hook renders it. `INFO-008` exists precisely to build that list.

### Arbitrary directory listing (CVE-2025-13891, 6.5, author+)

```php
public function ajax_list_folders() {
    // Check Nonce
    check_ajax_referer( 'list-files', 'security' );

    // Check user rights
    if ( ! $this->check_user_upload_rights() ) {
        wp_send_json_error( __( 'You do not have the rights to upload files.', 'modula-best-grid-gallery' ) );
    }
    ...
    $path = sanitize_text_field( wp_unslash( $_POST['path'] ) );
    // List all files
    $files = $this->list_folders( $path );
```
`https://plugins.trac.wordpress.org/browser/modula-best-grid-gallery/tags/2.12.26/includes/admin/class-modula-gallery-upload.php#L247`

and the "containment" helper is:

```php
public function check_folder( $folder ) {
    if ( empty( $folder ) ) { return false; }
    if ( ! is_dir( $folder ) ) { return false; }
    $files_folders = scandir( $folder );
    if ( ! $files_folders ) { return false; }
    return true;
}
```

**Root cause at that line:** the handler has both a nonce and a real capability check
(`upload_files` + `edit_posts`, i.e. Author+), which is why it reads as defended — but the
*target* is unconstrained. `sanitize_text_field()` does not remove `../` or a leading `/`,
and `check_folder()` asks only "is this a directory", never "is this directory mine". An
Author enumerates `/`, `/home`, the backup directory, and the plugin inventory. **Note that
this is exactly the shape of WP-LFI/WP-FILEREAD one level up:** the same missing
`realpath()` + strict-prefix containment, but the sink is `scandir()` and the yield is
metadata rather than content. Directory listing is worth its own sweep because reviewers
look for `readfile()` and skip `scandir()`.

### A setting standing in for an authorization check (CVE-2023-6266, 7.5, unauthenticated)

```php
} else if ($type == 'BMI_BACKUP') {
    if (Dashboard\bmi_get_config('STORAGE::DIRECT::URL') === 'true' || current_user_can('administrator')) {

        $backupname = $get_bid;
        $file = $this->fixSlashes(BMI_BACKUPS . DIRECTORY_SEPARATOR . $backupname);
        ...
        // Prevent parent directory downloading
        if (file_exists($file) && $this->fixSlashes(dirname($file)) == $this->fixSlashes(BMI_BACKUPS)) {
```
`https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.5/includes/initializer.php#L1049`

**Root cause at that line:** the capability check is `OR`ed with a stored configuration
value. When the option is set, `current_user_can()` is never evaluated and the endpoint
serves full site backups — database credentials, salts, every uploaded file — to anonymous
callers reachable through the front-end query string. Note that the containment check three
lines down (`dirname($file) == BMI_BACKUPS`) is written *correctly*; the flaw is entirely in
who is allowed to ask. **Audit move:** grep for `current_user_can` appearing on the same
line as `||` and read the other operand. A capability check disjoined with anything that is
not itself a capability check is not a capability check.

### Private files in a public directory (CVE-2024-13622, 7.5, unauthenticated)

The remediation shows exactly what was missing:

```php
$htaccess_path    = $custom_dir . '.htaccess';
$htaccess_content = $this->wau_get_htaccess_content();

if ( ! file_exists( $htaccess_path ) || $wp_filesystem->get_contents( $htaccess_path ) !== $htaccess_content ) {
    $wp_filesystem->put_contents( $htaccess_path, $htaccess_content, FS_CHMOD_FILE );
}

$web_config_path    = $custom_dir . 'web.config';
...
if ( ! file_exists( $custom_dir . 'index.php' ) ) {
    $wp_filesystem->put_contents( $custom_dir . 'index.php', '<?php // Silence is golden', FS_CHMOD_FILE );
}
```
`https://plugins.trac.wordpress.org/browser/woo-addon-uploads/trunk/includes/class-wau-front-end.php#L110`

**Root cause:** customer order attachments — identity documents, artwork, contracts — were
written into a plugin subdirectory of `uploads/` with names derived from the order, and
served by the web server to anyone who requested them. The fix adds three complementary
deny mechanisms (Apache `.htaccess`, IIS `web.config`, an `index.php` against directory
indexes) *and* migrates existing files into a private directory. Both halves matter: adding
deny rules does not help files that were already indexed by a search engine, and the plugin
has a separate `wau_maybe_migrate_legacy_uploads()` routine for exactly that reason. **When
auditing an upload feature, always ask where the file lands and what protects it — not just
whether the upload itself is validated (which is WP-UPLOAD's question).**

## Detection guidance

**What the regexes catch reliably**

- `INFO-002`, `INFO-003` and `INFO-011` are near-zero-false-positive: dumping a superglobal,
  enabling `display_errors`, and indexing `$_COOKIE`/`$_SERVER` with a variable are all
  indefensible in shipped plugin code.
- `INFO-007` catches request-controlled directory listing on the same statement.
- `INFO-008` is the cheapest high-value sweep in this file. It produces a short list, and
  each entry answers "can an anonymous visitor obtain this nonce?" — the question that
  decides whether a dozen other handlers are authenticated at all.

**What the regexes CANNOT catch — read the code**

1. **Where the file actually lands.** A log path assembled from `$dir_path . '/' . $module`
   has no literal filename for `INFO-001` to match (CVE-2024-12008). Grep for the *fragments*
   `'.log'`, `'.sql'`, `'.csv'`, `'.zip'`, `'.bak'` and trace each one back to its base.
2. **Whether a directory is actually served.** The finding depends on the host: Apache with
   `Options -Indexes`, nginx without `autoindex`, an object-storage offload, or a CDN in
   front all change the answer. Check for `.htaccess`/`web.config`/`index.php` in every
   directory the plugin creates with `wp_mkdir_p()`, and note that nginx ignores
   `.htaccess` entirely.
3. **Whether a nonce is secret.** Static analysis sees `check_ajax_referer()` and scores the
   handler protected. Follow `INFO-008` hits to their rendering hook.
4. **Multi-line response construction.** `INFO-005` and `INFO-006` only see single-line
   calls; real handlers build a `$response` array over twenty lines and send it at the end.
   Work backwards from every `wp_send_json*` / `rest_ensure_response` / `return new
   WP_REST_Response` and audit each field of the array it sends.
5. **Over-fetching in a legitimate response.** The endpoint is correctly authorised and
   still returns `user_email`, `_billing_phone`, a private post's `post_content`, or an
   attachment URL for a file the caller cannot otherwise reach. There is no pattern for
   "this field is more than the caller needed"; it requires knowing the product.
6. **Private post and meta leakage.** `WP_Query` with `'post_status' => 'any'`, a
   `pre_get_posts` filter that removes the status restriction, `get_post_meta()` on a
   protected (`_`-prefixed) key rendered into a template, and `register_post_meta()` with
   `'show_in_rest' => true` on a private key all publish content the post's status was
   supposed to hide. Grep for `post_status`, `'show_in_rest' => true`, and `suppress_filters`.
7. **User enumeration by side channel.** Differing responses for "no such user" vs "wrong
   password", a registration form that rejects taken usernames, author archives at `?author=N`,
   the core REST users route, and timing differences. None of these look like a disclosure
   sink in source.
8. **Secrets that are not string literals.** A credential read from an option and echoed
   into a template, a token embedded in an enqueued script's localisation array, an API key
   passed as a URL query parameter (which then lands in access logs, `Referer` headers and
   proxy caches). `INFO-004` sees none of these.
9. **`.git`, `.env`, `composer.lock`, `.DS_Store`, editor backups.** Shipped or left behind
   inside the plugin directory, and served. This is a filesystem audit, not a code grep.
10. **Disclosure through a non-HTTP channel.** Debug data mailed by `wp_mail()`, pushed to a
    third-party telemetry endpoint, or written to a database table that a public shortcode
    renders.

## Audit checklist

- [ ] Enumerate every directory the plugin creates (`wp_mkdir_p`, `mkdir`) and confirm each
      has `.htaccess`, `web.config` **and** `index.php`, or lives outside the webroot.
- [ ] For every file the plugin writes under `uploads/` or `wp-content/`, confirm the
      filename contains an unguessable component (`wp_generate_password( 32, false, false )`,
      not `uniqid()` or a sequential id).
- [ ] Grep for `'.log'`, `'.sql'`, `'.csv'`, `'.zip'`, `'.bak'` as fragments and trace the
      base directory of each; run `INFO-001` as the literal-filename subset.
- [ ] Run `INFO-003`; a plugin that enables `display_errors`, `WP_DEBUG` or
      `WP_DEBUG_DISPLAY` is a finding regardless of any guard around it.
- [ ] Run `INFO-008` and, for each nonce, find the hook that renders it. Flag every handler
      whose only guard is `check_ajax_referer()` against a nonce reachable anonymously.
- [ ] Grep for `current_user_can` on a line containing `||` and read the other operand.
- [ ] Work backwards from every `wp_send_json*`, `rest_ensure_response` and
      `new WP_REST_Response` and audit each field of the payload against what the caller is
      entitled to see.
- [ ] Run `INFO-005`/`INFO-006`; for each hit, identify the registration site and the
      required capability.
- [ ] Run `INFO-011`; any superglobal indexed by a variable is a finding unless an allowlist
      is adjacent.
- [ ] Run `INFO-002`/`INFO-010` and remove every debug dump that reaches the response.
- [ ] Run `INFO-009`; replace every raw `$wpdb->last_error` / exception message in a response
      with `error_log()` plus a generic message.
- [ ] Check `WP_Query`/`get_posts` calls for `'post_status' => 'any'` and for
      `suppress_filters`, and check `register_post_meta()` for `'show_in_rest' => true` on
      keys that are not public.
- [ ] Search the shipped plugin directory for `.git`, `.env`, `.sql`, `.log`, `*.bak`,
      `*~`, `.DS_Store` and `composer.lock`.
- [ ] Confirm no secret is passed as a URL query parameter anywhere (`add_query_arg` with a
      key or token), since URLs reach access logs, `Referer` headers and browser history.
