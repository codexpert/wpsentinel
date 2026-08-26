---
class_id: WP-LFI
title: Path Traversal / Local File Inclusion / Arbitrary File Read
cwe: [CWE-22, CWE-98, CWE-23, CWE-73]
owasp: A01:2021-Broken Access Control
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 6
detection:
  - id: LFI-001
    description: include/require reached by a request superglobal on the same statement
    regex: '\b(include|include_once|require|require_once)\b[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
    confidence: high
    false_positive_notes: >-
      Catches both concatenation (include $dir . $_GET['x'] . '.php') and interpolation
      (require_once "inc/{$_REQUEST['x']}Fn.php"). Near-zero false positives; a hit is a
      finding unless the value was already mapped through a hard-coded allowlist array on
      the same line, which is rare. Also matches $_SERVER, which is worth flagging because
      HTTP_HOST / PATH_INFO / HTTP_X_* are attacker-controlled too.
  - id: LFI-002
    description: include/require of a bare variable — source unknown, must be traced
    regex: '\b(include|include_once|require|require_once)\s*\(?\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*[;,)]'
    confidence: low
    false_positive_notes: >-
      Enormous volume; almost every plugin does this legitimately for its own templates.
      Use it only as a worklist, and triage by tracing the variable's assignment. Prioritise
      variables named $template, $tpl, $file, $path, $view, $page, $lang, $controller, $task.
  - id: LFI-003
    description: File-read primitive fed directly by a request superglobal
    regex: '\b(file_get_contents|readfile|fopen|highlight_file|show_source|fpassthru|parse_ini_file|SplFileObject|file)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      A hit is a finding unless the argument is a URL being fetched deliberately (in which
      case it is SSRF, a different class) or unless a realpath() containment check appears
      on an adjacent line. Check both.
  - id: LFI-004
    description: Request parameter with a path-like name — surface mapping
    regex: '\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[''"](file|filename|file_name|filepath|file_path|path|dir|folder|doc|document|download|src|source|template|tpl|page|view|lang|language|locale|include|controller|task|action_file|attachment)[''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      Deliberately broad. Its job is to enumerate every request parameter that might become
      a path, so the auditor can follow each one. Most hits are benign; the value is in the
      completeness of the worklist, not the precision.
  - id: LFI-005
    description: basename()/wp_basename() applied to request input and treated as the defence
    regex: '\b(basename|wp_basename)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: medium
    false_positive_notes: >-
      basename() strips directory components, so it does stop plain ../ traversal. It does
      NOT constrain WHICH file inside the base directory is reached, does not stop a
      leading URL scheme (php://, data://, phar://) when the value later reaches an
      include/fopen, and is bypassed on Windows by backslash handling in older PHP. Treat
      basename() alone as insufficient; the containment check is realpath()+prefix.
  - id: LFI-006
    description: Broken containment check — strpos(...) == 0 accepts false
    regex: 'strpos\s*\([^;]*\)\s*==\s*0'
    confidence: high
    false_positive_notes: >-
      In PHP, strpos() returns false when the needle is absent, and false == 0 is true.
      A "path must start with base" guard written with loose == therefore passes for every
      path that is NOT under the base. Does not match the correct === 0 / !== 0 forms.
      This is the highest-value regex in the class: it fires on code that already calls
      realpath() and therefore looks safe to a reviewer.
  - id: LFI-007
    description: Containment check written as strpos(...) !== false — substring, not prefix
    regex: 'strpos\s*\([^;]*\)\s*!==?\s*false'
    confidence: low
    false_positive_notes: >-
      Common and usually benign. It is a finding only when used as a directory-containment
      test: "does the resolved path contain the base string anywhere" is satisfied by
      /tmp/attacker/wp-content/uploads/../../../etc/passwd-style constructions and by any
      path where the base appears mid-string. Correct form is a strict prefix test.
  - id: LFI-008
    description: sanitize_text_field()/sanitize_key() used where a path control is required
    regex: '\b(include|include_once|require|require_once|readfile|file_get_contents|fopen|unlink|wp_delete_file)\b[^;]*\bsanitize_(text_field|key|title)\s*\('
    confidence: medium
    false_positive_notes: >-
      sanitize_text_field() strips tags and control characters. It does NOT remove ../,
      slashes, or a leading /. sanitize_key() does remove slashes and dots and is a genuine
      (if crude) control. Read which one is used.
  - id: LFI-009
    description: Directly-reachable plugin PHP file that bootstraps itself instead of using WordPress
    regex: '^\s*(include|include_once|require|require_once)[^;]*(dirname\s*\(\s*__FILE__|__DIR__|ABSWP|plugin_dir_path)'
    confidence: low
    false_positive_notes: >-
      Normal in most files. It becomes important when the file also reads $_GET/$_POST at
      top level and is not guarded by defined('ABSPATH') — that combination is a script an
      unauthenticated attacker can hit directly by URL, with no WordPress auth in the path.
      Pair with a check for a missing `if ( ! defined( 'ABSPATH' ) ) exit;` guard.
fix_apis:
  - realpath()
  - wp_basename()
  - sanitize_key()
  - validate_file()
  - trailingslashit()
  - plugin_dir_path()
  - wp_normalize_path()
  - current_user_can()
  - check_ajax_referer()
examples:
  - cve: CVE-2024-9047
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A directly-reachable downloader script resolved the target path from request-controlled state, including an attacker-supplied base directory, then streamed the file to the response and optionally deleted it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9047
    code_ref: https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L70
    root_cause: Both the file path and the base directory it was joined to were read from attacker-controlled state, so no containment boundary existed at all.
  - cve: CVE-2024-11613
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: The same downloader script performed require_once on a path whose directory prefix came from attacker-controlled state, turning an arbitrary-read bug into code execution.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-11613
    code_ref: https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L126
    root_cause: require_once on a user-defined directory prefix; an inclusion sink, not merely a read sink.
  - cve: CVE-2026-9662
    year: 2026
    severity: 8.1
    auth: unauthenticated
    summary: A public POST handler concatenated an unsanitised parameter into an include() with a fixed .php suffix, while sanitising the very same parameter a few lines later for logging.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-9662
    code_ref: https://plugins.trac.wordpress.org/browser/recoverexit-for-woocommerce/tags/1.0.3/recover_exit_main.php#L42
    root_cause: Raw $_POST value concatenated into include(); the sanitiser was applied to the logging copy, not to the value that reached the sink.
  - cve: CVE-2025-9991
    year: 2025
    severity: 8.1
    auth: unauthenticated
    summary: A standalone asset script under the plugin directory used a request parameter to build a require_once path, guarded only by file_exists().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-9991
    code_ref: https://plugins.trac.wordpress.org/browser/tiny-bootstrap-elements-light/trunk/assets/bootstrap-label.php#L14
    root_cause: Directly-reachable PHP file with no ABSPATH guard, no authentication, and file_exists() used as if it were a containment check.
  - cve: CVE-2025-9990
    year: 2025
    severity: 8.1
    auth: unauthenticated
    summary: A parameter was interpolated into a require_once path inside a double-quoted string with a fixed filename suffix.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-9990
    code_ref: https://plugins.trac.wordpress.org/browser/wp-helpdesk-integration/trunk/index.php#L85
    root_cause: String interpolation of $_REQUEST directly inside require_once(); other parameters in the same file were sanitised, this one was not.
  - cve: CVE-2026-0926
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A template-loading helper accepted a template name from a nested request parameter and passed the located path to include with only a file_exists()/is_dir() guard.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-0926
    code_ref: https://plugins.trac.wordpress.org/browser/prodigy-commerce/tags/3.2.9/includes/helpers/class-prodigy-template.php#L61
    root_cause: A "locate template" indirection layer let an arbitrary relative path reach include; existence was checked, containment was not.
  - cve: CVE-2026-5710
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: Client-supplied filenames were converted from an upload URL back to a filesystem path with str_replace() and attached to an outgoing email after only a file_exists() check.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-5710
    code_ref: https://plugins.trac.wordpress.org/browser/drag-and-drop-multiple-file-upload-contact-form-7/tags/1.3.9.6/inc/dnd-upload-cf7.php#L474
    root_cause: URL-to-path conversion by string replacement, with no canonicalisation and no containment check, and no provenance check that the file had actually been uploaded by this request.
  - cve: CVE-2026-13369
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: A client-supplied flag caused the upload processor to return early, after which a raw attacker-controlled file array reached the mail-attachment stage with only file_exists() as a gate.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-13369
    code_ref: https://plugins.trac.wordpress.org/browser/ninja-forms-uploads/trunk/includes/integrations/ninjaforms/attachments.php#L196
    root_cause: An early return controlled by request data skipped validation, path normalisation and record creation, leaving an unvalidated path to reach the read sink.
  - cve: CVE-2025-12493
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: An AJAX action accepted a template path parameter and included it, reachable without authentication.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-12493
    code_ref: https://plugins.trac.wordpress.org/browser/woolentor-addons/trunk/classes/class.ajax_actions.php#L213
    root_cause: Unauthenticated AJAX handler using a request-supplied template path as an inclusion target.
---

## What it is

A request parameter ends up inside a path that the plugin then includes, reads, or streams
back. With `../` sequences (or an absolute path, or a stream wrapper) the attacker escapes
the directory the developer had in mind. Reading `wp-config.php` yields the database
credentials and all eight authentication salts — enough to forge cookies and, on most
hosts, to connect to the database directly. When the sink is `include`/`require` rather
than `readfile`, the same bug is remote code execution against any file the attacker can
get content into: an uploaded "image", a log file, a session file, or a `.phar` archive.

## Why it happens in WordPress

- **Template indirection.** Plugins routinely offer a `template=` / `tpl=` / `view=`
  parameter so a shortcode, block, or AJAX call can pick a partial. The parameter is a
  path fragment by design, and the "which templates exist" question is answered by
  `file_exists()` rather than by an allowlist.
- **`file_exists()` is not a security control.** It answers "is there a file there",
  not "is that file inside the directory I meant". Nearly every case study below uses it
  as if it were the latter.
- **Standalone plugin PHP files are directly reachable.** Any `.php` under
  `wp-content/plugins/` can be requested by URL. Files that bootstrap themselves
  (`require dirname(__FILE__).'/lib/functions.php'`) instead of loading `wp-load.php`
  run with **no WordPress authentication anywhere in the call path** — and often no
  `if ( ! defined( 'ABSPATH' ) ) exit;` guard either.
- **`wp_ajax_nopriv_` and `permission_callback => '__return_true'`** put the same
  handlers on an unauthenticated route.
- **`sanitize_text_field()` looks like sanitisation but is not path sanitisation.** It
  leaves `../`, `/`, and `\` completely intact. It is the single most common false
  defence in this class.
- **Download handlers** are the archetype: `?action=download&file=invoice-12.pdf` with a
  `readfile()` at the end.

## Vulnerable pattern

```php
// wp-content/plugins/example/download.php — reachable directly, no WordPress auth.
require_once dirname( __FILE__ ) . '/inc/bootstrap.php';

$file = isset( $_GET['file'] ) ? $_GET['file'] : '';

// "Sanitised" — but sanitize_text_field() does not touch ../ or slashes.
$file = sanitize_text_field( $file );

$path = WP_CONTENT_DIR . '/uploads/example-docs/' . $file;

// Existence is not containment.
if ( file_exists( $path ) ) {
    header( 'Content-Type: application/octet-stream' );
    header( 'Content-Disposition: attachment; filename="' . basename( $path ) . '"' );
    readfile( $path );
    exit;
}
```

`?file=../../../wp-config.php` reads the credentials and salts. The inclusion variant is
worse:

```php
// AJAX, unauthenticated.
add_action( 'wp_ajax_nopriv_example_tpl', 'example_tpl' );
function example_tpl() {
    // Fixed suffix does not help: ../../../uploads/2026/08/avatar (which is really PHP)
    // resolves fine, and a stream wrapper skips the prefix entirely.
    include plugin_dir_path( __FILE__ ) . 'templates/' . $_POST['tpl'] . '.php';
}
```

And the *half-fixed* variant, which is the one that survives code review:

```php
$base = wp_upload_dir()['basedir'] . '/example-docs/';
$real = realpath( $base . $_GET['file'] );

// BUG: strpos() returns false when $base is not a prefix, and false == 0 is TRUE.
// This guard passes for every path OUTSIDE the base directory.
if ( strpos( $real, $base ) == 0 ) {
    readfile( $real );
}
```

## Secure pattern

Two correct shapes. Prefer the first whenever the set of reachable files is finite.

```php
/**
 * Shape 1 — ALLOWLIST MAP. The request never contributes to the path at all;
 * it selects a key. This is the only approach with no traversal surface.
 */
function example_render_template() {
    if ( ! current_user_can( 'edit_posts' ) ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_tpl', 'nonce' );

    $templates = array(
        'grid'     => 'templates/grid.php',
        'list'     => 'templates/list.php',
        'carousel' => 'templates/carousel.php',
    );

    $key = isset( $_POST['tpl'] ) ? sanitize_key( wp_unslash( $_POST['tpl'] ) ) : 'grid';
    if ( ! isset( $templates[ $key ] ) ) {
        wp_send_json_error( 'unknown template', 400 );
    }

    include plugin_dir_path( __FILE__ ) . $templates[ $key ];
}
```

```php
/**
 * Shape 2 — REALPATH CONTAINMENT. Use when filenames are genuinely dynamic
 * (user-uploaded documents, generated reports).
 */
function example_download() {
    if ( ! is_user_logged_in() ) { wp_die( 'forbidden', 403 ); }
    check_admin_referer( 'example_download' );

    // 1. Canonicalise the base ONCE. realpath() resolves symlinks and ".." here too.
    $base = realpath( wp_upload_dir()['basedir'] . '/example-docs' );
    if ( false === $base ) { wp_die( 'misconfigured', 500 ); }
    $base = trailingslashit( wp_normalize_path( $base ) );

    // 2. Strip directory components from the request value. Necessary, not sufficient.
    $requested = isset( $_GET['file'] ) ? wp_basename( wp_unslash( $_GET['file'] ) ) : '';
    if ( '' === $requested || validate_file( $requested ) !== 0 ) {
        wp_die( 'bad request', 400 );
    }

    // 3. Canonicalise the candidate and require a STRICT PREFIX match against the base.
    //    realpath() returns false if the file does not exist -> handled by the === false test.
    $real = realpath( $base . $requested );
    if ( false === $real ) { wp_die( 'not found', 404 ); }
    $real = wp_normalize_path( $real );

    // Note ===, not ==. `strpos(...) == 0` is the bug in CVE-2026-18855 and friends.
    if ( strpos( $real, $base ) !== 0 ) {
        wp_die( 'forbidden', 403 );
    }

    // 4. Refuse executable types even inside the base, in case the base was polluted.
    $type = wp_check_filetype( $real );
    if ( empty( $type['type'] ) ) { wp_die( 'forbidden', 403 ); }

    header( 'Content-Type: ' . $type['type'] );
    header( 'Content-Disposition: attachment; filename="' . $requested . '"' );
    header( 'X-Content-Type-Options: nosniff' );
    readfile( $real );
    exit;
}
```

Three details that are easy to get wrong:

- `realpath()` on the **base** as well as the candidate; comparing a canonical path
  against a non-canonical base fails whenever the base contains a symlink.
- **Strict** `!== 0`. Loose `== 0` accepts `false`, which is exactly the case you were
  trying to reject.
- Compare against a **trailing-slashed** base, or `/var/www/uploads-evil` passes a prefix
  test against `/var/www/uploads`.

`validate_file()` from WordPress core is a useful extra gate — it returns non-zero for
`..` segments, absolute Windows paths and drive letters — but it does not perform
containment, so it complements rather than replaces the `realpath()` check.

## Real-world case studies

### The base directory itself was attacker-controlled (CVE-2024-9047, 9.8, unauthenticated)

A standalone downloader file in the plugin root, reachable directly by URL. It never loads
`wp-load.php`; it bootstraps its own library:

```php
include_once( ABSWPFILEUPLOAD_DIR.'lib/wfu_functions.php' );
$handler = (isset($_POST['handler']) ? $_POST['handler'] : (isset($_GET['handler']) ? $_GET['handler'] : '-1'));
```

The user-state accessor it then relies on resolves to a **cookie** when the request asks it to:

```php
function WFU_USVAR_downloader($var) {
    global $wfu_user_state_handler;
    if ( $wfu_user_state_handler == "dboption" && WFU_VAR("WFU_US_DBOPTION_BASE") == "cookies" ) return $_COOKIE[$var];
    else return WFU_USVAR_session($var);
}
```
`https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L136`

Both the relative path *and* the directory it is joined to come from that accessor:

```php
$filepath = WFU_USVAR_downloader('wfu_storage_'.$file_code);
$filepath = wfu_flatten_path($filepath);
if ( substr($filepath, 0, 1) == "/" ) $filepath = substr($filepath, 1);
$filepath = ( ... ? $filepath : WFU_USVAR_downloader('wfu_ABSPATH').$filepath );
```
`https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L70`

**Root cause at that line:** there is no containment boundary to escape, because the
"intended base directory" is itself a request-controlled value. The path is then opened
and streamed:

```php
if ( $fd = wfu_fopen_for_downloader($filepath, "rb") ) { ... echo $buffer; ... }
```

`wfu_flatten_path()` is a traversal normaliser, and the advisory records that exploitation
needed PHP 7.4 or earlier — but the structural defect is independent of that detail: a
canonicalisation routine cannot help when the attacker also supplies the root. **When
auditing, always ask where the base path came from, not just the filename.** A `realpath()`
containment check is meaningless if the base is `$_COOKIE`.

### The same file, one line later: read becomes execute (CVE-2024-11613, 9.8, unauthenticated)

```php
function wfu_update_download_status($ticket, $new_status) {
    require_once WFU_USVAR_downloader('wfu_ABSPATH').'wp-load.php';
```
`https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L126`

**Root cause at that line:** the identical attacker-controlled prefix reaches
`require_once`. Anything the attacker can make resolve to a readable PHP file — including a
file previously placed in `uploads/` — is executed. NVD classifies this as CWE-94 rather
than CWE-22 precisely because the sink is an inclusion. This is why LFI-001 and LFI-003
must be separate rules with different severities: the *same* tainted value is
information disclosure through one sink and RCE through the other.

### Sanitised for the log, raw for the sink (CVE-2026-9662, 8.1, unauthenticated)

```php
if (isset($_POST["tpf"])){
include ($UserEditedTemplatesDir.$_POST["tpf"].'.php');
$DiscoCode = $CheckOutCode;
}else{
...
$LocalLog = date("d M Y") . ' @ ' . date("H:i:s") . ',DISCOUNT-BUTTON-CLICKED,' . sanitize_text_field($_POST["tpf"]);
```
`https://plugins.trac.wordpress.org/browser/recoverexit-for-woocommerce/tags/1.0.3/recover_exit_main.php#L42`

**Root cause at that line:** the raw `$_POST["tpf"]` is concatenated into `include()` on
line 42; the *same parameter* is passed through `sanitize_text_field()` on line 50 — for
the log message. The developer clearly knew the value was untrusted. This is a recurring
tell worth searching for explicitly: **the presence of a sanitiser on one use of a
parameter and its absence on the dangerous use.** Note also that
`sanitize_text_field()` would not have helped here anyway — it does not remove `../`.

### A standalone asset file with no WordPress in the picture (CVE-2025-9991, 8.1, unauthenticated)

```php
<?php
$css_paths = explode(",", addslashes($_GET['css_paths']));
...
if (file_exists('langs/' . $_GET['language'] . '.php')) {
    require_once 'langs/' . $_GET['language'] . '.php';
} else { // default
    require_once 'langs/en_EN.php';
}
```
`https://plugins.trac.wordpress.org/browser/tiny-bootstrap-elements-light/trunk/assets/bootstrap-label.php#L14`

**Root cause at that line:** the file lives under `wp-content/plugins/<slug>/assets/` and is
requested directly. Line 1 is `<?php` — no `defined('ABSPATH')` guard, no `wp-load.php`, no
capability check, nothing. `file_exists()` is used as the gate, which only confirms the
traversal target exists. This shape is worth a dedicated sweep: enumerate every `.php`
file in a plugin, and for each one that reads a superglobal at top level, check whether it
has an ABSPATH guard. If not, it is an unauthenticated endpoint regardless of what hooks
the plugin registers.

### Interpolation instead of concatenation (CVE-2025-9990, 8.1, unauthenticated)

```php
if(isset( $_REQUEST['portal_type'] ))
{
	require_once("includes/{$_REQUEST['portal_type']}Functions.php");
}
```
`https://plugins.trac.wordpress.org/browser/wp-helpdesk-integration/trunk/index.php#L85`

**Root cause at that line:** `{$_REQUEST['portal_type']}` inside a double-quoted string.
Seven lines below, a different parameter *is* run through `sanitize_text_field()`. Two
detection lessons: (a) any regex for this class must handle the interpolated form, not just
`. $_GET[...] .`; (b) the fixed `Functions.php` suffix constrains nothing useful — the
attacker only needs some readable path ending in that string, or a traversal to a
directory they can write into.

### Broken containment on a resolved path (pattern shared with WP-DELETE)

```php
$pathpos  = strpos( $delete_link_url, $uploads['baseurl'] );
$filepath = realpath( $uploads['basedir'] . substr( $delete_link_url, $pathpos + strlen( $uploads['baseurl'] ) ) );

if ( $pathpos !== false && strpos( $filepath, $uploads['baseurl'] ) == 0 ) {
```
`https://plugins.trac.wordpress.org/browser/link-library/tags/7.9.4/link-library-admin.php#L7863`

**Root cause at that line:** two independent defects in one guard. The resolved
*filesystem* path `$filepath` is compared against `$uploads['baseurl']`, a **URL** — so
`strpos()` always returns `false`. And `false == 0` evaluates to `true` under PHP's loose
comparison, so the guard passes unconditionally. `realpath()` is present, which is why a
reviewer skims past it. This is the case that justifies making LFI-006 a `high`-confidence
rule: it fires on code that has all the right function names in all the right places.

### URL-to-path by string replacement (CVE-2026-5710, 7.5, unauthenticated)

```php
// Convert url to dir
$new_file_name = str_replace( $uploads_dir['upload_url'], $uploads_dir['upload_dir'], $_file );

// Check if submitted and file exists then file is ready.
if ( $submission && file_exists( $new_file_name )  ) {
    $components['attachments'][] = $new_file_name;
}
```
`https://plugins.trac.wordpress.org/browser/drag-and-drop-multiple-file-upload-contact-form-7/tags/1.3.9.6/inc/dnd-upload-cf7.php#L474`

**Root cause at that line:** `$_file` is a client-submitted value that the code assumes is
one of the URLs it produced. `str_replace()` swaps the URL prefix for the directory prefix
and leaves everything after it — including `../../..` — untouched. `file_exists()` is again
the only gate. The exfiltration channel is an email attachment rather than an HTTP
response, which is why "arbitrary file read" sinks must be enumerated beyond `readfile()`:
`wp_mail()` attachments, ZIP builders, `WP_Http` POST bodies and CSV exporters all read
files and ship the bytes somewhere.

### Request-controlled early return skips all validation (CVE-2026-13369, 7.5, unauthenticated)

A client-supplied "save progress" flag made the upload processor return before validation,
path normalisation and database record creation ran; the raw attacker-supplied `files`
array then reached the mail-attachment builder with only `file_exists()` in the way.
`https://plugins.trac.wordpress.org/browser/ninja-forms-uploads/trunk/includes/integrations/ninjaforms/attachments.php#L196`

**Root cause:** the validation was not missing — it was *skippable*, from the request. Look
for `return`/`break`/`continue` statements inside a validation routine whose condition
reads request data.

## Detection guidance

**What the regexes catch reliably**

- `LFI-001` and `LFI-003` catch the direct one-statement cases, which are still the
  majority of disclosed bugs, and handle both concatenation and interpolation.
- `LFI-006` catches the broken-containment idiom — the highest-value single rule here,
  because it fires on code that already looks defended.
- `LFI-009` plus a missing-`ABSPATH`-guard check finds directly-reachable plugin scripts,
  which are unauthenticated by construction.

**What the regexes CANNOT catch — read the code**

1. **Multi-hop taint.** `$f = $_GET['file'];` … 40 lines … `$path = $base . $f;` …
   another function … `readfile( $path );`. This is the normal shape of real code and the
   normal shape of real bugs. `LFI-002` and `LFI-004` exist only to produce the worklist;
   the actual finding requires following the variable.
2. **An attacker-controlled *base* directory.** The CVE-2024-9047 case. A grep sees
   `$base . $file` and moves on. Ask, for every path join: where did the left-hand side
   come from? Cookies, options written by an unauthenticated endpoint, and session values
   set from request data are all attacker-controlled bases.
3. **Whether an existing `realpath()` check is correct.** Presence of `realpath()` proves
   nothing. Check: is the base also canonicalised; is the comparison a strict prefix; is
   the base trailing-slashed; is `false` handled.
4. **Indirection through a "locate template" helper.** `locate_template()`,
   `load_template()`, `get_template_part()`, and every plugin's own
   `plugin_locate_template()` accept a relative path and resolve it against several roots.
   The tainted value and the `include` are in different files.
5. **Stream wrappers.** `php://filter/convert.base64-encode/resource=../wp-config.php`,
   `data://`, `phar://` (which also triggers object deserialisation on any file operation),
   and `expect://`. A path-traversal regex looking for `..` sees none of these. Any sink
   reached by unvalidated input must be assumed reachable by a wrapper unless the code
   rejects anything containing `://`.
6. **Non-HTTP read sinks.** `wp_mail()` attachments, `WP_Http` request bodies,
   `ZipArchive::addFile()`, `fputcsv()` over file contents, image libraries
   (`getimagesize()` on `phar://`), and template engines. "Arbitrary file read" does not
   require `readfile()`.
7. **Whether `basename()` is enough.** It stops directory traversal but not
   *which file in the directory*; if the directory is `wp-content/uploads/` and the
   attacker can upload, `basename()` is no protection at all. And it does not stop a
   scheme prefix reaching an `include`.
8. **Skippable validation.** A `return` inside a validator, guarded by a request flag
   (CVE-2026-13369). The validator exists, the regex sees it, and it never runs.

## Audit checklist

- [ ] Run `LFI-001` and `LFI-003`; treat every hit as a finding until proven otherwise.
- [ ] Run `LFI-006` and `LFI-007`; inspect every containment comparison for strict-vs-loose
      and for base-vs-candidate type mismatches (path compared against URL).
- [ ] Enumerate every `.php` file in the plugin; for each, check for
      `if ( ! defined( 'ABSPATH' ) ) exit;` at the top. Any file without it that reads a
      superglobal is an unauthenticated endpoint.
- [ ] Run `LFI-004` to list every path-shaped request parameter, then trace each one to a
      sink by hand.
- [ ] For every path concatenation `$a . $b`, determine the provenance of **both** operands.
- [ ] For each `realpath()` present, verify: base canonicalised, base trailing-slashed,
      strict `!== 0` prefix comparison, `false` return handled.
- [ ] Grep for `sanitize_text_field` applied to a value that reaches a path sink and flag
      it — it is not a path control.
- [ ] Grep for `://` rejection; if absent, assume stream wrappers are reachable.
- [ ] Enumerate non-obvious read sinks: `wp_mail` attachments, ZIP builders, CSV/report
      exporters, remote POST bodies.
- [ ] For each validation routine, check whether any `return`/`exit` inside it is
      controlled by request data.
- [ ] Confirm the handler enforces `current_user_can()` and a nonce before any path
      resolution — containment bugs are far less exploitable behind a real capability check.
