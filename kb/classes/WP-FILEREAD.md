---
class_id: WP-FILEREAD
title: Arbitrary File Read / Download — file contents returned to the attacker
cwe: [CWE-22, CWE-200, CWE-73, CWE-552, CWE-158]
owasp: A01:2021-Broken Access Control
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 13
detection:
  - id: FILEREAD-001
    description: Content-returning read primitive fed by a request superglobal
    regex: '\b(readfile|readgzfile|file_get_contents|fpassthru|fopen|highlight_file|show_source|SplFileObject|file)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      A hit is a finding unless the argument was mapped through a hard-coded allowlist on
      the same statement. Overlaps deliberately with WP-LFI's LFI-003: the same tainted
      value is arbitrary READ through these sinks and remote code execution through
      include/require, so both classes must fire. Two benign shapes to rule out: the
      argument is a deliberate remote URL (that is WP-SSRF, a different class), or the
      handler is a legitimate importer whose input is a just-uploaded temp file. fopen() is
      included because the read happens later via fgets/fgetcsv/fread — the fopen line is
      where the path is chosen.
  - id: FILEREAD-002
    description: Download response headers — enumerate every streaming endpoint
    regex: 'header\s*\(\s*[''"]Content-Disposition\s*:\s*attachment'
    confidence: medium
    false_positive_notes: >-
      Not a vulnerability signature; a complete inventory of the plugin's file-download
      endpoints, which is almost always a short list. For each one answer: where does the
      streamed path come from, what capability is required, and is there a realpath()
      containment check against a canonicalised, trailing-slashed base. Every case study in
      this class would appear in this inventory.
  - id: FILEREAD-003
    description: Read primitive on a plain variable — provenance must be traced
    regex: '\b(readfile|readgzfile|fpassthru|file_get_contents|fopen|SplFileObject)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*(->[a-zA-Z0-9_]+)*\s*[\.,)]'
    confidence: low
    false_positive_notes: >-
      High volume — every plugin reads its own templates and JSON assets this way. Use it as
      a worklist and triage by tracing the variable back to its assignment. Prioritise
      variables named $file, $filepath, $path, $url, $doc, $attachment, $download, $target,
      and any variable assigned from get_post_meta()/get_option() (see FILEREAD-008) or from
      a registered query var (FILEREAD-009).
  - id: FILEREAD-004
    description: basename() applied to the download filename rather than to the read path
    regex: 'Content-Disposition.*\b(basename|wp_basename)\s*\('
    confidence: medium
    false_positive_notes: >-
      A specific and instructive shape: the developer calls basename() so the browser gets a
      tidy filename, and a reviewer reads it as path sanitisation. The variable passed to
      readfile() a few lines later is still the raw, traversable path. When this rule fires,
      compare the argument of the Content-Disposition basename() with the argument of the
      read sink; if they are the same variable and basename() was assigned back to it, the
      code is fine, and if the basename() result went into a different variable it is not.
  - id: FILEREAD-005
    description: Non-HTTP exfiltration sinks — files read and shipped elsewhere
    regex: '(->addFile\s*\(|->addFromString\s*\(|[''"]attachments[''"]\s*(=>|\]\s*\[\s*\])|wp_mail\s*\([^;]*,\s*array\s*\()'
    confidence: low
    false_positive_notes: >-
      "Arbitrary file read" does not require readfile(). wp_mail() attachments, ZipArchive
      builders, CSV/report exporters and WP_Http POST bodies all read a path and deliver the
      bytes to a destination the attacker may also control. Noisy and worth running anyway,
      because these sinks are invisible to every rule that looks for a read function.
      Cross-reference with WP-LFI CVE-2026-5710, where the channel was an email attachment.
  - id: FILEREAD-006
    description: URL converted to a filesystem path by string replacement
    regex: 'str_replace\s*\([^;]*(baseurl|base_url|upload_url|site_url|home_url|content_url|plugins_url|WP_CONTENT_URL)[^;]*(basedir|base_dir|upload_dir|ABSPATH|WP_CONTENT_DIR|WP_PLUGIN_DIR)'
    confidence: high
    false_positive_notes: >-
      The idiom assumes the client-supplied string is one the server previously produced.
      str_replace() swaps the URL prefix for the directory prefix and leaves everything
      after it untouched — including ../../.. — so the result is an arbitrary path with a
      trusted-looking prefix. There is no canonicalisation anywhere in the operation. A hit
      is a finding unless a realpath() prefix check follows; treat "the URL came from our own
      page" as an assumption, never a control.
  - id: FILEREAD-007
    description: Extension or MIME allowlist — confirm it is checked against the string that is opened
    regex: '\bin_array\s*\(\s*[^;,]*(ext|extension|mime|type)[a-zA-Z0-9_()\-]*\s*,'
    confidence: low
    false_positive_notes: >-
      Extension allowlists are common and usually fine. The failure mode is a DISCREPANCY:
      the validator derives the extension from one normalisation of the input and the sink
      opens a different one. Null bytes (validator sees "wp-config.php\0.css", opener
      truncates at the NUL), URL decoding applied on one side only, double extensions,
      trailing dots/spaces on Windows, and case folding all produce it. For every hit, find
      the exact expression the read sink receives and confirm it is byte-identical to the
      one the allowlist inspected.
  - id: FILEREAD-008
    description: Path taken from stored state rather than the request
    regex: '\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*get_(post_meta|user_meta|option|term_meta|transient|site_option)\s*\([^;]*(path|file|dir|url|attachment|document|download)'
    confidence: low
    false_positive_notes: >-
      The read sink contains no superglobal, so every request-centred rule misses it. Once a
      download handler is known to read its path from stored state, work backwards: which
      endpoints can write that meta key or option, and what authorization do THEY require? A
      Contributor who can set a post meta value owns the download handler's input. Same
      two-step shape as WP-DELETE's DELETE-008.
  - id: FILEREAD-009
    description: Registered query vars and rewrite rules — entry points with no superglobal
    regex: '(\badd_query_var\s*\(|\bget_query_var\s*\(|query_vars\s*\[)'
    confidence: low
    false_positive_notes: >-
      A value registered with add_query_var() arrives from ?name=... exactly like $_GET, but
      is read as $wp_query->query_vars['name'] or get_query_var('name'), so no
      superglobal appears anywhere near the sink. Rewrite rules feed the same array. Build
      the list of registered vars first, then treat every read of one as tainted input. This
      is the entry point in the Hide My WP Lite case study.
  - id: FILEREAD-010
    description: URL validator or validate_file() used where a containment check is required
    regex: '\b(esc_url_raw|esc_url|validate_file)\s*\(|filter_var\s*\([^;]*FILTER_VALIDATE_URL'
    confidence: low
    false_positive_notes: >-
      Both functions are legitimate and neither is a path control. esc_url_raw() preserves a
      schemeless absolute path such as /etc/passwd unchanged, because that is a valid
      root-relative URL. validate_file() returns non-zero for "..", "./" and Windows drive
      letters, but returns 0 — meaning valid — for any absolute POSIX path. Used together
      they look like belt and braces and stop neither. A hit matters only when the value
      goes on to reach a filesystem sink; noisy otherwise.
fix_apis:
  - realpath()
  - wp_normalize_path()
  - validate_file()
  - wp_basename()
  - trailingslashit()
  - wp_check_filetype()
  - current_user_can()
  - check_ajax_referer()
  - wp_get_attachment_url()
examples:
  - cve: CVE-2024-13671
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: An AJAX action registered for logged-out users passed a request parameter straight to file_get_contents() and returned the bytes in the JSON response.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13671
    code_ref: https://plugins.trac.wordpress.org/browser/music-sheet-viewer/trunk/music-sheet-viewer.php#L748
    root_cause: A raw $_POST value used as the argument to file_get_contents(), with the result echoed back; no capability check, no nonce, no containment.
  - cve: CVE-2024-12849
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: A log-download handler on a nopriv AJAX hook streamed any path supplied in the request, using is_admin() as its authorization check and applying basename() only to the response filename.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-12849
    code_ref: https://plugins.trac.wordpress.org/browser/error-log-viewer-wp/tags/1.0.1.3/error-log-viewer-wp.php#L479
    root_cause: is_admin() is true for any anonymous admin-ajax request, sanitize_text_field() does not remove ../, and the basename() call protected the Content-Disposition header rather than the readfile() argument.
  - cve: CVE-2026-13347
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: An asset-wrapper hook read a registered query variable, joined it to ABSPATH, and returned the file contents, so no request superglobal appeared anywhere near the read.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-13347
    code_ref: https://plugins.trac.wordpress.org/browser/hide-wp-login/tags/1.3/includes/functions.php#L139
    root_cause: A value registered with add_query_var() is attacker-controlled input; file_exists() was used as the containment check and str_replace() as the only filtering.
  - cve: CVE-2025-14388
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: The extension allowlist inspected the URL-decoded path while the path builder truncated the same string at the first null byte, so a name ending in an allowed extension resolved to a completely different file.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-14388
    code_ref: https://plugins.trac.wordpress.org/browser/phastpress/tags/3.6/sdk/phast.php#L9641
    root_cause: The validator and the sink normalised the input differently; the allowlist was applied to a string that was never the one opened.
  - cve: CVE-2026-14500
    year: 2026
    severity: 5.3
    auth: unauthenticated
    summary: An unauthenticated AJAX handler opened a request-supplied path with fopen() and echoed the first CSV row back as select options, filtered only by esc_url_raw() and validate_file().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14500
    code_ref: https://plugins.trac.wordpress.org/browser/bulk-order-update-for-woocommerce/tags/1.6/inc/plugin-html.php#L23
    root_cause: esc_url_raw() leaves an absolute filesystem path intact and validate_file() only rejects ../, so neither constrains the path to a directory.
  - cve: CVE-2025-1730
    year: 2025
    severity: 6.5
    auth: author+
    summary: A download endpoint resolved the file path from post meta on a published download post and streamed it with readfile(), so an author who could create such a post chose the path.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-1730
    code_ref: https://plugins.trac.wordpress.org/browser/simple-download-counter/tags/2.0/inc/functions-core.php#L306
    root_cause: The streamed path came from stored state with no containment check; whoever could write that meta key controlled the read.
---

## What it is

A request parameter reaches a function that **returns the bytes of a file** —
`readfile()`, `file_get_contents()`, `fpassthru()`, a `fopen()`+`fgetcsv()` pair, or a
download handler that streams with `Content-Disposition: attachment`. With `../`, an
absolute path, or a stream wrapper, the attacker chooses which file. `wp-config.php` yields
the database credentials and all eight authentication salts; `/etc/passwd` confirms the
account layout; a backup archive yields everything at once.

**The distinction from WP-LFI is the sink, and it is a real distinction.** In WP-LFI the
tainted path reaches `include`/`require`, so the file is **executed** and the bug is remote
code execution against any file the attacker can get content into. Here the file is
**read and returned**, so the bug is disclosure. The same tainted value frequently reaches
both kinds of sink in the same plugin — CVE-2024-9047 and CVE-2024-11613, analysed under
WP-LFI, are literally the same downloader script — which is why the two classes have
separate rules with separate severities rather than one merged class. When you find a hit
for `FILEREAD-001`, check whether the same variable also reaches an `include`; if it does,
escalate to WP-LFI. Conversely, WP-DELETE and WP-TRAVERSAL cover the same traversal
mechanics against `unlink()` and against write/move operations.

## Why it happens in WordPress

- **Download handlers are a product requirement.** Invoices, licences, exports, gated PDFs,
  purchase receipts, log viewers. Each one is `?action=download&file=…` with a `readfile()`
  at the bottom, and the "which files may be reached" question gets answered with
  `file_exists()`.
- **`file_exists()` is not a containment check.** It answers "is there a file there", not
  "is that file inside the directory I meant". Half the case studies below use it as if it
  were the latter.
- **`is_admin()` is not an authorization check.** It returns the value of the `WP_ADMIN`
  constant, and `admin-ajax.php` defines `WP_ADMIN` as `true` before any login check — so
  `is_admin()` is `true` for a completely anonymous POST. See
  `kb/reference/entry-points.md` §1. Guarding a download handler with `is_admin()` guards
  nothing.
- **`sanitize_text_field()` looks like sanitisation and is not path sanitisation.** It
  leaves `../`, `/` and `\` completely intact. Shared false defence with WP-LFI and
  WP-DELETE.
- **`esc_url_raw()` accepts root-relative paths.** `/etc/passwd` is a valid relative URL, so
  it survives `esc_url_raw()` unchanged. Applying a URL escaper to something destined for
  `fopen()` is a category error that reads as diligence.
- **`validate_file()` does not do containment.** It rejects `..`, `./` and Windows drive
  letters. It returns `0` (valid) for `/etc/passwd`. It is a useful extra gate and never a
  sufficient one.
- **Registered query vars hide the taint.** `add_query_var( 'x' )` plus a rewrite rule makes
  `?x=…` arrive as `get_query_var( 'x' )`. No `$_GET` appears anywhere near the sink, so
  every superglobal-based rule misses it.
- **The path often comes from post meta or an option**, written by a different endpoint at a
  different privilege level.
- **Standalone plugin `.php` files are directly reachable by URL** and frequently bootstrap
  themselves instead of loading `wp-load.php`, so no WordPress authentication is in the call
  path at all.

## Vulnerable pattern

```php
// The archetype: an AJAX action open to logged-out users that reads and returns a file.
add_action( 'wp_ajax_example_readfile',        array( $this, 'read_file' ) );
add_action( 'wp_ajax_nopriv_example_readfile', array( $this, 'read_file' ) );

public function read_file() {
    if ( isset( $_POST['url'] ) ) {
        $url = $_POST['url'];                       // no capability check, no nonce
        $out = array( 'status' => 'success', 'data' => file_get_contents( $url ) );
        echo wp_json_encode( $out );
    }
    wp_die();
}
```

The download-handler variant, with three false defences stacked on top of each other:

```php
public function example_log_download() {
    // is_admin() is TRUE for an anonymous POST to admin-ajax.php.
    if ( is_admin() && isset( $_POST['example_log'] ) ) {

        // Strips tags and control characters. Leaves ../ untouched.
        $file = sanitize_text_field( $_POST['example_log'] );

        header( 'Content-Type: application/octet-stream' );
        // basename() here protects the HEADER, not the path that is about to be read.
        header( 'Content-Disposition: attachment; filename=' . basename( $file ) );
        header( 'Content-Length: ' . filesize( $file ) );
        readfile( $file );                          // <-- still the raw traversable path
        exit;
    }
}
```

And the variant with no superglobal anywhere near the sink:

```php
// init: registers ?example_asset=... as a query var, so it never appears as $_GET.
$wp->add_query_var( 'example_asset' );

// wp: reads it back and streams the file.
public function example_serve_asset() {
    global $wp_query;
    $rel = $wp_query->query_vars['example_asset'];
    if ( ! empty( $rel ) && file_exists( ABSPATH . '/' . $rel ) ) {   // existence, not containment
        header( 'Content-type: text/css' );
        echo file_get_contents( ABSPATH . '/' . $rel );
        exit;
    }
}
```

## Secure pattern

Two correct shapes. Prefer the first whenever the reachable set is finite, and prefer
letting WordPress resolve the path over resolving it yourself.

```php
/**
 * Shape 1 — ID, NOT PATH. The request selects a record; the record knows its own file.
 * There is no attacker-controlled string in the path at any point.
 */
function example_download_attachment() {
    if ( ! is_user_logged_in() ) { wp_die( 'forbidden', 403 ); }
    check_ajax_referer( 'example_download', 'nonce' );

    $attachment_id = isset( $_GET['id'] ) ? absint( $_GET['id'] ) : 0;
    if ( ! $attachment_id || 'attachment' !== get_post_type( $attachment_id ) ) {
        wp_die( 'not found', 404 );
    }

    // Object-level authorization, not just "is logged in" — see WP-IDOR.
    if ( ! current_user_can( 'read_post', $attachment_id ) ) {
        wp_die( 'forbidden', 403 );
    }

    $path = get_attached_file( $attachment_id );          // core resolves it
    if ( ! $path || ! is_file( $path ) ) { wp_die( 'not found', 404 ); }

    $type = wp_check_filetype( $path );
    header( 'Content-Type: ' . ( $type['type'] ? $type['type'] : 'application/octet-stream' ) );
    header( 'Content-Disposition: attachment; filename="' . wp_basename( $path ) . '"' );
    header( 'X-Content-Type-Options: nosniff' );
    readfile( $path );
    exit;
}
```

```php
/**
 * Shape 2 — REALPATH CONTAINMENT. Use only when filenames are genuinely dynamic.
 */
function example_download_report() {
    if ( ! current_user_can( 'export' ) ) { wp_die( 'forbidden', 403 ); }
    check_admin_referer( 'example_report' );

    // 1. Canonicalise the base ONCE and trailing-slash it, so /reports-evil cannot
    //    satisfy a prefix test against /reports.
    $base = realpath( wp_upload_dir()['basedir'] . '/example-reports' );
    if ( false === $base ) { wp_die( 'misconfigured', 500 ); }
    $base = trailingslashit( wp_normalize_path( $base ) );

    // 2. Strip directory components. Necessary, not sufficient.
    $name = isset( $_GET['file'] ) ? wp_basename( wp_unslash( $_GET['file'] ) ) : '';
    if ( '' === $name || 0 !== validate_file( $name ) ) { wp_die( 'bad request', 400 ); }

    // 3. Reject anything that looks like a stream wrapper before it reaches a filesystem call.
    if ( false !== strpos( $name, '://' ) || false !== strpos( $name, "\0" ) ) {
        wp_die( 'bad request', 400 );
    }

    // 4. Canonicalise the candidate and require a STRICT PREFIX match.
    $real = realpath( $base . $name );
    if ( false === $real ) { wp_die( 'not found', 404 ); }
    $real = wp_normalize_path( $real );

    if ( 0 !== strpos( $real, $base ) ) {            // strict !==, never == 0
        wp_die( 'forbidden', 403 );
    }

    // 5. Derive the response type from the RESOLVED path, and refuse types with no mapping.
    $type = wp_check_filetype( $real );
    if ( empty( $type['type'] ) ) { wp_die( 'forbidden', 403 ); }

    header( 'Content-Type: ' . $type['type'] );
    header( 'Content-Disposition: attachment; filename="' . wp_basename( $real ) . '"' );
    header( 'X-Content-Type-Options: nosniff' );
    readfile( $real );
    exit;
}
```

Non-negotiables, in the order they are most often got wrong:

- **The capability check comes first.** A containment bug behind
  `current_user_can( 'manage_options' )` is a low-severity finding; the same bug on
  `wp_ajax_nopriv_` is a 7.5.
- **Canonicalise the base as well as the candidate**, and compare with a **strict** `!== 0`.
  `strpos(...) == 0` accepts `false`, which is exactly the case being rejected — the highest
  value single check in WP-LFI and WP-DELETE, and it applies here unchanged.
- **Validate the same bytes the sink receives.** If the allowlist inspects a decoded or
  pre-truncation string and the opener sees another, the allowlist is decorative.
- **Reject `://` and `\0` explicitly.** `php://filter/convert.base64-encode/resource=…`
  bypasses any check that looks for `..`, and a null byte defeats extension allowlists.

## Real-world case studies

### The whole bug in one statement (CVE-2024-13671, 7.5, unauthenticated)

```php
add_action('wp_ajax_readfile', array($this, 'read_score_file'));
add_action('wp_ajax_nopriv_readfile', array($this, 'read_score_file'));
```

```php
public function read_score_file()
{
    if (isset($_POST['url']))
    {
        $url = $_POST['url'];
        $array_return['status'] = 'success';
        if (strlen($url)<= 4 || strrpos($url, ".mxl", strlen($url)-4) === FALSE)
        {
            $array_return['data'] = file_get_contents($url);
```
`https://plugins.trac.wordpress.org/browser/music-sheet-viewer/trunk/music-sheet-viewer.php#L748`

**Root cause at that line:** `$_POST['url']` is passed unmodified to `file_get_contents()`
and the bytes are returned in the JSON response. There is no capability check, no nonce and
no path processing of any kind. The `.mxl` test is a *format* branch, not a filter — a name
not ending in `.mxl` takes the direct-read path, which is the one the attacker wants.

Note also the branch that is taken for `.mxl` names:

```php
if (strpos($url,'/') === 0) // local file
    $url = ABSPATH.$url;
```

It explicitly supports local absolute paths, which tells you the "url" parameter was never
intended to be a URL. **When a parameter's name says URL but the code handles paths, treat
it as a path parameter** — and note that a genuine URL here would also make this SSRF, so
both classes apply.

### Three false defences stacked (CVE-2024-12849, 7.5, unauthenticated)

The registration sits inside an `is_admin()` block, which is what makes it *look* internal:

```php
if ( is_admin() ) {
    ...
    add_action( 'wp_ajax_nopriv_elvwp_log_download', array(
        $this,
        'elvwp_log_download',
    ) );
```

and the handler repeats the same non-check:

```php
public function elvwp_log_download() {

    if ( is_admin() && isset( $_POST['elvwp_error_log_download'] ) && isset( $_POST['elvwp_error_log'] ) && !empty( sanitize_text_field( $_POST['elvwp_error_log'] ) ) ) {

        $elvwp_file = sanitize_text_field( $_POST['elvwp_error_log'] );

        try {
            $filename = basename( $elvwp_file );
            ...
            header( 'Content-Disposition: attachment; filename='.$filename );
            ...
            header( 'Content-Length: ' . filesize( $elvwp_file ) );
            flush();
            readfile( $elvwp_file );
            exit;
```
`https://plugins.trac.wordpress.org/browser/error-log-viewer-wp/tags/1.0.1.3/error-log-viewer-wp.php#L479`

**Root cause at those lines — three independent failures that each look like a control:**

1. `is_admin()` returns `WP_ADMIN`, which `admin-ajax.php` defines as `true` before any
   login check. It is `true` for an anonymous POST. Wrapping the `add_action` in
   `if ( is_admin() )` narrows *when the hook is registered*, not *who may call it*, and the
   hook that is registered is the `_nopriv_` one.
2. `sanitize_text_field()` strips tags and control characters and leaves `../` intact.
3. `basename()` **is** called — on line 484 — and its result goes into `$filename`, which is
   used only in the `Content-Disposition` header. The raw `$elvwp_file` is what reaches
   `filesize()` and `readfile()`.

Point 3 is why `FILEREAD-004` exists as its own rule. A reviewer greps for `basename`, sees
it two lines above the `readfile`, and moves on. **Compare the argument of the header's
`basename()` with the argument of the read sink; if they are different variables, the
sanitisation was never applied.**

### The taint arrives as a query var (CVE-2026-13347, 7.5, unauthenticated)

Registration, on `init`:

```php
$wp->add_query_var('he_wrapper_js');
$wp->add_query_var('he_wrapper_css');
```

and the sink, on `wp`:

```php
public function elementor_assets_filter() {
    global $wp, $wp_query;
    if (!is_admin()) {
        ...
        if (isset($wp_query->query_vars['he_wrapper_css']) && $wp_query->query_vars['he_wrapper_css'] && $this->is_permalink()) {
            $is_css = true;
            $request_path = str_replace('elem-', 'elementor-', $wp_query->query_vars['he_wrapper_css']);
        }
        if (!empty($request_path) && file_exists(ABSPATH . '/' . $request_path)) {
            $filepath = ABSPATH . '/' . $request_path;
            ...
            $code = file_get_contents($filepath);
            $code = str_replace('elementor-', 'elem-', $code);
            echo wp_kses_post($code);
            exit;
```
`https://plugins.trac.wordpress.org/browser/hide-wp-login/tags/1.3/includes/functions.php#L139`

**Root cause at that line:** `?he_wrapper_css=../../wp-config.php` is a plain GET, but
because the parameter was registered with `add_query_var()` it is read from
`$wp_query->query_vars`, so **no superglobal appears anywhere in the vulnerable function**.
`file_exists()` is again the only gate. `str_replace('elem-','elementor-')` is a naming
convention, not a filter, and `wp_kses_post()` on the way out is an HTML escaper applied to
file bytes — it mangles the output but does not stop the disclosure.

**Detection lesson:** build the list of registered query vars *first* (`add_query_var`, the
`query_vars` filter, `add_rewrite_rule`, `add_rewrite_endpoint`) and treat every read of one
as tainted. `FILEREAD-009` exists for exactly this, and the same blind spot applies to
WP-SQLI and WP-XSS-R.

### The validator and the sink saw different strings (CVE-2025-14388, 9.8, unauthenticated)

```php
private function guard(\Kibo\Phast\ValueObjects\URL $url, callable $cb)
{
    if (!in_array($this->getExtensionForURL($url), self::getAllowedExtensions())) {
        return false;
    }
    $file = $this->getFileForURL($url);
    ...
}
private function getExtensionForURL(\Kibo\Phast\ValueObjects\URL $url)
{
    $dotPosition = strrpos($url->getDecodedPath(), '.');
    ...
    return strtolower(substr($url->getDecodedPath(), $dotPosition + 1));
}
```

```php
private function appendNormalized($target, $appended)
{
    $appended = explode("\0", $appended)[0];
    $appended = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $appended);
```
`https://plugins.trac.wordpress.org/browser/phastpress/tags/3.6/sdk/phast.php#L9641`

**Root cause at that line:** the allowlist is real, the containment normaliser is real, and
they operate on **different strings**. `getExtensionForURL()` takes the last dot-suffix of
the *full decoded path*, so `/wp-config.php%00.css` has extension `css` and passes
`in_array()`. `appendNormalized()` then does `explode("\0", $appended)[0]`, discarding
everything from the null byte onward, so the path actually opened is `/wp-config.php`.

This is the most instructive shape in the class because **no single line is wrong**. The
defect is a discrepancy between two normalisations, which is invisible to any rule that
examines one statement at a time. Generalise it: whenever a validator and a sink both
process the same input, write down the exact transformation each applies and check they
agree. Null bytes are the classic wedge, but URL-decoding on one side only, `wp_unslash()`
ordering, case folding, Unicode normalisation, and trailing dots/spaces on Windows all
produce the same class of bug. `FILEREAD-007` is the worklist for it.

### Two URL-shaped guards, neither of which constrains a path (CVE-2026-14500, 5.3, unauthenticated)

```php
function bouw_fetch_csv_data() {
    if(isset($_POST['csv_url']) && !empty($_POST['csv_url'])){
        $csv_file_path = esc_url_raw($_POST['csv_url']);
    } else { ... }

    if(!validate_file( $csv_file_path )){
        $html = '<label for="select_order_field">Select the Column Containing Order ID :  </label>';
        $html .= '<select ...>';
        $f = fopen($csv_file_path, "r");
        $line = fgetcsv($f);
        ...
        foreach ($line  as $key => $value) {
            $html .= "<option value='".htmlspecialchars($key)."'>" .htmlspecialchars($key).'. '. htmlspecialchars($value) . "</option>";
        }
    ...
add_action('wp_ajax_nopriv_bouw_fetch_csv_data', 'bouw_fetch_csv_data');
```
`https://plugins.trac.wordpress.org/browser/bulk-order-update-for-woocommerce/tags/1.6/inc/plugin-html.php#L23`

**Root cause at those lines:** `esc_url_raw()` is a URL escaper. `/etc/passwd` is a valid
root-relative URL, so it comes back unchanged. `validate_file()` rejects `..`, `./` and
Windows drive letters — and returns `0` for an absolute POSIX path, so the `!validate_file()`
test passes. Neither function asks the only question that matters: *is this path inside a
directory I control?* The `htmlspecialchars()` on the way out is XSS defence, not
confidentiality defence.

Two further points worth carrying. First, the disclosure is **partial** — only the first CSV
row is echoed, as `<option>` labels. Partial reads are still findings: one row of
`wp-config.php` is enough for a `DB_PASSWORD` line, and repeated calls against a
`php://filter` chain can page through a file. Second, `menu_page` registration for this
plugin requires `manage_options`, but the AJAX action is registered on `_nopriv_` — **the
capability on the admin screen tells you nothing about the capability on the handler**.

### The path comes from stored state (CVE-2025-1730, 6.5, author+)

```php
if (isset($_GET[$key]) && !empty($_GET[$key])) {
    $wp->query_vars[$key] = sanitize_key($_GET[$key]);
}
...
$id = sanitize_title(wp_unslash($wp->query_vars[$key]));
...
$file_path = get_post_meta($id, 'sdc_download_path', true);
...
readfile($file_path);
```
`https://plugins.trac.wordpress.org/browser/simple-download-counter/tags/2.0/inc/functions-core.php#L306`

**Root cause at that line:** the request parameter is well sanitised (`sanitize_key()` then
`sanitize_title()`) and is used only as a post id. The path that is streamed comes from the
`sdc_download_path` post meta of that post, and nothing constrains it to any directory. An
Author can create a published download post and set its meta, so the meta value — and
therefore the read — is attacker-chosen. There is an optional `sdc_download_hash` gate, but
it is only applied when a hash has been stored.

This is the two-step shape `FILEREAD-008` exists for, and it is identical to WP-DELETE's
`DELETE-008`. **Once a read sink is known to take its path from stored state, the audit
question moves upstream: enumerate every writer of that key and audit *their*
authorization.** Grepping around the `readfile()` finds no superglobal and no bug.

## Detection guidance

**What the regexes catch reliably**

- `FILEREAD-001` catches the direct one-statement case, which is still the majority of
  disclosed bugs, and includes `fopen` so that `fgetcsv`/`fread` handlers are not missed.
- `FILEREAD-006` catches the URL-to-path conversion idiom, which is high-yield and
  essentially always wrong.
- `FILEREAD-002` produces a complete, short inventory of download endpoints. Exhaustive
  manual triage of that list is realistic and is the recommended workflow for this class.

**What the regexes CANNOT catch — read the code**

1. **Multi-hop taint.** `$f = $_GET['file'];` … forty lines … `$path = $base . $f;` …
   another file … `readfile( $path );`. The normal shape of real code and of real bugs.
   `FILEREAD-003` produces the worklist; the finding requires following the variable.
2. **Entry points that are not superglobals.** Registered query vars and rewrite endpoints
   (CVE-2026-13347), session values, cookies written by another endpoint, and the plugin's
   own router (`task=`, `do=`). Enumerate these before assuming the input surface is
   `$_GET`/`$_POST`.
3. **An attacker-controlled *base* directory.** A grep sees `$base . $file` and reasons
   about `$file`. Ask where the left-hand operand came from. A `realpath()` containment check
   against a base read from a cookie is worthless — the CVE-2024-9047 shape under WP-LFI.
4. **Whether an existing `realpath()` check is correct.** Presence proves nothing. Verify:
   base canonicalised, base trailing-slashed, strict `!== 0` comparison, `false` handled,
   and both operands the same *kind* of thing (path vs path, not path vs URL).
5. **Normalisation discrepancies.** CVE-2025-14388. Null bytes, one-sided URL decoding,
   `wp_unslash()` ordering, case folding, trailing dots and spaces. Write down what the
   validator sees and what the sink sees.
6. **Stream wrappers.** `php://filter/convert.base64-encode/resource=../wp-config.php`
   defeats every `..`-hunting check *and* returns the file base64-encoded so it survives an
   HTML-escaping output path. `data://`, `phar://` (which also triggers deserialisation on
   any file operation — see WP-POI), `expect://`, `zip://`. If the code does not reject
   `://`, assume all of these are reachable.
7. **Non-HTTP read sinks.** `wp_mail()` attachments, `ZipArchive::addFile()`, CSV/report
   exporters, `WP_Http` request bodies, image libraries, template engines. `FILEREAD-005`
   is a partial list; "arbitrary file read" does not require `readfile()`.
8. **Partial and blind reads.** Only the first line is echoed; only `filesize()` is
   returned; only "readable / not readable" is distinguishable; the file is parsed as XML
   and only errors leak. All are still disclosure, and `php://filter` chains turn a
   one-line leak into a full read.
9. **Whether `basename()` was applied to the value that reaches the sink** or only to the
   response header (CVE-2024-12849).
10. **Whether an authorization check exists at all**, and whether the one that exists is
    real. `is_admin()`, `wp_doing_ajax()`, `defined('WP_ADMIN')` and a bare nonce are not
    authorization; see `kb/reference/entry-points.md` §1 and WP-INFO's nonce discussion.

## Audit checklist

- [ ] Run `FILEREAD-002` to inventory every download endpoint, then triage each one
      exhaustively — the list is short and this is the highest-yield pass.
- [ ] Run `FILEREAD-001`; treat every hit as a finding until proven otherwise, and check
      whether the same variable also reaches an `include`/`require` (escalate to WP-LFI).
- [ ] Run `FILEREAD-006`; a URL-to-path `str_replace()` with no subsequent `realpath()`
      containment check is a finding.
- [ ] Build the entry-point list before the taint analysis: `add_query_var`, the
      `query_vars` filter, `add_rewrite_rule`, `add_rewrite_endpoint`, the plugin's own
      router, `$_SESSION`, `$_COOKIE`.
- [ ] For every read sink, establish provenance of **both** operands of the path
      concatenation, including the base directory.
- [ ] For each `realpath()` present, verify base canonicalised, base trailing-slashed,
      strict `!== 0` comparison, `false` handled, operands the same kind.
- [ ] Run `FILEREAD-004`; compare the `basename()` argument in the header with the argument
      of the read sink.
- [ ] Run `FILEREAD-007`; for each allowlist, confirm the validated string is byte-identical
      to the string the sink opens. Test explicitly with a `%00` suffix.
- [ ] Grep for `://` and `"\0"` rejection; if absent, assume stream wrappers and null bytes
      are reachable.
- [ ] Run `FILEREAD-008`; for every path read from meta/option/transient, enumerate the
      endpoints that can write that key and audit their authorization.
- [ ] Run `FILEREAD-005` and enumerate non-obvious read sinks: mail attachments, ZIP
      builders, exporters, remote POST bodies.
- [ ] Grep for `is_admin()` guarding a file operation — it is not an authorization check.
- [ ] Grep for `sanitize_text_field`, `esc_url_raw` and `validate_file` applied to a value
      that reaches a read sink; none of them constrains a path to a directory.
- [ ] Enumerate every `.php` file in the plugin and confirm each has
      `if ( ! defined( 'ABSPATH' ) ) exit;`; any file without it that reads request data is
      an unauthenticated endpoint regardless of the hooks the plugin registers.
- [ ] Confirm the handler enforces `current_user_can()` — and, where the file belongs to a
      specific record, a per-object check (see WP-IDOR) — before any path resolution.
