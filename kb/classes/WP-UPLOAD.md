---
class_id: WP-UPLOAD
title: Arbitrary File Upload leading to Remote Code Execution
cwe: [CWE-434, CWE-646, CWE-20]
owasp: A04:2021-Insecure Design
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 4
detection:
  - id: UPLOAD-001
    description: Raw move_uploaded_file() — bypasses wp_handle_upload()'s core MIME/extension enforcement
    regex: 'move_uploaded_file\s*\('
    confidence: high
    false_positive_notes: >-
      A plugin has almost no legitimate reason to call this directly. Safe only if the
      surrounding code ran wp_check_filetype_and_ext() on tmp_name AND rewrote the
      destination extension from the verified type. An extension allowlist checked before
      the move is necessary but not sufficient — verify the destination filename is built
      from the *verified* extension, not from $_FILES['x']['name'].
  - id: UPLOAD-002
    description: Client-supplied Content-Type ($_FILES[..]['type']) used as a security decision
    regex: '\$_FILES\s*\[[^\]]*\]\s*\[\s*[''"]type[''"]\s*\]'
    confidence: high
    false_positive_notes: >-
      Benign when the value is only stored/logged/echoed. It is a finding whenever it feeds
      in_array(), a switch, str_starts_with(), strpos(), preg_match() or any branch that
      decides whether the upload proceeds. This value is a request header field — fully
      attacker-controlled and never validated by PHP.
  - id: UPLOAD-003
    description: MIME prefix test on a variable that holds a client-declared type
    regex: '(str_starts_with|strpos)\s*\(\s*\$[a-zA-Z_0-9]+\s*,\s*[''"](image|video|audio|text|application)/'
    confidence: medium
    false_positive_notes: >-
      Safe if the variable came from finfo_file(), mime_content_type(), wp_get_image_mime()
      or wp_check_filetype_and_ext(). A finding if it was assigned from $_FILES[..]['type']
      or from an aliased copy of a $_FILES element — the assignment is usually several lines
      above, so this regex cannot resolve it. Always read the assignment.
  - id: UPLOAD-004
    description: wp_handle_upload()/wp_handle_sideload() with test_form disabled
    regex: '[''"]test_form[''"]\s*=>\s*false'
    confidence: low
    false_positive_notes: >-
      Downgraded to low after integration testing: this regex fired on a CORRECT upload
      config in tests/fixtures/safe.php. The conditions that make it a real finding are
      array-level, not line-level, so no single-line regex can express them and every hit
      needs triage by construction.
      test_form => false is normal and often required for AJAX/REST handlers. It is a finding
      only when (a) the same $overrides array has no 'mimes' key, or (b) 'test_type' => false
      is also present, or (c) the caller performs no capability/nonce check. Grep the matched
      line and the ~8 lines around it for 'mimes' and 'test_type' before triaging.
  - id: UPLOAD-005
    description: Dangerous-extension blocklist (denylist) rather than an allowlist
    regex: '[''"](php[0-9]?|phtml|phar|phps)[''"]\s*,\s*[''"](php[0-9]?|phtml|phar|phps|exe|sh|cgi|pl|asp|jsp)[''"]'
    confidence: high
    false_positive_notes: >-
      Matches the literal array of "banned" extensions. Every such list is incomplete by
      construction — .phtml, .phar, .phps, .php7, .pht, .shtml, .htaccess, .user.ini and
      server-specific handler extensions are routinely omitted. Also matches hardening
      .htaccess RemoveHandler lines, which are a *good* sign; check the file context.
  - id: UPLOAD-006
    description: wp_check_filetype() used as the only type check (filename-only, no content sniff)
    regex: '\bwp_check_filetype\s*\('
    confidence: medium
    false_positive_notes: >-
      wp_check_filetype() looks at the *name* only. It is acceptable as a first gate but must
      be paired with wp_check_filetype_and_ext() (which runs finfo/getimagesize on the actual
      bytes). Does not match wp_check_filetype_and_ext() because of the required '(' .
  - id: UPLOAD-007
    description: File written from a remote/fetched body — an upload sink with no $_FILES
    regex: '\b(file_put_contents|fwrite|fputs)\s*\('
    confidence: low
    false_positive_notes: >-
      Very noisy (caches, logs, .htaccess writers). Triage: is any part of the destination
      path or filename attacker-influenced (basename($url), $_POST value, a filename echoed
      back from a remote response), and is the destination inside a web-served directory?
      This is the sink that upload-focused rules miss entirely.
  - id: UPLOAD-008
    description: Unauthenticated entry point reachable without login
    regex: 'wp_ajax_nopriv_|[''"]permission_callback[''"]\s*=>\s*[''"]__return_true[''"]'
    confidence: medium
    false_positive_notes: >-
      Not a vulnerability on its own — it is the severity multiplier. Every UPLOAD-001..007
      hit that is reachable from one of these becomes a CVSS 9.8 candidate. Note that a
      handler hooked to a *public form processor* filter (e.g. a form plugin's
      "process_before" filter) is equally unauthenticated but matches neither pattern.
fix_apis:
  - wp_handle_upload()
  - wp_handle_sideload()
  - wp_check_filetype_and_ext()
  - get_allowed_mime_types()
  - wp_unique_filename()
  - sanitize_file_name()
  - current_user_can()
  - check_ajax_referer()
  - wp_insert_attachment()
examples:
  - cve: CVE-2026-15748
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A dangerous-extension blocklist matched MIME-map keys with exact string comparison, so a pipe-alternation key such as "phtml|php" never matched the banned entry "php" and survived the filter.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15748
    code_ref: https://plugins.trac.wordpress.org/browser/forminator/tags/1.55.1/library/helpers/helper-fields.php#L3430
    root_cause: Blocklist used in_array($key, $filters, true) against WordPress MIME-map keys, which are pipe-alternation groups, not single extensions.
  - cve: CVE-2026-14282
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A handler hooked into a public form processor accepted the attacker-supplied multipart Content-Type as proof the file was a video, kept the original filename, and moved the raw upload into a web-served uploads subdirectory.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14282
    code_ref: https://plugins.trac.wordpress.org/browser/godam/tags/1.11.2/inc/classes/wpforms/class-wpforms-field-godam-video.php#L393
    root_cause: str_starts_with($file['type'], 'video/') on the client-declared MIME, then $wp_filesystem->move() with the original extension — wp_handle_upload() never invoked.
  - cve: CVE-2026-6555
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: The validation gate read only element [0] of the multi-file $_FILES array while the downstream upload handler independently iterated and moved every element.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6555
    code_ref: https://plugins.trac.wordpress.org/browser/prosolution-wp-client/tags/2.0.0/public/class-prosolwpclient-public.php#L1006
    root_cause: Validation and use read different array elements — extension/finfo/getimagesize checks applied to $_FILES['files']['name'][0] only, while the handler looped over all tmp_name entries.
  - cve: CVE-2026-1405
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A REST route registered with permission_callback __return_true fetched an attacker-supplied URL and wrote the response body to the uploads directory under a filename derived from the URL, with no extension or content check at all.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1405
    code_ref: https://plugins.trac.wordpress.org/browser/slider-future/tags/1.0.5/slider-future.php#L198
    root_cause: basename($image_url) used as the destination filename and file_put_contents() as the sink — no $_FILES and no move_uploaded_file(), so upload-shaped detection rules never fire.
  - cve: CVE-2026-12476
    year: 2026
    severity: 7.2
    auth: admin+
    summary: An importer checked the client-supplied $_FILES[..]['type'] header against a CSV MIME allowlist and then used raw move_uploaded_file() to write the file under its original extension into a web-accessible exports directory.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12476
    code_ref: https://plugins.trac.wordpress.org/browser/easy-digital-downloads/tags/3.6.7/includes/admin/import/import-functions.php#L68
    root_cause: An allowlist applied to an attacker-controlled header is not an allowlist; the extension was never constrained and wp_handle_upload() was bypassed.
  - cve: CVE-2025-13516
    year: 2025
    severity: 8.1
    auth: unauthenticated
    summary: An email-logging feature duplicated every outbound attachment into a web-accessible uploads subdirectory with a content-derived (therefore predictable) filename and no extension or content-type validation.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-13516
    code_ref: https://plugins.trac.wordpress.org/browser/suremails/trunk/inc/emails/handler/uploads.php#L113
    root_cause: Directory hardening relied solely on an Apache .htaccess file, which is inert on nginx, IIS and Lighttpd, so the only real control was a validation step that did not exist.
  - cve: CVE-2025-7852
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A public image-upload handler called move_uploaded_file() on client-supplied files without restricting allowed extensions or MIME types and without sanitizing the filename.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-7852
    root_cause: move_uploaded_file() used as the primary upload API with no allowlist, on a route reachable without authentication.
  - cve: CVE-2024-6220
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: An image-download routine written for a content-import feature wrote fetched files to disk with no file type validation, reachable without authentication.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-6220
    code_ref: https://plugins.trac.wordpress.org/changeset/3127334/keydatas?contextall=1
    root_cause: Missing file type validation in a server-side fetch-and-store routine exposed on an unauthenticated endpoint.
---

## What it is

A plugin accepts a file from an HTTP request and writes it somewhere the web server will
execute. Because WordPress ships PHP under a document root, "somewhere executable" is the
default outcome unless the code deliberately prevents it. The attacker uploads a `.php`
file, requests its URL, and now runs arbitrary code as the web-server user. This is the
highest-impact class in the WordPress ecosystem: the unauthenticated variants are almost
uniformly scored CVSS 9.8 and are mass-exploited within days of disclosure.

## Why it happens in WordPress

WordPress has a correct upload API — `wp_handle_upload()`, backed by
`wp_check_filetype_and_ext()` and the `get_allowed_mime_types()` allowlist, which by
default contains no executable extension. Nearly every real vulnerability in this class
comes from stepping *around* that API rather than misconfiguring it:

- **`move_uploaded_file()` used directly.** It is the raw PHP primitive; it validates
  nothing but "this was really a POST upload". Any plugin calling it has opted out of
  every core control. `$wp_filesystem->move()` and `rename()` have the same effect.
- **`$_FILES['x']['type']` is not a fact.** PHP copies it verbatim from the
  `Content-Type` header of the multipart part. The attacker writes it. Checking it —
  even against a strict allowlist — is checking the attacker's own claim.
- **`$_FILES['x']['name']` is not a fact either.** It sets the extension that ends up on
  disk. Verification must decide the destination extension, not the other way round.
- **`wp_ajax_nopriv_*`, `permission_callback => '__return_true'`, `admin-post.php`
  nopriv actions, and hooks into another plugin's *public* form processor all run before
  any authentication.** A handler attached to a public form-submission filter is
  unauthenticated even though it contains neither `nopriv` nor `__return_true`.
- **`wp-content/uploads/` is web-served.** WordPress core does not disable PHP execution
  there. A file landing in `uploads/` is a URL away from execution.
- **Multi-file `$_FILES` arrays are parallel arrays, not a list of file objects.** Code
  that validates `$_FILES['f']['name'][0]` and then hands `$_FILES['f']` to a loop has a
  validation gate that guards nothing.

## Vulnerable pattern

```php
// Reachable with no login at all.
add_action( 'wp_ajax_nopriv_myplugin_upload', 'myplugin_upload' );
add_action( 'wp_ajax_myplugin_upload',        'myplugin_upload' );

function myplugin_upload() {
    $file = $_FILES['attachment'];

    // (1) The client wrote this header. It is not evidence of anything.
    if ( strpos( $file['type'], 'image/' ) !== 0 ) {
        wp_send_json_error( 'images only' );
    }

    // (2) A denylist. .phtml / .phar / .php7 / .pht / .htaccess are not on it.
    $blocked = array( 'php', 'php3', 'php4', 'php5', 'exe' );
    $ext     = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
    if ( in_array( $ext, $blocked, true ) ) {
        wp_send_json_error( 'nope' );
    }

    // (3) Destination extension comes from the attacker-supplied name.
    $dir  = wp_upload_dir();
    $dest = $dir['path'] . '/' . $file['name'];

    // (4) Raw move: no core validation, into a web-served directory with no .htaccess.
    move_uploaded_file( $file['tmp_name'], $dest );

    wp_send_json_success( $dir['url'] . '/' . $file['name'] );
}
```

Each numbered line is independently sufficient to lose the site. `shell.phtml`,
`shell.php.jpg` on a server with a permissive `AddHandler`, or a plain `.php` with
`Content-Type: image/png` all get through.

Two more shapes that are equally fatal and look nothing like the above:

```php
// Unrestricted core API: no 'mimes' allowlist, so it falls back to get_allowed_mime_types(),
// which any other plugin's upload_mimes filter may have widened to include executables.
$res = wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );

// No $_FILES at all: server-side fetch, attacker picks the URL and therefore the filename.
$body = wp_remote_retrieve_body( wp_remote_get( $_POST['image_url'] ) );
file_put_contents( wp_upload_dir()['path'] . '/' . basename( $_POST['image_url'] ), $body );
```

## Secure pattern

```php
add_action( 'wp_ajax_myplugin_upload', 'myplugin_upload' ); // no _nopriv_ variant

function myplugin_upload() {
    // 1. Authorisation and intent, before anything touches the filesystem.
    if ( ! current_user_can( 'upload_files' ) ) {
        wp_send_json_error( 'forbidden', 403 );
    }
    check_ajax_referer( 'myplugin_upload', 'nonce' );

    if ( empty( $_FILES['attachment'] ) || ! is_uploaded_file( $_FILES['attachment']['tmp_name'] ) ) {
        wp_send_json_error( 'no file', 400 );
    }

    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';

    // 2. An ALLOWLIST, keyed by extension regex -> real MIME type. Never a denylist.
    $allowed = array(
        'jpg|jpeg|jpe' => 'image/jpeg',
        'png'          => 'image/png',
        'gif'          => 'image/gif',
        'pdf'          => 'application/pdf',
    );

    // 3. Verify the BYTES, not the header. wp_check_filetype_and_ext() runs
    //    getimagesize()/finfo_file() on tmp_name and reports the real type.
    $check = wp_check_filetype_and_ext(
        $_FILES['attachment']['tmp_name'],
        $_FILES['attachment']['name'],
        $allowed
    );
    if ( empty( $check['ext'] ) || empty( $check['type'] ) ) {
        wp_send_json_error( 'file type not allowed', 400 );
    }

    // 4. Rebuild the filename from the VERIFIED extension. This kills shell.php.jpg,
    //    shell.phtml, embedded null bytes and every double-extension trick at once,
    //    because the attacker's string never determines the extension on disk.
    $_FILES['attachment']['name'] = sanitize_file_name(
        pathinfo( $_FILES['attachment']['name'], PATHINFO_FILENAME ) . '.' . $check['ext']
    );

    // 5. Let core do the move. 'mimes' pins the allowlist for this call only.
    $moved = wp_handle_upload(
        $_FILES['attachment'],
        array(
            'test_form' => false,  // fine: we already did our own nonce check
            'test_type' => true,   // NEVER false
            'mimes'     => $allowed,
        )
    );
    if ( isset( $moved['error'] ) ) {
        wp_send_json_error( $moved['error'], 400 );
    }

    // 6. Register it as an attachment so the media library owns cleanup and permissions.
    $attachment_id = wp_insert_attachment(
        array(
            'post_mime_type' => $moved['type'],
            'post_title'     => sanitize_text_field( basename( $moved['file'] ) ),
            'post_status'    => 'inherit',
        ),
        $moved['file']
    );
    wp_update_attachment_metadata(
        $attachment_id,
        wp_generate_attachment_metadata( $attachment_id, $moved['file'] )
    );

    wp_send_json_success( array( 'id' => $attachment_id ) );
}
```

If the plugin insists on a private directory outside the media library, it must create the
directory *and* harden it on activation — and must not treat the hardening as the primary
control:

```php
function myplugin_harden_dir( $dir ) {
    wp_mkdir_p( $dir );
    // index.php stops directory listing on every server.
    if ( ! file_exists( $dir . '/index.php' ) ) {
        file_put_contents( $dir . '/index.php', "<?php // Silence is golden." );
    }
    // .htaccess stops execution on Apache ONLY. nginx, IIS and Lighttpd ignore it.
    if ( ! file_exists( $dir . '/.htaccess' ) ) {
        file_put_contents(
            $dir . '/.htaccess',
            "<Files *>\n"
            . "  SetHandler none\n"
            . "  SetHandler default-handler\n"
            . "  Options -ExecCGI\n"
            . "  Options -Indexes\n"
            . "  RemoveHandler .cgi .php .php3 .php4 .php5 .php7 .phtml .phar .pl .py\n"
            . "</Files>\n"
            . "<IfModule mod_php.c>\n  php_flag engine off\n</IfModule>\n"
        );
    }
}
```

The strongest option is to keep uploads **outside the document root entirely** and serve
them through a PHP handler that performs its own capability check.

## Real-world case studies

### Blocklist keyed on the wrong string (CVE-2026-15748, 9.8, unauthenticated)

The helper responsible for stripping dangerous types from the allowed-MIME map:

```php
$filters = array( 'htm|html', 'js', 'jse', 'jar', 'php', 'php3', 'php4', 'php5', 'phtml', ... );
foreach ( array_keys( $mimes ) as $mime_key ) {
    $key = strtolower( $mime_key );
    if ( in_array( $key, $filters, true ) ) {
        unset( $mimes[ $mime_key ] );
    }
}
```
`https://plugins.trac.wordpress.org/browser/forminator/tags/1.55.1/library/helpers/helper-fields.php#L3430`

**Root cause at that line:** the keys of a WordPress MIME map are *extension-alternation
groups* (`'jpg|jpeg|jpe'`, `'php|phtml'`), not single extensions. `in_array(..., true)`
is an exact match. A key such as `'phtml|php'` is not equal to `'php'`, so the entry
survives the filter — and `wp_check_filetype()`, which splits keys on `|`, then happily
accepts `evil.php`. Note also the failure mode: the surviving map is later handed to
`wp_check_filetype()` at
`.../tags/1.55.1/library/fields/upload.php#L414`, so the "allowlist" the code believes it
is enforcing has been poisoned upstream. A denylist that has to be kept in sync with a
different data structure's key format is a denylist that will drift.

### The client's Content-Type header taken as truth (CVE-2026-14282, 9.8, unauthenticated)

```php
$mime_type = ! empty( $file['type'] ) ? $file['type'] : '';
$is_video  = ! empty( $mime_type ) && str_starts_with( $mime_type, 'video/' );
...
$filename   = wp_unique_filename( $wpforms_dir, $file['name'] );
$moved_file = $wp_filesystem->move( $file['tmp_name'], "{$wpforms_dir}/{$filename}" );
```
`https://plugins.trac.wordpress.org/browser/godam/tags/1.11.2/inc/classes/wpforms/class-wpforms-field-godam-video.php#L393`

**Root cause at that line:** `$file['type']` is the multipart `Content-Type` header the
client sent. Sending `Content-Type: video/mp4` with `filename="shell.php"` satisfies
`str_starts_with()`. `wp_unique_filename()` only de-duplicates — it preserves the
extension. `$wp_filesystem->move()` performs no validation, and `$wpforms_dir` is under
`wp-content/uploads/`. Three lines, no `move_uploaded_file()`, no `wp_handle_upload()`,
full RCE. Note that the handler is attached to a *form plugin's* public processing filter,
so it is unauthenticated without ever mentioning `nopriv`.

### Validation reads element [0]; the mover reads the whole array (CVE-2026-6555, 9.8, unauthenticated)

```php
$org_filename = isset( $submit_data['name'][0] ) ? sanitize_file_name( $submit_data['name'][0] ) : '';
$tmp_fileloc  = isset( $submit_data['tmp_name'][0] ) ? $submit_data['tmp_name'][0] : '';
...
$up_fileext    = strtolower( pathinfo( $org_filename, PATHINFO_EXTENSION ) );
$whitelist_ext = array( 'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'doc', 'docx' );
if ( ! in_array( $up_fileext, $whitelist_ext, true ) ) { die( ... ); }
...
$upload_handler = new CBXProSolWpClient_UploadHandler( $options );
```
`https://plugins.trac.wordpress.org/browser/prosolution-wp-client/tags/2.0.0/public/class-prosolwpclient-public.php#L1006`

**Root cause at that line:** the validation is genuinely good — extension allowlist, real
MIME via `finfo`, `wp_check_filetype()`, `getimagesize()` for images — but it is applied
to `[0]` only. The upload handler constructed afterwards re-reads `$_FILES` itself and
loops over every element:

```php
foreach ($upload['tmp_name'] as $index => $value) {
    $files[] = $this->proSol_handleFileUpload( $upload['tmp_name'][$index], ... );
}
```
`https://plugins.trac.wordpress.org/browser/prosolution-wp-client/tags/2.0.0/includes/UploadHandler.php#L1345`

Post `files[0]=cat.jpg` and `files[1]=shell.php` and the second file is written without
ever meeting the gate. **This is the single most important pattern for an auditor to
internalise: validation and use must read the same object.** No single-line regex can see
it — the check and the sink are 60 lines and one class boundary apart.

### An upload with no upload (CVE-2026-1405, 9.8, unauthenticated)

```php
register_rest_route('slider-future/v1', '/upload-image/', array(
    'methods' => 'POST',
    'callback' => 'slider_future_handle_image_upload',
    'permission_callback' => '__return_true',
));
...
$image_data = wp_remote_retrieve_body( $response );
$image_name = basename( $image_url );
$image_path = $upload_dir['path'] . '/' . $image_name;
$file_saved = file_put_contents( $image_path, $image_data );
```
`https://plugins.trac.wordpress.org/browser/slider-future/tags/1.0.5/slider-future.php#L198`

**Root cause at that line:** the only "validation" is `filter_var($image_url,
FILTER_VALIDATE_URL)`. The attacker hosts `http://evil/x.php`, the server fetches it,
`basename()` yields `x.php`, and `file_put_contents()` writes it into
`wp-content/uploads/`. There is no `$_FILES`, no `move_uploaded_file()`, no
`wp_handle_upload()` — every upload-shaped grep misses this, yet it is a clean 9.8. The
`permission_callback => '__return_true'` is the modern equivalent of `wp_ajax_nopriv_`
and belongs in every audit's first sweep.

### An allowlist applied to attacker-controlled input (CVE-2026-12476, 7.2, admin+)

```php
if ( empty( $_FILES['edd-import-file']['type'] )
     || ! in_array( strtolower( $_FILES['edd-import-file']['type'] ), edd_importer_accepted_mime_types(), true ) ) {
    wp_send_json_error( ... );
}
...
$file_path = trailingslashit( $exports_dir ) . wp_unique_filename( $exports_dir, $file_name );
if ( move_uploaded_file( $_FILES['edd-import-file']['tmp_name'], $file_path ) ) {
```
`https://plugins.trac.wordpress.org/browser/easy-digital-downloads/tags/3.6.7/includes/admin/import/import-functions.php#L68`

**Root cause at that line:** the code looks defensive — a strict `in_array(..., true)`
against a curated MIME list. But the value being matched is a request header. Declaring
`Content-Type: text/csv` while naming the part `shell.php` passes the gate; the extension
is never constrained anywhere, and `move_uploaded_file()` writes it into a web-accessible
exports directory. An allowlist is only as trustworthy as the thing it inspects.

### Directory hardening that only works on Apache (CVE-2025-13516, 8.1, unauthenticated)

Every outbound email attachment was duplicated into `wp-content/uploads/<plugin>/attachments/`
under a name derived from the content hash, with no extension or content-type validation.
The directory carried an `.htaccess` that disables PHP execution — which nginx, IIS and
Lighttpd never read.
`https://plugins.trac.wordpress.org/browser/suremails/trunk/inc/emails/handler/uploads.php#L113`

**Root cause:** hardening was treated as the control instead of as defence in depth. When
the `.htaccess` is inert, the plugin's actual validation is what remains — and there was
none. Any public form that emails an attachment became an RCE vector on the majority of
non-Apache hosts. When auditing, always ask *which server* the hardening assumes.

### Raw move with no restriction at all (CVE-2025-7852, 9.8, unauthenticated)

A public customer-creation route passed client-supplied files straight to
`move_uploaded_file()` with no extension allowlist, no MIME check and no filename
sanitisation. `https://nvd.nist.gov/vuln/detail/CVE-2025-7852`

**Root cause:** `move_uploaded_file()` treated as *the* upload API. This is the baseline
case the UPLOAD-001 regex exists to catch, and it remains common.

### Server-side fetch-and-store with no type validation (CVE-2024-6220, 9.8, unauthenticated)

A content-import routine downloaded remote images and wrote them to disk without file type
validation, on an endpoint reachable without authentication.
`https://plugins.trac.wordpress.org/changeset/3127334/keydatas?contextall=1`

**Root cause:** same shape as CVE-2026-1405 — the "upload" is a server-initiated fetch, so
the usual `$_FILES` reasoning never gets applied to it.

## Detection guidance

**What the regexes catch reliably**

- `UPLOAD-001` finds every direct `move_uploaded_file()`. In plugin code this is close to
  a 1:1 indicator that core validation was bypassed; it should be triaged, not ignored.
- `UPLOAD-002` finds the `$_FILES[..]['type']` trust pattern precisely, with essentially
  no false positives when the value feeds a branch.
- `UPLOAD-005` finds hard-coded extension denylists, which are always incomplete.
- `UPLOAD-008` finds the unauthenticated surface that converts a medium finding into a 9.8.

**What the regexes CANNOT catch — read the code**

1. **Split validation (the CVE-2026-6555 shape).** The gate validates
   `$_FILES['f']['name'][0]`; the sink loops the array. Both lines are individually
   innocuous. Whenever you see `['name'][0]`, `['tmp_name'][0]` or any indexed access into
   a `$_FILES` sub-array, trace what consumes `$_FILES` afterwards. Also watch for a
   library class (blueimp `UploadHandler` derivatives are everywhere) that re-reads
   `$_FILES` from the superglobal instead of receiving the validated file.
2. **Aliased `$_FILES` elements.** `$file = $_FILES['x'];` on line 40 and
   `$file['type']` on line 220 is the same bug as UPLOAD-002 but matches only the noisy
   UPLOAD-003 rule. Any `$something['type']` in an upload path needs the assignment read.
3. **Uploads with no upload.** `wp_remote_get()` → `file_put_contents()`, ZIP extraction
   (`unzip_file()`, `ZipArchive::extractTo()`), `base64_decode()` of a POST field written
   to disk, `WP_Filesystem::put_contents()`, `copy()`, `rename()`,
   `$wp_filesystem->move()`. None mention `$_FILES`. UPLOAD-007 is deliberately noisy
   because this family is otherwise invisible.
4. **Unauthenticated-by-proxy handlers.** A callback hooked to another plugin's public
   form-processing filter (`*_process_before`, `wpcf7_before_send_mail`,
   `gform_after_submission`, …) runs for anonymous visitors. Neither `nopriv` nor
   `__return_true` appears. Enumerate `add_action`/`add_filter` targets, not just hook
   name patterns.
5. **Whether the destination is web-served.** A regex cannot tell
   `wp_upload_dir()['path']` (public) from a directory outside the docroot, nor whether a
   hardening `.htaccess` exists, nor whether the host runs nginx (making it useless).
6. **Whether the destination extension is rebuilt from the verified type.** Code can call
   `wp_check_filetype_and_ext()` correctly and then still write `$_FILES['x']['name']` to
   disk, ignoring `proper_filename`. The presence of the right API is not proof of the
   right outcome.
7. **`upload_mimes` widening.** Another plugin or the theme may add `svg`, `phtml`, or a
   generic type to `get_allowed_mime_types()`. A `wp_handle_upload()` call with no
   `mimes` override inherits that. This is cross-file state a per-file grep cannot see.
8. **Null bytes and double extensions.** `shell.php%00.jpg` is dead on modern PHP, but
   `shell.php.jpg` still executes under a misconfigured `AddHandler`/`AddType`, and
   `.phtml`/`.phar`/`.php7`/`.pht`/`.shtml` remain live on default configurations. No
   regex knows the server config; the fix is always "derive the extension from the
   verified type", which is a code-reading judgement.

## Audit checklist

- [ ] Grep `UPLOAD-008` first and build the list of unauthenticated entry points; then
      grep every other rule and intersect. Anything in the intersection is a 9.8 candidate.
- [ ] For every `move_uploaded_file()`, `$wp_filesystem->move()`, `rename()` and `copy()`:
      identify the destination directory and decide whether it is web-served.
- [ ] For every `$_FILES[..]['type']` hit, confirm it is not used in any conditional.
- [ ] For every `$_FILES[..]['name']` hit, confirm the on-disk extension is derived from
      `wp_check_filetype_and_ext()['ext']`, not from this value.
- [ ] For every `wp_handle_upload()` / `wp_handle_sideload()` call, confirm the
      `$overrides` array contains a `mimes` allowlist and does not set `test_type => false`.
- [ ] Search for `['name'][0]`, `['tmp_name'][0]`, `[0]` indexing into `$_FILES`; if found,
      trace whether the eventual writer iterates the full array.
- [ ] Search for extension denylists (`UPLOAD-005`); replace each with an allowlist.
- [ ] Search for server-side fetch sinks: `wp_remote_get`, `curl_exec`, `file_get_contents`
      on a URL, `unzip_file`, `ZipArchive`, `base64_decode` — each followed by a write.
- [ ] Confirm every plugin-created upload directory gets both `index.php` and a hardening
      `.htaccess` on creation, and note in the report that `.htaccess` is Apache-only.
- [ ] Confirm the handler calls `current_user_can()` with a real capability and
      `check_ajax_referer()` / `wp_verify_nonce()` before any filesystem operation.
- [ ] Confirm `is_uploaded_file()` guards `tmp_name` before it is moved or read.
