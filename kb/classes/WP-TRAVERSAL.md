---
class_id: WP-TRAVERSAL
title: Path Traversal in file writes, moves and archive extraction
cwe: [CWE-22, CWE-23, CWE-73, CWE-434]
owasp: A01:2021-Broken Access Control
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 22
detection:
  - id: TRAVERSAL-001
    description: Write, move or directory-creation sink reached by a request superglobal
    regex: '\b(file_put_contents|fwrite|fputs|move_uploaded_file|rename|copy|wp_mkdir_p|mkdir|touch|symlink|link|imagejpeg|imagepng)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE|FILES)'
    confidence: high
    false_positive_notes: >-
      Essentially always a finding. The only safe form is a destination already reduced to a
      single filename by wp_basename()/sanitize_file_name() and joined to a fixed base on the
      same statement. Remember that BOTH operands of rename() and copy() matter: traversal in
      the SOURCE argument moves an arbitrary server file into a directory the attacker can
      read, which is the CVE-2025-2941 shape. $_FILES is included because a plugin that
      builds its own destination from $_FILES[...]["name"] has bypassed wp_handle_upload().
  - id: TRAVERSAL-002
    description: Archive extraction surface — Zip Slip
    regex: '(->extractTo\s*\(|->getStream\s*\(|->getFromName\s*\(|->getFromIndex\s*\(|->statIndex\s*\(|->getNameIndex\s*\(|\bunzip_file\s*\(|new\s+(ZipArchive|PharData|Phar)\b)'
    confidence: medium
    false_positive_notes: >-
      Entry names inside an archive are attacker-controlled strings and are the classic
      traversal vector. Core's unzip_file() and ZipArchive::extractTo() do their own
      normalisation and are the SAFE forms; the dangerous shape is a hand-rolled loop over
      statIndex()/getNameIndex() that concatenates $entry["name"] onto a destination
      directory, because that skips every check the library would have made. When this rule
      fires, look for the loop, not the class. PharData / Phar also deserialise metadata, so
      a hit there is a WP-POI candidate as well.
  - id: TRAVERSAL-003
    description: path_join() — WordPress core function that discards the base for absolute paths
    regex: '\bpath_join\s*\('
    confidence: medium
    false_positive_notes: >-
      path_join( $base, $path ) returns $path UNCHANGED when path_is_absolute( $path ) is
      true. It is a convenience helper, not a containment function, and its name invites the
      opposite reading. A hit is a finding when the second argument can be attacker-supplied:
      passing "/var/www/html" or a Windows drive letter makes the "base" disappear, and any
      downstream containment test that compares against the joined result then compares
      against the attacker's own directory. Benign when both arguments are internal.
  - id: TRAVERSAL-004
    description: URL converted to a filesystem path by string replacement before a write
    regex: 'str_replace\s*\([^;]*(site_url|home_url|content_url|plugins_url|baseurl|base_url|upload_url|WP_CONTENT_URL)[^;]*,\s*[^;]*(ABSPATH|WP_CONTENT_DIR|WP_PLUGIN_DIR|basedir|base_dir|upload_dir)'
    confidence: high
    false_positive_notes: >-
      Swapping a URL prefix for a directory prefix leaves everything after the prefix
      untouched, including ../../.., and performs no canonicalisation. The code assumes the
      client returned a URL the server had previously produced; nothing enforces that. A hit
      is a finding unless a realpath() prefix check against a canonicalised base follows.
      Shares its shape with WP-FILEREAD's FILEREAD-006 — the difference is only whether the
      resulting path is opened for reading or for writing.
  - id: TRAVERSAL-005
    description: Request parameter with a destination-shaped name — surface mapping
    regex: '\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[''"](dir|folder|path|subdir|sub_dir|target|dest|destination|category|filename|file_name|newname|new_name|rename|savepath|save_path|upload_path|output|outfile)[''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      Deliberately broad. Its job is to enumerate every request parameter that could become
      part of a destination path so each can be traced to a sink. Most hits are benign. Pay
      particular attention when TWO of these appear in the same handler — one supplying the
      directory and one the filename — because that means the attacker steers the base as
      well as the leaf, and any allowlist derived from the base is worthless.
  - id: TRAVERSAL-006
    description: Non-path sanitiser used as the path control at a write sink
    regex: '\b(move_uploaded_file|file_put_contents|rename|copy|wp_mkdir_p|->put_contents)\s*\([^;]*\b(sanitize_text_field|sanitize_key|sanitize_title|esc_url_raw|esc_attr|wp_unslash)\s*\('
    confidence: medium
    false_positive_notes: >-
      sanitize_text_field() strips tags and control characters and leaves ../, / and \
      completely intact. esc_url_raw() preserves a root-relative absolute path. wp_unslash()
      is a slash-removal helper for magic quotes, not a security control. sanitize_key() and
      sanitize_file_name() DO strip separators and are genuine (if crude) controls — read
      which one is present. Frequently a sanitiser is applied to the filename while a
      different, unsanitised variable supplies the directory portion of the same path.
  - id: TRAVERSAL-007
    description: Leading-slash stripping used as the traversal defence
    regex: '(substr\s*\([^;]*,\s*0\s*,\s*1\s*\)\s*[!=]==?\s*[''"][\\/][''"]|[!=]==?\s*strpos\s*\([^;]*,\s*[''"][\\/][''"]\s*\)|\bltrim\s*\([^;]*[''"][\\/.]+[''"]\s*\))'
    confidence: medium
    false_positive_notes: >-
      "Make sure it is not absolute" is a real check and an incomplete one: it does nothing
      about ../, it is defeated on Windows by a drive letter (C:\) or a backslash, and
      ltrim($p, "./") applied once still leaves "....//....//" reducible to "../../" by any
      normaliser that runs afterwards. A hit tells you the developer thought about traversal
      and stopped early. Also matches benign ltrim() calls on non-path strings, so read the
      variable.
  - id: TRAVERSAL-008
    description: Write or move sink on a bare variable — provenance must be traced
    regex: '\b(file_put_contents|move_uploaded_file|rename|copy|wp_mkdir_p|mkdir|touch|fwrite)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]|->(put_contents|move|copy|mkdir)\s*\(\s*\$[a-zA-Z_]'
    confidence: low
    false_positive_notes: >-
      The complete worklist of write/move sinks, and in most plugins it is short enough to
      triage exhaustively — the recommended workflow for this class. For each hit, establish
      the provenance of every operand, including the base directory, and remember that
      copy()/rename() have two path arguments and either can be the tainted one.
      $wp_filesystem->put_contents()/move() are the WP_Filesystem equivalents and provide no
      validation of their own.
  - id: TRAVERSAL-009
    description: Client-supplied upload filename used to build a destination
    regex: '\$_FILES\s*\[[^\]]*\]\s*\[\s*[''"]name[''"]\s*\]'
    confidence: medium
    false_positive_notes: >-
      $_FILES[...]["name"] is a raw client-controlled string; PHP does not sanitise it. A hit
      is benign when the value is only used for display or is passed to wp_handle_upload() /
      media_handle_upload(), which apply sanitize_file_name() and wp_unique_filename()
      internally. It is a finding when the plugin concatenates it onto a directory itself —
      that is the hand-rolled upload path, and it is also the WP-UPLOAD surface, so both
      classes apply.
fix_apis:
  - wp_handle_upload()
  - sanitize_file_name()
  - wp_unique_filename()
  - realpath()
  - wp_normalize_path()
  - validate_file()
  - wp_basename()
  - trailingslashit()
  - unzip_file()
  - current_user_can()
examples:
  - cve: CVE-2026-1311
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: A backup-restore routine iterated the entries of an uploaded ZIP and joined each entry name to the destination directory, creating directories and writing files without checking that the result stayed inside that directory.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1311
    code_ref: https://plugins.trac.wordpress.org/browser/worry-proof-backup/tags/0.2.4/inc/libs/upload-backup.php#L97
    root_cause: Classic Zip Slip — an archive entry named with ../ segments is a fully attacker-controlled path, and the hand-rolled extraction loop skipped every normalisation the library would have applied.
  - cve: CVE-2024-10629
    year: 2024
    severity: 8.8
    auth: subscriber+
    summary: An AJAX upload handler with no capability check built its destination from two separate request parameters — one for the directory and one for the filename — and wrote the request body to it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-10629
    code_ref: https://plugins.trac.wordpress.org/browser/gpx-viewer/tags/2.2.9/gpx-viewer-admin.php#L147
    root_cause: Both operands of the path join came from $_POST, so the attacker chose the directory as well as the file, and the content was request-supplied too.
  - cve: CVE-2024-10586
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: An unauthenticated AJAX action converted a request-supplied URL to a filesystem path with str_replace() and wrote content fetched from a second request-supplied URL into it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-10586
    code_ref: https://plugins.trac.wordpress.org/browser/debug-tool/trunk/tools/image-puller.php#L124
    root_cause: URL-to-path conversion by string replacement performs no canonicalisation, so everything after the swapped prefix — including ../ — reached file_put_contents() unchanged.
  - cve: CVE-2026-5436
    year: 2026
    severity: 8.1
    auth: unauthenticated
    summary: An upload-field key from the request was passed to WordPress's path_join(), which returns absolute paths unchanged, so supplying an absolute key replaced the intended base directory entirely.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-5436
    code_ref: https://plugins.trac.wordpress.org/browser/mw-wp-form/tags/5.1.1/classes/models/class.directory.php#L58
    root_cause: path_join() is not a containment function; the downstream prefix check compared the candidate against a base the attacker had just chosen.
  - cve: CVE-2025-2941
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A public add-to-cart hook renamed files named in the request from the upload directory, with traversal possible in the source path, so any file on the server could be moved into a web-readable location.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2941
    code_ref: https://plugins.trac.wordpress.org/browser/drag-and-drop-multiple-file-upload-for-woocommerce/tags/1.1.4/inc/functions/functions-dnd-upload-wc.php#L237
    root_cause: The destination of the rename was constrained with wp_basename() and the source was not; moving wp-config.php out of ABSPATH is both a disclosure and a takeover primitive.
  - cve: CVE-2024-5153
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A form field's hash value was interpolated into a glob() pattern, and every file the pattern matched was copied into the public uploads directory before the traversed directory itself was recursively deleted.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-5153
    code_ref: https://plugins.trac.wordpress.org/browser/startklar-elmentor-forms-extwidgets/trunk/widgets/dropzone_form_field.php#L279
    root_cause: An unvalidated request value became a directory segment in a glob pattern used as the source of a copy and as the root of a recursive delete.
  - cve: CVE-2024-10011
    year: 2024
    severity: 8.1
    auth: subscriber+
    summary: An avatar-upload flow used a request-supplied item identifier as a directory segment of the destination path, allowing the write target to be moved outside the intended avatar tree.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-10011
    code_ref: https://plugins.trac.wordpress.org/browser/buddypress/tags/14.1.0/bp-core/bp-core-avatars.php#L514
    root_cause: An identifier that was assumed to be numeric was concatenated into a filesystem path with no numeric validation and no containment check on the resulting directory.
---

## What it is

A request-influenced string becomes part of a path that the plugin **writes to, moves to, or
extracts into**. With `../` segments, an absolute path, or an archive entry name, the
attacker chooses where the bytes land. Writing a `.php` file anywhere the web server will
execute it is remote code execution; writing `.htaccess` into `uploads/` re-enables PHP
execution there; overwriting a plugin's main file replaces its code; and *moving* a file is
both a write and a delete, so moving `wp-config.php` out of `ABSPATH` triggers the
installer-takeover chain documented under WP-DELETE.

**This class is about the destination.** WP-LFI covers a traversed path reaching
`include`/`require` (execution), WP-FILEREAD covers a traversed path reaching
`readfile`/`file_get_contents` (disclosure), and WP-DELETE covers a traversed path reaching
`unlink()` (destruction). Here the sinks are `file_put_contents`, `fwrite`,
`move_uploaded_file`, `rename`, `copy`, `wp_mkdir_p`, and archive extraction. The
containment logic that fixes all four is identical; only the sink and the impact differ.
Move operations sit deliberately in this class rather than in WP-DELETE, because `rename()`
and `copy()` have *two* path arguments and the interesting bugs are as often in the source
as in the destination.

## Why it happens in WordPress

- **`wp_handle_upload()` exists and is skipped.** Core's upload handler runs
  `sanitize_file_name()`, `wp_unique_filename()` and a MIME check, and it puts the file in
  the uploads directory. Plugins that want their own directory layout reimplement all of it
  and reimplement none of the validation.
- **`path_join()` returns the second argument unchanged when it is absolute.** From core:
  `if ( path_is_absolute( $path ) ) { return $path; }`. The name promises containment; the
  implementation offers convenience. This is a genuinely WordPress-specific trap and it is
  the root cause of CVE-2026-5436.
- **`$_FILES[...]['name']` is not sanitised by PHP.** It is a raw client string. A plugin
  that builds `$dir . $_FILES['f']['name']` has an attacker-controlled leaf, and
  `$_FILES['f']['type']` is a client-supplied header on top of that (WP-UPLOAD's territory).
- **Archive entry names are attacker data.** Any plugin that imports, restores, or installs
  from a ZIP iterates entries whose names came from the archive. Core's `unzip_file()` and
  PHP's `ZipArchive::extractTo()` normalise; a hand-rolled `for ( $i = 0; $i < $zip->numFiles; $i++ )`
  loop with `statIndex()` does not.
- **`sanitize_text_field()` leaves `../` intact.** The single most common false defence
  across WP-LFI, WP-DELETE, WP-FILEREAD and this class.
- **The directory portion is often request-supplied too.** A "category", "session", "form
  id" or "field name" parameter is interpolated into the base. Once the base is
  attacker-chosen, any allowlist derived from listing that base is an allowlist the attacker
  wrote.
- **`wp_ajax_nopriv_` and `permission_callback => '__return_true'`** put upload and import
  handlers on anonymous routes, and front-end hooks such as `woocommerce_add_cart_item_data`
  run for every visitor.
- **Cleanup routines recursively delete the directory they just used.** If the directory was
  traversed, `$wp_filesystem->delete( $dir, true )` removes an arbitrary tree — a write bug
  and a delete bug from one parameter.

## Vulnerable pattern

```php
// Both operands of the join come from the request; no capability check, no nonce.
add_action( 'wp_ajax_example_upload', 'example_upload' );

function example_upload() {
    $target_path = EXAMPLE_UPLOAD_PATH . $_POST['category'];             // directory chosen by attacker
    $target_file = $target_path . DIRECTORY_SEPARATOR . $_POST['filename']; // leaf chosen by attacker

    if ( file_put_contents( $target_file, $_POST['body'] ) > 0 ) {       // content chosen by attacker
        echo 'ok';
    }
    wp_die();
}
```

`category=../../plugins/hello-dolly` + `filename=shell.php` is remote code execution in one
request.

The Zip Slip variant, which looks like careful code:

```php
$zip = new ZipArchive();
$zip->open( $this->archive_path );

for ( $i = 0; $i < $zip->numFiles; $i++ ) {
    $file_info = $zip->statIndex( $i );
    $file_path = $file_info['name'];               // <-- attacker wrote this string
    $dest_path = $this->backup_dir . '/' . $file_path;

    $dest_dir = dirname( $dest_path );
    if ( ! is_dir( $dest_dir ) ) {
        wp_mkdir_p( $dest_dir );                   // creates ../../../wp-content/plugins/evil/
    }
    file_put_contents( $dest_path, $zip->getFromIndex( $i ) );
}
```

The move variant, where the *destination* is contained and the *source* is not:

```php
$dir = trailingslashit( example_upload_dir() );

foreach ( (array) $_POST['example_files'] as $file ) {
    $tmp_file = $dir . sanitize_text_field( $file );   // ../ survives sanitize_text_field()
    if ( file_exists( $tmp_file ) ) {
        $new_name = wp_unique_filename( $dir, wp_basename( $file ) );   // destination: fine
        rename( $tmp_file, $dir . $new_name );                          // source: arbitrary
    }
}
```

`example_files[]=../../../wp-config.php` moves the config out of `ABSPATH` and into a
world-readable uploads directory: disclosure and site takeover in the same call.

And the WordPress-specific one:

```php
// path_join() returns $name unchanged if $name is absolute. The base silently disappears.
$user_dir      = wp_upload_dir()['basedir'] . '/example';
$user_file_dir = path_join( $user_dir, $name );        // $name from the request
```

## Secure pattern

```php
/**
 * Shape 1 — LET CORE DO IT. wp_handle_upload() sanitises the name, de-duplicates it,
 * checks the MIME type against get_allowed_mime_types(), and chooses the directory.
 * Nothing the client sends becomes part of the path.
 */
function example_handle_upload() {
    if ( ! current_user_can( 'upload_files' ) ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_upload', 'nonce' );

    if ( empty( $_FILES['example_file'] ) ) { wp_send_json_error( 'no file', 400 ); }

    require_once ABSPATH . 'wp-admin/includes/file.php';

    $result = wp_handle_upload(
        $_FILES['example_file'],
        array(
            'test_form' => false,
            'mimes'     => array( 'pdf' => 'application/pdf', 'csv' => 'text/csv' ),
        )
    );

    if ( isset( $result['error'] ) ) { wp_send_json_error( $result['error'], 400 ); }

    wp_send_json_success( array( 'url' => $result['url'] ) );
}
```

```php
/**
 * Shape 2 — WRITE INTO A DIRECTORY YOU CONTROL. Use when the layout must be custom.
 * The request contributes a NAME, never a path.
 */
function example_write_report( $requested_name, $contents ) {
    // 1. Canonicalise the base ONCE and trailing-slash it.
    $base = realpath( wp_upload_dir()['basedir'] . '/example-reports' );
    if ( false === $base ) { return new WP_Error( 'misconfigured' ); }
    $base = trailingslashit( wp_normalize_path( $base ) );

    // 2. Reduce the request value to a single, separator-free filename.
    $name = sanitize_file_name( wp_basename( $requested_name ) );
    if ( '' === $name || 0 !== validate_file( $name ) ) {
        return new WP_Error( 'bad_name' );
    }

    // 3. Refuse executable extensions explicitly. Do not rely on the base directory
    //    being non-executable; .htaccess rules get removed by other bugs.
    $type = wp_check_filetype( $name, array( 'csv' => 'text/csv', 'pdf' => 'application/pdf' ) );
    if ( empty( $type['ext'] ) ) { return new WP_Error( 'bad_type' ); }

    // 4. De-duplicate, then verify containment of the FINAL path before writing.
    $name = wp_unique_filename( $base, $name );
    $dest = wp_normalize_path( $base . $name );

    if ( 0 !== strpos( $dest, $base ) ) {          // strict !== , never == 0
        return new WP_Error( 'forbidden' );
    }

    return file_put_contents( $dest, $contents );
}
```

```php
/**
 * Shape 3 — ARCHIVE EXTRACTION. Prefer core. unzip_file() uses WP_Filesystem and
 * normalises entry names; a hand-rolled loop must re-implement the containment itself.
 */
function example_extract( $archive, $destination ) {
    if ( ! current_user_can( 'manage_options' ) ) { return new WP_Error( 'forbidden' ); }

    require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();

    return unzip_file( $archive, $destination );
}

// If a manual loop is unavoidable, every entry needs the full containment treatment:
function example_extract_manual( ZipArchive $zip, $base ) {
    $base = trailingslashit( wp_normalize_path( realpath( $base ) ) );

    for ( $i = 0; $i < $zip->numFiles; $i++ ) {
        $entry = $zip->statIndex( $i )['name'];

        // Reject absolute entries, traversal segments, null bytes and symlink-ish names
        // BEFORE building any path.
        if ( '' === $entry
             || 0 !== validate_file( $entry )
             || 0 === strpos( $entry, '/' )
             || false !== strpos( $entry, "\0" )
             || preg_match( '#^[A-Za-z]:#', $entry ) ) {
            continue;
        }

        $dest = wp_normalize_path( $base . $entry );

        // Belt and braces: the resolved parent must still be inside the base.
        $parent = realpath( dirname( $dest ) );
        if ( false === $parent || 0 !== strpos( trailingslashit( wp_normalize_path( $parent ) ), $base ) ) {
            continue;
        }

        // Refuse executable types on the way in.
        if ( ! wp_check_filetype( $dest )['ext'] ) {
            continue;
        }

        wp_mkdir_p( dirname( $dest ) );
        file_put_contents( $dest, $zip->getFromIndex( $i ) );
    }
}
```

The rules that decide this class:

- **The request contributes a name, never a path.** `sanitize_file_name( wp_basename( $x ) )`
  before the value goes anywhere near a join.
- **Canonicalise the base too**, trailing-slash it, and compare with a **strict** `!== 0`.
  `strpos(...) == 0` accepts `false` and passes for every path *outside* the base — the same
  defect documented in WP-LFI and WP-DELETE.
- **Check containment of the final destination**, after `wp_unique_filename()` and after any
  filter has had a chance to modify it.
- **Both operands of a move.** `rename( $src, $dst )` needs the check applied twice.
- **Never use `path_join()` on request data.** It is not a containment function.

## Real-world case studies

### Zip Slip in a hand-rolled extractor (CVE-2026-1311, 8.8, subscriber+)

```php
for ($i = 0; $i < $zip->numFiles; $i++) {
    $file_info = $zip->statIndex($i);
    $file_path = $file_info['name'];
    $dest_path = $this->backup_dir . '/' . $file_path;

    if (substr($file_path, -1) === '/') {
        if (!is_dir($dest_path) && !wp_mkdir_p($dest_path)) {
    ...
    } else {
        $dest_dir = dirname($dest_path);
        if (!is_dir($dest_dir) && !wp_mkdir_p($dest_dir)) {
    ...
        if (!$this->wp_filesystem->put_contents($dest_path, $contents, FS_CHMOD_FILE)) {
```
`https://plugins.trac.wordpress.org/browser/worry-proof-backup/tags/0.2.4/inc/libs/upload-backup.php#L97`

**Root cause at line 97:** `$file_info['name']` is a string the attacker chose when they
built the ZIP, and it is concatenated onto `$this->backup_dir` with no validation at all.
An entry named `../../../../wp-content/plugins/example/evil.php` causes `wp_mkdir_p()` on
line 106 to create the parent directory and `put_contents()` on line 128 to write the file.
The plugin uses `WP_Filesystem` throughout, which reads as care — but `put_contents()`
performs no path validation of its own.

Note what is *not* here: `unzip_file()`, which core provides and which normalises entry
names. **A manual `numFiles` loop is the signature of this bug**; `TRAVERSAL-002` is built
around it. Note also that the destination base itself is fine (`uploads/worry-proof-backup/<session>`);
containment fails on the entry name alone, so nothing about the base needs to be
attacker-controlled for this to work.

### The attacker supplies the directory, the filename and the content (CVE-2024-10629, 8.8, subscriber+)

```php
add_action("wp_ajax_gpxv_file_upload", "gpxv_file_upload");
function gpxv_file_upload() {
    if ($_POST['action'] == 'gpxv_file_upload') {
        $target_path = GPXV_UPLOAD_PATH.$_POST['category'];
        $target_file = $target_path.DIRECTORY_SEPARATOR.$_POST['filename'];
        if (! $response = gpxv_check_repository($target_path)) {
            if (file_put_contents($target_file, str_replace("\'", "'", str_replace('\"', '"', $_POST['gpx']))) > 0) {
```
`https://plugins.trac.wordpress.org/browser/gpx-viewer/tags/2.2.9/gpx-viewer-admin.php#L147`

**Root cause at lines 147–151:** three separate `$_POST` values reach the write —
`category` becomes the directory, `filename` becomes the leaf, and `gpx` becomes the
content. There is no `current_user_can()`, no nonce, and no path processing whatsoever. The
`if ($_POST['action'] == 'gpxv_file_upload')` guard is a routing check that the attacker
satisfies by definition.

Two lessons. First, `gpxv_check_repository($target_path)` *looks* like validation, and it
runs against the attacker-chosen directory — **a check derived from attacker-controlled
input is not a check**, the same observation as WP-DELETE's `in_array()` allowlist built
from a traversed directory. Second, the registration is `wp_ajax_` without `_nopriv_`, which
means "any logged-in user" and not "any administrator": on a site with open registration
that is one signup away from anonymous. See `kb/reference/entry-points.md` §2.

### URL-to-path by string replacement, on the write side (CVE-2024-10586, 9.8, unauthenticated)

```php
add_action( 'wp_ajax_nopriv_dbt_pull_image', array( $this, 'ajax_pull' ) );
add_action( 'wp_ajax_dbt_pull_image', array( $this, 'ajax_pull' ) );
```

```php
public function ajax_pull() {

    var_dump( $_POST );

    $path = str_replace(get_site_url() . '/', ABSPATH, $_POST['missed']);
    $path = explode('?', $path);
    $path = $path[0];
    var_dump($path);
    file_put_contents($path, file_get_contents($_POST['source']));

    exit();
}
```
`https://plugins.trac.wordpress.org/browser/debug-tool/trunk/tools/image-puller.php#L124`

**Root cause at line 124:** `str_replace()` swaps the site URL prefix for `ABSPATH` and
leaves the remainder — including `../` — untouched. No canonicalisation happens anywhere.
The destination is therefore an arbitrary path with a trusted-looking prefix, and the
content is fetched from a second attacker-supplied URL, so the attacker controls where the
bytes go *and* what they are. `wp_ajax_nopriv_` makes it anonymous.

Note the `var_dump( $_POST )` on line 122 — a WP-INFO finding sitting in the same function,
and a useful tell in general: **debug scaffolding in a handler is a strong signal that the
handler was never security-reviewed.** This exact `str_replace(url, dir, $input)` idiom
appears on the read side as CVE-2026-5710 under WP-LFI; `TRAVERSAL-004` and
`FILEREAD-006` are the same pattern pointed at different sinks.

### `path_join()` discards the base (CVE-2026-5436, 8.1, unauthenticated)

```php
public static function generate_user_file_dirpath( $form_id, $name ) {
    $user_dir      = static::generate_user_dirpath( $form_id );
    $user_file_dir = path_join( $user_dir, $name );

    return $user_file_dir;
}
```
`https://plugins.trac.wordpress.org/browser/mw-wp-form/tags/5.1.1/classes/models/class.directory.php#L58`

WordPress core's implementation is the whole story:

```php
function path_join( $base, $path ) {
    if ( path_is_absolute( $path ) ) {
        return $path;
    }
    return rtrim( $base, '/' ) . '/' . $path;
}
```

**Root cause at line 58:** `$name` is the upload-field key from the request. When it is
absolute, `path_join()` returns it verbatim and `$user_dir` is silently discarded. What
makes this case worth studying is the containment code that sits *downstream* and is
defeated by it:

```php
$user_file_dir = static::generate_user_file_dirpath( $form_id, $name );
...
$filepath      = path_join( $user_file_dir, $filename );
$filepath      = wp_normalize_path( $filepath );
$user_file_dir = trailingslashit( wp_normalize_path( $user_file_dir ) );

if ( 0 !== strpos( $filepath, $user_file_dir ) ) {
    throw new \RuntimeException( '[MW WP Form] Invalid file reference requested.' );
}
```

That prefix check is textbook — canonicalised, trailing-slashed, strict `!== 0`, and it
even rejects `../` and `./` on the following lines. It is also **useless**, because
`$user_file_dir` is the attacker's own directory. This is the same structural defect as
WP-LFI's CVE-2024-9047: *a containment boundary cannot help when the attacker supplies the
boundary.* When auditing, always ask where the base came from before evaluating the check
against it. And treat `path_join()` on request data as a finding on sight.

### Traversal in the source of a move (CVE-2025-2941, 9.8, unauthenticated)

```php
function dndmfu_wc_add_cart_data( $cart_item_data, $product_id, $variation_id ) {

    $dir        = trailingslashit( dndmfu_wc_dir() );
    $name       = dndmfu_wc_get_filename();
    $post_files = ( isset( $_POST[ $name ] ) ? array_map('sanitize_text_field', $_POST[ $name ] ) : null );
    ...
        foreach( $post_files as $file ) {
            $tmp_file = $dir . wc_clean( wp_unslash( $file ) );
            if( file_exists( $tmp_file ) ) {
                $file_name = wp_unique_filename( $dir, wp_basename( $file ) );
                $new_name  = apply_filters( 'dndmfu_wc_file_name', $file_name );
                if( rename( $tmp_file, $dir . $new_name ) ) {
```
`https://plugins.trac.wordpress.org/browser/drag-and-drop-multiple-file-upload-for-woocommerce/tags/1.1.4/inc/functions/functions-dnd-upload-wc.php#L237`

**Root cause at line 237:** look at the asymmetry. The **destination** is
`$dir . wp_unique_filename( $dir, wp_basename( $file ) )` — `wp_basename()` strips every
directory component, so it is safely inside `$dir`. The **source**, `$tmp_file`, is
`$dir . sanitize_text_field( $file )` with `../` fully intact. `file_exists()` is the only
gate and it merely confirms the traversal target exists.

`wc-upload-file[]=../../../wp-config.php` moves the site configuration into the public
upload directory under a predictable name: the credentials and salts become downloadable,
*and* `wp-config.php` is now missing from `ABSPATH`, which puts the site into the
installation wizard — the takeover chain spelled out in WP-DELETE. The handler runs on a
WooCommerce cart hook, so no account is needed.

**The transferable lesson is mechanical:** `rename()` and `copy()` take two paths. A
reviewer who sees `wp_basename()` on one of them stops reading. Apply the containment check
to both operands, every time, and note that a *move* is simultaneously a write at the
destination and a delete at the source — so WP-DELETE's audit questions apply to the source
argument as well.

### A traversed glob, a copy, and a recursive delete (CVE-2024-5153, 9.8, unauthenticated)

```php
$uploads_dir_info = wp_upload_dir();
$target_folder = $uploads_dir_info['basedir'] . "/elementor/forms/" . $user_id . "/temp/" . $options["dropzone_hash"] . "/*";
$files = glob($target_folder);

if (count($files)) {
    foreach ($files as $file) {
        $file_name = basename($file);
        $encoded_filename = rawurlencode($file_name);
        $rel_path = "/elementor/forms/" . $user_id . "/" . $encoded_filename;
        $new_path = $uploads_dir_info['basedir'] . $rel_path;
        ...
        copy($file, $new_path);
```

and, at the end of the same function:

```php
$temp_folder = $uploads_dir_info['basedir'] . "/elementor/forms/" . $user_id . "/temp/" . $options["dropzone_hash"];
...
$WP_Filesystem_Direct = new \WP_Filesystem_Direct(null);
@$WP_Filesystem_Direct->delete($temp_folder, true);
```
`https://plugins.trac.wordpress.org/browser/startklar-elmentor-forms-extwidgets/trunk/widgets/dropzone_form_field.php#L279`

**Root cause at line 279:** `$options["dropzone_hash"]` is decoded from a form field value
and interpolated into a `glob()` pattern. Setting it to `../../../../..` makes the pattern
match an arbitrary directory, and every file found there is `copy()`d into
`uploads/elementor/forms/0/` — a **publicly served** directory — under its own basename.
That is arbitrary file disclosure achieved entirely through a write primitive. The same
value then becomes `$temp_folder`, which is deleted **recursively**, so the same request
also destroys an arbitrary directory tree including the WordPress root.

Three things to carry forward. First, `basename()` is applied to the *destination* leaf
(line 285), which again makes the write look contained while the read side is wide open —
the same asymmetry as CVE-2025-2941. Second, **`glob()` is a path sink**: a pattern built
from request data enumerates and then acts on files the developer never intended, and it
matches no rule that looks for `file_get_contents`. Third, the recursive delete at line 334
means a single traversal parameter yields disclosure *and* destruction; enumerate every
`->delete( $x, true )` and `rmdir()` next to a write handler.

### An "id" that was never checked for being an id (CVE-2024-10011, 8.1, subscriber+)

```php
$avatar_folder_dir = apply_filters( 'bp_core_avatar_folder_dir', ( $avatar_loc->path . $avatar_loc->dir . $params['item_id'] ), $params['item_id'], $params['object'], $params['avatar_dir'] );
```
`https://plugins.trac.wordpress.org/browser/buddypress/tags/14.1.0/bp-core/bp-core-avatars.php#L514`

and the AJAX entry point that feeds it:

```php
function bp_avatar_ajax_set() {

    if ( ! bp_is_post_request() ) {
        wp_send_json_error();
    }

    // Check the nonce.
    check_admin_referer( 'bp_avatar_cropstore', 'nonce' );

    $avatar_data = bp_parse_args(
        $_POST,
        array( 'crop_w' => ..., 'crop_h' => ..., 'crop_x' => 0, 'crop_y' => 0 )
    );

    if ( empty( $avatar_data['object'] ) || empty( $avatar_data['item_id'] ) || empty( $avatar_data['original_file'] ) ) {
        wp_send_json_error();
    }

    // Capability check.
    if ( ! bp_attachments_current_user_can( 'edit_avatar', $avatar_data ) ) {
        wp_send_json_error();
    }
```

**Root cause:** `bp_parse_args( $_POST, ... )` merges the entire request into
`$avatar_data`, and `item_id` — documented as "the numeric ID of the item" — is
concatenated straight into a filesystem path without ever being cast to an integer or
validated as one. A nonce is verified and a capability is checked, so the handler is
authorised; what is missing is any assertion that `item_id` is a number.

**This is the most under-appreciated shape in the class.** A parameter whose *name* and
*documentation* say "integer" gets treated as an integer by every reader, including static
analysers, but PHP will happily concatenate `../../../..` into the path. Grep for every
`$params['*_id']`, `$args['id']` and `$data['item_id']` that appears in a path
concatenation and confirm an `absint()`/`(int)` cast exists between the request and the
join. The same reasoning applies to `form_id`, `session`, `slug` and `field_name` segments.

## Detection guidance

**What the regexes catch reliably**

- `TRAVERSAL-001` catches the direct one-statement case with near-zero false positives.
- `TRAVERSAL-003` is the highest-value single rule in this file: `path_join()` on request
  data is a WordPress-specific defect that looks like the fix.
- `TRAVERSAL-004` catches the URL-to-path idiom, which is essentially always wrong.
- `TRAVERSAL-008` produces a complete and usually short worklist of write/move sinks —
  exhaustive manual triage of that list is the recommended workflow for this class.

**What the regexes CANNOT catch — read the code**

1. **Multi-hop taint.** `$name = $_POST['f'];` … thirty lines … `$dest = $base . $name;` …
   another file … `file_put_contents( $dest, … )`. `TRAVERSAL-005` and `TRAVERSAL-008`
   produce the two halves of the worklist; joining them is manual.
2. **Which operand is tainted.** `rename()` and `copy()` take two paths, and CVE-2025-2941
   and CVE-2024-5153 are both bugs in the *source*. Never stop reading because you found
   `wp_basename()` on one side.
3. **Whether the base directory is attacker-controlled.** CVE-2026-5436 and CVE-2024-10629.
   For every join, ask about the left operand as well as the right, and remember that a
   containment check comparing against a tainted base is decorative.
4. **Whether an existing containment check is correct.** Base canonicalised, base
   trailing-slashed, strict `!== 0`, `false` from `realpath()` handled, both operands the
   same kind of thing. `strpos(...) == 0` accepts `false` and inverts the check — see
   WP-LFI's `LFI-006`, which is worth running against write handlers too.
5. **`glob()` as a path sink.** A pattern built from request data enumerates an arbitrary
   directory and hands every match to whatever comes next. It matches no read or write rule.
6. **Non-numeric "ids".** `item_id`, `form_id`, `session`, `post_id` used as directory
   segments with no `absint()`. The name creates the assumption; nothing enforces it.
7. **Filters that modify the path after validation.** `apply_filters( 'x_file_name', $name )`
   between the check and the write means a third-party callback can reintroduce traversal.
   Validate immediately before the sink, not before the filter.
8. **Symlinks and TOCTOU.** A validated destination inside the base that is (or becomes) a
   symlink to somewhere else. `realpath()` before the write narrows the window; it does not
   close it.
9. **Windows path semantics.** Backslash separators, `C:\` drive letters, alternate data
   streams (`file.php::$DATA`), and trailing dots/spaces that the filesystem strips after
   validation. A `../`-only check misses all of them; `validate_file()` catches drive
   letters, which is one reason to keep it as an extra gate.
10. **Where the write lands matters as much as whether it is contained.** A perfectly
    contained write into `uploads/` is still remote code execution if the file is a `.php`
    and the directory has no deny rules — that is WP-UPLOAD's question, and it should be
    asked about every write handler found here.

## Audit checklist

- [ ] Run `TRAVERSAL-008` to enumerate every write, move and directory-creation sink; the
      list is usually short enough to triage exhaustively. Do this first.
- [ ] For each sink, establish the provenance of **every** operand — including the base
      directory and, for `rename`/`copy`, both paths.
- [ ] Run `TRAVERSAL-001`; treat every hit as a finding until proven otherwise.
- [ ] Run `TRAVERSAL-003`; every `path_join()` whose second argument can be attacker-supplied
      is a finding, because absolute paths discard the base.
- [ ] Run `TRAVERSAL-004`; a URL-to-path `str_replace()` before a write with no subsequent
      `realpath()` containment check is a finding.
- [ ] Run `TRAVERSAL-002` and, for each archive handler, confirm it uses `unzip_file()` or
      `ZipArchive::extractTo()` rather than a manual `numFiles` loop. If the loop exists,
      verify each entry name is rejected for `..`, a leading `/`, a drive letter and a null
      byte before any path is built.
- [ ] For every containment check present, verify base canonicalised, base trailing-slashed,
      strict `!== 0` comparison, `false` handled, operands the same kind.
- [ ] Grep for every `*_id`, `form_id`, `session` or `slug` value used as a path segment and
      confirm an `absint()` / `(int)` cast or a strict format check sits between the request
      and the join.
- [ ] Run `TRAVERSAL-009`; any `$_FILES[...]['name']` concatenated into a destination is a
      hand-rolled upload path — audit it under WP-UPLOAD as well.
- [ ] Run `TRAVERSAL-006`; `sanitize_text_field()` and `esc_url_raw()` at a write sink are
      not path controls. Confirm which sanitiser is actually present.
- [ ] Grep for `glob(` and check whether any pattern is request-influenced.
- [ ] Grep for `apply_filters` between a path validation and its sink; validate immediately
      before the write.
- [ ] Enumerate recursive deletes next to write handlers (`->delete( $x, true )`, `rmdir`,
      `RecursiveDirectoryIterator`) — a traversed directory that is written and then removed
      is a WP-DELETE finding from the same parameter.
- [ ] For every write that succeeds, ask what happens if the file is a `.php`: confirm the
      destination has deny rules and an extension allowlist (see WP-UPLOAD).
- [ ] Confirm the handler enforces `current_user_can()` and a nonce before any path is
      built, and check whether it is registered on `wp_ajax_nopriv_`, `admin_post_nopriv_`,
      a `permission_callback => '__return_true'` route, or a public front-end hook.
