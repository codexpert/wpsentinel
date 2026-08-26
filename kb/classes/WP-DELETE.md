---
class_id: WP-DELETE
title: Arbitrary File Deletion via user-controlled path
cwe: [CWE-22, CWE-73, CWE-23]
owasp: A01:2021-Broken Access Control
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 8
detection:
  - id: DELETE-001
    description: unlink()/wp_delete_file() reached by a request superglobal on the same statement
    regex: '@?\s*\b(unlink|wp_delete_file)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      Essentially always a finding. The only safe form is when the superglobal has already
      been mapped through an allowlist or converted to an integer ID on the same line.
      Note the leading @? — suppressed unlink() is extremely common in this class because
      the developer expected failures.
  - id: DELETE-002
    description: unlink()/wp_delete_file() on a concatenated path
    regex: '@?\b(unlink|wp_delete_file)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_>-]*\s*\.'
    confidence: medium
    false_positive_notes: >-
      Matches "$base . $name" and "$this->_root_app . $this->_filename" forms. Triage by
      establishing the provenance of the right-hand operand. A concatenation means no
      canonicalisation happened at the call site, so the containment check (if any) must
      be found and verified upstream.
  - id: DELETE-003
    description: Any deletion sink — full triage worklist
    regex: '@?\b(unlink|wp_delete_file|wp_delete_file_from_directory|rmdir)\s*\('
    confidence: low
    false_positive_notes: >-
      Noisy but bounded: most plugins have only a handful. Every hit deserves the question
      "can the argument be influenced by a request, directly or through stored state?".
      wp_delete_file() is a thin core wrapper around unlink() and offers no protection —
      it only fires the wp_delete_file filter.
  - id: DELETE-004
    description: Recursive / filesystem-abstraction deletion
    regex: '->delete\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*true|\brmdir\s*\('
    confidence: medium
    false_positive_notes: >-
      $wp_filesystem->delete( $path, true ) removes a directory tree. If $path is
      influenced by a request, the impact is far worse than a single unlink(). Also covers
      hand-rolled recursive removers, which usually appear next to an rmdir().
  - id: DELETE-005
    description: Broken containment check — strpos(...) == 0 accepts false
    regex: 'strpos\s*\([^;]*\)\s*==\s*0'
    confidence: high
    false_positive_notes: >-
      PHP returns false when the needle is absent and false == 0 is true, so a loose
      "path starts with base" guard passes for every path outside the base. Fires on code
      that already calls realpath() and therefore reads as safe. Does not match the
      correct === 0 / !== 0 forms.
  - id: DELETE-006
    description: sanitize_text_field()/sanitize_file_name() used as the path control before a delete
    regex: '\b(unlink|wp_delete_file)\b[^;]*\bsanitize_(text_field|file_name|title)\s*\('
    confidence: medium
    false_positive_notes: >-
      sanitize_text_field() does not remove ../, / or \. sanitize_file_name() does strip
      directory separators, but it is frequently applied to one variable while a different,
      unsanitised variable supplies the directory portion of the same path.
  - id: DELETE-007
    description: Delete handler on an unauthenticated route
    regex: 'wp_ajax_nopriv_[a-z0-9_]*(remove|delete|unlink|clear|clean|cancel|discard)|[''"]permission_callback[''"]\s*=>\s*[''"]__return_true[''"]'
    confidence: medium
    false_positive_notes: >-
      A delete-shaped handler on an anonymous route is the 9.1 shape. Note that a nonce is
      NOT an authorization boundary here: in several disclosed cases the required nonce was
      printed into public page JavaScript or handed out by a separate public endpoint.
  - id: DELETE-008
    description: Path taken from stored state (post meta, option, session) rather than the request
    regex: '(get_post_meta|get_user_meta|get_option|get_transient)\s*\([^;]*\)\s*\)?\s*;?\s*$'
    confidence: low
    false_positive_notes: >-
      Deliberately broad; use it only when triaging a known deletion sink whose path comes
      from stored state. The question to answer is whether any endpoint — including a
      low-privilege or unauthenticated one — can write that meta/option/session key.
      Several disclosed bugs are exactly this two-step: poison the stored path, then
      trigger the cleanup routine.
fix_apis:
  - wp_delete_attachment()
  - realpath()
  - wp_normalize_path()
  - validate_file()
  - wp_basename()
  - current_user_can()
  - check_ajax_referer()
  - wp_verify_nonce()
examples:
  - cve: CVE-2024-9047
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A directly-reachable downloader script deleted the file it had just streamed whenever a request-controlled code prefix asked it to, with the whole path resolved from attacker-controlled state.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9047
    code_ref: https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L111
    root_cause: A delete-after-download flag was toggled by a request-controlled string prefix, and the path it applied to had no containment boundary.
  - cve: CVE-2026-18855
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: A cleanup routine resolved a stored URL to a filesystem path and guarded the unlink() with a containment test that compared a filesystem path against a URL using loose equality, so the guard always passed.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-18855
    code_ref: https://plugins.trac.wordpress.org/browser/link-library/tags/7.9.4/link-library-admin.php#L7865
    root_cause: strpos( $filesystem_path, $base_URL ) == 0 — wrong operand type and loose comparison, so false == 0 made the check unconditionally true.
  - cve: CVE-2026-6070
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: An unauthenticated frontend routing endpoint took a filename parameter with an explicit RAW (no-sanitisation) filter and passed it to unlink() after a helper that only normalised directory separators.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6070
    code_ref: https://plugins.trac.wordpress.org/browser/wp-businessdirectory/tags/4.0.0/site/controllers/upload.php#L450
    root_cause: Raw request value concatenated onto a base directory and unlinked; the "path helper" normalised separators without stripping traversal sequences.
  - cve: CVE-2026-14484
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: A remove-upload AJAX handler built the delete path from two sanitize_text_field()-processed request values — one supplying the filename and one supplying part of the directory — so the directory listing used as the containment check was itself attacker-chosen.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14484
    code_ref: https://plugins.trac.wordpress.org/browser/rapisafe-multi-file-cf7/trunk/src/RSMFCF7_Assets.php#L235
    root_cause: sanitize_text_field() leaves ../ intact, and the allowlist was derived from the same attacker-controlled directory it was meant to constrain. The required nonce was printed into public page JavaScript.
  - cve: CVE-2026-14487
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: An upload-directory removal routine accepted an unconstrained identifier that became part of the path, behind two controls that were not authorization boundaries at all.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14487
    code_ref: https://plugins.trac.wordpress.org/browser/simple-coherent-form/tags/2.4.13/includes/fields/file.php#L1387
    root_cause: A public endpoint issued the required nonce to any anonymous visitor, and the secondary hash was forgeable offline because the salt was hardcoded in the plugin source.
  - cve: CVE-2026-14524
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: A two-step chain in which one public handler wrote a path-traversal key into the caller's own session and a second public handler used that key as the filename to delete.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14524
    code_ref: https://plugins.trac.wordpress.org/browser/prosolution-wp-client/tags/2.0.3/public/class-prosolwpclient-public.php#L1135
    root_cause: The delete path was read from session state that the attacker could poison through a separate endpoint, so the delete handler's own input looked trusted.
  - cve: CVE-2026-8713
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: An unauthenticated form-submission handler stored a path-traversal value together with retention fields that forced an immediate cleanup, and a shutdown-hook privacy routine then deleted the referenced file with no administrator interaction.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-8713
    code_ref: https://plugins.trac.wordpress.org/browser/fusion-builder/trunk/inc/class-fusion-form-db-entries.php#L79
    root_cause: Insufficient path validation in a background cleanup routine whose input was an attacker-planted database entry, reached through a wp_ajax_nopriv_ handler.
  - cve: CVE-2026-8095
    year: 2026
    severity: 8.1
    auth: subscriber+
    summary: A meta-update handler unset a forbidden key by exact lowercase name; supplying the key in uppercase evaded the check and was then normalised back to the protected key by sanitize_key(), overwriting the stored file path that a later routine passed to unlink().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-8095
    code_ref: https://plugins.trac.wordpress.org/browser/nmedia-user-file-uploader/tags/23.6/inc/file.class.php#L729
    root_cause: A case-sensitive denylist upstream of a case-normalising sink; the stored path was then unlinked with no directory containment validation.
---

## What it is

A request causes the plugin to call `unlink()` (or `wp_delete_file()`, which is a thin
core wrapper around it) on a path the attacker influenced. Because path traversal escapes
whatever directory the developer intended, the attacker can delete any file the web-server
user can write to. In WordPress this is not merely destructive — it is a reliable
full-takeover primitive, which is why these bugs are consistently scored 9.1
(`C:N/I:H/A:H`) even though they leak nothing.

## Why it matters: the wp-config.php escalation chain

Deleting `wp-config.php` does not break the site into a 500 error. WordPress core handles
a missing config by starting the installer. From `wp-load.php`:

```php
if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
    require_once ABSPATH . 'wp-config.php';
} elseif ( ... ) {
    ...
} else {
    // A config file doesn't exist.
    ...
    $path = wp_guess_url() . '/wp-admin/setup-config.php';

    // Redirect to setup-config.php.
    if ( ! str_contains( $_SERVER['REQUEST_URI'], 'setup-config' ) ) {
        header( 'Location: ' . $path );
        exit;
    }
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-load.php` (lines 47–81)

The chain, in order:

1. Attacker deletes `wp-config.php`.
2. Every request to the site now redirects to `/wp-admin/setup-config.php` — the
   installation wizard — with **no authentication**, because the credentials that would
   have identified an administrator lived in the file that was just removed.
3. The attacker completes the wizard pointing at a database **they control** (any
   reachable MySQL host; on shared hosting, often one they can provision themselves).
4. WordPress writes a new `wp-config.php` and runs the install, creating an administrator
   account with the attacker's password. The site's original files — including every
   plugin and theme — are still on disk and still served.
5. As administrator, the attacker uses the plugin/theme editor or a plugin upload to write
   PHP, then repoints the config at the original database if they want the real content
   back.

Whoever wins the race after step 1 owns the site, so exploitation is typically automated
to complete steps 2–4 within seconds. This is why arbitrary file deletion must be triaged
at the same urgency as arbitrary file upload, and why "it only deletes files" is never a
mitigating argument. Related high-value targets: `wp-config-backup.php`, `.htaccess`
(removing upload-directory hardening, which re-enables PHP execution in `uploads/`),
a security plugin's main file (disabling a WAF), and `wp-content/db.php`.

## Why it happens in WordPress

- **`wp_delete_file()` reads as safe and is not.** It is `unlink()` plus a filter. Many
  plugins switch to it during a security review believing it validates something.
- **`sanitize_text_field()` does not remove `../`.** It is the most common false defence
  in this class, exactly as in WP-LFI.
- **Nonces are treated as authorization.** A nonce proves the request came from a page the
  server rendered — and public pages get rendered for anonymous visitors. In several
  disclosed cases the required nonce was printed into front-end JavaScript on every page
  containing the form, or handed out by a separate public endpoint on request. A nonce
  without a `current_user_can()` alongside it is not a boundary.
- **The path often comes from stored state, not the request.** Post meta, an option, or a
  `$_SESSION` key holds "the file to clean up". If any endpoint — including a
  Subscriber-level or anonymous one — can write that key, the delete handler's input is
  attacker-controlled even though it contains no superglobal.
- **Cleanup runs on hooks that nobody audits.** `shutdown`, cron events, "privacy
  retention" sweepers and `wp_scheduled_delete` all delete files with no request context
  at all, which makes the taint path invisible to anyone reading the AJAX handler.
- **File uploads and file deletes ship together.** Any plugin with a front-end uploader has
  a matching "remove" endpoint, and the remove endpoint gets a fraction of the scrutiny.

## Vulnerable pattern

```php
// The remove half of a front-end uploader. The nonce is printed into the page's JS,
// so any anonymous visitor can obtain it.
add_action( 'wp_ajax_nopriv_example_remove_upload', 'example_remove_upload' );
add_action( 'wp_ajax_example_remove_upload',        'example_remove_upload' );

function example_remove_upload() {
    check_ajax_referer( 'example_nonce', 'nonce' );   // NOT an authorization check

    // sanitize_text_field() strips tags and control chars. It leaves ../ untouched.
    $file_name = sanitize_text_field( wp_unslash( $_POST['file_name'] ) );
    $field     = sanitize_text_field( wp_unslash( $_POST['field_name'] ) );
    $session   = sanitize_text_field( wp_unslash( $_POST['session'] ) );

    // Both the filename AND part of the directory come from the request.
    $dir  = wp_upload_dir()['basedir'] . "/example/{$session}/{$field}/";
    $path = $dir . $file_name;

    if ( file_exists( $path ) ) {
        wp_delete_file( $path );      // == unlink()
    }
    wp_send_json_success();
}
```

`file_name=../../../../wp-config.php` deletes the config. Note the second, subtler defect:
because `$session` and `$field` also feed the *directory*, any "is this file in the folder
we manage" listing built from `$dir` is a listing of a folder the attacker chose.

The half-fixed variant, which is what survives review:

```php
$base     = wp_upload_dir()['basedir'] . '/example/';
$filepath = realpath( $base . $rel );

// BUG 1: comparing a filesystem path against a URL — strpos() always returns false.
// BUG 2: loose ==, and false == 0 is TRUE. The guard never rejects anything.
if ( strpos( $filepath, wp_upload_dir()['baseurl'] ) == 0 ) {
    unlink( $filepath );
}
```

And the stored-state variant, where no superglobal appears near the sink at all:

```php
function example_cleanup( $post_id ) {
    $path = get_post_meta( $post_id, 'example_file_path', true );  // written elsewhere
    if ( $path && file_exists( $path ) ) {
        unlink( $path );
    }
}
```

## Secure pattern

The best fix is to stop handling paths. If the file is in the media library, delete it by
ID and let core resolve the path:

```php
function example_remove_attachment() {
    // 1. Real authorization, not just a nonce.
    if ( ! is_user_logged_in() ) {
        wp_send_json_error( 'forbidden', 403 );
    }
    check_ajax_referer( 'example_remove', 'nonce' );

    $attachment_id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
    if ( ! $attachment_id || 'attachment' !== get_post_type( $attachment_id ) ) {
        wp_send_json_error( 'not found', 404 );
    }

    // 2. Ownership / capability on THIS object, not a global capability.
    if ( ! current_user_can( 'delete_post', $attachment_id ) ) {
        wp_send_json_error( 'forbidden', 403 );
    }

    // 3. Core resolves the path. There is no attacker-controlled string anywhere.
    wp_delete_attachment( $attachment_id, true );
    wp_send_json_success();
}
```

When a raw path is genuinely unavoidable (a private working directory outside the media
library), the containment check must be written exactly like this:

```php
function example_delete_working_file() {
    if ( ! current_user_can( 'upload_files' ) ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_delete', 'nonce' );

    // 1. Canonicalise the base ONCE, and trailing-slash it so /base-evil cannot match /base.
    $base = realpath( wp_upload_dir()['basedir'] . '/example-work' );
    if ( false === $base ) { wp_send_json_error( 'misconfigured', 500 ); }
    $base = trailingslashit( wp_normalize_path( $base ) );

    // 2. Strip every directory component. Necessary, not sufficient.
    $name = isset( $_POST['file'] ) ? wp_basename( wp_unslash( $_POST['file'] ) ) : '';
    if ( '' === $name || 0 !== validate_file( $name ) ) {
        wp_send_json_error( 'bad request', 400 );
    }

    // 3. Canonicalise the candidate and require a STRICT prefix match.
    $real = realpath( $base . $name );
    if ( false === $real ) { wp_send_json_error( 'not found', 404 ); }
    $real = wp_normalize_path( $real );

    if ( 0 !== strpos( $real, $base ) ) {   // strict !== , never == 0
        wp_send_json_error( 'forbidden', 403 );
    }

    // 4. Only ever delete regular files; never follow into a directory or a symlink.
    if ( ! is_file( $real ) || is_link( $base . $name ) ) {
        wp_send_json_error( 'forbidden', 403 );
    }

    wp_delete_file( $real );
    wp_send_json_success();
}
```

Non-negotiables: the base is canonicalised and trailing-slashed; the comparison is strict;
`realpath()` returning `false` is handled; a capability check accompanies the nonce; and
neither the directory portion nor the filename may originate from the request
independently.

## Real-world case studies

### Delete-after-download on an unbounded path (CVE-2024-9047, 9.8, unauthenticated)

The same directly-reachable downloader analysed under WP-LFI also deletes:

```php
if ( substr($file_code, 0, 10) == "exportdata" ) {
    $file_code = substr($file_code, 10);
    $filepath = WFU_USVAR_downloader('wfu_storage_'.$file_code);
    $disposition_name = "wfu_export.csv";
    $delete_file = true;
}
...
if ( $delete_file ) wfu_unlink_for_downloader($filepath);
```
`https://plugins.trac.wordpress.org/browser/wp-file-upload/tags/4.24.11/wfu_file_downloader.php#L111`

and the helper is a bare suppressed unlink:

```php
function wfu_unlink_for_downloader($filepath) {
    if ( substr($filepath, 0, 7) != "sftp://" ) return @unlink($filepath);
```

**Root cause at that line:** the delete flag is switched on by a request-controlled string
prefix (`exportdata…`), and the path it applies to is read from state the same request can
supply. There is no containment check to bypass because none exists. Two things worth
carrying into every audit: (a) a *conditional* delete flag driven by request data is as
dangerous as a delete parameter; (b) `@unlink()` — suppressed — is the norm in this class,
so detection rules must allow a leading `@`.

### realpath() present, containment check inert (CVE-2026-18855, 9.1, unauthenticated)

```php
$pathpos  = strpos( $delete_link_url, $uploads['baseurl'] );
$filepath = realpath( $uploads['basedir'] . substr( $delete_link_url, $pathpos + strlen( $uploads['baseurl'] ) ) );

if ( $pathpos !== false && strpos( $filepath, $uploads['baseurl'] ) == 0 ) {
    ...
    } elseif ( file_exists( $filepath ) ) {
        $unlinkreturn = unlink( $filepath );
    }
```
`https://plugins.trac.wordpress.org/browser/link-library/tags/7.9.4/link-library-admin.php#L7863`

**Root cause at that line:** `$filepath` is a **filesystem** path built from
`$uploads['basedir']`, but it is compared against `$uploads['baseurl']`, a **URL**.
`strpos()` therefore returns `false` every time. PHP's loose `==` evaluates `false == 0`
as `true`, so the guard is unconditionally satisfied. Because `realpath()` appears on the
preceding line, this reads as a properly defended delete. The delete itself is reached
when an administrator performs a routine moderation action on an attacker-submitted link,
so no further interaction is needed beyond what a moderator does daily.

**This is the single most important shape in the class**, and the reason DELETE-005 is
rated `high` rather than `medium`: the vulnerability is invisible to "does it call
realpath()" reasoning and visible only to "is the comparison correct".

### An explicitly unsanitised parameter (CVE-2026-6070, 9.1, unauthenticated)

```php
} elseif ($type == TYPE_REMOVE) {
    $this->_filename = Factory::getApplication()->input->get('_filename', null, 'RAW');
...
$file_tmp = JBusinessUtil::makePathFile($this->_root_app . $this->_filename);

if (@unlink($file_tmp)) {
```
`https://plugins.trac.wordpress.org/browser/wp-businessdirectory/tags/4.0.0/site/controllers/upload.php#L450`

**Root cause at that line:** the input is fetched with an explicit `RAW` filter — the
framework offered sanitisation and the code opted out — and the "path helper" only
normalises directory separators without stripping `../`. The base directory is selectable
by a second parameter. The endpoint is reached through the plugin's own front-end routing
(`task=upload.remove`), so it never appears in an `add_action( 'wp_ajax_...' )` grep.
**Custom routing layers are a blind spot:** enumerate `$_GET['task']`, `$_GET['action']`,
`$_REQUEST['do']`-style dispatchers, not just WordPress hook names.

### Attacker supplies both halves of the path (CVE-2026-14484, 9.1, unauthenticated)

```php
$field_name = sanitize_text_field( wp_unslash( $_POST['field_name'] ?? '' ) );
...
$file_name  = sanitize_text_field( wp_unslash( $_POST['file_name'] ?? '' ) );
$toDelete[] = $file_name;
...
$sessionId  = sanitize_text_field( wp_unslash( $_POST['rsmfcf7_session'] ?? '' ) );
$upload_path = RSMFCF7_Assets::getUploadDir( $form_id, $field_name, $sessionId, false );
$uploaded_files = RSMFCF7_Helpers::getFilesInFolder( $upload_path );
foreach ( $toDelete as $file_name ) {
    $full_path = $upload_path . $file_name;
    ...
    if ( !in_array( $full_path, $uploaded_files ) ) { ... }
    @wp_delete_file( $full_path );
}
```
`https://plugins.trac.wordpress.org/browser/rapisafe-multi-file-cf7/trunk/src/RSMFCF7_Assets.php#L235`

**Root cause at that line:** three distinct failures compound. `sanitize_text_field()` does
not remove `../`. `$field_name` and `$sessionId` are interpolated into the *directory*
(`.../{$formId}-{$sessionId}/{$field_name}/`), so the attacker steers the base as well as
the leaf. And the `in_array( $full_path, $uploaded_files )` allowlist is built by listing
that same attacker-chosen directory — **an allowlist derived from attacker-controlled
input is not an allowlist**. The advisory further records that the required nonce is
published as a JavaScript variable on every page rendering the upload field, so
`check_ajax_referer()` stops nobody.

### Controls that are not authorization boundaries (CVE-2026-14487, 9.1, unauthenticated)

The removal endpoint required a nonce plus a secondary hash. A separate public endpoint
issued a valid nonce to any anonymous visitor:

```php
public function generateUploadFileID() {
    ...
    $id = strval(crc32(wp_rand() . $ip . round(microtime(true))));
    wp_send_json_success(array(
        'ID' => esc_attr($id),
        'hash' => esc_attr(wp_hash_password($this->salt.esc_attr($id))),
        'nonce' => esc_attr(wp_create_nonce('scf_upload_file_removal')),
    ));
}
```
`https://plugins.trac.wordpress.org/browser/simple-coherent-form/tags/2.4.13/includes/fields/file.php#L1486`

and the hash's salt was a constant compiled into the plugin, so it could be forged offline.
The identifier then becomes part of the deletion path:

```php
public function deletingFile($id, $error = false) {
    $dir  = wp_get_upload_dir();
    $path = $dir['basedir'] . '/scf_uploads/' . $id . '/';
    $this->removeUploadDir($path, $error);
```
`https://plugins.trac.wordpress.org/browser/simple-coherent-form/tags/2.4.13/includes/fields/file.php#L1387`

**Root cause:** the deletion path is `basedir . '/scf_uploads/' . $id . '/'` with `$id`
unconstrained, and `removeUploadDir()` is recursive. Both "controls" are ceremony: a nonce
that a public endpoint hands out, and a keyed hash with a public key. When auditing, the
question is never "is there a nonce" but "can an anonymous attacker obtain a valid one",
and never "is there a hash" but "where does the key live".

### Poison the store, then trigger the sweep (CVE-2026-14524 and CVE-2026-8713)

Two variants of the same two-step shape:

- One public handler writes a path-traversal value into the attacker's **own session**
  under a key the delete handler later reads as a filename, and a second public handler
  performs the delete. Both steps need only the publicly available front-end nonce.
  `https://plugins.trac.wordpress.org/browser/prosolution-wp-client/tags/2.0.3/public/class-prosolwpclient-public.php#L1135`
- An unauthenticated form-submission handler (`wp_ajax_nopriv_…`) stores a traversal
  payload as a form entry, together with retention fields that force the retention interval
  to expire immediately; a **shutdown-hook** privacy-cleanup routine then deletes the
  referenced path with no administrator interaction.
  `https://plugins.trac.wordpress.org/browser/fusion-builder/trunk/inc/class-fusion-form-db-entries.php#L79`

**Root cause in both:** the code at the `unlink()` reads a value from trusted-looking
storage (session, database row), so nothing near the sink looks tainted. Any grep centred
on the sink finds no superglobal. The taint enters through a completely different endpoint.
This is what DELETE-008 exists for: once a deletion sink is known, work backwards to every
writer of the key it reads.

### Case-sensitivity bypass into a stored path (CVE-2026-8095, 8.1, subscriber+)

A meta-update handler removed a protected key from the incoming array by exact lowercase
name. Supplying `WPFM_DIR_PATH` in uppercase evaded the `unset()`, and `sanitize_key()`
inside `update_post_meta()` then lower-cased it back to the protected key — overwriting the
stored file path. The stored path is later used directly:

```php
function delete_file_locally() {
    ...
    $file_path = $this->path;
    ...
    if (file_exists($file_path)) {
        ...
        if (unlink($file_path)) {
```
`https://plugins.trac.wordpress.org/browser/nmedia-user-file-uploader/tags/23.6/inc/file.class.php#L729`

**Root cause:** a case-sensitive denylist sitting upstream of a case-normalising sink, and
then no directory containment on the resulting path at all. Any time a denylist filters
keys or names before something calls `sanitize_key()`, `strtolower()`, `sanitize_title()`
or a database collation-insensitive comparison, the denylist can be evaded by changing
case. Compare and reject after normalisation, never before.

## Detection guidance

**What the regexes catch reliably**

- `DELETE-001` catches the direct case with near-zero false positives; the `@?` prefix
  matters because suppressed `unlink()` dominates this class.
- `DELETE-005` catches the broken-containment idiom and is the highest-value rule here for
  the same reason as in WP-LFI: it fires on code that already calls `realpath()`.
- `DELETE-003` produces a small, complete worklist — most plugins have only a handful of
  deletion sinks, so exhaustive manual triage of DELETE-003 hits is realistic and is the
  recommended workflow for this class.

**What the regexes CANNOT catch — read the code**

1. **Paths from stored state.** `get_post_meta()`, `get_option()`, `$_SESSION`, a
   database row, a transient. The `unlink()` line contains no superglobal and no
   concatenation of request data. This accounts for several of the 9.1 cases above.
   The audit move is: find the sink, identify the storage key, then find every writer of
   that key and check *its* authorization.
2. **Deletes that never run in a request.** `shutdown`, `wp_scheduled_delete`, custom cron
   events, privacy-retention sweepers, `admin_init` maintenance routines. The attacker
   plants data; a background routine does the deleting. Enumerate `add_action('shutdown'`,
   `wp_schedule_event`, and any `*_cleanup` / `*_purge` / `*_maybe_delete*` function.
3. **Custom routing.** `task=upload.remove`-style dispatchers, REST routes built from a
   loop, and `$_GET['action']` switches never match a `wp_ajax_` grep. Enumerate the
   plugin's own router before assuming the hook list is complete.
4. **Whether an existing containment check is correct.** Same checklist as WP-LFI: base
   canonicalised, base trailing-slashed, strict prefix comparison, `false` handled, and
   the two operands the same *kind* of thing (path vs path, not path vs URL).
5. **Whether the directory portion is attacker-controlled.** A regex sees
   `$upload_path . $file_name` and reasons about `$file_name`. In CVE-2026-14484 the real
   defect was that `$upload_path` was also built from `$_POST`.
6. **Whether a nonce is an authorization boundary.** Static analysis sees
   `check_ajax_referer()` and scores the handler as protected. Determine whether the nonce
   is rendered into a public page, or issued by another public endpoint, and whether any
   `current_user_can()` accompanies it.
7. **Recursive deletion.** `$wp_filesystem->delete( $path, true )`, hand-rolled
   `RecursiveDirectoryIterator` removers, and `array_map( 'unlink', glob( $pattern ) )`.
   A `glob()` pattern built from request data is an arbitrary *mass* delete and matches no
   `unlink( $_POST` rule.
8. **Symlink following.** `unlink()` on a symlink removes the link, but a
   preceding `is_file()`/`realpath()` on the target plus a TOCTOU window, or a recursive
   remover that descends into symlinked directories, extends the blast radius. Not
   expressible as a pattern.
9. **Case- and encoding-normalisation gaps.** The CVE-2026-8095 shape: a denylist compared
   before `sanitize_key()`/`strtolower()` runs. Also URL-decoding, `wp_unslash()` ordering,
   and UTF-8 overlong sequences.

## Audit checklist

- [ ] Run `DELETE-003` to enumerate every deletion sink in the codebase; the list is
      usually short enough to triage exhaustively. Do this first.
- [ ] For each sink, answer: where does the argument come from — request, stored state, or
      a constant? If stored state, enumerate every writer of that key and audit *their*
      authorization.
- [ ] Run `DELETE-005` and inspect every containment comparison for loose `==`, for
      `false` handling, and for path-vs-URL operand mismatches.
- [ ] Run `DELETE-007` and cross-reference with the sink list; anything in both is a 9.1
      candidate.
- [ ] For every `check_ajax_referer()` / `wp_verify_nonce()` in a delete handler, find where
      that nonce is created and whether an anonymous visitor can obtain it. Confirm a
      `current_user_can()` check exists alongside it.
- [ ] Enumerate background deletion: `add_action('shutdown'`, `wp_schedule_event`,
      `wp_cron`, retention/privacy sweepers, `*_cleanup`, `*_purge`, `*_maybe_delete*`.
- [ ] Enumerate the plugin's own request router (`task=`, `action=`, `do=`, custom REST
      registration loops) — deletion endpoints frequently live there rather than on
      `wp_ajax_*`.
- [ ] For every path concatenation feeding a delete, establish provenance of **both**
      operands, including the directory portion.
- [ ] Grep for `sanitize_text_field` on a value that reaches a delete sink and flag it —
      it does not remove `../`.
- [ ] Grep for `glob(`, `->delete( $x, true )`, `rmdir(`, `RecursiveDirectoryIterator` and
      check whether any pattern or root is request-influenced.
- [ ] Check every denylist/`unset()` of a forbidden key for case sensitivity when the
      downstream sink normalises case (`sanitize_key`, `strtolower`, `sanitize_title`).
- [ ] Verify the fix converts to `wp_delete_attachment( absint( $id ), true )` wherever the
      file is a media-library item; a path-based delete should be the exception, not the norm.
