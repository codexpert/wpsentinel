---
class_id: WP-POI
title: PHP Object Injection via unserialize() on attacker-influenced data
cwe: [CWE-502, CWE-915]
owasp: A08:2021-Software and Data Integrity Failures
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 7
detection:
  - id: POI-001
    description: Any call to unserialize() (optionally @-suppressed). In a WordPress plugin/theme codebase this function name is almost never a false alarm — it has no safe idiomatic use that json_decode() would not cover.
    regex: '(^|[^_A-Za-z0-9])@?unserialize\s*\(\s*[^,;)]*\)'
    confidence: high
    false_positive_notes: >-
      Tightened after integration testing so the safe two-argument form is no longer matched:
      the pattern now requires a single argument (no comma before the closing paren), which
      keeps every true positive including nested decoders. Previously it also matched
      the safe two-argument form unserialize($d, ['allowed_classes' => false]) and
      matches function/method *declarations* named unserialize(). Rust-regex has no lookahead, so
      the allowed_classes exclusion cannot live in the pattern — post-filter hits whose line also
      contains "allowed_classes". A wrapper method named unserialize() is itself worth reading:
      wrappers are the single most common way the real sink gets hidden from a grep-based reviewer.
  - id: POI-002
    description: Request superglobal flowing directly into unserialize()/maybe_unserialize(), optionally through base64_decode/stripslashes/wp_unslash.
    regex: '(@?unserialize|maybe_unserialize)\s*\(\s*(base64_decode\s*\(\s*|stripslashes\s*\(\s*|wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|FILES)'
    confidence: high
    false_positive_notes: Essentially none. Every hit is a real object-injection sink; only the reachability (which hook, which capability check) is in question.
  - id: POI-003
    description: maybe_unserialize() applied to a value read back out of the database or a plugin row object — the "round trip" variant where the attacker writes the value first and triggers deserialization later.
    regex: 'maybe_unserialize\s*\(\s*(get_option|get_post_meta|get_user_meta|get_term_meta|get_comment_meta|get_transient|\$row|\$result|\$field|\$item|\$data)'
    confidence: medium
    false_positive_notes: >-
      Safe when the stored value can only ever be written by trusted code. Triage by finding the
      write side: if any request path (profile field, form submission, import, REST route) can put
      a string into that option/meta/column, the read side is a live sink. get_option/get_post_meta
      already auto-unserialize, so an explicit maybe_unserialize on their result usually signals a
      value that was serialize()d twice — a strong hint the data is user-supplied.
  - id: POI-004
    description: PHAR deserialization bridge — a filesystem function taking a request-controlled path. Any stream-wrapper-aware file op on a phar:// path deserializes the archive metadata with no unserialize() call in sight (PHP < 8.0 unconditionally; PHP >= 8.0 still exposes it where the file is opened as a phar).
    regex: '(file_exists|filesize|is_dir|is_file|file_get_contents|getimagesize|md5_file|sha1_file|stat|fileatime|filemtime|copy|unlink|hash_file|exif_read_data|get_meta_tags|parse_ini_file)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES)'
    confidence: medium
    false_positive_notes: >-
      Overlaps with path-traversal and arbitrary-file-read findings; a hit is only a POI issue if the
      attacker can also plant a .phar (or a polyglot GIF/JPEG containing a phar) somewhere readable —
      which an upload endpoint usually provides. Flag, do not auto-classify.
fix_apis:
  - json_decode()
  - json_encode()
  - unserialize($data, ['allowed_classes' => false])
  - wp_json_encode()
  - current_user_can()
  - check_ajax_referer()
examples:
  - cve: CVE-2024-5932
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A public donation-form endpoint deserialized a request field, and a gadget chain shipped inside the same package turned the object injection into remote code execution and arbitrary file deletion.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-5932
    code_ref: https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420
    root_cause: Untrusted POST data reached a deserializer on an unauthenticated form-submission path; the only control was a serialized-format sniff, not an allowed_classes restriction.
  - cve: CVE-2024-8353
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: The patch for the previous issue was bypassed because the serialized-format check ran before a slash-stripping step that reconstituted a valid serialized payload.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-8353
    code_ref: https://plugins.trac.wordpress.org/browser/give/tags/3.16.0/includes/process-donation.php#L154
    root_cause: Order-of-operations flaw — is_serialized() validated the pre-normalisation string while stripslashes_deep() was applied afterwards, so an escaped payload passed the check and then became live serialized data.
  - cve: CVE-2023-6933
    year: 2023
    severity: 9.8
    auth: unauthenticated
    summary: A database search-and-replace routine deserialized every string column value it walked, so any row an attacker could write became an object-injection trigger.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-6933
    code_ref: https://plugins.trac.wordpress.org/browser/better-search-replace/trunk/includes/class-bsr-db.php#L334
    root_cause: A private static unserialize() wrapper called @unserialize() with a single argument, gated only by is_serialized() — a format check that says nothing about which classes may be instantiated.
  - cve: CVE-2025-0724
    year: 2025
    severity: 8.8
    auth: subscriber+
    summary: Profile-field rendering ran maybe_unserialize() over user meta that the same low-privileged user had written, giving a store-then-render object injection.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-0724
    code_ref: https://plugins.trac.wordpress.org/browser/profilegrid-user-profiles-groups-and-communities/tags/5.9.4.2/includes/class-profile-magic-html-generator.php#L259
    root_cause: maybe_unserialize() was applied to a self-authored meta value on the display path, treating the database as if it were a trust boundary.
  - cve: CVE-2024-13921
    year: 2025
    severity: 7.2
    auth: admin+
    summary: An AJAX import handler passed a raw POST field through maybe_unserialize() before any validation, in the same statement that also fed a server-side fetch.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13921
    code_ref: https://plugins.trac.wordpress.org/browser/order-import-export-for-woocommerce/trunk/admin/modules/import/classes/class-import-ajax.php
    root_cause: maybe_unserialize($_POST['form_data']) used as a transport decoder for a structured AJAX payload where json_decode() was the correct tool.
  - cve: CVE-2026-12115
    year: 2026
    severity: 6.6
    auth: admin+
    summary: A settings importer wrote attacker-supplied rows into a custom table whose column was later read back with maybe_unserialize().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12115
    code_ref: https://plugins.trac.wordpress.org/browser/counter-box/tags/2.0.13/classes/Admin/DBManager.php#L168
    root_cause: A custom-table accessor deserialized a column value with no allowed_classes restriction, and the import path let that column be set from an uploaded file.
---

## What it is

PHP Object Injection happens when attacker-influenced bytes reach `unserialize()`. Unlike
`json_decode()`, `unserialize()` does not just rebuild scalars and arrays — it *instantiates
classes* named in the payload and populates their properties with attacker-chosen values. The
attacker never gets to call a method directly, but PHP calls "magic" methods
(`__destruct`, `__wakeup`, `__toString`, `__call`, `__get`, `__unserialize`) automatically on
those objects, and every one of those is a free method call on an object whose state the attacker
authored.

In WordPress this is rated critical almost by default, and the reason is unusual enough to state
plainly: the severity does not depend on the vulnerable component containing anything exploitable.

## Why the class is critical even when the advisory names no chain

A **POP chain** (Property-Oriented Programming chain) is the exploit half of the bug. The
deserializer gives the attacker a *primitive*: "instantiate any class that is loaded, with any
property values." To turn that into an effect, the attacker needs a class whose magic method does
something useful with a property — a `__destruct()` that calls `unlink($this->file)`, a
`__toString()` that renders a template path, a `__call()` that dispatches to a variable method
name. Chains are built by linking such gadgets: object A's `__destruct` calls a method on object
B, which is itself another attacker-supplied object, and so on until control reaches a file write,
a file delete, an SQL query, or `call_user_func`.

The chain must exist **in the code loaded into the same PHP process** — not in the vulnerable
plugin specifically. That distinction is what makes this class so dangerous on WordPress:

- Every request loads WordPress core, the active theme, *and every active plugin*, plus their
  bundled `vendor/` trees (Guzzle, Monolog, Twig, TCPDF, Faker, PHPMailer, League/Flysystem,
  Symfony components). Public gadget-chain catalogues target exactly these libraries.
- A typical production site runs 20–30 plugins. Each one adds classes to the same autoload space.
  The vulnerable plugin is the door; every other plugin is a potential key.
- The gadget surface is therefore **not a property of the vulnerable code and not under the
  vendor's control**. A plugin that is "safe" on a clean install becomes exploitable the day the
  site owner installs an unrelated page builder.
- The chain surface also grows over time. A payload that fizzles today may work after the next
  dependency bump, and it works retroactively against every site still running the old plugin.

This is why advisories phrase it as: *"No known POP chain is present in the vulnerable software.
If a POP chain is present via an additional plugin or theme installed on the target system, it
could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code."*
Across the CVEs surveyed for this class, roughly half carry that exact caveat — and they are still
scored 8.1–9.8. **Treat "no known POP chain" as "not yet weaponised", never as "not exploitable".**
An audit tool must flag the sink; proving the chain is not the auditor's job and its absence is
not a mitigating factor.

For the same reason, do not write the chain. Auditing this class requires locating the sink and
the trust boundary — not building a working gadget.

## Why it happens in WordPress

Several WordPress-specific traps push developers toward `unserialize()`:

1. **Serialization is baked into the storage APIs.** `update_option()`, `update_post_meta()`,
   `update_user_meta()` and `set_transient()` silently call `maybe_serialize()`; the matching
   getters call `maybe_unserialize()`. Developers absorb "serialize is how WordPress stores
   arrays" and then reach for the same tool for HTTP transport, where it is wrong.
2. **`maybe_unserialize()` looks like a safe wrapper. It is not.** It is
   `is_serialized($data) ? @unserialize($data) : $data` — a *format sniff* followed by a fully
   unguarded deserialize. It performs no class filtering whatsoever.
3. **`is_serialized()` is likewise a format check, not a safety check.** Guarding a deserialize
   with it stops nothing: the attacker's payload is by construction well-formed serialized data.
   It is also easy to desynchronise — validating the raw string and then running
   `stripslashes_deep()` / `wp_unslash()` afterwards lets an escaped payload pass the check and
   become valid only after it has been approved.
4. **Double serialization forces an explicit call.** When a plugin stores
   `update_option('x', serialize($arr))`, the getter returns a *string* (core unserialized once),
   so the plugin adds its own `maybe_unserialize()` on the read side. Every one of those explicit
   calls is a sink, and their presence is a reliable tell that the value round-trips through
   user-writable storage.
5. **`wp_ajax_nopriv_*` and public REST routes run before any capability check.** A single
   `add_action('wp_ajax_nopriv_...')` turns an internal helper into an unauthenticated sink.
6. **The database is not a trust boundary.** Postmeta, usermeta, options, comment meta and custom
   plugin tables are all writable through some request path — a profile field, a form submission,
   an importer, a REST endpoint. "It comes from the database" is the single most common reason a
   real sink gets waved through in review.
7. **PHAR turns file operations into deserializers.** `phar://` archive metadata is deserialized
   whenever a stream-wrapper-aware filesystem function touches the path. `file_exists()`,
   `filesize()`, `getimagesize()` and friends therefore become object-injection sinks when the
   path is request-controlled — and no `unserialize` token appears anywhere in the file.

## Vulnerable pattern

```php
// 1. Classic: request data straight into the deserializer on a public AJAX route.
add_action( 'wp_ajax_nopriv_myplugin_state', 'myplugin_restore_state' );
add_action( 'wp_ajax_myplugin_state', 'myplugin_restore_state' );

function myplugin_restore_state() {
    $state = unserialize( base64_decode( $_COOKIE['myplugin_state'] ) ); // sink
    wp_send_json_success( $state );
}

// 2. The "is_serialized() guard" that guards nothing.
public static function decode( $value ) {
    if ( ! is_serialized( $value ) ) {
        return false;
    }
    return @unserialize( trim( $value ) );   // sink: format was checked, classes were not
}

// 3. Order-of-operations bypass: validate, then normalise.
if ( myplugin_has_serialized_fields( $post_data ) ) {   // is_serialized() over the raw strings
    wp_die( 'Serialized fields detected.' );
}
$record = array(
    'user_info' => stripslashes_deep( $user_info ),      // payload becomes valid *after* the check
);

// 4. Store-then-render round trip: the database is treated as trusted.
$field_options = maybe_unserialize( $field->field_options ); // sink
$field_value   = maybe_unserialize( $field_value );          // sink; written by the same user

// 5. PHAR bridge: an object-injection sink with no unserialize() token in the file.
if ( file_exists( $_POST['template'] ) ) {   // phar:///var/www/uploads/avatar.jpg/x
    include $_POST['template'];
}
```

## Secure pattern

```php
// 1. For data interchange, do not serialize at all. JSON cannot instantiate objects.
add_action( 'wp_ajax_nopriv_myplugin_state', 'myplugin_restore_state' );

function myplugin_restore_state() {
    check_ajax_referer( 'myplugin_state' );

    $state = json_decode( wp_unslash( $_COOKIE['myplugin_state'] ), true ); // assoc arrays only
    if ( ! is_array( $state ) ) {
        wp_send_json_error( 'bad payload', 400 );
    }
    // Validate the shape explicitly; json_decode guarantees types, not semantics.
    $clean = array(
        'step'  => isset( $state['step'] ) ? absint( $state['step'] ) : 0,
        'label' => isset( $state['label'] ) ? sanitize_text_field( $state['label'] ) : '',
    );
    wp_send_json_success( $clean );
}

// 2. When you inherit a serialized format you cannot change, forbid class instantiation.
//    On PHP >= 7.0 this makes every "O:" entry decode as __PHP_Incomplete_Class: inert,
//    no constructor, no magic method, no gadget.
public static function decode( $value ) {
    if ( ! is_serialized( $value ) ) {
        return false;
    }
    return @unserialize( trim( $value ), array( 'allowed_classes' => false ) );
}

// 3. If a specific class genuinely must survive the round trip, allow-list it — never `true`.
$obj = unserialize( $blob, array( 'allowed_classes' => array( 'MyPlugin_Settings' ) ) );

// 4. Normalise first, validate second — never the other way round.
$user_info = stripslashes_deep( $user_info );
if ( myplugin_has_serialized_fields( $user_info ) ) {
    wp_die( 'Serialized fields detected.' );
}

// 5. Store JSON, so the read side never needs a deserializer.
update_post_meta( $post_id, 'myplugin_config', wp_json_encode( $config ) );
$config = json_decode( get_post_meta( $post_id, 'myplugin_config', true ), true );

// 6. Block the PHAR bridge: resolve and constrain the path, and reject stream wrappers.
$path = realpath( $candidate );
if ( false === $path || 0 !== strpos( $path, realpath( MYPLUGIN_TEMPLATE_DIR ) ) ) {
    wp_die( 'invalid template' );
}
```

Note the two-argument form is the whole fix: `unserialize($data, ['allowed_classes' => false])`
keeps arrays and scalars working while removing the object primitive entirely. There is no
partial-credit sanitiser for this class — no amount of `is_serialized()`, regex filtering, or
`stripslashes()` substitutes for it.

## Real-world case studies

### Unauthenticated form field into a deserializer, with a chain in the box (CVE-2024-5932)

A public donation form deserialized a submitted field. The advisory scored it 10.0 because a POP
chain was present in the plugin's own bundled dependencies, so the injection reached remote code
execution and arbitrary file deletion with no other plugin required. The follow-up hardening added
a pre-flight scan for serialized-looking values in the POST body
(`plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420`):

```php
function give_donation_form_has_serialized_fields(array $post_data): bool
{
    $post_data_keys = [ 'give-form-id', 'give-gateway', 'card_name', /* ... */ ];
    ...
        if (is_serialized($value)) {
```

**Root cause at that line:** the mitigation is a denylist of *field names* combined with
`is_serialized()`. It enumerates which parameters to inspect and what a payload looks like — two
things the attacker controls — instead of removing the object primitive at the sink.

### The same bug reopened by normalisation order (CVE-2024-8353)

The next release was bypassed. In the 3.16.0 tree the record assembled after validation reads
(`.../tags/3.16.0/includes/process-donation.php`, line 159):

```php
'user_info'    => stripslashes_deep( $user_info ),
```

**Root cause at that line:** `is_serialized()` ran against the raw, still-escaped request strings.
A payload written with backslash escapes fails that check, is waved through, and is then
reconstituted into valid serialized data by `stripslashes_deep()` before storage and later
deserialization. **Validate after normalising, never before** — and note that if the sink had used
`allowed_classes => false`, the ordering bug would have been harmless.

### A search-and-replace routine that deserialized every row it touched (CVE-2023-6933)

A database search-and-replace utility recursively unpacked serialized values so it could rewrite
strings inside them. The sink at tag 1.4.4 of `includes/class-bsr-db.php` is a small private
wrapper (lines 442–450):

```php
public static function unserialize( $serialized_string ) {
    if ( ! is_serialized( $serialized_string ) ) {
        return false;
    }
    $serialized_string   = trim( $serialized_string );
    $unserialized_string = @unserialize( $serialized_string );
    return $unserialized_string;
}
```

**Root cause at line 448:** single-argument `@unserialize()` with no `allowed_classes`, reached
from `recursive_unserialize_replace()` (line 334) which is called on *every string column value in
the selected tables*. Any option, postmeta, or comment row an attacker can write becomes the
payload carrier. The advisory explicitly records that no POP chain existed in this plugin — and it
was still scored 9.8, precisely because the chain would come from elsewhere on the site. Two
lessons for auditors: (a) a method *named* `unserialize` is a wrapper hiding the sink from
name-based review, and (b) code that iterates database contents makes the whole database the input.

### Store-then-render on self-authored user meta (CVE-2025-0724)

Profile rendering at tag 5.9.4.2 of `includes/class-profile-magic-html-generator.php`:

```php
$field_options = maybe_unserialize( $field->field_options );     // L259
...
$field_value = maybe_unserialize( $field_value );                // L266
```

**Root cause at L259/L266:** `$field_value` is fetched immediately above via
`profile_magic_get_user_field_value( $uid, ... )` — i.e. meta the subscriber-level user wrote
themselves. The write path and the read path are both reachable by the same low-privileged
account, so "it comes from the database" provides no isolation at all. This is the shape to look
for whenever a plugin lets users author structured profile/form data.

### One statement, two vulnerability classes (CVE-2024-13921 / CVE-2024-13923)

An AJAX import handler at tag 2.6.0 of
`admin/modules/import/classes/class-import-ajax.php`, line 180:

```php
$form_data = ( isset($_POST['form_data']) ? ...::process_formdata( maybe_unserialize( ($_POST['form_data']) ) ) : array() );
$response  = $this->import_obj->download_remote_file( $form_data );
```

**Root cause at line 180:** `maybe_unserialize()` is being used as a *transport decoder* for a
structured AJAX payload — a job `json_decode()` does without the object primitive. The very next
line feeds the same decoded structure into a server-side fetch, which is why this file also
appears in `WP-SSRF`. When you find a deserialization sink on an AJAX route, always keep reading:
the decoded structure usually flows onward into another sink.

### Import writes the row, accessor deserializes it (CVE-2026-12115)

`classes/Admin/DBManager.php` at tag 2.0.13, line 168:

```php
return isset( $result->param ) ? maybe_unserialize( $result->param ) : false;
```

**Root cause at line 168:** a custom-table accessor deserializes a column with no class
restriction. The reachability comes from `classes/Admin/ImporterExporter.php`, which loops
uploaded settings rows straight into `$data[$name] = $val->$name` and writes them — so the
attacker supplies the column contents through an import file and the accessor detonates them
later. Custom plugin tables get audited far less often than postmeta, but they are exactly as
untrusted.

## Detection guidance

**Why the plain function-name regex is unusually good here.** For most vulnerability classes a
bare function-name grep is a triage nightmare. `unserialize(` is one of the rare exceptions, and
it is worth stating explicitly because it makes POI an ideal high-confidence rule: the function has
essentially no safe idiomatic use in a modern WordPress plugin that `json_decode()` would not cover,
its name is unambiguous (no overloading, no namespace collisions worth worrying about), and the
single-argument form is *always* the dangerous one. A hit rate near 100 % "worth a human look" is
achievable with POI-001 alone. Run it first and read every hit.

**What the regexes catch:**

- POI-001 — every direct call site, including `@`-suppressed ones and wrapper method declarations.
- POI-002 — the unambiguous unauthenticated shape: superglobal into deserializer, including via
  `base64_decode`, `stripslashes` or `wp_unslash`.
- POI-003 — the round-trip shape: `maybe_unserialize()` over options/meta/transients/row objects.
- POI-004 — PHAR bridges, which contain no `unserialize` token at all.

**What they MISS — read code manually when you see these:**

- **Wrapper indirection.** `$this->unserialize($x)`, `Helper::decode($x)`, `$this->maybe_decode()`.
  POI-001 catches the *declaration*, but the interesting question — who calls it, with what — is a
  second search. After any POI-001 hit on a `function unserialize(` / `function decode(` line,
  grep for that method name across the tree.
- **Multi-line and variable-indirected calls.** `$fn = 'unserialize'; $fn($data);`,
  `call_user_func('unserialize', $data)`, or a call split across lines. Line-oriented regexes see
  none of these.
- **The taint path.** POI-001 tells you a sink exists; it cannot tell you whether the argument is
  reachable. The reachability question is always: which hook registers the handler
  (`wp_ajax_nopriv_*`, `register_rest_route` with `permission_callback` returning `__return_true`,
  `admin_post_nopriv_*`, `init`, a shortcode, a public webhook), and what capability/nonce check
  runs before the sink.
- **Indirect deserialization by libraries.** `Symfony\Component\Serializer` with the PHP encoder,
  Laravel-style `Illuminate\Support\Facades\Crypt` payloads, session handlers configured with
  `session.serialize_handler = php`, `WP_Object_Cache` backends, and any framework "cache" layer
  that stores serialized blobs. Grep bundled `vendor/` trees separately — `unserialize(` inside
  `vendor/` is both a possible sink *and* a possible gadget source.
- **The PHAR path in general.** Beyond POI-004's superglobal-adjacent form, any file operation on a
  path derived from an option, a meta value, or an uploaded filename is a candidate. Grep for
  `phar://` handling and for filesystem calls whose argument is a `$variable` rather than a
  constant-prefixed path.
- **`allowed_classes => true`.** Semantically identical to the unguarded call, but reads like a
  fix in review. Grep for `allowed_classes` and inspect the value — `true` and a wide class list
  are both findings.

**Triage order that works:** run POI-002 first (near-zero false positives, highest severity), then
POI-001 (read every hit; check the second argument), then POI-003 (find the write side before
judging), then POI-004 (correlate with any upload endpoint).

## Audit checklist

- [ ] Run POI-001 across the whole tree, including `vendor/`, `lib/`, and any minified or
      concatenated PHP. Read every hit; do not filter by directory.
- [ ] For each hit, check the **second argument**. No second argument, or
      `['allowed_classes' => true]`, or a broad class list — all are findings.
- [ ] Run POI-002. Treat every hit as critical until the hook registration proves otherwise.
- [ ] Run POI-003, then locate the **write side** of each option/meta/table column. If any request
      path can set it (profile field, form field, import, REST route, webhook), the read side is a
      live sink regardless of the capability required to trigger the read.
- [ ] Grep for `function unserialize`, `function decode`, `function maybe_decode`,
      `function get_data` and similar wrapper names; then grep for calls to each one found.
- [ ] Trace every sink back to its entry point and record the gate: `wp_ajax_nopriv_*`,
      `register_rest_route` `permission_callback`, `admin_post_nopriv_*`, shortcode, `init`,
      `template_redirect`, cron. Record `unauthenticated` if no capability check runs first.
- [ ] Check whether validation runs **before** `wp_unslash()` / `stripslashes_deep()` /
      `urldecode()` / `base64_decode()`. Validate-then-normalise is a bypass waiting to happen.
- [ ] Treat `is_serialized()` and `is_serialized_string()` guards as *absent* controls. Note them,
      but do not downgrade the finding.
- [ ] Run POI-004 and cross-reference with any file-upload endpoint in the same codebase; an upload
      plus a request-controlled path is a complete PHAR chain.
- [ ] Grep bundled `vendor/` for classes declaring `__destruct`, `__wakeup`, `__toString`, and
      `__call` to gauge the *gadget surface* the site carries — enough to justify the severity in
      the report. Do not build or ship a working chain.
- [ ] Confirm the fix, when present, is `json_decode()` or `allowed_classes => false`. A patch that
      only adds a nonce, a capability check, or an input-format filter reduces reachability but
      leaves the sink intact — report it as partially fixed.
