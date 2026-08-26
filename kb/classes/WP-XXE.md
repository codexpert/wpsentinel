---
class_id: WP-XXE
title: XML external entity injection and unsafe XML parsing
cwe: [CWE-611, CWE-827]
owasp: A05:2021-Security Misconfiguration
severity_typical: high
auth_required_typical: author+
prevalence_rank: 14
detection:
  - id: XXE-001
    description: >-
      An explicitly dangerous libxml flag passed to a parser. LIBXML_NOENT turns entity substitution
      back ON, and LIBXML_DTDLOAD makes the parser fetch the external DTD subset. Since libxml 2.9.0
      both are off by default, so their presence is a deliberate opt-in to the vulnerable behaviour.
    regex: '\b(?:LIBXML_NOENT|LIBXML_DTDLOAD|XML_PARSE_NOENT|XML_PARSE_DTDLOAD)\b'
    confidence: high
    false_positive_notes: >-
      The flag is safe only when paired with a working external-entity block for the PHP version in
      use, and on PHP 8 no such block exists any more (libxml_disable_entity_loader() is a no-op).
      Treat LIBXML_NOENT on modern PHP as a finding by default. Note the rule deliberately does not
      match the benign constants LIBXML_NOCDATA, LIBXML_NOBLANKS or LIBXML_NONET, which look similar
      in review and are frequently confused with these two.
  - id: XXE-002
    description: >-
      Any call to libxml_disable_entity_loader(). Both arguments are findings for different reasons -
      (false) re-enables external entity loading process-wide, and (true) is deprecated and has no
      effect from PHP 8.0, so code relying on it for protection is unprotected on modern PHP.
    regex: 'libxml_disable_entity_loader\s*\('
    confidence: high
    false_positive_notes: >-
      A (true) call is harmless in itself on PHP 8; the finding is whatever it was protecting. Always
      read the parse call it wraps and check for LIBXML_NOENT. A version gate around the call
      (`if ( PHP_VERSION_ID < 80000 )`) is a specific and serious anti-pattern - see the WordPress
      core case study - because it removes the guard on exactly the versions where the developer
      assumed it was unnecessary.
  - id: XXE-003
    description: DOMDocument construction and its load family (load, loadXML, loadHTMLFile). DOMDocument is safe by default on current libxml but is the most common carrier for an explicit LIBXML_NOENT.
    regex: '->(?:loadXML|loadHTMLFile|load)\s*\(|new\s+\\?DOMDocument\s*\('
    confidence: low
    false_positive_notes: >-
      Reclassified low by scripts/test_rules.py: this fires on correct code in
      tests/fixtures/safe.php, and kb/SCHEMA.md reserves high/medium for rules that stay
      silent there. No coverage is lost - the high-confidence rules in this class still
      cover the unambiguous shapes; this one is the worklist that needs triage.
      The correctly hardened form also matches - `$dom->resolveExternals = false;
      $dom->substituteEntities = false; $dom->load( $f, LIBXML_NONET );` produces two hits and is
      fine. Triage by reading the flags argument and the two properties. `->load(` is a generic
      method name and will also match unrelated loaders (`$config->load()`, `$template->load()`);
      confirm the receiver is a DOM object.
  - id: XXE-004
    description: The SimpleXML family - simplexml_load_string(), simplexml_load_file() and new SimpleXMLElement(). The third argument of the load functions is the flags argument that carries LIBXML_NOENT.
    regex: '(?:^|[^_A-Za-z0-9>:$])(?:simplexml_load_string|simplexml_load_file)\s*\(|new\s+\\?SimpleXMLElement\s*\('
    confidence: medium
    false_positive_notes: >-
      A default-flag call is safe on PHP 8 and on any PHP built against libxml 2.9.0 or later with the
      entity loader left alone. It is not safe on PHP 7 in a process where anything has called
      libxml_disable_entity_loader( false ), which is why the calls still need to be enumerated.
      Priority order for reading hits - those with a third argument first, then those parsing an
      uploaded or fetched document, then the rest.
  - id: XXE-005
    description: A request superglobal reaching an XML parser directly, optionally through one or two wrapping calls such as file_get_contents(), wp_unslash() or stripslashes().
    regex: '(?:simplexml_load_string|simplexml_load_file|SimpleXMLElement|loadXML|xml_parse)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\(\s*){0,2}\$_(?:GET|POST|REQUEST|COOKIE|FILES)'
    confidence: high
    false_positive_notes: >-
      Essentially none as a finding of "untrusted XML is parsed here". Whether it is exploitable
      still depends on the PHP/libxml version and the flags, so record the PHP version constraint in
      the report rather than dropping the finding.
  - id: XXE-006
    description: The property form of the same opt-in - DOMDocument::$substituteEntities or ::$resolveExternals set to true. Equivalent to LIBXML_NOENT / LIBXML_DTDLOAD but contains none of those tokens.
    regex: '->(?:substituteEntities|resolveExternals)\s*=\s*(?:true|1)\b'
    confidence: high
    false_positive_notes: >-
      Very low volume. The only benign reason to set substituteEntities = true is a document with
      internal entity definitions the code genuinely needs expanded, which still requires the
      external loader to be blocked separately. The `= false` form is the hardening and is
      deliberately not matched.
  - id: XXE-007
    description: Legacy and streaming XML parsers - the expat wrappers xml_parser_create()/xml_parse(), and XMLReader. Different API surface, same entity semantics, and none of the other rules see them.
    regex: '(?:^|[^_A-Za-z0-9>:$])(?:xml_parser_create(?:_ns)?|xml_parse)\s*\(|new\s+\\?XMLReader\s*\('
    confidence: medium
    false_positive_notes: >-
      expat does not expand external entities at all, so xml_parser_create() hits are usually
      informational - but they mark a file that consumes untrusted XML, which is exactly where the
      *other* parsers in the same file matter. XMLReader needs LIBXML_NOENT (or ::setParserProperty
      with SUBST_ENTITIES) to be dangerous; check for those on any XMLReader hit.
  - id: XXE-008
    description: >-
      SVG upload surface. An SVG is an XML document, so a plugin that whitelists the SVG MIME type or
      branches on image/svg+xml has created an author-level channel for attacker-authored XML - the
      entry point for the majority of recent WordPress XXE reports.
    regex: 'image/svg\+xml|[\x27"]svg[\x27"]\s*=>|upload_mimes'
    confidence: medium
    false_positive_notes: >-
      Not a vulnerability on its own; it is a *reachability* rule. Many hits are icon pickers, MIME
      allowlists or front-end sprite handling with no parser anywhere. Its value is correlation - an
      XXE-008 hit in a codebase that also has XXE-003 or XXE-004 hits means untrusted XML almost
      certainly reaches a parser. Also matches `upload_mimes` filters that have nothing to do with
      SVG; read the callback.
fix_apis:
  - LIBXML_NONET
  - DOMDocument::$resolveExternals = false
  - DOMDocument::$substituteEntities = false
  - libxml_use_internal_errors()
  - json_decode()
  - wp_json_encode()
  - fetch_feed()
  - wp_safe_remote_get()
  - wp_check_filetype_and_ext()
  - current_user_can()
examples:
  - cve: CVE-2021-29447
    year: 2021
    severity: 7.1
    auth: author+
    summary: Core's bundled ID3 library parsed the XML chunks of an uploaded media file with LIBXML_NOENT, while the call that blocked external entities was skipped on PHP 8 as "no longer needed".
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2021-29447
    code_ref: https://core.svn.wordpress.org/tags/5.7/wp-includes/ID3/getid3.lib.php
    root_cause: A PHP_VERSION_ID < 80000 gate removed libxml_disable_entity_loader(true) on PHP 8 while LIBXML_NOENT stayed in the parse call - libxml's safe default only holds when NOENT is not requested.
  - cve: CVE-2024-50442
    year: 2024
    severity: 7.2
    auth: admin+
    summary: A function named sanitize_svg(), hooked on every SVG upload, loaded the file with LIBXML_NOENT | LIBXML_DTDLOAD and then wrote the parsed result back over the uploaded file.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-50442
    code_ref: https://plugins.trac.wordpress.org/browser/royal-elementor-addons/tags/1.3.980/admin/templates-kit.php#L939
    root_cause: Both dangerous libxml flags were passed explicitly, and the comment "Remove external entities" was followed by no code; saveXML() then persisted the substituted entity content into the stored file.
  - cve: CVE-2025-14478
    year: 2026
    severity: 7.5
    auth: author+
    summary: A media-library filter measured SVG dimensions with simplexml_load_file() on the attachment path, using default flags.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-14478
    code_ref: https://plugins.trac.wordpress.org/browser/demo-importer-plus/tags/2.0.6/inc/importers/class-demo-importer-plus-sites-helper.php#L88
    root_cause: An uploaded SVG parsed with no explicit hardening; the advisory limits impact to PHP below 8.0, where the process-global entity loader can still be enabled.
  - cve: CVE-2013-2202
    year: 2013
    severity: 4.3
    auth: unauthenticated
    summary: Core's oEmbed discovery parsed the XML *response* of a remote provider, so an attacker-chosen provider URL returning a document with an external entity declaration produced arbitrary local file read. Scored under CVSS v2 only.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2013-2202
    root_cause: Untrusted XML arriving over HTTP rather than by upload - the parser was hardened for neither case, and the "file" the entity referenced was on the victim server.
---

## What it is

XML has a feature that no other common data format has: a document can declare *entities* that the
parser expands, and an entity can point at a URI. `<!ENTITY xxe SYSTEM "file:///etc/passwd">` asks
the parser to go and read that file and paste the contents into the document. If the parsed result
is then rendered, echoed, saved or returned, the attacker has arbitrary file read on the server;
if the URI is `http://internal/`, they have SSRF; and specially shaped entity definitions produce
denial of service (the "billion laughs" expansion).

WP-XXE is rare in the WordPress corpus — two records in the Wordfence prevalence sample, and NVD
carries only a handful more — but it is cheap to detect, severe when present, and its safety depends
on a *runtime environment* rather than on the code alone, which makes it uniquely easy to get wrong
in a way that review misses.

## Why it happens in WordPress

**The single most important fact: on a current stack, XML parsing is safe by default, and almost
every real WordPress XXE is a case of code deliberately turning that default off.**

1. **libxml has been safe by default since 2.9.0 (2012).** `XML_PARSE_NOENT` (entity substitution)
   and `XML_PARSE_DTDLOAD` (fetch the external DTD) are *off* unless requested. A plain
   `simplexml_load_string( $xml )` or `$dom->loadXML( $xml )` does not resolve external entities.

2. **`LIBXML_NOENT` switches it back on.** Every one of the flag-carrying cases below passes it
   explicitly. Developers add it because it makes entity references resolve — including the
   perfectly ordinary internal ones — and the flag's name reads like "no entities", which is the
   opposite of what it does. (It means "substitute entities", from libxml's `noent` = *no entity
   references remain in the tree*.)

3. **`libxml_disable_entity_loader()` is history, and its history is the trap.** It was the
   pre-2012 defence: a process-global switch turning the external loader off. As of **PHP 8.0 it is
   deprecated and has no effect** — libxml's own default is relied upon instead. Three consequences
   an auditor must hold simultaneously:
   - Calling it with `true` on PHP 8 is a **no-op**, so code that "protects itself" this way is
     unprotected. It is still worth writing for PHP 7 compatibility, but it must not be the only
     control.
   - Calling it with `false` — including a *restore* of a saved previous value — re-enables loading
     **process-wide** on PHP 7, for every plugin in the request, not just the caller.
   - Removing the call on PHP 8 because it is "no longer needed" is only correct **if you also
     removed `LIBXML_NOENT`**. WordPress core shipped precisely that mistake; see below.

4. **SVG uploads are an XML channel dressed as an image channel.** WordPress core does not allow SVG
   uploads, so any plugin that adds `image/svg+xml` to `upload_mimes` has opened an
   author-level path for arbitrary attacker-authored XML — and will then usually want to parse it,
   to read its dimensions or to "sanitise" it. Two of the four cases below arrive this way. That is
   why XXE-008 exists: the MIME allowlist is the reachability half of the finding.

5. **Media metadata parsing is XML parsing.** ID3/RIFF containers embed XMP and iXML chunks, which
   core's bundled getID3 parses as XML on upload. A `.wav` or `.jpg` is therefore an XML delivery
   vehicle, which is how the core CVE below was reached with no SVG involved at all.

6. **Untrusted XML does not have to be uploaded.** oEmbed discovery, RSS/Atom consumption, SOAP,
   XML-RPC pingbacks and any "import from URL" feature parse documents fetched over HTTP from a
   host the attacker may choose. The 2013 core case is exactly this shape, and it is the one most
   often missed because there is no file upload to notice.

7. **Version-dependence makes advisories look contradictory, and they are not.** CVE-2025-14478's
   advisory says it *only* affects PHP below 8.0. CVE-2021-29447's says it *requires* PHP 8. Both
   are correct: the first relies on the pre-8.0 process-global loader still being enable-able, the
   second exists because the 8.0 deprecation caused the guard to be gated away while `LIBXML_NOENT`
   remained. **Never conclude "PHP 8, therefore safe" — check the flags.**

## Vulnerable pattern

```php
// 1. The opt-in. Both flags requested explicitly; libxml's safe default no longer applies.
$dom = new DOMDocument();
$dom->loadXML( $svg_content, LIBXML_NOENT | LIBXML_DTDLOAD );
// ... transform ...
return $dom->saveXML();          // the expanded entity content is now written back out

// 2. The property form of the same thing - contains no LIBXML_ token at all.
$dom = new DOMDocument();
$dom->substituteEntities = true;
$dom->resolveExternals   = true;
$dom->load( $file );

// 3. The version gate that removes the guard exactly where it is still needed.
if ( PHP_VERSION_ID < 80000 ) {
    // "deprecated in PHP 8.0 because in libxml 2.9.0 external entity loading is
    //  disabled by default, so this function is no longer needed"
    $loader = libxml_disable_entity_loader( true );
}
$obj = simplexml_load_string( $xml, 'SimpleXMLElement', LIBXML_NOENT );   // NOENT stayed

// 4. Re-enabling the loader process-wide on PHP 7 - affects every plugin in the request.
libxml_disable_entity_loader( false );
$old = libxml_disable_entity_loader( true );
$doc = simplexml_load_file( $path );
libxml_disable_entity_loader( $old );      // "restore" may hand control back to false

// 5. Request data straight into a parser.
$xml = simplexml_load_string( file_get_contents( $_FILES['import']['tmp_name'] ) );
$dom->loadXML( wp_unslash( $_POST['payload'] ) );

// 6. Parsing a document fetched from an attacker-chosen URL.
$body = wp_remote_retrieve_body( wp_remote_get( $_GET['provider'] ) );
$feed = simplexml_load_string( $body );

// 7. Opening the SVG channel and then parsing what comes through it.
add_filter( 'upload_mimes', function ( $m ) { $m['svg'] = 'image/svg+xml'; return $m; } );
add_filter( 'wp_prepare_attachment_for_js', function ( $r, $a ) {
    $svg = simplexml_load_file( get_attached_file( $a->ID ) );   // author-supplied XML
    ...
}, 10, 2 );
```

## Secure pattern

```php
// 1. Do not ask for the dangerous behaviour. Default flags are already safe on libxml >= 2.9.
$dom = new DOMDocument();
$dom->resolveExternals   = false;   // explicit, so review can see the intent
$dom->substituteEntities = false;
libxml_use_internal_errors( true ); // parse errors become data, not warnings on the page
$ok = $dom->load( $file, LIBXML_NONET );   // LIBXML_NONET also blocks network access outright
libxml_clear_errors();
libxml_use_internal_errors( false );

// 2. Same for SimpleXML - no third argument means no NOENT.
$xml = simplexml_load_string( $raw, 'SimpleXMLElement', LIBXML_NONET );

// 3. If you must support PHP 7 as well, keep the legacy guard AND drop NOENT.
//    Never gate the guard on the PHP version; gate nothing, and remove the flag instead.
if ( function_exists( 'libxml_disable_entity_loader' ) && PHP_VERSION_ID < 80000 ) {
    $prev = @libxml_disable_entity_loader( true );
}
$xml = simplexml_load_string( $raw, 'SimpleXMLElement', LIBXML_NONET );
if ( isset( $prev ) ) {
    @libxml_disable_entity_loader( $prev );
}

// 4. Reject documents that declare a DOCTYPE at all, when your format does not need one.
//    This is a cheap, version-independent belt to go with the braces.
if ( preg_match( '/<!DOCTYPE/i', $raw ) ) {
    return new WP_Error( 'xxe', 'DOCTYPE declarations are not accepted.' );
}

// 5. For data interchange, do not use XML. JSON has no entities and no external references.
$data = json_decode( $body, true );
update_post_meta( $post_id, 'myplugin_config', wp_json_encode( $data ) );

// 6. For feeds, use core - it owns the parser configuration so you do not have to.
$feed = fetch_feed( esc_url_raw( $url ) );

// 7. Gate the upload channel, not just the parser.
add_filter( 'upload_mimes', function ( $mimes ) {
    if ( current_user_can( 'unfiltered_html' ) ) {      // administrators only
        $mimes['svg'] = 'image/svg+xml';
    }
    return $mimes;
} );
```

The whole fix, in one line: **do not pass `LIBXML_NOENT` or `LIBXML_DTDLOAD`, and do not set
`substituteEntities`/`resolveExternals` to true.** Everything else — `LIBXML_NONET`, the DOCTYPE
check, `libxml_disable_entity_loader()` on PHP 7 — is defence in depth around that one decision.

## Real-world case studies

### The version gate that removed the guard (CVE-2021-29447, WordPress core 5.6–5.7)

`wp-includes/ID3/getid3.lib.php` at tag 5.7, lines 721–735:

```php
public static function XML2array($XMLstring) {
    if (function_exists('simplexml_load_string') && function_exists('libxml_disable_entity_loader')) {
        if (PHP_VERSION_ID < 80000) {
            // This function has been deprecated in PHP 8.0 because in libxml 2.9.0, external entity loading is
            // disabled by default, so this function is no longer needed to protect against XXE attacks.
            $loader = libxml_disable_entity_loader(true);
        }
        $XMLobject = simplexml_load_string($XMLstring, 'SimpleXMLElement', LIBXML_NOENT);
        $return = self::SimpleXMLelement2array($XMLobject);
        if (PHP_VERSION_ID < 80000 && isset($loader)) {
            libxml_disable_entity_loader($loader);
        }
```

The 5.7.2 patch deletes the version gate and amends one clause of the comment:

```php
// This function has been deprecated in PHP 8.0 because in libxml 2.9.0, external entity loading is
// disabled by default, but is still needed when LIBXML_NOENT is used.
$loader = @libxml_disable_entity_loader(true);
$XMLobject = simplexml_load_string($XMLstring, 'SimpleXMLElement', LIBXML_NOENT);
$return = self::SimpleXMLelement2array($XMLobject);
@libxml_disable_entity_loader($loader);
```

**Root cause at L722–L730:** the premise in the original comment is true and the conclusion drawn
from it is false. libxml's default *is* safe — but only for callers who accept the default, and this
caller passes `LIBXML_NOENT`, which is precisely the request to substitute entities. The author read
"deprecated" as "unnecessary" and gated the guard behind `PHP_VERSION_ID < 80000`, so the protection
disappeared on exactly the PHP versions where it was still load-bearing. That is why the advisory
records this bug as *requiring* PHP 8.

Reachability: `XML2array()` is reached from the RIFF/WAVE and XMP metadata parsers, so an author who
can upload a media file supplies the XML. This is the case to cite whenever someone argues that
"WordPress does not accept XML uploads" — a `.wav` file is an XML upload if a chunk inside it is
parsed as XML. It is also the reason XXE-002 is high-confidence even for the apparently harmless
`(true)` argument: what matters is the parse call it wraps.

### A sanitiser that requested the vulnerability (CVE-2024-50442)

`admin/templates-kit.php` at tag 1.3.980, lines 920–951:

```php
function wpr_sanitize_svg_on_upload($file) {
    if ($file['type'] === 'image/svg+xml') {
        $file_content = file_get_contents($file['tmp_name']);
        $sanitized_content = sanitize_svg($file_content);
        file_put_contents($file['tmp_name'], $sanitized_content);
    }
    return $file;
}
add_filter('wp_handle_upload_prefilter', 'wpr_sanitize_svg_on_upload');

function sanitize_svg($svg_content) {
    $dom = new DOMDocument();
    $dom->loadXML($svg_content, LIBXML_NOENT | LIBXML_DTDLOAD);

    // Remove scripts
    $scripts = $dom->getElementsByTagName('script');
    ...
    // Remove external entities
    // Additional sanitization can be added here as needed

    return $dom->saveXML();
}
```

**Root cause at L939:** both dangerous flags, passed together, inside a function called
`sanitize_svg()`. Four things make this the most instructive case in the class:

- The comment `// Remove external entities` is followed by **no code**. An intention was recorded
  and never implemented, while the line above actively requested entity expansion.
- The hook is `wp_handle_upload_prefilter`, so this runs on *every* SVG upload — it is not an
  opt-in code path.
- `saveXML()` writes the parsed tree back over the uploaded file. Whatever `file:///etc/passwd`
  expanded to is now persisted in the media library and served to the uploader. The exfiltration
  channel is built into the "sanitiser".
- The same plugin's WXR importer (`admin/import/class-parsers.php`, lines 411–423) does it the old
  way — `libxml_disable_entity_loader( true )`, `$dom->loadXML( ... )` with **no flags**, restore
  afterwards — and is fine, because it never asks for `NOENT`. One plugin, two parsers, opposite
  outcomes, and the difference is a single constant.

### Default flags, but an old PHP (CVE-2025-14478)

`inc/importers/class-demo-importer-plus-sites-helper.php` at tag 2.0.6, lines 51–88:

```php
public function add_svg_image_support( $response, $attachment, $meta ) {
    if ( ! function_exists( 'simplexml_load_file' ) ) { return $response; }
    ...
    if ( 'image/svg+xml' !== $response['mime'] ) { return $response; }

    $svg_path   = get_attached_file( $attachment->ID );
    $dimensions = self::get_svg_dimensions( $svg_path );
    ...
}

public static function get_svg_dimensions( $svg ) {
    $svg = simplexml_load_file( $svg );      // L88 - default flags
```

**Root cause at L88:** no explicit hardening at all on an author-uploaded document, reached through
the `wp_prepare_attachment_for_js` filter — i.e. any time the SVG is shown in the media library.
There is no `LIBXML_NOENT` here, which is why the advisory restricts impact to *"sites on versions
of PHP older than 8.0"*: before 8.0 the external entity loader is a process-global that can be
enabled by this plugin, by another plugin, or by a library restoring a saved value, and a
default-flag parse in that state will resolve external entities.

The vendor's patch is worth reading as an example of a *partial* fix:

```php
$dom = new DOMDocument();
$dom->resolveExternals   = false;
$dom->substituteEntities = false;
$previous_error_handler  = libxml_use_internal_errors( true );
$loaded = $dom->load( $svg, LIBXML_NONET | LIBXML_DTDLOAD | LIBXML_DTDATTR );
```

The two properties are correct and `LIBXML_NONET` blocks network retrieval, but `LIBXML_DTDLOAD` is
still requested — the code will load an external DTD from the local filesystem. With
`substituteEntities = false` that is not an exfiltration primitive, so the fix holds, but it is
strictly more permissive than it needs to be. When you review a patch in this class, check the flags
that *remain*, not only the ones that were removed.

### Untrusted XML that was never uploaded (CVE-2013-2202, WordPress core < 3.5.2)

Core's oEmbed discovery fetched a provider URL over HTTP and parsed the XML response. An attacker
who could cause a request to a provider they controlled received back a document containing an
external entity declaration and an entity reference, and the resulting expansion read a file from
the *victim's* server. NVD classifies it under CWE-200 while stating plainly that it is an XXE
issue; it predates CVSS v3, so only the v2 score of 4.3 exists.

**Root cause:** the trust boundary was drawn at "file upload" and the XML arrived over the network
instead. This case belongs in the knowledge base precisely because none of the upload-oriented
heuristics — SVG MIME allowlists, `$_FILES`, media metadata — would have found it. Any code that
parses a *response* is parsing untrusted XML: oEmbed, RSS/Atom, SOAP, XML-RPC pingback, sitemap
consumers, "import from URL" features, and licence/update checks against a configurable endpoint.
It is also the shape that overlaps most with `WP-SSRF`; a finding in either class should prompt a
scan for the other.

## Detection guidance

**Triage order that works:** XXE-001 and XXE-006 first — they identify the explicit opt-in and are
findings on sight. Then XXE-002 (read what each call wraps). Then XXE-005. Then XXE-008 to establish
whether an untrusted-XML channel exists at all, and only then XXE-003/004/007 to enumerate the
parsers that channel can reach. Running the parser rules first on a large codebase produces a long
list of calls that are safe by default; running the reachability rules first tells you which of them
matter.

**What the regexes catch:**

- XXE-001/006 — the deliberate opt-in, in both its constant form and its property form.
- XXE-002 — every appearance of the legacy guard, in all three of its wrong uses.
- XXE-003/004/007 — the parser call sites: DOM, SimpleXML, expat and XMLReader.
- XXE-005 — the unambiguous shape of a superglobal reaching a parser.
- XXE-008 — the SVG/`upload_mimes` reachability surface.

**What they MISS — read code manually when you see these:**

- **The PHP/libxml version, which decides exploitability.** No regex can tell you whether the site
  runs PHP 7.4 with a stale libxml or PHP 8.3. A default-flag parse is a finding on one and not on
  the other. Record the constraint in the report — "exploitable on PHP < 8.0" — rather than dropping
  or promoting the finding on assumption.
- **Cross-plugin process state on PHP 7.** `libxml_disable_entity_loader( false )` in *any* plugin
  affects the whole request. A plugin that parses XML safely can be made unsafe by an unrelated
  plugin on the same site, exactly as WP-POI gadget chains come from elsewhere. Grep the whole
  install, not just the component under review.
- **Bundled libraries.** `vendor/` trees carry their own parsers — Guzzle/PSR-7 XML bodies,
  `SimplePie`, `PHPExcel`/`PhpSpreadsheet` (XLSX is a zip of XML), `TCPDF`, SOAP clients,
  `symfony/serializer` with the XML encoder. Grep `vendor/` separately; a hit there is as real as
  one in plugin code.
- **XLSX, DOCX, ODT and EPUB importers.** Every one of those formats is a ZIP of XML documents. An
  importer that unzips and parses is an XXE surface with no `.xml` extension in sight. Grep for
  `ZipArchive`, `->extractTo(`, and the office MIME types.
- **`SoapClient` and XML-RPC.** `new SoapClient( $wsdl )` parses a WSDL — attacker-controlled if the
  endpoint is configurable. `xmlrpc.php` and `IXR_Message` parse pingback bodies from anyone.
  Neither contains a token from these rules.
- **Wrapper methods.** `$this->parse_xml( $raw )`, `Importer::read()`, `XmlHelper::toArray()`. As
  everywhere else, the sink hides one call away. After any parser hit inside a function, grep for
  that function's name.
- **`LIBXML_NOENT` behind a variable.** `$flags = LIBXML_NOENT; ... load( $f, $flags )` — XXE-001
  catches the assignment but nothing links it to the parse. Read the surrounding function.
- **Billion-laughs / quadratic-blowup denial of service.** Purely *internal* entity definitions need
  no external loader and are therefore unaffected by every control in this document except
  `LIBXML_PARSEHUGE` being absent and a DOCTYPE rejection. If availability is in scope, check for a
  DOCTYPE check and for `LIBXML_PARSEHUGE` (which removes libxml's own expansion limits and should
  never appear).
- **Blind XXE.** When the parsed result is not echoed, exfiltration still works via an external
  parameter entity in an out-of-band DTD. Absence of an obvious output channel is not a mitigation;
  `LIBXML_NONET` is what actually closes it.

**A note on scoring.** Because the fix is a constant and the exposure is version-dependent, this
class attracts arguments about whether a given finding is "really" exploitable. The auditor's job is
to record the sink, the flags, the entry point and the PHP constraint. `LIBXML_NOENT` on a path
reachable by untrusted XML is a finding on every PHP version; a default-flag parse of untrusted XML
is a finding on PHP below 8.0 and a hardening recommendation above it.

## Audit checklist

- [ ] Run XXE-001 across the whole tree including `vendor/`. Every hit on a path that parses
      untrusted XML is a finding. Confirm the hit is `LIBXML_NOENT`/`LIBXML_DTDLOAD` and not the
      benign `LIBXML_NOCDATA`/`LIBXML_NOBLANKS`/`LIBXML_NONET`.
- [ ] Run XXE-006 for the property form, which carries no `LIBXML_` token.
- [ ] Run XXE-002. For each hit, determine the argument and read the parse call it wraps:
      `(false)` re-enables loading process-wide on PHP 7; `(true)` is a no-op on PHP 8; a
      `PHP_VERSION_ID` gate around either is a finding in its own right.
- [ ] Run XXE-005 and treat every hit as untrusted XML reaching a parser.
- [ ] Run XXE-008 to establish reachability. Determine which capability the upload requires, and
      whether the MIME allowlist is gated on `current_user_can()`.
- [ ] Run XXE-003, XXE-004 and XXE-007 to enumerate every parser. Prioritise calls that (a) carry a
      third/flags argument, (b) parse an uploaded file, or (c) parse an HTTP response.
- [ ] For every parser reached by untrusted XML, record the required PHP version for exploitation
      and state it in the finding rather than dropping the finding.
- [ ] Enumerate the *non-upload* XML inputs: oEmbed, RSS/Atom consumption, SOAP/WSDL, XML-RPC
      pingback, sitemap readers, licence/update checks and any "import from URL" feature. Confirm
      each parses with safe flags, and cross-reference with `WP-SSRF`.
- [ ] Grep for `ZipArchive`, `->extractTo(` and office MIME types; XLSX/DOCX/ODT/EPUB importers are
      XML parsers wearing a different extension.
- [ ] Grep bundled `vendor/` for `SimplePie`, `SoapClient`, `PhpSpreadsheet`, `TCPDF` and any
      serializer with an XML encoder, and check their parser configuration.
- [ ] Grep for wrapper names — `function .*parse.*xml`, `function .*load.*xml`, `function .*to_array`
      — and then for calls to each one found.
- [ ] Confirm that any claimed fix removes `LIBXML_NOENT`/`LIBXML_DTDLOAD` or sets
      `substituteEntities`/`resolveExternals` to false. A patch that only adds a capability check or
      a MIME restriction reduces reachability and leaves the parser configured to expand entities —
      report it as partially fixed.
- [ ] Check which flags *remain* in a patched call. `LIBXML_DTDLOAD` surviving alongside
      `substituteEntities = false` is safe but unnecessarily permissive; `LIBXML_PARSEHUGE` should
      never be present.
- [ ] Where the format does not require it, recommend rejecting documents containing a `<!DOCTYPE`
      declaration outright — a version-independent control that also closes internal-entity
      expansion attacks.
