---
class_id: WP-SSRF
title: Server-Side Request Forgery via unvalidated outbound HTTP
cwe: [CWE-918]
owasp: A10:2021-Server-Side Request Forgery
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 20
detection:
  - id: SSRF-001
    description: Non-validating wp_remote_* call with a request superglobal on the same statement
    regex: 'wp_remote_(get|post|head|request)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
    confidence: high
    false_positive_notes: >-
      Deliberately does NOT match wp_safe_remote_* — those set reject_unsafe_urls and are
      validated by core. A hit is a finding unless the superglobal contributes only to the
      body/headers rather than to the URL (read which argument it lands in), or unless the
      value is first mapped through a hard-coded host allowlist on the same line. Note that
      $_SERVER is included: HTTP_HOST, HTTP_REFERER and HTTP_X_FORWARDED_FOR are
      attacker-controlled and are routinely concatenated into callback URLs.
  - id: SSRF-002
    description: Core's private-IP protection disabled globally via the http_request_host_is_external filter
    regex: 'add_filter\s*\(\s*[''"]http_request_host_is_external[''"]\s*,\s*([''"]__return_true[''"]|function\s*\(|fn\s*\(|static\s+function)'
    confidence: high
    false_positive_notes: >-
      This filter is the ONLY escape hatch from wp_http_validate_url()'s private-range
      check, and it is global: registering it turns off loopback/RFC1918 rejection for every
      wp_safe_remote_* call made by core, by every other plugin, and by every theme on the
      site for the rest of the request. '__return_true' is unconditionally a finding. The
      closure form is matched too and must be read — a closure that inspects $host and
      returns true only for one known internal hostname is legitimate. The array/[$this,...]
      callback form is deliberately NOT matched, to keep this rule high-confidence; sweep
      for the bare filter name separately when auditing a plugin end to end.
  - id: SSRF-003
    description: reject_unsafe_urls explicitly switched off in a request args array
    regex: 'reject_unsafe_urls[''"]?\]?\s*(=>|=)\s*(false|0|null)'
    confidence: high
    false_positive_notes: >-
      wp_safe_remote_*() works by setting this key to true; setting it to false converts a
      "safe" call back into an unvalidated one while leaving the reassuring function name in
      place. Also matches the $args['reject_unsafe_urls'] = false; assignment form. The only
      benign hit is a http_request_args filter callback that sets it false for a specific,
      hard-coded internal URL — verify the URL is not request-derived.
  - id: SSRF-004
    description: PHP-native fetch primitive fed by a request superglobal
    regex: '\b(file_get_contents|fopen|get_headers|getimagesize|simplexml_load_file|copy|fsockopen|curl_setopt|curl_init|readfile|exif_read_data|imagecreatefromstring)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      These functions have no URL validation whatsoever and PHP's stream wrappers make them
      dual-use: the same call is SSRF for http://, arbitrary file read for a relative path,
      and object injection for phar://. A hit is a finding; the only question is which of
      the three classes it belongs to (often all three — see CVE-2023-2249). Overlaps
      WP-LFI/LFI-003 by design; do not suppress one in favour of the other.
  - id: SSRF-005
    description: Option / meta / transient NAME built from request data — the attacker chooses which stored value is used
    regex: '\b(get_option|get_site_option|get_transient|get_post_meta|get_user_meta)\s*\([^;]*[''"][A-Za-z0-9_\-]*[''"]\s*\.\s*[^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: medium
    false_positive_notes: >-
      Extremely common and usually benign (per-form, per-post, per-widget settings keyed by
      an ID). It becomes a finding when the retrieved value is then used as a URL, a path or
      a capability: the request controls which stored string is dereferenced, so any option
      the attacker can also write becomes the request target. Prioritise hits whose key
      prefix contains url/webhook/endpoint/callback/api/host, and hits that appear inside a
      wp_remote_*/curl statement (CVE-2026-17123 matches this rule and SSRF-001 on the same
      line).
  - id: SSRF-006
    description: Outbound HTTP whose target is not a string literal — the full worklist
    regex: 'wp_remote_(get|post|head|request)\s*\(\s*[^''"\s)]'
    confidence: low
    false_positive_notes: >-
      Enormous volume; nearly every plugin builds its API URL from a constant or property.
      Its job is completeness, not precision: it is the only rule that catches the
      multi-hop shape where the tainted fragment is concatenated inside a helper
      (CVE-2026-78003 is invisible to every other rule here and shows up only as
      `wp_remote_request( $url, $args )`). Triage by tracing the first argument backwards.
      Misses the case where the first argument starts with a quote and is then
      concatenated ("https://api/" . $x) — SSRF-001 covers that when $x is a superglobal.
  - id: SSRF-007
    description: URL sanitiser/validator being used where an SSRF control is required
    regex: '\b(esc_url_raw|sanitize_url|esc_url|filter_var)\s*\(\s*(wp_unslash\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE)'
    confidence: medium
    false_positive_notes: >-
      esc_url_raw()/sanitize_url() normalise a URL and strip disallowed protocols. They do
      NOT restrict the host, so http://169.254.169.254/, http://127.0.0.1:6379/ and
      http://internal-jenkins/ all pass unchanged. filter_var(..., FILTER_VALIDATE_URL) is
      weaker still. Hits are only findings when the result reaches a fetch sink; a hit
      followed on the next line by wp_http_validate_url(), a parse_url() host allowlist, or
      a wp_safe_remote_* call is correct code — the fixed Getwid release matches this rule
      and is not vulnerable. Expect a high benign rate; the rule earns its place because
      this exact false defence appears in CVE-2026-6203, CVE-2026-1277 and CVE-2023-1895.
  - id: SSRF-008
    description: URL-shaped request parameter — surface mapping
    regex: '\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[''"](url|uri|link|src|source|target|endpoint|callback|callback_url|webhook|webhook_url|feed|feed_url|rss|remote|remote_url|image_url|img|imgurl|proxy|fetch|host|domain|redirect_uri|api_url|import_url|xml_url|site_url|server)[''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      Deliberately broad. Most hits never reach an outbound request. The value is a complete
      worklist of parameters that might become one, so each can be traced by hand; in
      CVE-2024-5021 this is the only rule that fires, because the sink 14 lines later takes
      a bare variable.
  - id: SSRF-009
    description: TLS certificate verification disabled on an outbound request
    regex: '(sslverify[''"]?\s*(=>|=)\s*(false|0)|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0))'
    confidence: medium
    false_positive_notes: >-
      Not SSRF by itself, but it belongs to the same audit: it makes every outbound request
      MITM-able, and it is the standard workaround developers reach for when an internal
      host has a self-signed certificate — which is a strong hint that the code path is
      pointed at internal infrastructure. Occasionally legitimate in a local-development
      guard (`if ( WP_DEBUG )`); read the surrounding condition. Always a finding when the
      request carries an API key or an auth header.
fix_apis:
  - wp_safe_remote_get()
  - wp_safe_remote_post()
  - wp_safe_remote_request()
  - wp_http_validate_url()
  - wp_parse_url()
  - current_user_can()
  - check_ajax_referer()
  - rest_ensure_response()
examples:
  - cve: CVE-2026-78003
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: An unauthenticated AJAX handler took array KEYS from a POST parameter, passed them through sanitize_text_field(), and interpolated them into the path segment of a fixed API base URL that was then fetched with the site's API key attached.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-78003
    code_ref: https://plugins.trac.wordpress.org/browser/mailgun/tags/2.1.10/mailgun.php#L331
    root_cause: sanitize_text_field() does not remove slashes or dot segments, so a request-supplied path fragment could traverse out of the intended endpoint prefix; the Authorization header was attached regardless of where the path ended up.
  - cve: CVE-2024-13905
    year: 2025
    severity: 9.1
    auth: unauthenticated
    summary: A class file registered add_filter('http_request_host_is_external', '__return_true') at file scope, disabling core's private-IP rejection for every outbound request made anywhere on the site.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13905
    code_ref: https://plugins.trac.wordpress.org/browser/onestore-sites/trunk/classess/class-export.php#L3
    root_cause: The one control that makes wp_safe_remote_* meaningful was switched off globally and unconditionally, at load time, for the whole site.
  - cve: CVE-2024-13924
    year: 2025
    severity: 9.1
    auth: unauthenticated
    summary: An independently-published plugin shipped a byte-identical export class with the same file-scope http_request_host_is_external override.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13924
    code_ref: https://plugins.trac.wordpress.org/browser/starter-templates/trunk/classess/class-export.php#L3
    root_cause: Copy-pasted boilerplate; the same one-line global disable, demonstrating that this is a propagating idiom rather than a single mistake.
  - cve: CVE-2026-17123
    year: 2026
    severity: 8.8
    auth: contributor+
    summary: An AJAX action registered for both authenticated and unauthenticated callers read a webhook URL out of an option whose NAME was built from a request parameter, then dispatched it with the non-validating wp_remote_post().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-17123
    code_ref: https://plugins.trac.wordpress.org/browser/royal-elementor-addons/tags/1.7.1061/classes/modules/forms/wpr-send-webhook.php#L56
    root_cause: The request chose which stored option supplied the URL, and a separate widget render path let a Contributor write that option; the plugin's own private-IP helper was never called on this route.
  - cve: CVE-2024-5021
    year: 2024
    severity: 9.3
    auth: unauthenticated
    summary: A standalone PHP file under the plugin's asset directory read a URL from a query parameter, fetched it with file_get_contents(), and echoed the bytes back to the caller.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-5021
    code_ref: https://plugins.trac.wordpress.org/browser/nimble-portfolio/trunk/includes/prettyphoto/download-image.php#L17
    root_cause: A directly-reachable script with no WordPress bootstrap, no authentication, and a raw PHP stream function as the fetch primitive; the only check was on the file extension, which does not constrain the host.
  - cve: CVE-2023-2249
    year: 2023
    severity: 8.8
    auth: subscriber+
    summary: >-
      An AJAX handler expected a base64 "data:" URI, and when the value did not contain a
      comma it fell through to file_get_contents() on the raw request value, writing the
      result to a publicly reachable file.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-2249
    code_ref: https://plugins.trac.wordpress.org/browser/wpforo/tags/2.1.7/classes/Actions.php#L457
    root_cause: A single unvalidated PHP stream-function call reachable by a Subscriber, simultaneously SSRF (http://), arbitrary file read (relative path) and object injection (phar://) — and non-blind, because the response body was persisted to a public URL.
  - cve: CVE-2026-1313
    year: 2026
    severity: 8.3
    auth: contributor+
    summary: A the_content filter parsed link hrefs out of post content and issued a cURL request to each one to display its file size, following up to five redirects with no host validation.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1313
    code_ref: https://plugins.trac.wordpress.org/browser/mimetypes-link-icons/tags/3.2.20/mime_type_link_images.php#L1612
    root_cause: The URL never passes through a superglobal at all — it arrives as post content — so no request-parameter-based control existed and none of the superglobal-anchored detection rules can see it.
  - cve: CVE-2023-1895
    year: 2023
    severity: 9.6
    auth: subscriber+
    summary: A REST route whose permission callback required only a low-privilege login accepted an arbitrary URL parameter, ran it through esc_url_raw(), and fetched it with wp_remote_get().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-1895
    code_ref: https://plugins.trac.wordpress.org/browser/getwid/trunk/includes/rest-api.php#L344
    root_cause: esc_url_raw() was treated as the validation step; the fix added a host-plus-path allowlist (content_url_is_valid()) and raised the capability, which is the shape a correct fix takes.
---

## What it is

The plugin fetches a URL that the request influenced. Because the fetch happens from the
web server, it reaches everything the web server can reach and nothing the attacker could:
`127.0.0.1` services with no authentication (Redis, Elasticsearch, memcached, an internal
admin panel), RFC1918 hosts on the hosting provider's network, other tenants on the same
box, and — the prize — the cloud instance metadata endpoint at `169.254.169.254`, which on
a misconfigured instance hands out IAM credentials to anyone who asks. When the response
body is echoed back the bug is a read primitive against the internal network; when it is
not, it is still a blind write primitive (POST to an internal queue, trigger an internal
webhook, port-scan by timing).

Three WordPress-specific twists raise the ceiling. The outbound request often carries the
site's own credentials (`Authorization` headers built by the plugin), so path-only control
is enough to call privileged third-party API endpoints as the site. PHP's stream wrappers
mean the same sink is frequently also arbitrary file read and object injection. And a
single line anywhere in a plugin can switch core's protection off for the entire site.

## Why it happens in WordPress

- **The safe function and the unsafe function differ by one word.** `wp_remote_get()` does
  *no* URL validation. `wp_safe_remote_get()` does. They have the same signature, the same
  return type and adjacent entries in the handbook. Autocomplete picks the shorter one.
- **`reject_unsafe_urls` defaults to `false`.** In `WP_Http::request()` the default args
  contain `'reject_unsafe_urls' => apply_filters( 'http_request_reject_unsafe_urls', false, $url )`.
  The four `wp_safe_remote_*` wrappers do nothing except set that key to `true` before
  delegating. Everything else about the two families is identical.
- **`http_request_host_is_external` is a global, load-time kill switch.** It is the only
  way past `wp_http_validate_url()`'s private-range check, and it is not scoped to the
  plugin that registers it. `add_filter( 'http_request_host_is_external', '__return_true' )`
  in one plugin removes the protection from core's own update checks, from every other
  plugin, and from the theme.
- **`http_request_args` can rewrite anyone's request.** A filter on `http_request_args` sees
  `$parsed_args` and `$url` for *every* outbound request on the site and can set
  `reject_unsafe_urls` to false, add headers, or change `sslverify`. Audit these callbacks
  as carefully as the request sites themselves.
- **`esc_url_raw()` looks like the validator and is not.** It normalises the URL and strips
  disallowed schemes. It says nothing about the host. This is the single most common false
  defence in the class.
- **`wp_ajax_nopriv_` and `permission_callback => '__return_true'`** put fetch handlers on
  unauthenticated routes; `the_content`, shortcode and block render callbacks put them
  behind nothing but "a Contributor saved a draft".
- **Import/export, oEmbed proxies, link previews, webhook dispatch, "check my API key",
  favicon/OG-image scrapers and PDF/screenshot generators** are all, structurally,
  "fetch a URL the user gave us". Every one of them is a candidate.

## Vulnerable pattern

```php
// wp-content/plugins/example/includes/proxy.php
add_action( 'wp_ajax_nopriv_example_fetch', 'example_fetch' );
add_action( 'wp_ajax_example_fetch',        'example_fetch' );

function example_fetch() {
    // esc_url_raw() strips bad schemes. It does not restrict the host.
    $url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';

    // wp_remote_get() performs NO url validation at all.
    $res = wp_remote_get( $url, array( 'timeout' => 15 ) );

    wp_send_json_success( wp_remote_retrieve_body( $res ) );
}
```

`url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns the
instance role's temporary credentials in the JSON response.

The variant that survives review, because it *does* call the safe wrapper:

```php
// Somewhere else in the same plugin — often in an unrelated class file, at file scope.
add_filter( 'http_request_host_is_external', '__return_true' );

// ...and now this is no safer than the code above, sitewide.
$res = wp_safe_remote_get( $url );
```

And the one that no host allowlist would have caught, because the host is fixed:

```php
function api_call( $uri ) {                       // $uri comes from $_POST array keys
    $url = 'https://api.vendor.example/v3/' . $uri;
    return wp_remote_request( $url, array(
        'headers' => array( 'Authorization' => 'Basic ' . base64_encode( "api:{$key}" ) ),
    ) );
}
```

`$uri = "../../../routes"` reaches a completely different, privileged endpoint on the
vendor API **with the site's own API key attached** — cURL removes dot segments before
sending, so the traversal resolves server-side.

## Secure pattern

```php
/**
 * Shape 1 — ALLOWLIST. Correct whenever the set of reachable hosts is known,
 * which is almost always. Validate host AND path; a host allowlist alone still
 * lets an open redirector or a path-traversal on the vendor API through.
 */
function example_fetch_allowlisted() {
    if ( ! current_user_can( 'edit_posts' ) ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_fetch', 'nonce' );

    $raw    = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';
    $parsed = wp_parse_url( $raw );

    $allowed_hosts = array( 'templates.example.com', 'cdn.example.com' );
    $allowed_path  = '/wp-json/example/v1/get_content';

    if ( empty( $parsed['host'] ) || ! in_array( $parsed['host'], $allowed_hosts, true ) ) {
        wp_send_json_error( 'host not allowed', 400 );
    }
    if ( empty( $parsed['scheme'] ) || 'https' !== $parsed['scheme'] ) {
        wp_send_json_error( 'https required', 400 );
    }
    if ( ! isset( $parsed['path'] ) || $allowed_path !== $parsed['path'] ) {
        wp_send_json_error( 'path not allowed', 400 );
    }

    // Belt and braces: the safe wrapper still validates every redirect hop.
    $res = wp_safe_remote_get( $raw, array(
        'timeout'     => 10,
        'redirection' => 0,     // do not follow redirects at all where you can avoid it
        'sslverify'   => true,
    ) );
    if ( is_wp_error( $res ) ) { wp_send_json_error( 'fetch failed', 502 ); }

    wp_send_json_success( wp_remote_retrieve_body( $res ) );
}
```

```php
/**
 * Shape 2 — genuinely arbitrary user URLs (a link checker, an OG-image scraper).
 * There is no way to make this safe with a string check alone; you need core's
 * resolver plus a redirect policy plus an explicit deny of the metadata range.
 */
function example_fetch_arbitrary( $raw ) {
    // 1. Core's validator: http/https only, no user:pass, no ':#?[]' in host,
    //    resolves the name and rejects private IPv4 ranges.
    $url = wp_http_validate_url( $raw );
    if ( false === $url ) { return new WP_Error( 'bad_url', 'Rejected' ); }

    // 2. Core's IPv4 blocklist did not include 169.254.0.0/16 before WordPress 7.1.
    //    On any older site the metadata endpoint passes wp_http_validate_url().
    $host = wp_parse_url( $url, PHP_URL_HOST );
    $ip   = filter_var( $host, FILTER_VALIDATE_IP ) ? $host : gethostbyname( $host );
    if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
        return new WP_Error( 'bad_url', 'Rejected' );
    }

    // 3. Do not follow redirects. A 302 to http://169.254.169.254/ is the standard
    //    bypass for any check performed on the first URL only.
    return wp_safe_remote_get( $url, array(
        'timeout'     => 5,
        'redirection' => 0,
        'sslverify'   => true,
        'limit_response_size' => 512 * 1024,
    ) );
}
```

Points that are easy to get wrong:

- **`wp_safe_remote_*` validates redirects; `wp_remote_*` does not.** With
  `reject_unsafe_urls` true, `WP_Http::request()` registers
  `WP_Http::validate_redirects` on the `requests.before_redirect` hook, so every hop runs
  through `wp_http_validate_url()`. With it false, no hop is checked. (`handle_redirects()`
  recurses through `wp_remote_request()` — the *unsafe*-named wrapper — but carries `$args`
  forward, so the safety travels with the args, not the function name.)
- **Setting `'redirection' => 0` is stronger than validating hops**, because it removes the
  DNS-rebinding window entirely for that request.
- **`wp_http_validate_url()` skips the IP check when the host equals the site's own `home`
  host.** Verified in core: `$same_host` short-circuits the entire private-range block.
- **It is IPv4-only.** The literal-IP regex matches dotted quads and `gethostbyname()`
  returns IPv4; `http://[::1]/` and a hostname with only an AAAA record are not covered.
- **TOCTOU.** Validation resolves the name; the transport resolves it again. A DNS record
  with a 0-second TTL that answers `93.184.216.34` once and `169.254.169.254` next is the
  standard bypass. Only an allowlist, or resolving once and connecting to the resolved IP
  with the `Host` header pinned, closes it.

## Real-world case studies

### One line, whole-site protection removed (CVE-2024-13905, 9.1, unauthenticated)

The first executable line of a class file, before any class declaration:

```php
<?php

add_filter( 'http_request_host_is_external', '__return_true' );

class OneStore_Sites_Export {
```
`https://plugins.trac.wordpress.org/browser/onestore-sites/trunk/classess/class-export.php#L3`

**Root cause at that line:** `http_request_host_is_external` is the sole escape hatch from
the private-IP rejection inside `wp_http_validate_url()`. Filtering it to `__return_true`
at file scope means that from the moment this file is loaded, *no* `wp_safe_remote_*` call
anywhere on the site — not core's, not another plugin's — rejects `127.0.0.1`,
`10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`. The plugin does not even need to make
the request itself; it only has to be installed.

An independently-published plugin ships the byte-identical file (CVE-2024-13924, 9.1,
`https://plugins.trac.wordpress.org/browser/starter-templates/trunk/classess/class-export.php#L3`),
which is why SSRF-002 is worth running across a whole site rather than a single plugin:
this is a copy-paste idiom, not an isolated mistake.

### The host was fixed and it was still critical (CVE-2026-78003, 9.8, unauthenticated)

```php
add_action('wp_ajax_nopriv_add_list', array( &$mailgun, 'add_list' ));
```
`https://plugins.trac.wordpress.org/browser/mailgun/tags/2.1.10/mailgun.php#L557`

```php
public function add_list(): void {
    ...
    foreach ( $_POST['addresses'] as $address => $val ) {
        $list_addresses[ sanitize_text_field( $address ) ] = sanitize_text_field( $val );
    }
    ...
            $result[] = $this->api_call( "lists/{$address}/members", [ ... ] );
```
`https://plugins.trac.wordpress.org/browser/mailgun/tags/2.1.10/mailgun.php#L331`

```php
public function api_call( string $uri, array $params = [], string $method = 'POST' ): string {
    ...
    $url     = $this->api_endpoint . $uri;
    $headers = [ 'Authorization' => 'Basic ' . base64_encode( "api:{$apiKey}" ) ];
    ...
    $result = wp_remote_request( $url, $args );
```
`https://plugins.trac.wordpress.org/browser/mailgun/tags/2.1.10/mailgun.php#L259`

**Root cause at those lines:** the tainted value is an **array key**, which is a shape most
sanitisation habits skip entirely — the loop dutifully sanitises `$val` and the key on the
same line, but `sanitize_text_field()` removes tags and control characters and leaves `/`
and `.` untouched. `$address = "../../routes"` produces
`https://api.mailgun.net/v3/lists/../../routes/members`; cURL removes dot segments before
sending, so the request lands on a different, privileged endpoint of the vendor API —
**with the site's own API key in the `Authorization` header**. NVD's summary records the
end state: an attacker can create an inbound email-forwarding route and intercept password
reset mail.

Three lessons. (a) A fixed host does not make a URL safe when the path is attacker-shaped
and the request is authenticated. (b) `$_POST` array *keys* are untrusted input; grep for
`foreach ( $_POST` and `as $key =>`. (c) None of SSRF-001…005 fire on this file — the
taint crosses a function boundary. Only SSRF-006's `wp_remote_request( $url, $args )` puts
it on the worklist, and a human has to do the rest.

### The request chose which option held the URL (CVE-2026-17123, 8.8, contributor+)

```php
add_action('wp_ajax_wpr_form_builder_webhook' , [$this, 'send_webhook']);
add_action('wp_ajax_nopriv_wpr_form_builder_webhook',[$this, 'send_webhook']);
...
$response = wp_remote_post( trim(get_option('wpr_webhook_url_' . $_POST['wpr_form_id'])), $args );
```
`https://plugins.trac.wordpress.org/browser/royal-elementor-addons/tags/1.7.1061/classes/modules/forms/wpr-send-webhook.php#L56`

**Root cause at that line:** the URL is not read from the request — it is read from an
*option whose name is built from the request*. The widget's `render()` persisted the
attacker-controlled `webhook_url` setting into `wpr_webhook_url_{widget_id}` on every
render, including a Contributor previewing their own draft, so the attacker both writes the
value and selects it. The plugin already ships `wpr_is_blocked_remote_host()` and
`wpr_is_private_or_local_ip()` helpers; neither is called on this path.

This is why SSRF-005 exists as a rule in its own right. A reviewer reading
`get_option(...)` sees "trusted, admin-controlled configuration" and moves on. Ask two
questions at every `get_option()` that feeds a sink: *can a low-privileged user write this
option*, and *does the request choose which option is read*.

### A standalone file with PHP's own fetch primitive (CVE-2024-5021, 9.3, unauthenticated)

```php
<?php

$img = $_GET['img'];
if ($img && strrpos($img, ".")) {
    $ext = substr($img, strrpos($img, "."));
    switch ($ext) {
        case ".gif": $ctype = "image/gif";
            ...
        default: exit;
    }

    $img_data = file_get_contents( $img );
```
`https://plugins.trac.wordpress.org/browser/nimble-portfolio/trunk/includes/prettyphoto/download-image.php#L17`

**Root cause at that line:** line 1 is `<?php` — no `wp-load.php`, no
`defined( 'ABSPATH' )` guard, no capability check. The file sits under
`wp-content/plugins/<slug>/includes/prettyphoto/` and is requested directly. The only
"validation" is a suffix test, and a suffix constrains nothing about a host:
`http://169.254.169.254/latest/meta-data/iam/security-credentials/x.jpg` satisfies it, and
so does `http://127.0.0.1:6379/x.png`. The body is then echoed, so it is a fully
interactive read primitive, not a blind one.

Note which rule fires: only SSRF-008, on `$img = $_GET['img'];`. The sink 14 lines down
takes a bare `$img`. **Multi-hop taint inside a 37-line file already defeats
single-statement regexes.**

### One sink, three vulnerability classes (CVE-2023-2249, 8.8, subscriber+)

```php
$data = explode( ',', $image_blob );
if( isset( $data[1] ) ){
    $file_content = base64_decode($data[1]);
} else {
    // This part can be removed, I just leave it for an unknown case
    $file_content = file_get_contents($image_blob);
}
```
`https://plugins.trac.wordpress.org/browser/wpforo/tags/2.1.7/classes/Actions.php#L457`

**Root cause at that line:** `$image_blob` is `$_POST['image_blob']`, expected to be a
`data:image/png;base64,...` URI. When it contains no comma the code falls into a branch the
developer's own comment says is dead, and `file_get_contents()` receives the raw request
value. That single call is SSRF for `http://`, arbitrary file read for
`../../wp-config.php`, and PHAR deserialisation for `phar://` — NVD lists all three. And
the fetched bytes are written to `wp-content/.../covers/profiles_custom_default_cover.jpg`
and the URL stored in an option, so the attacker reads the response from a public URL.

Two audit lessons: **a comment saying a branch is unreachable is not a control**, and a
fetch sink that persists its response to a public path turns blind SSRF into full read.

### The URL never touched a superglobal (CVE-2026-1313, 8.3, contributor+)

```php
add_filter( 'the_content', array( $this, 'mimetype_to_icon' ), 15 );
```
`https://plugins.trac.wordpress.org/browser/mimetypes-link-icons/tags/3.2.20/mime_type_link_images.php#L715`

```php
curl_setopt( $this->curl, CURLOPT_MAXREDIRS, 5 );
...
curl_setopt( $this->curl, CURLOPT_URL, $url );
$header = curl_exec( $this->curl );
```
`https://plugins.trac.wordpress.org/browser/mimetypes-link-icons/tags/3.2.20/mime_type_link_images.php#L1612`

**Root cause at that line:** `mimetype_to_icon()` regex-extracts every link `href` from post
content and calls `get_filesize()` on it so the theme can print "(2.4 MB)" after the link.
The URL therefore originates in **post content**, which any Contributor can write, and
which is also reachable through comments, custom fields and any other filter that runs
`the_content`. `CURLOPT_FOLLOWLOCATION` with `MAXREDIRS 5` is set, so even a URL that
passed a host check would be re-pointed by a 302.

Every one of the nine rules in this class returns zero hits on this file. There is no
superglobal to anchor on. **When enumerating SSRF sources, treat post content, comment
content, user meta, `oEmbed` providers, imported feeds and webhook payloads as
attacker-controlled inputs on the same footing as `$_GET`.**

### What a correct fix looks like (CVE-2023-1895, 9.6, subscriber+)

The vulnerable route accepted an arbitrary URL parameter behind a low-privilege permission
callback and fetched it. The patched code is worth reading as a template:

```php
$get_content_url = isset( $_GET['get_content_url'] ) ? esc_url_raw( $_GET['get_content_url'] ) : false;

if ( ! $this->content_url_is_valid( $get_content_url ) ) {
    return __( 'Please provide a valid URL.', 'getwid' );
}
```

```php
private function content_url_is_valid( $url ) {
    $parsed_url  = wp_parse_url( $url );
    ...
    $valid_hosts = array( 'elements.getwid.getmotopress.com' );
    $valid_path  = '/wp-json/getwid-templates-server/v1/get_content';
    ...
    if ( isset( $parsed_url['host'] ) && in_array( $parsed_url['host'], $valid_hosts ) ) { ... }
    if ( isset( $parsed_url['path'] ) && $valid_path == $parsed_url['path'] ) { ... }
```
`https://plugins.trac.wordpress.org/browser/getwid/trunk/includes/rest-api.php#L344`

**Why this is the right shape:** the fix is not a better sanitiser, it is an **allowlist of
host and path**, plus a raised capability (`current_user_can( 'edit_posts' )` in the
permission callback). Note that `esc_url_raw()` is still there — it was never the control,
and it is not the fix. SSRF-007 still fires on line 219 of the patched file; that is the
expected false positive, and it is why SSRF-007 is `medium`, not `high`.

## Detection guidance

**What the regexes catch reliably**

- `SSRF-001` and `SSRF-004` catch the single-statement cases, which are still the majority
  of published bugs.
- `SSRF-002` and `SSRF-003` catch the two ways a plugin disables core's protection while
  keeping a safe-looking call. These are the highest-value rules here, because the code
  they flag passes every "does it use `wp_safe_remote_get`?" review.
- `SSRF-005` catches option-name injection, the shape a reviewer's eye slides past.

**What the regexes CANNOT catch — read the code**

1. **Multi-hop taint across a function boundary.** CVE-2026-78003 is the canonical case:
   the sink is `wp_remote_request( $url, $args )` in a generic `api_call()` helper, and the
   tainted fragment enters as a caller argument two functions away. Only the low-confidence
   `SSRF-006` worklist puts it in front of a human.
2. **Sources that are not superglobals.** Post/comment content (CVE-2026-1313), custom
   fields, terms, user meta, imported CSV/XML rows, webhook payloads, values written by an
   earlier unauthenticated endpoint, and `$_POST` **array keys** (CVE-2026-78003). Enumerate
   the sinks first, then ask where each argument came from — never the other way round.
3. **Whether an existing host check is correct.** A `parse_url()` host comparison is often
   `strpos( $host, 'vendor.com' ) !== false`, which `vendor.com.evil.tld` and
   `evil.tld/?x=vendor.com` both satisfy. Require exact `in_array( $host, $allow, true )`.
4. **Redirect following.** A host allowlist applied to the first URL is bypassed by a 302
   from an allowlisted host, and by any open redirector on the allowlisted host. Check for
   `'redirection' => 0` / `CURLOPT_FOLLOWLOCATION`, and remember that `wp_remote_*` does
   not validate hops even when the first URL was validated by hand.
5. **DNS rebinding.** Any check that resolves a name and then hands the *name* to the
   transport is racy by construction. This includes `wp_http_validate_url()` itself.
6. **IPv6 and alternate literal encodings.** `http://[::1]/`, `http://[::ffff:127.0.0.1]/`,
   `http://2130706433/` (decimal), `http://0x7f.0x0.0x0.0x1/` (hex), `http://127.1/`,
   and `http://localtest.me/` (a public name resolving to 127.0.0.1). Core's IPv4-only
   dotted-quad regex plus `gethostbyname()` misses several of these.
7. **The metadata range on older cores.** Verified against core source: through WordPress
   **7.0**, `wp_http_validate_url()` rejected only `127/8`, `10/8`, `0/8`, `172.16/12` and
   `192.168/16`. `169.254.169.254` was **not** in the list; the expanded blocklist
   (link-local, CGNAT, TEST-NET, multicast, reserved) first appears in **7.1**. On any site
   below 7.1, `wp_safe_remote_get( 'http://169.254.169.254/...' )` succeeds. Do not treat
   "uses the safe wrapper" as sufficient without knowing the core version floor.
8. **Same-host short-circuit.** `wp_http_validate_url()` skips the whole IP-range block when
   the URL host equals the site's `home` host. On a shared hostname, or where the site host
   resolves internally, that is a hole.
9. **Non-`WP_Http` transports.** Guzzle or Requests vendored inside the plugin,
   `WP_REST_Request` dispatched internally, `wp_oembed_get()`, `wp_safe_remote_*` inside a
   library the plugin bundles, `SimplePie`, `getID3`, and image libraries that accept URLs.
   Grep the `vendor/` directory too.
10. **Blind ≠ harmless.** Absence of a response body in the handler does not close the bug:
    timing differences enumerate internal hosts and ports, and POST-style SSRF can trigger
    state changes on internal services that have no authentication.

## Audit checklist

- [ ] Run `SSRF-002` and `SSRF-003` across the **whole site**, not just the plugin under
      review — both are global kill switches and one plugin can disarm another.
- [ ] Grep for `add_filter( 'http_request_args'` and read every callback: does it set
      `reject_unsafe_urls`, `sslverify`, or rewrite the URL?
- [ ] List every outbound sink: `wp_remote_*`, `wp_safe_remote_*`, `curl_*`,
      `file_get_contents`, `fopen`, `get_headers`, `simplexml_load_file`, `getimagesize`,
      `wp_oembed_get`, `WP_Http`, and anything under `vendor/`.
- [ ] For each sink, trace the first argument to its origin. Include post content, comment
      content, meta, options, transients, imported rows and `$_POST` **array keys** as
      possible origins, not just superglobals.
- [ ] For every `get_option()` / `get_post_meta()` feeding a URL: can a low-privileged user
      write that value, and does the request choose the key (`SSRF-005`)?
- [ ] Replace every `wp_remote_*` reached by request data with `wp_safe_remote_*`, and
      verify the change is not undone by `reject_unsafe_urls => false` in the args.
- [ ] For each host check, confirm it is an exact `in_array( $host, $allow, true )` on
      `wp_parse_url( $url, PHP_URL_HOST )` — not `strpos`, not a regex on the whole URL.
- [ ] Check the redirect policy: `'redirection' => 0` where possible; otherwise confirm the
      call is `wp_safe_remote_*` so `validate_redirects` runs on every hop.
- [ ] Establish the site's minimum core version. Below 7.1, add an explicit
      `169.254.0.0/16` (and IPv6 loopback/ULA) deny on top of `wp_http_validate_url()`.
- [ ] Flag every `'sslverify' => false` and `CURLOPT_SSL_VERIFYPEER, false` (`SSRF-009`),
      especially on requests that carry credentials.
- [ ] Confirm the handler enforces `current_user_can()` and a nonce before any fetch, and
      that the route is not registered with `wp_ajax_nopriv_` or
      `permission_callback => '__return_true'`.
- [ ] Check whether the response body, or any file written from it, is reachable by the
      attacker — that is what separates blind SSRF from an internal-network read primitive.
