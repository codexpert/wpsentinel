---
class_id: WP-REDIRECT
title: Open Redirect via unvalidated redirect target
cwe: [CWE-601]
owasp: A01:2021-Broken Access Control
severity_typical: medium
auth_required_typical: unauthenticated
prevalence_rank: 23
detection:
  - id: RED-001
    description: wp_redirect() with a request superglobal on the same statement
    regex: 'wp_redirect\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
    confidence: high
    false_positive_notes: >-
      Deliberately does NOT match wp_safe_redirect(), which routes through
      wp_validate_redirect() and is correct by default. A hit is a finding unless the
      superglobal only contributes a query-string fragment appended to a hard-coded local
      base on the same line. $_SERVER is included on purpose: HTTP_REFERER is the classic
      "send them back where they came from" source and is fully attacker-controlled, and
      HTTP_HOST is attacker-controlled on most default vhost configurations.
  - id: RED-002
    description: header() built from a request superglobal — open redirect and response splitting
    regex: '\bheader\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
    confidence: high
    false_positive_notes: >-
      Broader than redirects on purpose. wp_redirect() runs wp_sanitize_redirect(), which
      strips %0d/%0a and everything outside a safe character set, so it is CRLF-safe; a raw
      header() call has neither that protection nor host validation. Hits on
      Content-Disposition/Content-Type built from request data are also findings (header
      injection, content-type confusion) — they just belong to a different class. Read
      which header is being written.
  - id: RED-003
    description: URL escaper or decoder used as if it were a redirect validator
    regex: 'wp_redirect\s*\([^;]*\b(esc_url|esc_url_raw|sanitize_url|urldecode|rawurldecode|filter_var|base64_decode)\s*\('
    confidence: high
    false_positive_notes: >-
      esc_url()/esc_url_raw()/sanitize_url() normalise a URL and drop disallowed schemes.
      None of them restricts the destination host, which is the entire point of an open
      redirect. urldecode() is actively harmful here — it re-introduces characters an
      upstream filter already removed, and enables double-encoding bypasses. This regex
      fires on code that looks defended, which is why it is high confidence: in three of
      the case studies below, the sanitiser is the only thing between $_GET and the
      Location header.
  - id: RED-004
    description: Location header emitted directly, bypassing wp_validate_redirect entirely
    regex: '\bheader\s*\(\s*[''"]\s*[Ll]ocation\s*:'
    confidence: medium
    false_positive_notes: >-
      Matches constant destinations too (header( 'Location: ' . home_url( '/done' ) )),
      which are safe. The rule is worth running because every raw Location header is
      outside WordPress's redirect pipeline: no allowed_redirect_hosts check, no
      wp_sanitize_redirect(), no wp_redirect filter for other plugins to observe. Triage by
      asking whether any part of the string is dynamic, and prefer converting the call to
      wp_safe_redirect() even when the current value is constant.
  - id: RED-005
    description: allowed_redirect_hosts filtered — the allowlist wp_safe_redirect() depends on
    regex: 'add_filter\s*\(\s*[''"]allowed_redirect_hosts[''"]'
    confidence: medium
    false_positive_notes: >-
      Legitimate and common: payment gateways, SSO providers and OAuth flows must add their
      own host. It is a finding when the callback appends a request-derived value, returns
      a wildcard, or adds a host the attacker can control content on (a user-content CDN, a
      shortener). Read the callback body — this filter is global, so widening it here
      weakens wp_safe_redirect() for core and every other plugin on the site.
  - id: RED-006
    description: Redirect-shaped request parameter — surface mapping
    regex: '\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[''"](redirect|redirect_to|redirect_url|redirect_uri|redirectto|redirect_to_on_logout|return|returnurl|return_url|return_to|next|goto|go|dest|destination|continue|forward|target|requested_page|back|backurl|referer|referrer|out|to|url)[''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      Deliberately broad; most hits are benign and some are correct code (a
      wp_validate_redirect( $_POST['redirect_to'], admin_url() ) call matches this rule and
      is the recommended pattern). Its job is to enumerate every parameter that could
      become a Location header so each can be traced. It is the only rule that fires on
      CVE-2026-1277, where the assignment and the redirect are on different lines.
  - id: RED-007
    description: wp_redirect() of a bare variable — provenance must be traced
    regex: 'wp_redirect\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*(->[A-Za-z0-9_]+\s*)?[,)]'
    confidence: low
    false_positive_notes: >-
      High volume; most plugins redirect to internally-built admin URLs. Excludes
      wp_safe_redirect() to keep the list workable. This is the worklist rule for
      stored/indirect open redirects, where the destination arrives from the database, from
      an option, or from a REST request object rather than from a superglobal — the shape
      of CVE-2024-8761 and CVE-2025-6238, neither of which any superglobal-anchored rule
      can see.
  - id: RED-008
    description: Weak "is this URL local" test — leading-slash or http-prefix check
    regex: '(substr\s*\(\s*\$[A-Za-z0-9_]+\s*,\s*0\s*,\s*1\s*\)\s*===?\s*[''"]/[''"]|strpos\s*\(\s*\$[A-Za-z0-9_]+\s*,\s*[''"]https?[''"]\s*\)\s*===?\s*0)'
    confidence: medium
    false_positive_notes: >-
      A leading "/" test is bypassed by "//evil.tld", which browsers treat as
      protocol-relative and follow off-site; core handles this explicitly by rewriting a
      leading "//" to "http://" before parsing. A `strpos( $u, 'http' ) === 0` test accepts
      every absolute URL on the internet and is not a check at all. Occasionally the
      surrounding code also rejects "//" on an adjacent line, which makes the hit benign —
      read both lines. Correct form is wp_validate_redirect(), or a strict
      "starts with / and does not start with //" pair.
  - id: RED-009
    description: Redirect-decision filters whose callbacks commonly return request data
    regex: 'add_filter\s*\(\s*[''"][a-z_]*(login_redirect|logout_redirect|registration_redirect|redirect_after|_redirect_url)[''"]'
    confidence: low
    false_positive_notes: >-
      Registering these filters is entirely normal. The rule exists to build a worklist:
      the value a login_redirect / logout_redirect callback returns is handed to
      wp_safe_redirect() by core (safe) or to wp_redirect() by whatever plugin owns the
      form (not safe), and callbacks routinely do `return $_REQUEST['redirect_to'];`.
      Read every callback body; the finding is in the callback, not in the registration.
fix_apis:
  - wp_safe_redirect()
  - wp_validate_redirect()
  - wp_sanitize_redirect()
  - allowed_redirect_hosts (filter, narrowly)
  - wp_parse_url()
  - home_url()
  - admin_url()
  - check_admin_referer()
examples:
  - cve: CVE-2025-14451
    year: 2025
    severity: 4.7
    auth: unauthenticated
    summary: A front-end click tracker read the destination from a query parameter and passed it straight to wp_redirect() with no validation of any kind.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-14451
    code_ref: https://plugins.trac.wordpress.org/browser/solutions-ad-manager/tags/1.0.0/public/class-solutions-ad-manager-public.php#L30
    root_cause: wp_redirect() used where wp_safe_redirect() was required; the else-branch two lines below builds a safe local URL, so the safe idiom was known and simply not applied to the attacker-supplied path.
  - cve: CVE-2026-1296
    year: 2026
    severity: 6.1
    auth: unauthenticated
    summary: Handlers hooked to the authenticate and wp_login_failed hooks took a hidden form field as the login page URL, ran it through esc_url(), and redirected to it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1296
    code_ref: https://plugins.trac.wordpress.org/browser/frontend-post-submission-manager-lite/tags/1.2.6/includes/classes/class-fpsml-shortcode.php#L108
    root_cause: esc_url() is an output escaper for HTML attributes, not a destination check; it leaves any http/https host intact, and the redirect fires on a pre-authentication hook so no login is needed to reach it.
  - cve: CVE-2026-6203
    year: 2026
    severity: 6.1
    auth: unauthenticated
    summary: A logout handler redirected to a GET parameter passed through esc_url_raw(), five lines above an identical redirect that correctly used wp_safe_redirect().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6203
    code_ref: https://plugins.trac.wordpress.org/browser/user-registration/tags/5.1.4/includes/functions-ur-template.php#L39
    root_cause: The wrong function on one branch. The same handler's fall-through path uses wp_safe_redirect(), so the presence of the safe API in a file proves nothing about the branch an attacker takes.
  - cve: CVE-2026-1277
    year: 2026
    severity: 4.7
    auth: unauthenticated
    summary: A notice-dismissal handler had four redirect branches; three used wp_safe_redirect() with internally-built URLs and the fourth used wp_redirect() with an esc_url_raw()'d request parameter.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1277
    code_ref: https://plugins.trac.wordpress.org/browser/url-shortify/tags/1.11.4/lite/includes/Promo.php#L64
    root_cause: A request-controlled branch bypasses the validated redirect used by every other branch; the sanitiser call on the preceding line reads as the validation step and is not one.
  - cve: CVE-2025-6238
    year: 2025
    severity: 8.0
    auth: subscriber+
    summary: An OAuth authorization endpoint accepted redirect_uri from the request with no client registration or allowlist and redirected the authenticated user to it with the authorization code attached.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-6238
    code_ref: https://plugins.trac.wordpress.org/browser/ai-engine/tags/2.8.4/labs/oauth.php#L118
    root_cause: redirect_uri was never validated against a registered client URI, so the open redirect also exfiltrated the authorization code — this is credential theft, not just a phishing pivot.
  - cve: CVE-2024-8761
    year: 2024
    severity: 6.1
    auth: unauthenticated
    summary: An unauthenticated AJAX action stored an arbitrary URL in a shortlink table under an attacker-chosen hash, and a template_redirect handler later redirected to whatever that row contained.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-8761
    code_ref: https://plugins.trac.wordpress.org/browser/share-this-image/tags/2.03/includes/class-sti-shortlink.php#L221
    root_cause: >-
      A stored open redirect. The write path (wp_ajax_nopriv_) validated neither the URL
      nor the caller, and the read path trusted the database as if it were trusted
      configuration.
  - cve: CVE-2025-3433
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: A template_redirect click handler verified a nonce before writing its click log and then performed the redirect outside that check, on a urldecode()'d query parameter.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-3433
    code_ref: https://plugins.trac.wordpress.org/browser/advanced-advertising-system/trunk/includes/class-log.php#L297
    root_cause: The nonce guarded only the logging statement, not the redirect below it; and the nonce action string itself came from the request, so the check was decorative either way.
---

## What it is

The plugin sends a `Location:` header to a destination the request chose. The attacker
sends a victim a link on the real, trusted domain — with a valid TLS certificate, a
familiar brand and, often, an existing session — and the browser lands on the attacker's
page. That is the phishing use, and it is why these are usually scored around 6.1: user
interaction is required and the site itself is not directly compromised.

The severity floor is misleading, though. An open redirect is a *transport*: it is the
standard bypass for SSRF host allowlists (allowlist the host, get 302'd off it), for OAuth
`redirect_uri` checks, for CSP `form-action` and for password-reset "return here" flows.
When the redirect happens *after* an authorization step, whatever that step produced —
an OAuth `code`, a one-time token in the URL, a `Referer` header carrying a session
identifier — is handed to the attacker's server. CVE-2025-6238 is scored 8.0 for exactly
that reason.

## Why it happens in WordPress

- **`wp_redirect()` and `wp_safe_redirect()` differ by one word.** `wp_redirect()` performs
  no destination validation at all; it runs `wp_sanitize_redirect()` (which strips `%0d`
  and `%0a`, so it *is* CRLF-safe) and emits the header. `wp_safe_redirect()` is a
  three-line wrapper that calls `wp_validate_redirect( $location, $fallback_url )` first
  and then delegates to `wp_redirect()`. Same signature, same return type.
- **`esc_url()` / `esc_url_raw()` look like the validator.** They are output escapers. They
  normalise, they drop `javascript:` and `data:`, and they leave `https://evil.tld/` exactly
  as it was. This is the single most common false defence in the class and it appears in
  three of the seven cases below.
- **`redirect_to` is a first-class WordPress convention.** `wp-login.php` has taken a
  `redirect_to` parameter since forever, so every login/logout/registration plugin copies
  the interface — and core validates it while the copies do not.
- **The pre-auth hooks are unauthenticated by construction.** `authenticate`,
  `wp_login_failed`, `login_form`, `login_init` and `template_redirect` all run before, or
  regardless of, a successful login. A redirect on one of those hooks needs no account.
- **Neither function exits.** `wp_redirect()` and `wp_safe_redirect()` return a bool. A
  missing `exit;` means the header is queued and the rest of the handler still runs —
  including the "protected" code the redirect was supposed to prevent reaching. Core's own
  docblock spells this out.
- **`allowed_redirect_hosts` is global.** Any plugin can widen the allowlist that
  `wp_safe_redirect()` depends on, for the whole site.
- **`wp_redirect` is itself a filter.** `apply_filters( 'wp_redirect', $location, $status )`
  runs inside `wp_redirect()`, so a third-party callback can rewrite an otherwise-validated
  destination *after* `wp_validate_redirect()` has approved it.

## Vulnerable pattern

```php
// Hooked to template_redirect — runs for anonymous visitors on every front-end request.
add_action( 'template_redirect', 'example_click_tracker' );

function example_click_tracker() {
    if ( ! isset( $_GET['example_click'] ) ) {
        return;
    }

    example_log_click( $_GET['data'] );

    if ( ! empty( $_GET['redir'] ) ) {
        // No host check. urldecode() actively undoes any upstream filtering.
        wp_redirect( urldecode( $_GET['redir'] ) );
        exit;
    }
}
```

The version that survives code review, because it calls a sanitiser:

```php
add_filter( 'authenticate', 'example_verify', 1, 3 );   // pre-authentication hook

function example_verify( $user, $username, $password ) {
    if ( isset( $_POST['requested_page'] ) ) {
        // esc_url() escapes for HTML output. It does not constrain the host.
        $login_page = esc_url( $_POST['requested_page'] );
        if ( '' === $username || '' === $password ) {
            wp_redirect( $login_page . '?login=empty' );
            exit;
        }
    }
    return $user;
}
```

`requested_page=https://evil.tld` produces `Location: https://evil.tld?login=empty` — from
the real domain, on a failed login, which is precisely when a user expects to be bounced
somewhere and to re-enter their password.

And the two shapes no `$_GET` grep will find:

```php
// Stored: an unauthenticated writer, a trusting reader.
add_action( 'wp_ajax_nopriv_example_shorten', 'example_shorten' );
function example_shorten() {
    $hash = sanitize_key( $_POST['hash'] );
    $link = $_POST['link'];                       // never validated
    example_insert( $hash, $link );
    wp_send_json_success( '1' );
}
add_action( 'template_redirect', function () {
    if ( $link = example_lookup( $_GET['s'] ) ) { // the DB is not a trust boundary
        wp_redirect( $link, 301 );
        exit;
    }
}, 1 );

// Indirect: the destination arrives on a REST request object, not a superglobal.
public function handle_authorize( $request ) {
    $redirect_uri = $request->get_param( 'redirect_uri' );   // no client registry
    ...
    $redirect_url = add_query_arg( array( 'code' => $code, 'state' => $state ), $redirect_uri );
    wp_redirect( $redirect_url );
    exit;
}
```

## Secure pattern

```php
/**
 * Shape 1 — the default. wp_safe_redirect() validates against allowed_redirect_hosts
 * (which contains only the site's own host unless a plugin widened it) and falls back
 * to admin_url() when the destination is rejected.
 */
function example_after_save() {
    if ( ! current_user_can( 'edit_posts' ) ) { wp_die( 'forbidden', 403 ); }
    check_admin_referer( 'example_save' );

    // wp_validate_redirect() returns the fallback, not false, when the host is not allowed.
    $target = isset( $_POST['redirect_to'] )
        ? wp_validate_redirect( wp_unslash( $_POST['redirect_to'] ), admin_url( 'admin.php?page=example' ) )
        : admin_url( 'admin.php?page=example' );

    wp_safe_redirect( $target );
    exit;                       // REQUIRED — neither function terminates the request.
}
```

```php
/**
 * Shape 2 — ALLOWLIST MAP. The request selects a key; it never contributes a URL.
 * Use this wherever the set of destinations is finite, which is most of the time.
 */
function example_after_login( $redirect_to, $requested, $user ) {
    $destinations = array(
        'account'   => '/my-account/',
        'downloads' => '/my-account/downloads/',
        'courses'   => '/courses/',
    );

    $key = isset( $_REQUEST['dest'] ) ? sanitize_key( wp_unslash( $_REQUEST['dest'] ) ) : '';

    return isset( $destinations[ $key ] )
        ? home_url( $destinations[ $key ] )
        : home_url( '/' );
}
add_filter( 'login_redirect', 'example_after_login', 10, 3 );
```

```php
/**
 * Shape 3 — when a genuinely external destination is required (a payment gateway,
 * an SSO provider), allowlist the exact host and keep the filter as narrow as possible.
 */
add_filter( 'allowed_redirect_hosts', function ( $hosts ) {
    // Exact hosts only. Never a wildcard, never a request-derived value, never a
    // host whose content other people can control.
    $hosts[] = 'checkout.gateway.example';
    return $hosts;
} );
```

Details that are easy to get wrong:

- **`exit;` after every redirect.** `wp_safe_redirect( $url );` on its own is a bug even
  when `$url` is perfect.
- **`wp_validate_redirect()` returns the fallback string, not `false`.** Code written as
  `if ( ! wp_validate_redirect( $u ) )` never fires when a fallback was supplied.
- **A leading-slash test is not a local-URL test.** Browsers follow `//evil.tld` as
  protocol-relative. Core handles this by rewriting a leading `//` to `http://` *before*
  parsing, so `wp_validate_redirect()` catches it; a hand-rolled `substr( $u, 0, 1 ) === '/'`
  does not.
- **Validate, then use the validated value.** Validating `$_GET['x']` and then redirecting
  to `$_GET['x']` again re-reads the raw value.
- **Do not `urldecode()` before validating.** It reverses whatever the layer above removed.

## Real-world case studies

### The canonical shape (CVE-2025-14451, 4.7, unauthenticated)

```php
public function solutions_ad_manager_redirect(){
    if( isset($_GET['sam-redirect-to']) && isset($_GET['sam-post-id']) ){
        //add to clicks
        $clicks = get_post_meta($_GET['sam-post-id'], 'solutions_ad_clicks', true);
        $clicks++;
        update_post_meta($_GET['sam-post-id'], 'solutions_ad_clicks', $clicks);
        //redirect
        if( !empty($_GET['sam-redirect-to']) ){
            wp_redirect( $_GET['sam-redirect-to'], 302 );
            exit;
        }else{
            wp_redirect( esc_url("https://" . $_SERVER['HTTP_HOST']  . strtok($_SERVER['REQUEST_URI'],'?') ) );
            exit;
        }
    }
}
```
`https://plugins.trac.wordpress.org/browser/solutions-ad-manager/tags/1.0.0/public/class-solutions-ad-manager-public.php#L30`

**Root cause at that line:** `wp_redirect()` on a raw query parameter. Two things worth
noticing beyond the obvious. First, the `else` branch builds its destination from
`$_SERVER['HTTP_HOST']` — also attacker-controlled on a default vhost — so *both* branches
are request-influenced; RED-001 flags both, and this is exactly why `$_SERVER` is in the
character class. Second, the handler updates post meta on an arbitrary post ID with no
capability check and no nonce, which is a separate finding: **click-tracking endpoints are
reliably worth a full read**, because they are written to be reachable by anonymous users
and are rarely reviewed.

### The sanitiser that is not a validator (CVE-2026-1296, 6.1, unauthenticated)

```php
add_action('wp_login_failed', array($this, 'login_failed'));
add_filter('authenticate', array($this, 'verify_username_password'), 1, 3);
```

```php
function verify_username_password($user, $username, $password) {
    if (isset($_POST['requested_page'])) {
        $login_page = esc_url($_POST['requested_page']);
        if ($username == "" || $password == "") {
            wp_redirect($login_page . "?login=empty");
            exit;
```
`https://plugins.trac.wordpress.org/browser/frontend-post-submission-manager-lite/tags/1.2.6/includes/classes/class-fpsml-shortcode.php#L108`

**Root cause at that line:** `esc_url()` is `esc_url_raw()`'s HTML-escaping sibling. It
percent-encodes, it strips protocols outside the kses allowlist, and it returns
`https://evil.tld` unchanged because that is a perfectly valid URL. The destination host
is never compared to anything.

The hook choice is what makes it unauthenticated: `authenticate` (priority 1) and
`wp_login_failed` both run for anonymous POSTs to `wp-login.php`, and the parameter arrives
in a hidden field the plugin itself injects via `login_form`. So the attacker's payload
travels in a form the plugin taught the browser to submit. **When triaging a redirect,
resolve the hook before the code: a redirect on `authenticate` or `wp_login_failed` needs
no account, and a redirect on `admin_init` needs only a subscriber.**

### The right function five lines away (CVE-2026-6203, 6.1, unauthenticated)

```php
// Check if external url is present in URL.
if ( isset( $_GET['redirect_to_on_logout'] ) ) {
    wp_logout();
    wp_redirect( esc_url_raw( wp_unslash( $_GET['redirect_to_on_logout'] ) ) );
    exit;
}
$redirect_url = apply_filters( 'user_registration_redirect_after_logout', $redirect_url );
wp_logout();
wp_safe_redirect( ur_get_page_permalink( $redirect_url ) );
exit;
```
`https://plugins.trac.wordpress.org/browser/user-registration/tags/5.1.4/includes/functions-ur-template.php#L39`

**Root cause at that line:** the correct API is used on line 44 and the incorrect one on
line 39, in the same function, for the same purpose. The comment above it — "Check if
external url is present in URL" — shows the author knew the value could be external and
treated that as a feature.

There is a second defect in the same block worth recording, because it recurs. The guard
reads:

```php
if ( isset( $wp->query_vars['user-logout'] )
    || ( isset( $wp->query_vars['name'] ) && 'user-logout' === $wp->query_vars['name'] )
        && ! empty( $_REQUEST['_wpnonce'] )
       && wp_verify_nonce( $_REQUEST['_wpnonce'], 'user-logout' ) ) {
```

PHP binds `&&` tighter than `||`, so this parses as `A || (B && C && D)`. When `A` is
true — the ordinary logout URL — the nonce is never checked. **Indentation is not
precedence; re-parse every mixed `||`/`&&` condition that contains a security check.**

### One unsafe branch among three safe ones (CVE-2026-1277, 4.7, unauthenticated)

```php
if ( isset( $_GET['redirect_to'] ) && ! empty( $_GET['redirect_to'] ) ) {
    $redirect_to = esc_url_raw( $_GET['redirect_to'] );
    wp_redirect( $redirect_to );
} elseif ( 'lifetime' === sanitize_text_field( Helper::get_data( $_GET, 'billing_cycle', '' ) ) ) {
    wp_safe_redirect( US()->get_pricing_url( 'lifetime' ) );
} elseif ( (boolean) Helper::get_data( $_GET, 'landing', false ) ) {
    wp_safe_redirect( US()->get_landing_page_url( $pricing ) );
} else {
    wp_safe_redirect( US()->get_pricing_url() );
}
exit();
```
`https://plugins.trac.wordpress.org/browser/url-shortify/tags/1.11.4/lite/includes/Promo.php#L64`

**Root cause at that line:** three of four branches use `wp_safe_redirect()`. The one the
attacker controls uses `wp_redirect()`. A file-level check for "does this plugin know about
`wp_safe_redirect`?" answers yes and is useless.

Note the detection consequence: `RED-001` does **not** fire here, because the assignment
and the redirect are on separate lines. `RED-006` fires on line 63/64 and `RED-007` on line
65, and only a human joining them produces the finding. This two-line split is the normal
shape of real code.

### Open redirect as credential theft (CVE-2025-6238, 8.0, subscriber+)

```php
$redirect_uri = $request->get_param( 'redirect_uri' );
...
if ( empty( $client_id ) || empty( $redirect_uri ) || empty( $code_challenge ) ) {
    return new WP_Error( 'invalid_request', 'Missing required parameters' );
}
...
$code = $this->generate_authorization_code( get_current_user_id(), $client_id, $redirect_uri, $code_challenge, $scope ?: 'mcp' );

$redirect_params = [ 'code' => $code, 'state' => $state ];
$redirect_url = add_query_arg( $redirect_params, $redirect_uri );
wp_redirect( $redirect_url );
exit;
```
`https://plugins.trac.wordpress.org/browser/ai-engine/tags/2.8.4/labs/oauth.php#L118`

**Root cause at that line:** the OAuth spec requires `redirect_uri` to be matched against a
URI registered for `client_id`. There is no client registry here at all — `client_id` is
accepted as a string and never looked up — so `redirect_uri` is whatever the request says,
and the authorization `code` is appended to it. The victim only has to be logged in and
click the link; the attacker receives the code and exchanges it for an access token. The
same defect appears a second time at line 352, where the params are replayed from a
transient after the login form.

Two lessons. **PKCE does not save you** — `code_challenge` is also attacker-supplied here,
so the attacker holds the verifier. And **the destination did not come from a
superglobal**: it arrived on a `WP_REST_Request` object, so `RED-001` cannot see it and
only `RED-007` puts the line on the worklist.

### Stored open redirect (CVE-2024-8761, 6.1, unauthenticated)

```php
add_action( 'wp_ajax_sti_shortLinks', array( $this, 'ajax_add_link' ) );
add_action( 'wp_ajax_nopriv_sti_shortLinks', array( $this, 'ajax_add_link' ) );
...
public function ajax_add_link() {
    ...
    $hash = sanitize_key( $_POST['hash'] );
    $link = $_POST['link'];
    $this->insert_into_links_table( $hash, $link );
```

```php
} elseif ( isset( $_GET['sti'] ) ) {
    $hash = $_GET['sti'];
...
if ( $link ) {
    wp_redirect( $link, 301 );
```
`https://plugins.trac.wordpress.org/browser/share-this-image/tags/2.03/includes/class-sti-shortlink.php#L221`

**Root cause at that line:** the write path is `wp_ajax_nopriv_`, has no nonce and no
capability check, and stores `$_POST['link']` verbatim. The read path treats the table as
trusted configuration. The attacker picks the hash too, so the resulting link is a stable,
shareable URL on the victim's domain — and it is a **301**, so browsers cache it.

Detection consequence: at the redirect line there is no superglobal, no sanitiser, nothing
suspicious — `wp_redirect( $link, 301 )` is what correct code looks like. Only `RED-007`
fires. **For every `wp_redirect()` of a stored value, find the write path and check who can
reach it.**

### The nonce that guarded the wrong statement (CVE-2025-3433, 6.1, unauthenticated)

```php
function aas_ads_click(){
if(!isset($_GET['ads_click']))
return;
if(wp_verify_nonce($_GET['nonce'],$_GET['data']))
new AAS_Log($_GET['data'],'c');
if(!empty($_GET['redir'])){
	wp_redirect(urldecode($_GET['redir']));
	exit;
	}
}
add_action('template_redirect','aas_ads_click');
```
`https://plugins.trac.wordpress.org/browser/advanced-advertising-system/trunk/includes/class-log.php#L297`

**Root cause at that line:** the `wp_verify_nonce()` call has no braces, so it guards
exactly one statement — the log write. The redirect below it executes unconditionally. And
the nonce action is `$_GET['data']`, supplied by the same request, so even the statement it
does guard is not meaningfully protected.

`urldecode()` makes it worse rather than better: it re-decodes a value the transport
already decoded once, so a payload that survived any upstream filter as `%252f%252fevil.tld`
becomes `//evil.tld` at the sink. This is why RED-003 lists `urldecode`/`rawurldecode`
alongside the escapers.

## Detection guidance

**What the regexes catch reliably**

- `RED-001` and `RED-002` catch the direct one-statement cases and handle concatenation and
  interpolation.
- `RED-003` catches the escaper-as-validator idiom, which is the highest-value single rule
  here because it fires on code that already looks defended.
- `RED-008` catches the two weak local-URL tests, both of which are bypassable.

**What the regexes CANNOT catch — read the code**

1. **Two-line taint.** `$u = esc_url_raw( $_GET['redirect_to'] );` then `wp_redirect( $u );`
   (CVE-2026-1277). This is the ordinary shape of real code. `RED-006` plus `RED-007`
   produce the pair; a human joins them.
2. **Sources that are not superglobals.** `WP_REST_Request::get_param()`
   (CVE-2025-6238), `$request->get_json_params()`, database rows (CVE-2024-8761), options,
   user meta, `wp_get_referer()`, and values a *different* unauthenticated endpoint wrote
   earlier.
3. **A missing `exit;`.** Line-oriented regexes cannot see that the next statement is not
   `exit`. Check every redirect call site by hand; a redirect without `exit` means the code
   below it — including deletes, updates and output — still runs.
4. **Whether an `allowed_redirect_hosts` callback is safe.** `RED-005` finds the
   registration; only reading the callback tells you whether it appends a constant host, a
   request value, or a wildcard.
5. **The `wp_redirect` filter.** `apply_filters( 'wp_redirect', $location, $status )` runs
   *inside* `wp_redirect()`, after `wp_validate_redirect()` has already approved the value
   in the `wp_safe_redirect()` path. A callback on that filter can replace an approved
   destination. Grep `add_filter( 'wp_redirect'` separately.
6. **Non-`Location` redirect sinks.** `<meta http-equiv="refresh" content="0;url=...">`
   emitted from PHP, `window.location = '<?php echo $url; ?>'`,
   `wp_localize_script()` shipping a destination to JS that then assigns it, and
   `wp_die()`'s `$args['link_url']`. None of these go through `wp_redirect()` and none are
   matched here.
7. **Whether an existing host check is correct.** `strpos( $url, home_url() ) === 0` looks
   like a prefix test and is satisfied by `https://example.com.evil.tld/`; `preg_match`
   against an unanchored host pattern has the same problem. Require exact
   `in_array( wp_parse_url( $url, PHP_URL_HOST ), $allow, true )` or
   `wp_validate_redirect()`.
8. **Encoding tricks.** `\/\/evil.tld`, `/\evil.tld`, `https:/\evil.tld`,
   `//evil.tld\@example.com`, and `%09`/`%0d` inside the host. `wp_validate_redirect()`
   handles the ones core knows about; a hand-rolled check almost certainly does not.
9. **Whether an open redirect is "only" phishing.** Check what the redirect carries: an
   OAuth `code`, a reset token in the query string, or a `Referer` that leaks one. If it
   does, the finding is credential disclosure and should be scored accordingly.

## Audit checklist

- [ ] Run `RED-001`, `RED-002` and `RED-003`; treat every hit as a finding until the
      destination is proven host-constrained.
- [ ] Grep for every `wp_redirect(` in the codebase (`RED-007`) and, for each, answer: where
      did the argument come from, and is there an `exit;` on the next line?
- [ ] For each redirect, resolve the **hook**. `authenticate`, `wp_login_failed`,
      `login_init`, `template_redirect`, `init` and `wp_ajax_nopriv_*` are all
      unauthenticated.
- [ ] Run `RED-005` and read every `allowed_redirect_hosts` callback body.
- [ ] Grep `add_filter( 'wp_redirect'` — a callback there overrides validation performed by
      `wp_safe_redirect()`.
- [ ] Run `RED-009` and read every `login_redirect` / `logout_redirect` /
      `registration_redirect` callback; `return $_REQUEST['redirect_to'];` is the bug.
- [ ] For every `wp_redirect()` of a stored value, find the write path for that value and
      check its authorization.
- [ ] Grep for `http-equiv` refresh, `location.href =`, `location.replace(` and
      `wp_localize_script` entries whose value is a URL — redirects that never touch
      `wp_redirect()`.
- [ ] Verify each hand-rolled local-URL check against `//evil.tld`, `/\evil.tld` and
      `https://example.com.evil.tld/`.
- [ ] For any OAuth/SSO flow, confirm `redirect_uri` is compared against a URI registered
      for the presented `client_id`, not merely non-empty.
- [ ] Where the destination set is finite, replace URL passing with an allowlist map keyed
      by `sanitize_key()`.
