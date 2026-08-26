---
class_id: WP-SECRETS
title: Hardcoded credentials, exposed secrets and weak randomness
cwe: [CWE-798, CWE-338, CWE-330, CWE-321, CWE-259, CWE-522]
owasp: A02:2021-Cryptographic Failures
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 19
detection:
  - id: SEC-001
    description: Provider-recognisable credential literal in source (AWS, Stripe, Google, Slack, GitHub, SendGrid, Mailgun, PEM private key)
    regex: '(AKIA[0-9A-Z]{16}|\b(sk|rk)_live_[0-9a-zA-Z]{16,}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|\bgh[pousr]_[A-Za-z0-9]{36}|\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}|\bkey-[0-9a-f]{32}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
    confidence: high
    false_positive_notes: >-
      Anchored on issuer-defined prefixes and lengths, so it cannot fire on prose or on a
      field label. The realistic false positives are (a) provider documentation examples
      pasted into a comment — AKIAIOSFODNN7EXAMPLE is AWS's own published sample — and
      (b) revoked keys left in a fixture. Both still warrant a look: a key in a public
      plugin ZIP is compromised whether or not it currently works. Note the pattern
      requires PRIVATE KEY, not PUBLIC KEY; a PEM public key is not a finding. Zero hits
      across 78k lines of real plugin code in testing.
  - id: SEC-002
    description: Security-relevant value generated from a non-cryptographic PRNG
    regex: '(?i)\$[A-Za-z0-9_]*(token|secret|otp|salt|passwd|password|apikey|api_key|activation|verif|reset|auth|key|code|hash|nonce|pin)[A-Za-z0-9_]*\s*=\s*[^;=]*\b(rand|mt_rand|uniqid|str_shuffle|lcg_value)\s*\('
    confidence: high
    false_positive_notes: >-
      rand()/mt_rand() are Mersenne Twister, seeded from a small space and fully
      reconstructable from a few outputs; uniqid() is the microsecond clock in hex and is
      guessable to within a few hundred candidates. None is a CSPRNG. The name list
      includes the generic `key` and `code`, which is where the false positives live —
      `$cache_key = ... mt_rand()`, `$widget_id`-style uniqueness values and
      `$key = array_rand( $items )` are harmless. Triage by asking whether the value is
      ever compared for authentication or emailed to a user. Two hits across 78k lines in
      testing, both genuine (one is CVE-2025-4607).
  - id: SEC-003
    description: Hash of a timestamp or a PRNG value used where a secret is expected
    regex: '\b(md5|sha1|crc32|hash)\s*\(\s*([''"][A-Za-z0-9\-]*[''"]\s*,\s*)?[^;)]*\b(time|microtime|uniqid|date|rand|mt_rand)\s*\('
    confidence: medium
    false_positive_notes: >-
      Hashing does not add entropy. md5( time() ) has at most one candidate per second and
      an attacker who triggers the generation knows the second. BUT this idiom is also the
      standard way to build MIME boundaries, temporary filenames, cache-busting strings
      and dedup keys, and those are harmless. Measured on real plugin code: 10 hits, 2
      genuine (CVE-2024-4185, CVE-2024-5149), 8 benign — roughly 20% precision, hence
      medium. Triage rule: is the output ever used as a credential, an activation link
      parameter, or a comparison target?
  - id: SEC-004
    description: Explicit reseeding of the Mersenne Twister
    regex: '\b(mt_srand|srand)\s*\('
    confidence: high
    false_positive_notes: >-
      PHP seeds mt_rand() from a strong source automatically since PHP 7.1; calling
      mt_srand() can only make the stream weaker, and seeding it from microtime() (the
      universal idiom) reduces the whole sequence to about 10^6 candidates. The only
      legitimate use is deterministic test fixtures — if the file is not a test, it is a
      finding. Nothing else in this class produces so much impact from one line; one hit
      across 78k lines in testing, and it was CVE-2026-14495.
  - id: SEC-005
    description: WordPress salt/key or DB password defined with a literal value
    regex: 'define\s*\(\s*[''"](AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT|DB_PASSWORD)[''"]\s*,\s*[''"][^''"]'
    confidence: medium
    false_positive_notes: >-
      This is exactly what a normal wp-config.php looks like, so the rule is meaningless
      inside a correctly-ignored config file and critical anywhere else. It is a finding
      when the file is tracked in version control, shipped inside a plugin/theme ZIP,
      present in a backup that is web-reachable, or when the value is still the installer
      placeholder ("put your unique phrase here") — which means every auth cookie on the
      site can be forged. Pair with a check of .gitignore and of what the deployment
      artifact contains, not just with a grep.
  - id: SEC-006
    description: Secret-named identifier assigned a long literal string
    regex: '(?i)(\$(key|iv|secret|token|salt|passphrase|pepper)\s*=|[A-Za-z0-9_]*(client_secret|api_?key|api_?secret|access_?token|auth_?token|secret_key|secret_iv|encryption_key|private_key|app_secret|consumer_secret)[A-Za-z0-9_]*[''"]?\s*(=>|=))\s*[''"][A-Za-z0-9+/=_.@#$%^&!*()\-]{12,}[''"]'
    confidence: high
    false_positive_notes: >-
      The literal must be 12+ characters with no whitespace, which eliminates almost all
      English placeholder text ("Enter your password", "Paste your API key here") and all
      empty defaults. The residual false positive is a long *identifier* constant assigned
      to a generic name — `$key = 'my_plugin_settings_v2';` or
      `'api_key' => 'wc_gateway_api_key_field'` — so read the value and ask whether it
      looks like an option name or like entropy. Measured on real plugin code: 7 hits
      across 78k lines, all 7 genuine (CVE-2023-3947, CVE-2023-3371, CVE-2024-5810).
      This is the highest-precision rule in the class; do not weaken it by adding bare
      `password` to the name list, which would flag every form field on the internet.
  - id: SEC-007
    description: Request value compared directly against a literal secret
    regex: '(?i)\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[\s*[''"][A-Za-z0-9_]*(token|key|secret|pass|auth|sig|hash|code)[A-Za-z0-9_]*[''"]\s*\]\s*===?\s*[''"][^''"]{6,}[''"]'
    confidence: high
    false_positive_notes: >-
      Restricted to secret-shaped parameter names so it does not fire on
      `$_GET['action'] === 'my_plugin_export'`. A hit is an authentication decision made
      against a value that ships in the plugin ZIP: every installation shares it and
      anyone can read it. Low recall by design — the far more common shape assigns the
      literal to a variable first (`$token = '...'; if ( $data['token'] == $token )`),
      which SEC-006 catches instead. Run both.
  - id: SEC-008
    description: Secret compared with loose or non-constant-time equality instead of hash_equals()
    regex: '(?i)\$[A-Za-z0-9_>\-]*(token|secret|signature|otp|hash|passwd|apikey|api_key)[A-Za-z0-9_]*\s*[!=]=[^=]'
    confidence: medium
    false_positive_notes: >-
      Matches `==`/`!=` and deliberately does NOT match `===`/`!==` (the trailing [^=]
      excludes them). Two distinct defects hide here: PHP's loose comparison type-juggles
      numeric-looking strings, so a purely numeric token can match a different numeric
      token; and byte-by-byte comparison leaks timing. Emptiness checks
      (`if ( $api_key != '' )`) are the main false positive — 1 of 5 hits in testing.
      The fix is hash_equals( (string) $expected, (string) $given ).
  - id: SEC-009
    description: Credential shipped to the browser or into a JSON response
    regex: '(?i)\b(wp_localize_script|wp_add_inline_script|wp_send_json[a-z_]*|echo|print|json_encode)\b[^;]*[''"$][A-Za-z0-9_]*(api_?key|client_secret|access_?token|refresh_token|app_secret|private_key|consumer_secret)[A-Za-z0-9_]*'
    confidence: medium
    false_positive_notes: >-
      Catches the one-statement form where the key name and the emitting call are on the
      same line. It cannot see the far more common two-step shape —
      `$accounts = get_option('..._accounts'); wp_send_json_success( $accounts );` — where
      no credential name appears at the emit site at all; that is exactly CVE-2026-6446
      and it must be found by reading the handler. Also flags settings screens that
      legitimately re-render a saved key into a password field for the administrator who
      owns it; the finding is when the emitting route has no capability check.
fix_apis:
  - wp_generate_password()
  - wp_rand()
  - random_bytes()
  - random_int()
  - bin2hex()
  - hash_equals()
  - wp_hash_password()
  - wp_generate_uuid4()
  - wp_salt()
  - current_user_can()
examples:
  - cve: CVE-2026-14495
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: A passwordless-login token generator reseeded the Mersenne Twister from microtime() and then drew every character of a 32-character magic-link token with mt_rand().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-14495
    code_ref: https://plugins.trac.wordpress.org/browser/dologin/tags/4.3/src/s.cls.php#L240
    root_cause: >-
      mt_srand( (double) microtime() * 1000000 ) discards the integer-seconds component, so
      the entire token is a deterministic function of a ~10^6-value seed; the verifier then
      compared the hash with a non-constant-time loose != and called wp_set_auth_cookie()
      directly, bypassing the plugin's own lockout.
  - cve: CVE-2025-4607
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A password-reset flow emailed a four-digit code produced by rand(4000,9999), stored it in user meta, and accepted it back over an unauthenticated AJAX action with a loose == comparison and no rate limiting.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-4607
    code_ref: https://plugins.trac.wordpress.org/browser/psw-login-and-registration/trunk/public/class-prositegeneralfeatures-public.php#L329
    root_cause: A 6000-value keyspace from a non-cryptographic PRNG, verified with == over an unauthenticated endpoint, is a brute-forceable path to wp_set_password() on any account including administrators.
  - cve: CVE-2024-4185
    year: 2024
    severity: 8.1
    auth: unauthenticated
    summary: The email-verification code for a new account was md5(time()) — the MD5 of the current UNIX second at the moment of registration.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-4185
    code_ref: https://plugins.trac.wordpress.org/browser/emails-verification-for-woocommerce/tags/2.7.4/includes/alg-wc-ev-functions.php#L305
    root_cause: Hashing a timestamp produces no entropy; the attacker triggers the generation and therefore knows the second, leaving a handful of candidates and, with auto-login-after-verify enabled, an authentication bypass.
  - cve: CVE-2024-5149
    year: 2024
    severity: 5.3
    auth: unauthenticated
    summary: An account-activation code was sha1( $user_id . time() ), combining a sequential identifier with a clock value.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-5149
    code_ref: https://plugins.trac.wordpress.org/browser/buddyforms/tags/2.8.9/includes/wp-insert-user.php#L334
    root_cause: Both inputs are known or enumerable to the attacker, so the "random" activation key is computable; a stronger hash function does not change that.
  - cve: CVE-2023-3371
    year: 2023
    severity: 7.5
    auth: unauthenticated
    summary: Password-protected embed content was encrypted with an AES key and IV written as string literals in a plugin file, so every installation worldwide shared the same key.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-3371
    code_ref: https://plugins.trac.wordpress.org/browser/embedpress/tags/3.7.3/EmbedPress/Includes/Classes/Helper.php#L231
    root_cause: A key committed to a publicly downloadable plugin is not a key; the ciphertext was also rendered into the page for unauthenticated visitors, so possession of the plugin ZIP was sufficient to decrypt the protected content.
  - cve: CVE-2023-3947
    year: 2023
    severity: 5.3
    auth: unauthenticated
    summary: A generic encrypt/decrypt helper used a hardcoded secret key and a hardcoded IV to protect meeting IDs and passwords placed in URLs.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-3947
    code_ref: https://plugins.trac.wordpress.org/browser/video-conferencing-with-zoom-api/tags/4.2.1/includes/helpers.php#L550
    root_cause: Both the key and the AES-CBC IV are literals in the shipped source, so the scheme is shared across all sites and deterministic — identical plaintext always yields identical ciphertext.
  - cve: CVE-2024-5810
    year: 2024
    severity: 5.3
    auth: unauthenticated
    summary: REST routes used a permission callback that compared a query parameter against a hardcoded token string, and several sibling routes used __return_true outright.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-5810
    code_ref: https://plugins.trac.wordpress.org/browser/wp2speed/trunk/lib/includes/optimize.php#L72
    root_cause: A shared secret published in the plugin source is an authentication decision every attacker can pass; the permission_callback looked like access control and enforced nothing.
  - cve: CVE-2026-6446
    year: 2026
    severity: 5.4
    auth: subscriber+
    summary: An AJAX action returned the full contents of an option holding connected social accounts — including OAuth access and refresh tokens — with no capability check and no nonce.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6446
    code_ref: https://plugins.trac.wordpress.org/browser/my-social-feeds/tags/1.0.2/includes/TiktokAPI.php#L184
    root_cause: The handler was registered on wp_ajax_ (any logged-in user) and echoed a credential-bearing option straight into a JSON response; the sibling handler on the same class does verify a nonce, so the omission is per-action, not per-plugin.
---

## What it is

Three related failures that all end with an attacker holding something they should not.
**Hardcoded credentials** — a key, password, salt or encryption key written as a literal in
code that ships to every installation and, on wordpress.org, is downloadable by anyone.
**Weak randomness** — tokens, one-time codes, activation keys and reset PINs generated with
`rand()`, `mt_rand()`, `uniqid()` or `md5( time() )`, all of which are predictable to
somebody who knows roughly when they were generated. **Exposed secrets** — API keys stored
correctly in an option and then handed to the browser, or returned by an endpoint with no
capability check.

The severity range is wide because the *consequence* is whatever the secret protects. The
same defect is a 5.3 when it leaks a meeting password and a 9.8 when it is the reset code
for the administrator account.

This class is also the least reliably represented in CVE data. Weak randomness is usually
reported as the vulnerability it enables ("Authentication Bypass", "Email Verification
Bypass", "Sensitive Information Exposure") and is filed under CWE-330/338 rather than as a
"secrets" bug, and hardcoded keys in private plugins are simply never reported at all. The
examples below are the ones that carry both a published CVE and readable source; treat the
class as far more prevalent than its CVE count implies.

## Why it happens in WordPress

- **`rand()` and `mt_rand()` are the obvious-looking functions.** WordPress ships
  `wp_rand()` (which uses `random_int()` when available) and `wp_generate_password()`, but
  neither has a name that says "use me for tokens", so plugin authors reach for the PHP
  built-ins. Since PHP 7.1, `mt_rand()` is auto-seeded from a strong source — but any
  explicit `mt_srand()` call *replaces* that seed with something weak.
- **`uniqid()` is marketed as unique, not unguessable.** It is the current microsecond in
  hex. `uniqid( '', true )` appends `lcg_value()`, which is also not a CSPRNG. PHP's own
  manual says it is not suitable for security purposes.
- **Every plugin on wordpress.org is public source.** A key committed to a plugin is not a
  secret, it is a published constant, and it is identical on every one of the plugin's
  installations. Automated scanners diff plugin ZIPs specifically for this.
- **Nonces are not secrets and not authorization.** `wp_create_nonce()` returns a
  user-and-action-bound token with a 12–24 hour lifetime (two ticks of
  `nonce_life`, default `DAY_IN_SECONDS / 2`). It is CSRF protection. It is not a capability
  check, not an unguessable identifier for a resource, and not usable as a password-reset
  token — and `wp_verify_nonce()` returns `1` or `2` (or `false`), so `=== true` never
  matches.
- **The salts in `wp-config.php` are the crown jewels.** `AUTH_KEY` and friends key the
  authentication cookie HMAC. An attacker with the salts can forge a valid `wordpress_logged_in`
  cookie for any user without ever touching the database. Anything that reads
  `wp-config.php` — an LFI, a web-reachable backup, a `.git` directory — is therefore an
  authentication bypass, and installer placeholders left unreplaced are the same bug with
  no attacker effort at all.
- **Options are readable by more people than authors expect.** `get_option()` results end up
  in `wp_localize_script()` payloads, in AJAX responses, in REST responses and in settings
  screens whose handlers were never given a `current_user_can()` check.
- **`==` looks like a comparison.** For secrets it is two bugs: PHP type-juggles
  numeric-looking strings, and the comparison short-circuits on the first differing byte.
  `hash_equals()` exists precisely for this and is rarely used.

## Vulnerable pattern

```php
// 1. HARDCODED KEY — identical on every installation, readable in the plugin ZIP.
function example_encrypt_decrypt( $action, $string ) {
    $encrypt_method = 'AES-256-CBC';
    $secret_key     = 'DPEN_X3!3#23121';        // shipped to the world
    $secret_iv      = '1231232133213221';       // static IV: same input -> same output

    $key = hash( 'sha256', $secret_key );
    $iv  = substr( hash( 'sha256', $secret_iv ), 0, 16 );

    return 'encrypt' === $action
        ? base64_encode( openssl_encrypt( $string, $encrypt_method, $key, 0, $iv ) )
        : openssl_decrypt( base64_decode( $string ), $encrypt_method, $key, 0, $iv );
}
```

```php
// 2. WEAK TOKEN — a four-digit reset code from a non-CSPRNG, verified with ==.
public function forget( $nonce, $token, $email ) {
    $user = get_user_by( 'email', sanitize_email( $email ) );
    $key  = rand( 4000, 9999 );                        // 6000 possibilities
    wp_mail( $email, 'Password reset', "Here is your code: {$key}" );
    update_user_meta( $user->ID, 'security_token', $key );
}

public function validation( $nonce, $token, $email, $password ) {
    $user   = get_user_by( 'email', sanitize_email( $email ) );
    $tokens = get_user_meta( $user->ID, 'security_token', true );
    if ( $token == $tokens && ! empty( $password ) ) {  // loose ==, no rate limit
        wp_set_password( $password, $user->ID );
    }
}
add_action( 'wp_ajax_nopriv_example_registration', array( $this, 'customer_registration' ) );
```

```php
// 3. HASHED TIMESTAMP — no entropy is added by hashing.
$code = md5( time() );                 // one candidate per second
$code = sha1( $user_id . time() );     // both inputs known to the attacker
```

```php
// 4. SHARED SECRET AS AUTHORIZATION.
function rest_permission_check( $data = null ) {
    $token = 'hw837939@code140390';                 // in the public plugin source
    if ( ! $data ) { $data = $_GET; }
    return isset( $data['token'] ) && $data['token'] == $token;
}
register_rest_route( 'example', '/purge_cache', array(
    'methods'             => 'GET',
    'callback'            => array( $this, 'purge' ),
    'permission_callback' => array( $this, 'rest_permission_check' ),
) );
```

```php
// 5. CREDENTIALS HANDED OUT. No capability check, no nonce.
add_action( 'wp_ajax_example_get_accounts', array( $this, 'get_accounts' ) );
public function get_accounts() {
    $accounts = get_option( 'example_connected_accounts', array() );  // holds OAuth tokens
    wp_send_json_success( array_values( $accounts ) );
}
```

## Secure pattern

```php
/**
 * TOKENS. Use a CSPRNG, size the token for the keyspace you need, store a HASH of it,
 * expire it, rate-limit verification, and compare in constant time.
 */
function example_issue_reset_token( $user_id ) {
    // 32 hex chars = 128 bits. wp_generate_password() and random_bytes() are both fine;
    // rand()/mt_rand()/uniqid() are not.
    $token = bin2hex( random_bytes( 16 ) );

    // Store only a hash, so a database read does not yield usable tokens.
    update_user_meta( $user_id, '_example_reset_hash', hash( 'sha256', $token ) );
    update_user_meta( $user_id, '_example_reset_exp', time() + 15 * MINUTE_IN_SECONDS );

    return $token;                       // emailed once, never stored in plaintext
}

function example_verify_reset_token( $user_id, $provided ) {
    $stored  = (string) get_user_meta( $user_id, '_example_reset_hash', true );
    $expires = (int) get_user_meta( $user_id, '_example_reset_exp', true );

    if ( '' === $stored || time() > $expires ) {
        return false;
    }

    // Constant time, and === semantics without PHP's numeric type juggling.
    $ok = hash_equals( $stored, hash( 'sha256', (string) $provided ) );

    // Single use, whatever the outcome, plus an attempt counter elsewhere.
    delete_user_meta( $user_id, '_example_reset_hash' );

    return $ok;
}
```

```php
/**
 * SECRETS AT REST. Never a literal. Prefer a constant defined outside the repository
 * (wp-config.php, an environment variable, a secrets manager) and fall back to an option.
 */
function example_api_key() {
    if ( defined( 'EXAMPLE_API_KEY' ) && EXAMPLE_API_KEY ) {
        return EXAMPLE_API_KEY;                       // set in wp-config.php / env
    }
    return (string) get_option( 'example_api_key', '' );
}

/**
 * If a per-site secret is genuinely needed, generate one per install at activation.
 * This is what a hardcoded key should have been.
 */
function example_install_secret() {
    $secret = get_option( 'example_install_secret' );
    if ( ! $secret ) {
        $secret = bin2hex( random_bytes( 32 ) );
        add_option( 'example_install_secret', $secret, '', false ); // autoload off
    }
    return $secret;
}
```

```php
/**
 * SECRETS IN TRANSIT TO THE BROWSER. Send a capability-scoped nonce, never the key.
 * The server holds the credential; the browser holds permission to ask the server.
 */
add_action( 'wp_ajax_example_accounts', 'example_accounts' );
function example_accounts() {
    if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_accounts', 'nonce' );

    $accounts = get_option( 'example_connected_accounts', array() );

    // Strip every credential-bearing field before the response is built.
    $safe = array_map(
        static function ( $a ) {
            return array(
                'id'           => $a['open_id'],
                'display_name' => $a['display_name'],
            );
        },
        array_values( $accounts )
    );

    wp_send_json_success( $safe );
}
```

Rules of thumb:

- **`wp_rand()` / `random_int()` / `random_bytes()` for anything a security decision depends
  on; `mt_rand()` only for cosmetics.** Never call `mt_srand()` outside a test.
- **Never `uniqid()` for a token**, with or without `more_entropy`.
- **`hash_equals()` for every secret comparison.** Cast both sides to string first.
- **Nonces are CSRF tokens with a ~24 h life.** Do not use them as reset tokens, download
  tokens, unsubscribe links or object identifiers. Check `wp_verify_nonce()` truthily, not
  with `=== true`.
- **Store a hash of a token, not the token**, so a SQL injection or a backup leak does not
  hand over live credentials.
- **A per-install secret generated at activation** is the correct replacement for a
  hardcoded key.

## Real-world case studies

### Reseeding the PRNG turned a 32-character token into 20 bits (CVE-2026-14495, 8.8, subscriber+)

```php
public static function rrand( $len, $type = 7 ) {
    mt_srand( ( double ) microtime() * 1000000 );
    ...
    $max = strlen( $charlist ) - 1;
    for( $i = 0; $i < $len; $i++ ) {
        $str .= $charlist[ mt_rand( 0, $max ) ];
    }
    return $str;
}
```
`https://plugins.trac.wordpress.org/browser/dologin/tags/4.3/src/s.cls.php#L240`

```php
$hash = s::rrand( 32 );
$q = "INSERT INTO `$this->_tb` SET user_id = %d, hash = %s, ... expired_at = %d";
...
return admin_url( '?dologin=' . $id . '.' . $hash );
```
`https://plugins.trac.wordpress.org/browser/dologin/tags/4.3/src/pswdless.cls.php#L197`

**Root cause at that line:** a 32-character token over a 62-character alphabet is about 190
bits *if the generator is good*. It is not. `(double) microtime()` returns something like
`0.51234500 1712345678`, and casting the whole string to double keeps only the fractional
part — so the seed is an integer in roughly `[0, 10^6)`. Every subsequent `mt_rand()` is
determined by it, which means the entire token is a function of about 20 bits. Since PHP
7.1 the Twister is already seeded from a strong source; this line makes it worse, on
purpose, for no benefit.

The consumer compounds it:

```php
if ( ! $row || $row->hash != $info[ 1 ] ) {
    return $this->_failed_login( $username );
}
...
wp_set_auth_cookie( $user_info->ID, false );
```
`https://plugins.trac.wordpress.org/browser/dologin/tags/4.3/src/pswdless.cls.php#L58`

The link ID is the table's auto-increment primary key (enumerable), the hash comparison is
non-constant-time loose `!=`, and success calls `wp_set_auth_cookie()` directly rather than
going through `wp_authenticate()` — so the plugin's own brute-force lockout, which hooks
the authentication pipeline, never runs. **Whenever you see `wp_set_auth_cookie()` outside
`wp_authenticate()`, check what stopped the attacker getting there.**

### A four-digit reset code (CVE-2025-4607, 9.8, unauthenticated)

```php
$key = rand(4000,9999);
$subject = get_bloginfo( 'name' )." account password reset";
$body = ... "Here is your code:" ... esc_attr($key) ...
wp_mail( $to, $subject, $body, $headers );
update_user_meta($user->ID, 'website_security_token', $key);
```
`https://plugins.trac.wordpress.org/browser/psw-login-and-registration/trunk/public/class-prositegeneralfeatures-public.php#L329`

```php
$tokens = get_user_meta( $user->ID, 'website_security_token' , true );
if($token == $tokens && !empty($password)) {
    wp_set_password( $password, $user->ID);
```
`https://plugins.trac.wordpress.org/browser/psw-login-and-registration/trunk/public/class-prositegeneralfeatures-public.php#L364`

**Root cause at those lines:** the keyspace is 6000 values, the generator is
non-cryptographic, the code is stored in plaintext user meta, there is no expiry, there is
no attempt counter — and the verifier is reachable through
`add_action('wp_ajax_nopriv_psw_registration', ...)`. Six thousand requests recovers any
account, including an administrator's.

Note the interaction of two weaknesses that are individually "medium": low entropy and a
loose `==`. `$key` is an integer written to user meta, so it comes back as a numeric
string; `==` between two numeric strings compares them numerically, which means leading
zeros, `"+4567"`, `" 4567"` and `4567.0` all satisfy it. **Low entropy plus loose
comparison plus no rate limit is a 9.8, and each ingredient on its own reads as a nitpick.**

### Hashing a timestamp adds nothing (CVE-2024-4185, 8.1 / CVE-2024-5149, 5.3)

```php
function alg_wc_ev_generate_user_code( $args = null ) {
    ...
    if ( 'base64_encode' === $args['encoding_method'] ) {
        $code = md5( time() );
    } elseif ( 'hashids' === $args['encoding_method'] ) {
        $code = time();
    }
    return $code;
}
```
`https://plugins.trac.wordpress.org/browser/emails-verification-for-woocommerce/tags/2.7.4/includes/alg-wc-ev-functions.php#L305`

```php
function buddyforms_add_activation_data_to_user( $user_id, $form_slug, $buddyforms, $source = 'registration' ) {
    $code = sha1( $user_id . time() );
```
`https://plugins.trac.wordpress.org/browser/buddyforms/tags/2.8.9/includes/wp-insert-user.php#L334`

**Root cause at those lines:** MD5 and SHA-1 are deterministic functions. `md5( time() )`
has exactly as many possible outputs as `time()` has possible inputs — one per second — and
the attacker who submits the registration form knows the second to within the network
round-trip. The second case adds `$user_id`, which is sequential and returned by the
registration response. In the first plugin, with "log the user in automatically after
verification" enabled, guessing the code is an authentication bypass rather than merely an
email-verification bypass; that is the difference between 8.1 and 5.3.

`SEC-003` fires on both, and also on eight benign lines in the same corpus (MIME
boundaries, temp filenames, widget IDs). That measured 20%-ish precision is why the rule is
`medium`: it is a reading list, not a verdict.

### Keys published in the plugin ZIP (CVE-2023-3371, 7.5 and CVE-2023-3947, 5.3)

```php
// Set the decryption key and initialization vector (IV)
$key = "g72@QKgEcANy8%D7xq8%@n%#";
$iv = "^ZCC$93vsbyYjz01";
...
$embed = openssl_decrypt($cipher, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv) . '<script> ... </script>';
```
`https://plugins.trac.wordpress.org/browser/embedpress/tags/3.7.3/EmbedPress/Includes/Classes/Helper.php#L231`

```php
$encrypt_method = "AES-256-CBC";
$secret_key     = 'DPEN_X3!3#23121';
$secret_iv      = '1231232133213221';
```
`https://plugins.trac.wordpress.org/browser/video-conferencing-with-zoom-api/tags/4.2.1/includes/helpers.php#L550`

**Root cause at those lines:** these are the *same* bug in two unrelated plugins. The key
and the IV are literals in a file that anyone can download from wordpress.org, so the key
is public and identical on every installation. The password-protected embed HTML is
rendered into the page for unauthenticated visitors as ciphertext — possession of the
plugin is the whole attack. A static IV in CBC mode is a second, independent defect:
identical plaintext always produces identical ciphertext, so equal values are visibly
equal even without the key.

The correct replacement is three lines: generate `bin2hex( random_bytes( 32 ) )` once at
activation, store it in an autoload-off option, and derive a fresh IV per operation with
`openssl_random_pseudo_bytes( openssl_cipher_iv_length( $method ) )` — prepending it to the
ciphertext.

### A shared secret used as authorization (CVE-2024-5810, 5.3, unauthenticated)

```php
function rest_permission_check($data=null) {
  $token = 'hw837939@code140390';
  if(!$data) $data = $_GET;
  return isset($data['token']) && $data['token']==$token;
}
```
`https://plugins.trac.wordpress.org/browser/wp2speed/trunk/lib/includes/optimize.php#L72`

```php
register_rest_route( 'hw', '/purge_cache', array(
  'methods' => 'GET',
  'callback' => array($this,'_hw_purge_cache'),
  'permission_callback' => array($this, 'rest_permission_check')
) );
...
register_rest_route( 'hw', '/list_criticalcss', array(
  'methods' => 'GET',
  'callback' => array($this,'_list_criticalcss'),
  'permission_callback' => '__return_true'
) );
```
`https://plugins.trac.wordpress.org/browser/wp2speed/trunk/lib/includes/optimize.php#L85`

**Root cause at those lines:** `permission_callback` is present, non-trivial, and enforces
nothing — the token it checks ships in the plugin. This is worse than `__return_true`
because it passes a "does every route have a permission callback?" audit. Four sibling
routes on the same file *are* `__return_true`, including one where the real check is
commented out on the line above it.

**When auditing `permission_callback`, read the callback body. A named callback is not
evidence of a capability check.**

### The credential leak with no credential name at the sink (CVE-2026-6446, 5.4, subscriber+)

```php
add_action('wp_ajax_ttp_get_accounts', [$this, 'get_accounts']);
```

```php
public function get_accounts() {
    $accounts = get_option('ttp_tiktok_accounts', []);
    if ( empty($accounts) ) { ... }
    wp_send_json_success(array_values($accounts));
}
```
`https://plugins.trac.wordpress.org/browser/my-social-feeds/tags/1.0.2/includes/TiktokAPI.php#L184`

**Root cause at those lines:** the option holds the administrator's connected TikTok
accounts, `access_token` and `refresh_token` included. The handler is registered on
`wp_ajax_` — every logged-in user, down to Subscriber — with no `current_user_can()` and no
`check_ajax_referer()`. The class's *other* handler, `get_videos()`, does verify a nonce
twelve lines below, so this is a per-action omission rather than a plugin-wide habit.

Detection consequence: `SEC-009` returns nothing here. There is no credential name on the
emitting line, only `array_values($accounts)`. **For every `wp_send_json*` /
`wp_localize_script` / `rest_ensure_response` in a plugin, resolve what the argument
actually contains, and check the handler's capability gate — the name of the variable tells
you nothing.**

## Detection guidance

**What the regexes catch reliably**

- `SEC-001` and `SEC-006` catch literal credentials with very high precision. Across
  78,740 lines of real plugin source, `SEC-006` produced 7 hits and all 7 were published
  vulnerabilities; `SEC-001` produced none, which is the correct answer for that corpus.
- `SEC-004` is a single-line, near-zero-noise rule with outsized impact: one hit in the same
  corpus, and it was CVE-2026-14495.
- `SEC-002` catches the weak-token-generator shape, including the generic `$key = rand(...)`
  form that produced a 9.8.

**What the regexes CANNOT catch — read the code**

1. **Entropy that is destroyed downstream.** `substr( wp_generate_password( 64 ), 0, 4 )`
   uses a perfect CSPRNG and yields a four-character token. Check the *length and alphabet
   at the point of use*, not at the point of generation.
2. **Whether a token is rate-limited, expiring or single-use.** A 6-digit code from
   `random_int()` is fine with a 5-attempt lockout and fatal without one. No regex sees
   the absence of a counter.
3. **Whether a "random" value is a secret at all.** The same `md5( time() )` is a bug in a
   reset link and harmless in a MIME boundary. This is the dominant false positive for
   `SEC-003`, and it can only be resolved by following the value.
4. **Secrets emitted without a credential-shaped name at the sink** (CVE-2026-6446).
   Enumerate what every `wp_send_json*`, `wp_localize_script`, `rest_ensure_response` and
   settings-field renderer actually serialises.
5. **Secrets in non-PHP files.** `.env`, `wp-config-sample.php`, `composer.json`,
   `package.json` scripts, `.sql` dumps, `readme.txt`, minified JS bundles, source maps,
   `.git/config`, and CI files. Sweep the whole tree, not just `*.php`.
6. **Secrets in version-control history.** A key removed in the latest commit is still in
   the pack file, and a plugin's SVN tags directory keeps every released version forever.
7. **Nonce misuse.** `wp_create_nonce()` used as an unsubscribe token, a download token or
   a resource identifier. It is user-bound and expires in about 24 hours, so it is neither
   a stable identifier nor a secret. Also `wp_verify_nonce( $n ) === true`, which is always
   false because the function returns `1` or `2`.
8. **Weak custom PRNGs.** A hand-rolled loop over `str_shuffle`, a "random" value derived
   from `$_SERVER['REQUEST_TIME']`, `getmypid()`, `spl_object_hash()` or an
   auto-increment ID. `SEC-002` covers the common function names, not every invention.
9. **Where the plugin actually lives.** A key hardcoded in a private client plugin is not
   in any CVE feed and is exactly as exploitable as one on wordpress.org for anyone who
   obtains the file — through an LFI, a backup, or a former contractor.
10. **Whether an existing `hash_equals()` is comparing the right things.** Constant-time
    comparison of a value the attacker also controls both sides of proves nothing.

## Audit checklist

- [ ] Run `SEC-001` across the **whole tree**, not just `*.php` — include `.env`, `.json`,
      `.sql`, `.yml`, `.js`, `.map`, `readme.txt` and any `dist/`/`build/` output.
- [ ] Run `SEC-006` and read each hit's value: entropy or an option name?
- [ ] Run `SEC-004`; treat any `mt_srand()`/`srand()` outside a test as a finding on sight.
- [ ] For every token, code, key, OTP or activation value the plugin generates, find the
      generator and confirm it is `wp_rand()`, `random_int()`, `random_bytes()` or
      `wp_generate_password()` — then confirm the value is not truncated afterwards.
- [ ] For every generated token, check four properties: entropy, expiry, single-use, and
      attempt limiting. Record which are missing.
- [ ] Grep for `hash_equals`; then grep for every `==` / `!=` involving a token, hash,
      signature or key (`SEC-008`) and convert them.
- [ ] Read every `permission_callback` **body**. A shared-secret comparison is not
      authorization.
- [ ] Enumerate every `wp_send_json*`, `wp_localize_script`, `wp_add_inline_script` and
      REST response; resolve what each payload contains and confirm a `current_user_can()`
      gate precedes it.
- [ ] Check whether `wp-config.php`, `.env` or database dumps are tracked in version
      control or included in the distributed artifact (`SEC-005`), and whether any salt is
      still the installer placeholder.
- [ ] Grep for `wp_create_nonce` used as anything other than CSRF protection, and for
      `wp_verify_nonce( ... ) === true`.
- [ ] For every hardcoded key you find, check the plugin's SVN tags and git history — the
      old value is still published even after a "fix".
- [ ] Where a per-site secret is needed, confirm it is generated once at activation with a
      CSPRNG and stored with autoload off, not compiled into the source.
