---
class_id: WP-AUTHBYPASS
title: Authentication bypass — the login decision itself is wrong
cwe: [CWE-288, CWE-287, CWE-290, CWE-697]
owasp: A07:2021-Identification and Authentication Failures
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 10
detection:
  - id: AUTHBYPASS-001
    description: The account to authenticate as is named by the request
    regex: '\b(wp_set_auth_cookie|wp_set_current_user|wp_signon)\s*\([^;]*\$_(POST|GET|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      There is no benign form. Casting with absint()/intval() on the same line does not help —
      it produces a valid user ID, and user ID 1 is the original administrator on almost every
      install. The only safe sources for this argument are get_current_user_id() or an ID
      derived from a credential the server has just verified.
  - id: AUTHBYPASS-002
    description: Loose comparison of an OTP, token, secret or signature
    regex: '(\$[A-Za-z0-9_>\[\]''"-]*(otp|token|secret|signature|passcode|pincode|authcode|hash)[A-Za-z0-9_>\[\]''"-]*\s*(==|!=)[^=]|[^=!<>]\s*(==|!=)\s*\$[A-Za-z0-9_>\[\]''"-]*(otp|token|secret|signature|passcode|pincode|authcode|hash))'
    confidence: high
    false_positive_notes: >-
      Matches both operand orders and is written so that === and !== cannot match: the first
      branch requires a non-'=' character after the operator, and the second requires a
      non-operator character before it. Two distinct exploits fall out of a loose comparison
      here — PHP 8 compares a string against a bool by casting the string, so any non-empty
      stored secret equals true; and an absent value read back as '' equals an empty submitted
      value. Neither requires knowing the secret. The correct form is hash_equals().
  - id: AUTHBYPASS-003
    description: Identity taken from a cookie
    regex: '(\b(get_user_by|get_userdata|wp_get_current_user|get_user_meta)\s*\([^;]*\$_COOKIE|\$_COOKIE\s*\[\s*[''"][^''"]*(email|user|login|uid|role|auth|admin)[''"]*[''"])'
    confidence: medium
    false_positive_notes: >-
      A cookie is request data with better manners; it is set by the client and can be set to
      anything. The false positives are cookies whose name merely contains one of the keywords
      without carrying identity (a login_redirect_url, a user_locale preference), so read what
      the value is used for. The finding is a cookie value that selects WHICH account a flow
      operates on — especially as a fallback when a provider omits an email address.
  - id: AUTHBYPASS-004
    description: A value normalised to an int before its error state is checked — absint( WP_Error ) is 1
    regex: '(\$[A-Za-z0-9_]*(user_id|userid|uid)\s*=\s*(absint|intval)\s*\(\s*\$[A-Za-z0-9_]+\s*\)|\b(absint|intval)\s*\(\s*(wp_insert_user|wp_update_user|wp_create_user|wp_authenticate|wp_signon)\s*\()'
    confidence: medium
    false_positive_notes: >-
      `$user_id = absint( $user_id );` is idiomatic and usually harmless. It is a critical bug
      when $user_id holds the return of wp_insert_user()/wp_update_user()/wp_authenticate(),
      because casting a WP_Error object to int yields 1 — the original administrator — and any
      subsequent is_wp_error() check can then never fire. Establish what the variable held
      before the cast; validate first, normalise second.
  - id: AUTHBYPASS-005
    description: Authentication token or OTP generated from a predictable source
    regex: '\$[A-Za-z0-9_]*(otp|token|secret|authcode|passcode|resetkey|reset_key)[A-Za-z0-9_]*\s*=\s*[^;]*\b(rand|mt_rand|uniqid|time|microtime|str_shuffle|shuffle|array_rand)\s*\('
    confidence: medium
    false_positive_notes: >-
      rand()/mt_rand() are not cryptographically secure, uniqid() is derived from the clock, and
      time() is fully known to the attacker. Hashing the output does not add entropy. Also grade
      the search space independently of the source: a six-digit numeric OTP is 10^6 candidates
      and is only safe behind strict rate limiting that this rule cannot see. Correct
      alternatives are random_bytes(), wp_generate_password() and wp_generate_uuid4().
  - id: AUTHBYPASS-006
    description: Plugin overriding a core authentication decision through a filter
    regex: 'add_filter\s*\(\s*[''"](determine_current_user|rest_authentication_errors|authenticate|wp_authenticate_user|application_password_is_api_request|auth_cookie_valid)[''"]'
    confidence: medium
    false_positive_notes: >-
      Legitimate for SSO, API-key and app-password integrations, so hits need reading rather than
      reporting. These filters ARE the login decision: returning a user object from
      determine_current_user authenticates that user for the whole request, and returning true
      from rest_authentication_errors short-circuits core's REST nonce check in
      rest_cookie_check_errors(). Check the failure path (does it return null on error, or
      something truthy) and the scope (does the filter apply to every request or only the
      plugin's own routes).
  - id: AUTHBYPASS-007
    description: Anonymous AJAX route on a login-shaped action
    regex: 'wp_ajax_nopriv_[A-Za-z0-9_]*(login|logon|signin|register|auth|otp|verify|token|sso|social|impersonat|switch_user)'
    confidence: medium
    false_positive_notes: >-
      A login endpoint must be anonymous, so this is a reachability signal rather than a defect.
      It matters because it enumerates the exact handlers where AUTHBYPASS-001 through -005
      apply. Treat any nopriv handler that reaches a login sink as in scope for full manual
      review, and remember that a nonce on such a handler is not an authorization control.
  - id: AUTHBYPASS-008
    description: Hash or signature compared with a loose operator instead of hash_equals()
    regex: '(\b(md5|sha1|crc32|hash_hmac|hash|base64_encode)\s*\([^;]*\)\s*(==|!=)[^=]|\bstrcmp\s*\([^;]*\)\s*(==|!=)\s*0)'
    confidence: medium
    false_positive_notes: >-
      Two problems in one shape. The comparison is not constant-time, and with == PHP's numeric
      string juggling historically made distinct hashes compare equal (the "0e" magic-hash case)
      — still worth flagging because the same code is often ported to contexts where it applies.
      strcmp() compared loosely against 0 additionally treats a null return (non-string argument)
      as a match. Replace with hash_equals().
  - id: AUTHBYPASS-009
    description: Every login sink — the exhaustive worklist
    regex: '\b(wp_set_auth_cookie|wp_set_current_user|wp_signon|wp_authenticate|wp_clear_auth_cookie)\s*\('
    confidence: low
    false_positive_notes: >-
      Matches correct code by design, and the list is short in almost every plugin — which makes
      exhaustive manual triage the recommended workflow for this class. For each hit, walk
      backwards and answer one question: what fact did the server establish, using data the
      attacker cannot control, that justifies logging in as THIS account? If the answer involves
      a value that arrived in the request, the finding is here.
fix_apis:
  - hash_equals()
  - wp_check_password()
  - wp_signon()
  - wp_authenticate()
  - random_bytes()
  - wp_generate_password()
  - is_wp_error()
  - wp_set_auth_cookie()
  - openssl_verify() checked with === 1
examples:
  - cve: CVE-2026-7458
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: An email-OTP login flow compared the stored one-time code against the submitted one with a loose operator, so submitting a boolean true satisfied the check for any account with a verified address.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-7458
    code_ref: https://plugins.trac.wordpress.org/browser/user-verification/tags/2.0.46/templates/email-otp-login-form/hook.php#L164
    root_cause: '$saved_otp != $otp_code — PHP compares a string against a bool by casting the string, so any non-empty stored OTP is equal to true, and wp_set_auth_cookie() follows.'
  - cve: CVE-2026-6456
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: An account-switch REST endpoint compared a per-user secret loosely and never required it to be non-empty, so for any account that had never used the feature an empty secret matched and logged the caller in as that user.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6456
    code_ref: https://plugins.trac.wordpress.org/browser/account-switcher/tags/1.0.2/app/RestAPI.php#L111
    root_cause: get_user_meta() returns '' for a key that does not exist, and '' != '' is false, so the absent-secret case authenticated instead of rejecting; every route used permission_callback __return_true.
  - cve: CVE-2026-15981
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A SAML SSO plugin evaluated the tri-state integer returned by openssl_verify() in a boolean context, so the -1 "processing error" value was treated as a valid signature and any crafted assertion authenticated its named subject.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15981
    code_ref: https://plugins.trac.wordpress.org/browser/miniorange-saml-20-single-sign-on/tags/5.4.4/class-mo-saml-utilities.php#L403
    root_cause: '! $dsig->verify( $key ) instead of 1 !== $dsig->verify( $key ); -1 is truthy in PHP, and the library docblock immediately above the function says so explicitly.'
  - cve: CVE-2026-15826
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A registration auto-login helper cast the return of wp_insert_user() with absint() before its is_wp_error() check, so a deliberately rejected registration produced user ID 1 and an autologin token bound to the site administrator.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15826
    code_ref: https://plugins.trac.wordpress.org/browser/profile-builder/tags/3.16.4/front-end/class-formbuilder.php#L262
    root_cause: Normalise-before-validate. absint() on a WP_Error object yields 1, and the is_wp_error() check on the next line then inspects an integer that can never be an error.
  - cve: CVE-2026-5229
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A social-login flow fell back to reading the account's email address from a client-set cookie when the OAuth provider did not return one, and logged in whichever account that address matched.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-5229
    code_ref: https://plugins.trac.wordpress.org/browser/form-notify/tags/1.1.08/src/APIs/Line/Login/Route.php#L116-L118
    root_cause: The identity used to select the account came from request data rather than from the provider's verified claims, so completing the OAuth flow with the attacker's own provider account authenticated the victim's WordPress account.
  - cve: CVE-2026-3655
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A phone-OTP flow verified that the Firebase session was genuine but never compared the phone number Firebase returned against the phone number the request asked to log in as.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-3655
    code_ref: https://plugins.trac.wordpress.org/browser/login-with-phone-number/tags/1.8.60/inc/ajax-handlers.php#L649
    root_cause: The proof of possession was validated but never bound to the identity being claimed — the attacker verifies their own number and names the victim's in the same request.
  - cve: CVE-2026-12761
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A profile-completion flow accepted an arbitrary email address, mailed an OTP to it, and returned the hash of that OTP to the client, where the code could be brute-forced offline against a 99,000-value space keyed with a static, often-empty option.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12761
    code_ref: https://plugins.trac.wordpress.org/browser/miniorange-login-openid/tags/7.7.0/view/profile_completion/mo_openid_prof_comp_funct.php#L191
    root_cause: Three failures compounding — the target identity was request-supplied and unverified, the OTP verifier was handed to the client as a hash, and the OTP space was small enough to exhaust offline in under a second.
  - cve: CVE-2026-15341
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A session-synchronisation handler running on init derived its AES key from an option that did not exist for an unregistered slot, collapsing the key to md5 of the empty string and the referer allowlist to an empty-string match.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-15341
    code_ref: https://plugins.trac.wordpress.org/browser/user-session-synchronizer/tags/1.4.0/includes/class-user-session-synchronizer.php#L286
    root_cause: get_option() returning false for an unconfigured key degraded the shared secret to a constant, so an attacker could encrypt any known email address and have wp_set_auth_cookie() called for it.
  - cve: CVE-2024-10924
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: The two-factor REST actions of a security plugin mishandled the error return of their user-lookup helper, allowing an unauthenticated caller to complete the second factor as any existing user.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-10924
    code_ref: https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L277
    root_cause: Improper error handling around check_login_and_get_user() — the failure path continued into the login rather than terminating, which is the same defect shape as an ignored return value.
---

## What it is

The site's decision about **who you are** is wrong. Not "you reached a handler you should not
have" (WP-AUTHZ) and not "you gained a role you should not hold" (WP-PRIVESC) — the request
ends with `wp_set_auth_cookie()` called for an account that never proved it was you.

Average CVSS in the corpus is **8.89**, and the modal case is 9.8: unauthenticated, network,
no user interaction, administrator. The class is small (45 sampled records, 0.8%) because
WordPress core's own login path is sound; every instance is a plugin that built a *second*
login path beside it — social login, OTP, magic links, app integrations, user impersonation,
SSO — and got one step of it wrong.

## The shape of every bug in this class

A login flow has exactly three obligations. Real bugs are always a failure of one of them, and
naming which one is the fastest way to triage a candidate.

| # | Obligation | Failure mode | Rules |
|---|---|---|---|
| 1 | **Establish a fact using data the attacker cannot forge** | a secret compared loosely, a signature whose verifier returns a tri-state, a token from `mt_rand()`, an empty stored value matching an empty submitted one | AUTHBYPASS-002, -005, -008 |
| 2 | **Bind that fact to a specific identity** | the OTP session is genuine but belongs to the attacker's phone; the OAuth token is genuine but the email came from a cookie; the signature is valid but the `NameID` is unchecked | AUTHBYPASS-003 |
| 3 | **Act on the result correctly** | the error return is cast away, the failure branch continues, a `-1` is truthy, the account is taken from `$_POST` | AUTHBYPASS-001, -004, -006 |

Obligation 2 is the one plugin authors miss most and reviewers notice least, because the code
*does* contain real cryptography and it *does* verify something. CVE-2026-3655 validates a
genuine Firebase session and CVE-2026-5229 completes a genuine LINE OAuth handshake; in both, the
verified fact is simply never compared to the identity being claimed.

## Why it happens in WordPress

- **`wp_set_auth_cookie( $user_id )` is a one-argument, no-questions login.** It does not check a
  password, a capability, or anything else. Reaching it with an attacker-chosen integer is a
  complete compromise, and **user ID 1 is the original administrator on nearly every install** —
  which is why any type-confusion or cast that can yield `1` is critical rather than theoretical.
- **PHP's loose comparison is a bypass primitive, twice.** Under PHP 8, `"ABC123" == true` is
  `true` (the string is cast to bool), so `$stored != $submitted` with a JSON `true` passes for
  any non-empty stored secret. Separately, `get_user_meta()` and `get_option()` return `''` /
  `false` for absent keys, so `'' != ''` is `false` and the *unconfigured* case authenticates.
- **`WP_Error` is an object, and objects cast to `1`.** `absint()`, `intval()` and `(int)` on a
  `WP_Error` produce `1`. Any code that normalises before it validates converts "registration
  failed" into "you are user 1".
- **`openssl_verify()` is tri-state.** It returns `1` (valid), `0` (invalid) and `-1` (error),
  and `-1` is truthy. Every XML-DSig library in the ecosystem ships a docblock warning about
  this, and the warning is regularly ignored by the calling code in the same repository.
- **Social-login providers do not always return an email.** LINE, Discord, X and others may omit
  it depending on scopes and user settings. The fallback path — ask the client — is the bug, and
  it only triggers for some provider accounts, so it survives testing.
- **A verified session is not a verified identity.** Firebase, OTP gateways and SMS providers
  tell you "this session completed successfully". They do not tell you it completed for the
  identity in *this* request unless you compare the returned subject yourself.
- **Core's own login decision is filterable.** `determine_current_user`, `authenticate` and
  `rest_authentication_errors` are the actual mechanism; a plugin that hooks them owns
  authentication for every request, including requests that have nothing to do with the plugin.
  Returning a truthy value from `rest_authentication_errors` also short-circuits
  `rest_cookie_check_errors()`, which is where core's REST nonce check lives.
- **Impersonation features are login endpoints.** "Switch to user", "view as customer",
  "browse as" and support-login features all end in `wp_set_auth_cookie()` and are frequently
  guarded by a shared secret rather than a capability.
- **Rate limiting is usually absent.** A six-digit OTP is 10^6 candidates; without a lockout it
  is minutes of requests. Several disclosed cases also hand the verifier hash to the client,
  reducing it to an offline problem.

## Vulnerable pattern

```php
// 1. Loose comparison of a one-time code. Submit JSON true and it matches.
if ( $saved_otp != $otp_code ) {
    return array( 'errors' => array( 'wrong_otp' => 'Wrong OTP used.' ) );
}
wp_set_current_user( $user_id, $user->user_login );
wp_set_auth_cookie( $user_id );

// 2. Loose comparison against a secret that may not exist. Submit ''.
if ( get_user_meta( $user_id, 'switch_secret', true ) != $secret ) {
    wp_send_json_error( 'Invalid request' );
}
wp_set_auth_cookie( $user_id, false );

// 3. Tri-state verifier evaluated as a boolean. A malformed signature returns -1.
if ( ! $dsig->verify( $key ) ) {            // -1 is truthy, so this branch is skipped
    throw new Invalid_Assertion_Exception( 'Unable to validate Signature' );
}

// 4. Normalise-before-validate. absint( WP_Error ) === 1 === the administrator.
$user_id = absint( $user_id );              // $user_id was wp_insert_user()'s return
if ( ! $user_id || is_wp_error( $user_id ) ) {
    return $redirect_old;                   // unreachable for the error case
}

// 5. Identity from a cookie when the provider omits it.
if ( isset( $_COOKIE['sso_email'] ) ) {
    $fallback = sanitize_text_field( wp_unslash( $_COOKIE['sso_email'] ) );
}
$email = $provider_profile->email ? $provider_profile->email : $fallback;
$user  = get_user_by( 'email', $email );
wp_set_auth_cookie( $user->ID );

// 6. Verified session, unverified subject.
$session = firebase_verify_session( $_POST['session_token'] );   // genuine, and the attacker's
if ( $session->ok ) {
    $user = get_users( array( 'meta_key' => 'phone', 'meta_value' => $_POST['phone'] ) )[0];
    wp_set_auth_cookie( $user->ID );        // $session->phoneNumber is never compared
}

// 7. Predictable one-time code.
$otp = substr( md5( time() ), 0, 6 );
```

Shapes 3, 4 and 6 are the ones that survive review, because each contains real verification code.
A reviewer looking for "is the signature checked" or "is the session validated" answers yes.

## Secure pattern

```php
add_action( 'wp_ajax_nopriv_example_verify_otp', 'example_verify_otp' );

function example_verify_otp() {
    // 1. Rate limit BEFORE any comparison. A 6-digit code is 10^6 candidates.
    $ip  = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
    $key = 'example_otp_fail_' . md5( $ip );
    if ( (int) get_transient( $key ) >= 5 ) {
        wp_send_json_error( array( 'message' => 'too many attempts' ), 429 );
    }

    // 2. Both operands must be strings, and the submitted one must be non-empty.
    //    Rejecting non-strings is what stops the JSON `true` payload.
    $submitted = isset( $_POST['otp'] ) ? wp_unslash( $_POST['otp'] ) : '';
    if ( ! is_string( $submitted ) || '' === $submitted ) {
        wp_send_json_error( array( 'message' => 'invalid code' ), 400 );
    }

    $login = isset( $_POST['login'] ) ? sanitize_user( wp_unslash( $_POST['login'] ) ) : '';
    $user  = get_user_by( 'login', $login );
    if ( ! $user ) {
        // Same response and same timing as a wrong code: do not confirm which accounts exist.
        set_transient( $key, (int) get_transient( $key ) + 1, 15 * MINUTE_IN_SECONDS );
        wp_send_json_error( array( 'message' => 'invalid code' ), 403 );
    }

    // 3. The stored value must exist. An absent secret is a rejection, never a match.
    $stored = get_user_meta( $user->ID, 'example_otp_hash', true );
    $expiry = (int) get_user_meta( $user->ID, 'example_otp_expires', true );
    if ( ! is_string( $stored ) || '' === $stored || time() > $expiry ) {
        wp_send_json_error( array( 'message' => 'invalid code' ), 403 );
    }

    // 4. Constant-time comparison. Never ==, never !=, never strcmp() == 0.
    if ( ! hash_equals( $stored, hash( 'sha256', $submitted ) ) ) {
        set_transient( $key, (int) get_transient( $key ) + 1, 15 * MINUTE_IN_SECONDS );
        wp_send_json_error( array( 'message' => 'invalid code' ), 403 );
    }

    // 5. Single use. Consume before authenticating so a replay cannot race it.
    delete_user_meta( $user->ID, 'example_otp_hash' );
    delete_transient( $key );

    wp_set_current_user( $user->ID, $user->user_login );
    wp_set_auth_cookie( $user->ID, false, is_ssl() );
    do_action( 'wp_login', $user->user_login, $user );

    wp_send_json_success();
}
```

Generating the code, and the two rules that matter:

```php
// Cryptographically strong source, and stored hashed with an expiry.
$otp = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
update_user_meta( $user->ID, 'example_otp_hash', hash( 'sha256', $otp ) );
update_user_meta( $user->ID, 'example_otp_expires', time() + 10 * MINUTE_IN_SECONDS );
// The plaintext OTP leaves the server ONLY through the delivery channel (email/SMS).
// It — and any hash of it — must never appear in the HTTP response.
```

For a social-login or SSO flow, obligation 2 is the whole fix:

```php
// The identity MUST come from the provider's verified claims, never from the request.
$claims = example_verify_id_token( $id_token );          // signature, issuer, audience, expiry
if ( is_wp_error( $claims ) ) {
    wp_die( esc_html__( 'Login failed.', 'example' ), 403 );
}
if ( empty( $claims['email'] ) || empty( $claims['email_verified'] ) ) {
    // No verified email from the provider: STOP. Do not fall back to a cookie or a POST field.
    wp_die( esc_html__( 'Your provider did not supply a verified email address.', 'example' ), 403 );
}

// Bind on the provider's immutable subject id, not on an email a user can change.
$users = get_users( array(
    'meta_key'   => 'example_provider_sub',
    'meta_value' => $claims['sub'],
    'number'     => 1,
) );
if ( empty( $users ) ) {
    wp_die( esc_html__( 'No linked account.', 'example' ), 403 );
}
wp_set_auth_cookie( $users[0]->ID, false, is_ssl() );
```

And for anything that returns a tri-state:

```php
if ( 1 !== openssl_verify( $data, $signature, $public_key, OPENSSL_ALGO_SHA256 ) ) {
    throw new Invalid_Assertion_Exception( 'Signature verification failed' );
}
```

Non-negotiables: comparisons of secrets use `hash_equals()`; absent or empty stored values are a
rejection; tri-state returns are compared with `=== 1`; error objects are checked before any
cast; the identity comes from provider-verified claims or from a credential the server checked;
codes come from `random_int()`/`random_bytes()`; verifiers never travel to the client; and the
attempt is rate-limited.

## Real-world case studies

### `!=` on a one-time code (CVE-2026-7458, 9.8, unauthenticated)

```php
    if ($steps == 2) {

        $saved_otp = get_user_meta($user_id, 'uv_otp', true);

        if(empty($otp_code)){
            ...
            return $response;
        }

        if(empty($saved_otp)){
            ...
            return $response;
        }

        if ($saved_otp != $otp_code) {
            ...
            return $response;
        }

        if (!is_wp_error($user)) {
            wp_set_current_user($user_id, $user->user_login);
            wp_set_auth_cookie($user_id);
```
`https://plugins.trac.wordpress.org/browser/user-verification/tags/2.0.46/templates/email-otp-login-form/hook.php#L164`

**Root cause at that line:** the account is chosen earlier by
`get_user_by( 'email', $email )` on a request field, and the only thing standing between that and
`wp_set_auth_cookie()` is `$saved_otp != $otp_code`. Submitting the JSON value `true` for `otp`
makes PHP compare a string against a bool by casting the string: `(bool) "A7X2K9"` is `true`,
so `true != true` is `false` and the guard passes.

Note how much correct-looking code surrounds it. There are two `empty()` guards — and `true` is
not empty, so both are satisfied. The handler verifies a nonce at the top
(`wp_verify_nonce( $_wpnonce, 'wp_rest' )`), which proves nothing here because the `wp_rest`
nonce is available to anonymous visitors; see **WP-CSRF**. And the `!is_wp_error( $user )` check
immediately before the login is a real check of the wrong thing.

### The empty secret that matched (CVE-2026-6456, 8.8, subscriber+)

```php
        $userId = $request->get_param('userId');
        $secret = $request->get_param('secret');
        ...
        if (get_user_meta($userId, 'asSecret', true) != $secret) {
            Response::error(esc_html__('Invalid request', 'account-switcher'), null, 'ERR');
        }

        clean_user_cache($userId);
        wp_clear_auth_cookie();

        wp_set_current_user($userId);
        wp_set_auth_cookie($userId, false);
```
`https://plugins.trac.wordpress.org/browser/account-switcher/tags/1.0.2/app/RestAPI.php#L111`

**Root cause at that line:** `get_user_meta()` returns `''` when the key does not exist, which is
the state of every account that has never used the "remember me" feature. Sending `secret=` makes
the comparison `'' != ''`, which is `false`, and execution falls through to
`wp_set_auth_cookie( $userId, false )` with `$userId` straight from the request.

Two lessons generalise. First, **the absent-value case is the one to test**: `get_user_meta()`,
`get_option()` and `get_transient()` all return a falsy value for a missing key, and a loose
comparison turns "not configured" into "matches". Second, `$userId` is entirely attacker-chosen
and every route in the file used `permission_callback => '__return_true'`, so this is
simultaneously an AUTHBYPASS-001 finding — the two rules fire on lines four apart.

### A tri-state verifier read as a boolean (CVE-2026-15981, 9.8, unauthenticated)

The library's own documentation states the rule, immediately above the function that breaks it:

```php
	 * Returns:
	 *  1 on succesful signature verification,
	 *  0 when signature verification failed,
	 *  -1 if an error occurred during processing.
	 *
	 * NOTE: be very careful when checking the return value, because in PHP,
	 * -1 will be cast to True when in boolean context. So always check the
	 * return value in a strictly typed way, e.g. "$obj->verify(...) === 1".
```
`https://plugins.trac.wordpress.org/browser/miniorange-saml-20-single-sign-on/tags/5.4.4/includes/lib/SAML2Core/class-mo-saml-xml-security-key.php#L621`

and the caller:

```php
		/* Check the signature. */
		if ( ! $obj_xml_sec_dsig->verify( $key ) ) {
			Mo_SAML_Logger::mo_saml_add_log( 'Unable to validate Signature', Mo_SAML_Logger::ERROR );
			throw new Mo_SAML_Invalid_Assertion_Exception( 'Unable to validate Signature' );
		}
```
`https://plugins.trac.wordpress.org/browser/miniorange-saml-20-single-sign-on/tags/5.4.4/class-mo-saml-utilities.php#L403`

**Root cause at that line:** `verify()` returns `openssl_verify()`'s integer unchanged. A
deliberately malformed `SignatureValue` makes OpenSSL return `-1`, `! -1` is `false`, the
exception is not thrown, and the assertion — with an attacker-chosen `NameID` — proceeds to
`wp_set_auth_cookie()`. Everything else in the function is correct: the `SignatureMethod` element
is required, the algorithm is checked against an allowlist, symmetric algorithms are refused.

**This is the single most important shape in the class** and the reason to look at *how* a
verifier's result is consumed rather than *whether* a verifier is called. Any function documented
as returning `1|0|-1` — `openssl_verify()` and every XML-DSig wrapper around it — must be compared
with `=== 1`. Search for `openssl_verify` in the codebase and read its call site, not its
presence.

### `absint()` on a `WP_Error` (CVE-2026-15826, 9.8, unauthenticated)

```php
        $user_id = absint( $user_id );

        if ( ! $user_id || is_wp_error( $user_id ) ) {
            return $redirect_old;
        }

        $user = get_userdata( $user_id );
```
`https://plugins.trac.wordpress.org/browser/profile-builder/tags/3.16.4/front-end/class-formbuilder.php#L262`

with `$user_id` originating a few hundred lines earlier as:

```php
            // insert user to database
            $user_id = wp_insert_user( $userdata );
```

**Root cause at that line:** the two statements are in the wrong order. `wp_insert_user()`
returns either an integer ID or a `WP_Error`; `absint()` casts the `WP_Error` **object** to
`1`. By the time `is_wp_error( $user_id )` runs, `$user_id` is the integer `1` and the check can
never be true. The advisory records the trigger: a 61–70 character username, which core rejects
with a `WP_Error`. The helper then binds an autologin token to user ID 1 — the original
administrator.

`if ( ! $user_id || is_wp_error( $user_id ) )` is a *defensive-looking* condition that checks for
both failure modes, which is exactly why the ordering bug is invisible. **Validate first,
normalise second**: `if ( is_wp_error( $user_id ) ) { return; } $user_id = absint( $user_id );`

### Identity from a cookie (CVE-2026-5229, 9.8, unauthenticated)

```php
			if ( isset( $_COOKIE['form_notify_line_email'] ) ) {
				$line_email = sanitize_text_field( wp_unslash( $_COOKIE['form_notify_line_email'] ) );
			}
			$user_email = ( $user->email ) ? $user->email : $line_email;
			...
			$user_obj = new User();
			if ( $user_obj->is_member( $user_email, $user_avatar ) ) {
				$user_obj->login( $user_raw_id, $user_display, $user_avatar );
```
`https://plugins.trac.wordpress.org/browser/form-notify/tags/1.1.08/src/APIs/Line/Login/Route.php#L116-L118`

and `login()` is a bare authentication:

```php
	public function login( ... ): void {
		if ( ! is_user_logged_in() ) {
			wp_clear_auth_cookie();
			wp_set_current_user( $this->user->ID );
			wp_set_auth_cookie( $this->user->ID, true, is_ssl() );
```

**Root cause at that line:** the OAuth handshake is genuine — the access token really was issued
by the provider for the attacker's own account. What is not genuine is `$user_email`. The
provider commonly omits `email` (it depends on scopes and the user's provider-side settings), and
the fallback reads a cookie the client set. `$user_obj->is_member()` then does
`get_user_by( 'email', $user_email )` and `login()` issues the auth cookie for whatever account
that returned.

`sanitize_text_field()` is present and irrelevant; the value is well-formed, it is simply the
wrong person's. **The fix is not sanitisation but provenance:** when a provider omits a claim the
flow needs, the correct behaviour is to fail, and account linkage should key on the provider's
immutable subject id rather than on a mutable email address.

### A real session bound to the wrong identity (CVE-2026-3655, 9.8, unauthenticated)

An OTP-over-phone plugin validated that a Firebase session was legitimate and then looked up the
account by the phone number supplied in the same request, never comparing it against the
`phoneNumber` Firebase returned.
`https://plugins.trac.wordpress.org/browser/login-with-phone-number/tags/1.8.60/inc/ajax-handlers.php#L649`

**Root cause:** obligation 2, in isolation. The attacker verifies their own phone number through
Firebase exactly as intended, obtains a genuine session, and submits it alongside the
administrator's phone number. Every cryptographic operation succeeds.

**The audit question for any third-party verification step is: "which field of the provider's
response identifies the subject, and where is that field compared against the account being
logged in?"** If the answer is "it isn't", the flow is broken regardless of how sound the
provider integration is. The same question applies to SAML `NameID`, OIDC `sub`, SMS gateway
recipient numbers and payment-processor customer ids.

### The verifier handed to the attacker (CVE-2026-12761, 9.8, unauthenticated)

A profile-completion flow accepted an arbitrary `email_field`, mailed an OTP to it, and returned
`SHA-512( customer_key || otp )` to the client as a transaction hash. The OTP came from
`wp_rand( 1000, 99999 )` — about 99,000 values — and `customer_key` was a static option, empty on
installs that had never registered with the vendor.
`https://plugins.trac.wordpress.org/browser/miniorange-login-openid/tags/7.7.0/view/profile_completion/mo_openid_prof_comp_funct.php#L191`

**Root cause:** three failures that are individually survivable and jointly fatal. The identity
was request-supplied and unverified (obligation 2). The verifier — a hash of the secret — was
sent to the client, converting an online guessing problem into an offline one. And the search
space was 99,000 candidates with a known or empty key, so the offline crack completes in under a
second.

Two rules to carry forward: **never return a hash of a secret to the party being challenged**
(the hash *is* the verifier), and **grade an OTP by its search space, not by its generator** — a
5- or 6-digit numeric code is only safe behind strict, per-account rate limiting.

### A secret that degrades to a constant (CVE-2026-15341, 9.8, unauthenticated)

A session-synchronisation handler ran on `init` for every request and derived its AES-256-CBC key
from an option selected by a request-supplied slot identifier. For an unregistered slot
`get_option()` returned `false`, the key collapsed to `md5( '' )`, and the referer allowlist
collapsed to an empty-string match; the IV was a hardcoded `md5( 'another-secret' )`.
`https://plugins.trac.wordpress.org/browser/user-session-synchronizer/tags/1.4.0/includes/class-user-session-synchronizer.php#L286`

**Root cause:** the unconfigured path was never treated as an error. `get_option()` returning
`false` fed straight into key derivation, so the "shared secret" became a value anyone can
compute, and encrypting a known administrator email address produced a token the handler accepted
— ending in `wp_set_auth_cookie()`.

This is the same underlying mistake as CVE-2026-6456's empty meta value, generalised: **any
security decision that reads configuration must handle "not configured" explicitly, and the
handling must be rejection.** When auditing, set every option the flow reads to absent and ask
what the code does.

### Error handling around a user lookup (CVE-2024-10924, 9.8, unauthenticated)

The two-factor REST actions of a widely deployed security plugin mishandled the error return of
their `check_login_and_get_user()` helper, allowing an unauthenticated caller to complete the
second factor as any existing user when two-factor authentication was enabled.
`https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L277`

**Root cause:** the helper's failure signal did not terminate the caller. Structurally this is the
same defect as WP-CSRF's ignored `wp_verify_nonce()` return: a check runs, produces the correct
answer, and the answer does not change control flow. It is worth recording because it happened in
a security plugin — the presence of a verification helper with a sound-looking name is not
evidence that its result is acted on, and the only way to know is to read the caller.

## Detection guidance

**What the regexes catch reliably**

- `AUTHBYPASS-001` has no benign form; treat every hit as critical.
- `AUTHBYPASS-002` is the workhorse. It is written so `===`/`!==` cannot match, it covers both
  operand orders, and it catches both the "bool cast" and the "empty stored value" exploits with
  one pattern.
- `AUTHBYPASS-004` catches the normalise-before-validate shape, which is invisible to review
  because the surrounding condition looks more defensive than usual.
- `AUTHBYPASS-009` produces a short, complete list of login sinks. **Exhaustive manual triage of
  that list is the recommended workflow for this class** — every bug here is reachable from one
  of those calls, and there are rarely more than a handful.

**What the regexes CANNOT catch — read the code**

1. **Missing identity binding.** The defining bug of this class (CVE-2026-3655, CVE-2026-5229,
   CVE-2026-12761) is an *absent comparison*. No pattern finds code that is not there. For every
   login sink, name the provider field that identifies the subject and find where it is compared.
2. **Tri-state and multi-state returns.** `openssl_verify()` is the classic, but any wrapper
   (`->verify()`, `validateSignature()`, `checkSignature()`) inherits the problem while hiding
   the name. Grep for `openssl_verify` once, then trace every layer that returns its value.
3. **Configuration-absent paths.** `get_option()`/`get_user_meta()`/`get_transient()` returning
   `false`/`''` into a key derivation, an allowlist, or a comparison. Audit by imagining every
   option unset.
4. **Whether an OTP's search space is adequate.** `wp_rand( 1000, 99999 )` looks like a
   reasonable call. Count the candidates and then look for a lockout.
5. **Whether a verifier leaves the server.** A transaction hash, a signed state parameter, or a
   debug field in a JSON response can hand the attacker the thing they are supposed to prove.
   Read what the handler returns, not only what it accepts.
6. **Comparison semantics under `switch`.** PHP's `switch` uses loose comparison, so
   `switch ( $token ) { case $expected: }` has the same defect as `==` and matches no `==` rule.
7. **Timing side channels.** Any non-`hash_equals()` comparison of a secret leaks length and
   prefix information. Whether it is practically exploitable is a judgement call.
8. **Race conditions in single-use tokens.** Whether the token is consumed before or after the
   login, and whether two concurrent requests can both succeed.
9. **Filter-based authentication.** `AUTHBYPASS-006` finds the registration; the defect is in the
   callback — an over-broad URL match, a failure path returning something truthy, or a filter
   applied to every request rather than the plugin's own routes.
10. **Session fixation and cookie scope.** Whether `wp_clear_auth_cookie()` is called before
    issuing a new one, and whether the "remember me" flag and `is_ssl()` are set correctly.

## Audit checklist

- [ ] Run `AUTHBYPASS-009` and triage every hit exhaustively — the list is short and it is
      complete. For each, answer: what fact did the server establish, from data the attacker
      cannot control, that justifies logging in as this account?
- [ ] Run `AUTHBYPASS-001`; every hit is critical. Check specifically whether the value can be
      `1`.
- [ ] Run `AUTHBYPASS-002` and `AUTHBYPASS-008`; replace each with `hash_equals()` and confirm
      the absent/empty stored value is rejected rather than matched.
- [ ] For every comparison of a secret, set the stored value to absent and the submitted value to
      `''`, `true`, `0` and `[]`, and trace which branch runs.
- [ ] Run `AUTHBYPASS-004`, then separately grep for `absint(`, `intval(` and `(int)` applied to
      anything that can be a `WP_Error`: `wp_insert_user`, `wp_update_user`, `wp_create_user`,
      `wp_authenticate`, `wp_signon`, `wp_update_post`.
- [ ] Grep for `openssl_verify` and every wrapper that returns its value; require `=== 1`.
- [ ] For every third-party verification (OAuth, OIDC, SAML, Firebase, SMS gateway, payment
      processor), name the subject field in the provider's response and find the line that
      compares it to the account being authenticated. If there is no such line, that is the
      finding.
- [ ] Check what happens when a provider omits an optional claim (email, phone). A fallback that
      reads a cookie, a POST field or a session value is a bypass.
- [ ] Run `AUTHBYPASS-003` and classify each cookie: preference, or identity.
- [ ] Run `AUTHBYPASS-005`, then independently count the OTP search space and look for
      per-account and per-IP rate limiting.
- [ ] Check whether any hash, signature or "transaction id" derived from the secret is returned
      to the client.
- [ ] Run `AUTHBYPASS-006` and read each callback's failure path and URL scope; a truthy return
      from `rest_authentication_errors` also disables core's REST nonce check.
- [ ] Enumerate impersonation features (`switch_to_user`, `browse_as`, `view_as`, `masquerade`,
      `support_login`, `temporary_login`) and confirm each is gated on a capability, not only on
      a token.
- [ ] Run `AUTHBYPASS-007` and treat every nopriv login-shaped handler as in scope for full
      manual review.
- [ ] Confirm single-use tokens are deleted before the auth cookie is issued, and that
      `wp_clear_auth_cookie()` precedes `wp_set_auth_cookie()` in any switch/impersonate flow.
