---
class_id: WP-REST
title: REST Routes with a Missing or Non-Authorizing permission_callback
cwe: [CWE-862, CWE-863, CWE-285, CWE-306]
owasp: A01:2021-Broken Access Control
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 17
detection:
  - id: REST-001
    description: permission_callback set to a __return_* helper that PASSES the dispatch test
    regex: 'permission_callback[''"]?\s*=>\s*[''"]__return_(true|zero|empty_string|empty_array)[''"]'
    confidence: high
    false_positive_notes: >-
      The four listed helpers all satisfy WP_REST_Server::dispatch(), which rejects only on a
      STRICT false === or null === comparison: __return_zero gives int 0, __return_empty_string
      gives '', __return_empty_array gives array() — falsy in PHP, but none of them is false or
      null, so the endpoint executes for anonymous callers. __return_false and __return_null
      are deliberately excluded because they DENY. A hit is not automatically a vulnerability:
      a genuinely public read endpoint is supposed to look like this, and core's own docs
      recommend __return_true for public routes. It is a vulnerability whenever the callback
      writes, reads non-public data, or trusts a request-supplied identifier.
  - id: REST-002
    description: permission_callback that only proves the caller is logged in, or nothing at all
    regex: 'permission_callback[''"]?\s*=>\s*([''"]|array\s*\(\s*\$this\s*,\s*[''"])(is_user_logged_in|is_admin|is_user_member_of_blog|wp_doing_ajax|is_singular)[''"]'
    confidence: high
    false_positive_notes: >-
      is_user_logged_in as a permission callback admits every Subscriber, which on a site with
      open registration, WooCommerce customers or LMS students is one signup form away from
      unauthenticated. is_admin is worse than useless: it returns the WP_ADMIN constant and is
      false on the REST route in the first place, so it fails closed for everyone and the
      author will "fix" it by switching to __return_true. Neither answers "may this user do
      this". Legitimate only when the route exposes exactly what any logged-in user may
      already see and the handler performs its own object-level check.
  - id: REST-003
    description: Named permission-callback definitions — read each body
    regex: 'function\s+[A-Za-z0-9_]*([Pp]ermission|_perm)[A-Za-z0-9_]*\s*\('
    confidence: low
    false_positive_notes: >-
      This is an inventory rule and it exists because REST-001 has a blind spot that shows up
      in real CVEs: a callback named check_permission() whose entire body is "return true;" is
      functionally identical to __return_true and matches none of the string rules. Expect
      many benign hits in well-written controllers (WP_REST_Controller subclasses define
      get_items_permissions_check() and friends by convention). Read every body and classify:
      returns true unconditionally, checks login only, checks a capability that is too low,
      checks the right capability, or checks the right capability against the object ID.
  - id: REST-004
    description: Permission callback gated on a capability EVERY logged-in user holds
    regex: 'return\s+current_user_can\s*\(\s*[''"](read|exist|level_0|level_1|subscriber)[''"]\s*\)'
    confidence: high
    false_positive_notes: >-
      read, exist and level_0 are held by every account that exists, including a Subscriber
      created by open registration; 'subscriber' is a role name, not a capability, and is
      covered here because it appears in the same position. None of them can authorize
      anything a route does, so a hit is a finding whenever the route is not intended to be
      readable by every logged-in user. The only benign case is a route deliberately scoped to
      "any authenticated user", which should say is_user_logged_in() and be reviewed under
      REST-002 instead. Contributor/Author primitives such as edit_posts are handled
      separately by REST-008 because they are legitimate on post-scoped routes.
  - id: REST-005
    description: Inline closure or arrow function used as the permission callback
    regex: 'permission_callback[''"]?\s*=>\s*(static\s+)?(function|fn)\s*\('
    confidence: low
    false_positive_notes: >-
      A worklist rule, and confirmed as such against tests/fixtures/safe.php, where a correct
      inline permission callback matches it. Neutral as a construct — many correct callbacks
      are one-line closures. Flagged because the body is on the same or the next line and is
      therefore cheap to read, and because
      arrow functions in particular invite the non-boolean return that REST-006 covers
      (fn( $r ) => get_current_user_id() grants access to anonymous callers). Read every hit;
      it is a two-second triage per occurrence.
  - id: REST-006
    description: Permission callback returning a non-boolean — falsy values other than false/null ALLOW
    regex: 'return\s+(get_current_user_id|count|sizeof|strpos|stripos|absint|intval|array_search|get_option|get_user_meta)\s*\('
    confidence: medium
    false_positive_notes: >-
      Only a finding when the enclosing function is a permission callback, so pair it with
      REST-003 and REST-005 and check the line numbers overlap. The rule matters because
      dispatch rejects on false === $permission || null === $permission and nothing else:
      get_current_user_id() returns int 0 for an anonymous caller and 0 is neither, so the
      route executes. The same trap applies to count() returning 0, strpos() returning 0 at
      offset zero, absint() of a missing parameter, and get_option()/get_user_meta() returning
      '' when unset. Any permission callback whose final expression is not obviously a bool or
      a WP_Error is a finding.
  - id: REST-007
    description: Every REST route registration — the inventory to diff against permission_callback
    regex: '\bregister_rest_route\s*\('
    confidence: low
    false_positive_notes: >-
      Pure inventory. Its job is to be counted: since WordPress 5.5, an omitted
      permission_callback triggers only a silent _doing_it_wrong() notice, the route is still
      registered, and dispatch skips the authorization block entirely because it is guarded by
      ! empty( $handler['permission_callback'] ). A route count higher than the
      permission_callback count therefore means one or more routes are fully public and no
      string rule will ever find them. Note also that one register_rest_route() call can
      define several endpoints (an array of method/callback groups), each needing its own
      permission_callback — count endpoints, not calls.
  - id: REST-008
    description: Permission callback gated on a Contributor/Author primitive with no ownership logic
    regex: 'return\s+current_user_can\s*\(\s*[''"](edit_posts|delete_posts|upload_files|publish_posts|edit_published_posts|read_private_posts)[''"]\s*\)'
    confidence: low
    false_positive_notes: >-
      Deliberately low, and verified against tests/fixtures/safe.php where exactly this shape
      appears as correct code: on a route that operates on the caller's own posts and re-checks
      with a meta capability plus the object ID, edit_posts is the right gate. It is a finding
      when the route touches users, options, settings, files, other people's content, or any
      request-supplied object ID — because these are primitives with no ownership, status or
      post-type logic whatsoever (capability-matrix.md §4). This rule found CVE-2025-4672,
      where edit_posts guarded an arbitrary user-meta write; nothing higher-confidence can,
      because syntactically the code is a correct capability check.
  - id: REST-009
    description: Permission callback is an inline closure that unconditionally returns true — semantically identical to __return_true
    regex: 'permission_callback[\x27"]?\s*=>\s*(static\s+)?(function|fn)\s*\([^)]*\)\s*(:\s*[A-Za-z]+\s*)?(\{\s*)?(use\s*\([^)]*\)\s*\{\s*)?return\s+true\s*;|permission_callback[\x27"]?\s*=>\s*fn\s*\([^)]*\)\s*=>\s*true\s*[,)]'
    confidence: high
    multiline: true
    false_positive_notes: >-
      Added after auditing a real plugin that wrote `permission_callback => function () {
      return true; }` across three lines. That is exactly as open as
      `permission_callback => __return_true`, but REST-001 only matches the string form, so
      the route was invisible at default confidence and only REST-005 (low, hidden by
      default) saw it. Formatting must not decide whether a route is reported, hence
      multiline: true — the rule is matched against a short joined window.
      A genuinely public read-only endpoint is a legitimate use of an always-true callback:
      a front-end search or a public directory. Treat it as a finding whenever the route
      writes, or when the callback returns anything the site owner would not publish. For a
      read route, verify what the callback constrains — a query pinned to
      post_status => publish and an admin-configured post type list is safe; the same route
      without those returns drafts and private posts to anonymous callers.

fix_apis:
  - register_rest_route()
  - current_user_can()
  - rest_authorization_required_code()
  - WP_Error
  - WP_REST_Controller::get_items_permissions_check()
  - hash_equals()
  - sanitize_callback
  - validate_callback
examples:
  - cve: CVE-2023-6875
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: Five mobile-app REST routes were registered with permission_callback set to __return_true, leaving all authorization to a loose comparison of a request header against a transient that is false when unset.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-6875
    code_ref: https://plugins.trac.wordpress.org/browser/post-smtp/tags/2.8.7/Postman/Mobile/includes/rest-api/v1/rest-api.php#L28
    root_cause: Authorization was delegated from the permission_callback into the handler, where it was implemented as a type-juggleable == comparison, so an anonymous request reset the API key and read the email log.
  - cve: CVE-2024-9234
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: Two sibling routes were both registered with permission_callback => __return_true; the read route re-checked the nonce and capability inside its callback, and the route that installs and activates a plugin from a supplied URL did not.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9234
    code_ref: https://plugins.trac.wordpress.org/browser/gutenkit-blocks-addon/tags/2.1.0/includes/Admin/Api/ActivePluginData.php#L19
    root_cause: __return_true used as the default with the real check moved into the callback body, a pattern that fails whenever one callback is written without it.
  - cve: CVE-2023-3956
    year: 2023
    severity: 9.8
    auth: unauthenticated
    summary: A sync route pointed permission_callback at a method of the controller named check_permission(), whose entire body was "return true;".
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-3956
    code_ref: https://plugins.trac.wordpress.org/browser/instawp-connect/tags/0.0.9.18/includes/class-instawp-rest-apis.php#L58
    root_cause: A permission callback that is __return_true under a different name; the route accepted a payload that created users, installed plugins and rewrote options.
  - cve: CVE-2026-6456
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: A base API class registered every route from its route table with permission_callback hard-coded to __return_true, deferring authorization to an optional middleware layer that one login-related route did not use.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-6456
    code_ref: https://plugins.trac.wordpress.org/browser/account-switcher/tags/1.0.2/app/PluginHero/BaseAPI.php#L51
    root_cause: One framework line made every route in the plugin public; the exposed route then compared a secret with != against an unset user meta value that is the empty string.
  - cve: CVE-2026-2262
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: An appointments route was registered with permission_callback => __return_true and returned full customer records — names, email addresses, phone numbers, IP addresses and prices — to any anonymous caller.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-2262
    code_ref: https://plugins.trac.wordpress.org/browser/easy-appointments/tags/3.12.19/ea-blocks/ea-blocks.php#L190
    root_cause: __return_true shipped as a placeholder, annotated in the source with the comment "Secure this if needed", on a route reading a private table.
  - cve: CVE-2025-4672
    year: 2025
    severity: 8.8
    auth: contributor+
    summary: A user-meta route had a real named permission callback on every method, but the callback checked edit_posts, so any Contributor could write any meta key on any user ID.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-4672
    code_ref: https://plugins.trac.wordpress.org/browser/offsprout-page-builder/tags/2.15.2/api/class-offsprout-api-extensions.php#L32
    root_cause: The permission_callback existed and returned a genuine capability check, but the capability did not match the impact and no object-level check was performed on the userId route parameter.
  - cve: CVE-2025-12903
    year: 2025
    severity: 7.5
    auth: unauthenticated
    summary: A payment route registered with permission_callback => __return_true accepted a stored payment-token ID from the request and returned a usable payment nonce for it, with no ownership check.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-12903
    code_ref: https://plugins.trac.wordpress.org/browser/woo-payment-gateway/tags/3.2.78/includes/api/class-wc-braintree-controller-3ds.php#L18
    root_cause: __return_true combined with a request-supplied object identifier — public route plus IDOR, where either alone would have been survivable.
---

## What it is

`register_rest_route()` publishes a callback at `/wp-json/{namespace}/{route}`. The REST API
is public infrastructure: **routes are anonymous by default**, and the only thing that
changes that is the `permission_callback` argument returning `false`, `null`, or a
`WP_Error`. Setting it to `__return_true`, omitting it, or pointing it at something that
does not actually answer *"may this user do this"* leaves the endpoint open to the internet.

Like **WP-AJAX**, this is a **registration-side** class: the evidence is one line in the
route definition, not in the handler. Like WP-AJAX, it overlaps CWE-862 with **WP-AUTHZ**,
and the split is the same:

| Class | Question | Where the evidence lives |
|---|---|---|
| **WP-REST** (this) | Does the route authorise the caller? | the `permission_callback` line |
| **WP-AJAX** | Is this handler published to anonymous callers? | `add_action( 'wp_ajax_nopriv_…' )` |
| **WP-AUTHZ** | What does the handler fail to check once reached? | the function body |

A route can be a finding in this class **and** in WP-AUTHZ simultaneously — a
`permission_callback` of `__return_true` on a handler that also never calls
`current_user_can()`. Report both: the registration line is the one-line fix, the handler is
the defence in depth.

Wordfence has no bucket for this pattern (these findings land in "Authorization Bypass"), so
prevalence rank 17 is an artefact of the source taxonomy, not a measure of rarity.
`permission_callback => '__return_true'` is among the most common single lines in disclosed
WordPress vulnerabilities, and unlike most classes it is found by an exact string match.

## Why it happens in WordPress

- **"Required" is documentation, not enforcement.** Since WP 5.5, `register_rest_route()`
  emits `_doing_it_wrong()` when `permission_callback` is absent. That notice is **silent
  without `WP_DEBUG`**, the route is still registered, and the request still executes. Never
  assume 5.5 closed these holes.
- **Dispatch is guarded by `! empty()`.** From `WP_REST_Server::dispatch()`:
  `if ( ! is_wp_error( $response ) && ! empty( $handler['permission_callback'] ) ) { … }`.
  A **missing**, `null`, `false` or `''` `permission_callback` skips the authorization block
  **entirely** — it does not fail closed, it is not evaluated at all.
- **The rejection test is strict.** `false === $permission || null === $permission`.
  Everything else allows:

  | Callback returns | Result |
  |---|---|
  | `true` | Allowed |
  | `false` | Denied |
  | `null` (including falling off the end of the function) | Denied — fails closed |
  | `WP_Error` | Denied, with your message |
  | `0`, `'0'`, `''`, `array()`, `0.0` | **ALLOWED** — falsy, but not `false`/`null` |

  So `fn( $r ) => get_current_user_id()` grants access to anonymous users, because
  `get_current_user_id()` returns `int 0` when logged out and `0 !== false`.
- **The core docs recommend `__return_true`.** The `_doing_it_wrong()` message itself says
  *"For REST API routes that are intended to be public, use `__return_true` as the permission
  callback."* Developers reach for it to silence the notice, on routes that are not public.
- **"The nonce protects it."** Cookie-authenticated REST requests *are* CSRF-protected by
  core via `rest_cookie_check_errors()` and the `X-WP-Nonce` header. That protection applies
  **only when the caller chose cookie auth**. An anonymous, cookie-less request never enters
  that code path. Removing `permission_callback` because "the nonce handles it" is a
  category error.
- **Framework and base-class registration.** A `BaseAPI::addRoutes()` that hard-codes
  `permission_callback` once publishes every route the plugin owns. One line, N endpoints.
- **`?rest_route=` bypasses `/wp-json/` WAF rules.** When pretty permalinks are off (or
  always, in fact), `GET /?rest_route=/namespace/route` reaches the same handler. Rules keyed
  on the `/wp-json/` path prefix miss it.
- **`args` validation runs *after* `permission_callback`.** `sanitize_callback` and
  `validate_callback` are data hygiene, never access control, and they cannot compensate for
  a missing permission callback.

## Vulnerable pattern

```php
add_action( 'rest_api_init', function () {

    // 1. The literal. Anonymous write access to a plugin's settings.
    register_rest_route( 'example/v1', '/settings', array(
        'methods'             => WP_REST_Server::EDITABLE,
        'callback'            => 'example_save_settings',
        'permission_callback' => '__return_true',
    ) );

    // 2. Omitted entirely. WP 5.5+ logs a notice nobody sees; dispatch skips the
    //    authorization block because ! empty( $handler['permission_callback'] ) is false.
    register_rest_route( 'example/v1', '/users', array(
        'methods'  => WP_REST_Server::READABLE,
        'callback' => 'example_list_users',
    ) );

    // 3. Disguised. Identical to __return_true, invisible to a string rule.
    register_rest_route( 'example/v1', '/sync', array(
        'methods'             => 'POST',
        'callback'            => array( $this, 'events_receiver' ),
        'permission_callback' => array( $this, 'check_permission' ),
    ) );

    // 4. Login-only. Every Subscriber passes.
    register_rest_route( 'example/v1', '/export', array(
        'methods'             => WP_REST_Server::READABLE,
        'callback'            => 'example_export',
        'permission_callback' => 'is_user_logged_in',
    ) );

    // 5. Non-boolean. get_current_user_id() returns int 0 when logged out, and
    //    0 !== false, so this ALLOWS anonymous callers.
    register_rest_route( 'example/v1', '/profile', array(
        'methods'             => WP_REST_Server::EDITABLE,
        'callback'            => 'example_save_profile',
        'permission_callback' => fn( $r ) => get_current_user_id(),
    ) );
} );

function check_permission() {
    return true;                       // rule 3's callback, in full
}
```

The sixth shape is the one that passes review, because a real capability check is present:

```php
register_rest_route( $ns, '/usermeta/(?P<metaKey>[\S]+)/(?P<userId>[\d]+)', array(
    array(
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => array( $this, 'create_usermeta' ),
        'permission_callback' => array( $this, 'create_meta_permissions_check' ),
    ),
) );

public function create_meta_permissions_check( $request ) {
    return current_user_can( 'edit_posts' );      // Contributor+. Writes ANY user's meta.
}
```

## Secure pattern

```php
add_action( 'rest_api_init', function () {

    register_rest_route( 'example/v1', '/settings', array(
        array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => 'example_get_settings',
            // Each method group needs its OWN permission_callback. Read and write are
            // different authorization questions and must not share one gate.
            'permission_callback' => function () {
                return current_user_can( 'manage_options' );   // returns a real bool
            },
        ),
        array(
            'methods'             => WP_REST_Server::EDITABLE,
            'callback'            => 'example_save_settings',
            'permission_callback' => function () {
                if ( current_user_can( 'manage_options' ) ) {
                    return true;
                }
                // Returning WP_Error gives the caller a correct status code instead of a
                // bare 403, and makes the denial explicit in the code.
                return new WP_Error(
                    'rest_forbidden',
                    __( 'You cannot edit these settings.', 'example' ),
                    array( 'status' => rest_authorization_required_code() )
                );
            },
            'args'                => array(
                'email' => array(
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => 'sanitize_email',
                    'validate_callback' => 'is_email',
                ),
            ),
        ),
    ) );
} );
```

Object-scoped routes need the object ID in the capability check, and the check must happen
in the `permission_callback` — where the route parameter is already available:

```php
register_rest_route( 'example/v1', '/posts/(?P<id>\d+)', array(
    'methods'             => WP_REST_Server::DELETABLE,
    'callback'            => 'example_delete_post',
    'permission_callback' => function ( WP_REST_Request $request ) {
        $id = (int) $request['id'];
        // Meta capability WITH the object ID: map_meta_cap() resolves author, status
        // and post type. current_user_can( 'delete_posts' ) would let a Contributor
        // delete anyone's published post.
        return current_user_can( 'delete_post', $id );
    },
    'args'                => array(
        'id' => array( 'required' => true, 'sanitize_callback' => 'absint' ),
    ),
) );
```

And when the route really is for an unauthenticated third party, `__return_true` is correct —
but it is a *statement that authorization happens elsewhere*, and that elsewhere must exist:

```php
register_rest_route( 'example/v1', '/webhook', array(
    'methods'             => WP_REST_Server::CREATABLE,
    'callback'            => 'example_webhook',
    // Intentional: the remote service has no WordPress identity. Authorization is by
    // payload signature, verified in the permission_callback so it runs BEFORE the handler.
    'permission_callback' => function ( WP_REST_Request $request ) {
        $sent = (string) $request->get_header( 'x_example_signature' );
        $mine = hash_hmac( 'sha256', $request->get_body(), EXAMPLE_WEBHOOK_SECRET );
        // hash_equals(), never == / === on the raw strings.
        if ( $sent && hash_equals( $mine, $sent ) ) {
            return true;
        }
        return new WP_Error( 'rest_forbidden', 'bad signature',
            array( 'status' => rest_authorization_required_code() ) );
    },
) );
```

Five rules that close this class:

1. **Every endpoint group gets its own `permission_callback`.** Never one for the whole
   route when the route serves both `GET` and `POST`.
2. **The callback returns `true`, `false`, or a `WP_Error`.** Nothing else. Cast if you must:
   `return (bool) $x;`.
3. **Put the check in `permission_callback`, not in the handler.** It receives the
   `WP_REST_Request`, it runs before `args` sanitisation, and it is the line a reviewer and a
   scanner both look at.
4. **Pick the capability from the impact.** Use the table in capability-matrix.md §2. A route
   that writes user meta needs `edit_users`, not `edit_posts`.
5. **`__return_true` is a claim, not a default.** If you write it, the review question is
   "what authenticates this caller instead" — and there must be an answer.

## Real-world case studies

### Authorization moved out of the callback and into a loose comparison (CVE-2023-6875, 9.8, unauthenticated)

Five routes, five identical registrations:

```php
register_rest_route( 'post-smtp/v1', '/connect-app', array(
    'methods'               => WP_REST_Server::CREATABLE,
    'callback'              => array( $this, 'connect_app' ),
    'permission_callback'   => '__return_true',
) );

register_rest_route( 'post-smtp/v1', '/get-logs', array(
    'methods'               => WP_REST_Server::READABLE,
    'callback'              => array( $this, 'get_logs' ),
    'permission_callback'   => '__return_true',
) );
```
`https://plugins.trac.wordpress.org/browser/post-smtp/tags/2.8.7/Postman/Mobile/includes/rest-api/v1/rest-api.php#L28`

The entire access control for the mobile API is one line inside the handler:

```php
public function connect_app( WP_REST_Request $request ) {
	$nonce = get_transient( 'post_smtp_auth_nonce' );
	$auth_key = $request->get_header( 'auth_key' );
	...
	if( $auth_key == $nonce ) {
		...
		update_option( 'post_smtp_mobile_app_connection', $data );
```

**Root cause at that line:** `get_transient()` returns `false` when the transient is absent
or expired, and `WP_REST_Request::get_header()` returns `null` for a header that was not
sent. `null == false` is **true** under PHP's loose comparison, so an anonymous request with
no `auth_key` header at all passes the gate whenever the transient is not set. The handler
then rewrites the app-connection option, and `/get-logs` returns the plugin's email log —
which contains password-reset messages for every account on the site.

**The structural lesson:** `permission_callback => '__return_true'` did not, on its own,
cause the bug. What it did was move authorization from a place core evaluates uniformly, with
a strict `false ===` test, into hand-written handler code where PHP's comparison semantics
apply. That relocation is the finding. When you see `__return_true`, the audit question is
*"where did authorization go, and is it correct there?"* — and the answer is very often "into
a `==`".

### Two sibling routes, one of which remembered (CVE-2024-9234, 9.8, unauthenticated)

```php
public function __construct() {
    add_action('rest_api_init', function() {
        register_rest_route('gutenkit/v1', 'active-plugin',
            array(
                'methods'             => \WP_REST_Server::READABLE,
                'callback'            => [$this, 'action_get_active_plugin'],
                'permission_callback' => '__return_true',
            ),
        );
    });

    add_action('rest_api_init', function() {
        register_rest_route('gutenkit/v1', 'install-active-plugin',
            array(
                'methods'             => \WP_REST_Server::EDITABLE,
                'callback'            => [$this, 'install_and_activate_plugin_from_external'],
                'permission_callback' => '__return_true',
            ),
        );
    });
}
```
`https://plugins.trac.wordpress.org/browser/gutenkit-blocks-addon/tags/2.1.0/includes/Admin/Api/ActivePluginData.php#L19`

The read callback does the work `permission_callback` should have done:

```php
public function action_get_active_plugin($request) {
    /**
    * turn on this section when fully functional from frontend and need Nonce check Permission check
    */
    if (!wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest')) { ... }

    if (!is_user_logged_in() || !current_user_can('manage_options')) { ... }
```

The write callback does not:

```php
public function install_and_activate_plugin_from_external($request) {
    // The external plugin URL
    $plugin_url = $request->get_param('plugin');
    ...
    $temp_file = download_url($plugin_url);
```

**Root cause at that line:** an arbitrary URL is downloaded and unpacked into
`wp-content/plugins/`, then activated — arbitrary PHP execution for an anonymous caller. The
plugin author clearly understood the requirement: the check exists, twelve lines above, on
the *other* route.

**The generalisable defect is the pattern, not the omission.** Using `__return_true`
everywhere and doing the real check inside each callback means the safe state depends on
remembering, per callback, forever. Placing the check in `permission_callback` makes the
absence structurally visible on the registration line. **Whenever you find one route in a
controller with an in-callback check, read every sibling callback — that plugin has adopted
the pattern, and the pattern fails by omission.**

### `__return_true` under an assumed name (CVE-2023-3956, 9.8, unauthenticated)

```php
add_action( 'rest_api_init', function () {
    register_rest_route( 'instawp-connect/v1', '/sync',
    array(
    'methods' => 'POST',
    'callback' => [$this, 'events_receiver'],
    'permission_callback' => [$this, 'check_permission'],
    ) );
} );

function check_permission(){
    return true;
}
```
`https://plugins.trac.wordpress.org/browser/instawp-connect/tags/0.0.9.18/includes/class-instawp-rest-apis.php#L58`

**Root cause at that line:** three lines of code that are indistinguishable from
`__return_true` at runtime and completely distinguishable from it to a scanner. The route it
guards accepts a payload that inserts and updates posts and taxonomies, installs and toggles
plugins, changes customizer settings, and creates, modifies and deletes users **including
administrators**.

**This case is the entire justification for REST-003.** A rule that greps for
`__return_true` scores this file clean. The only reliable method is to enumerate every named
permission callback and read its body — which is cheap, because a controller has a handful,
and each is three to ten lines. Classify each into: unconditional true, login-only,
capability too low, capability right but no object check, correct. Four of those five are
findings.

### One framework line, every route (CVE-2026-6456, 8.8, subscriber+)

```php
if ('rest' == $this->type) {
    $this->nameSpaces = array_keys($routeList);
    add_action('rest_api_init', function () use ($routeList): void {
        foreach ($routeList as $nameSpace => $routes) {
            foreach ($routes as $route => $config) {
                $callback = is_array($config) ? $config['callback'] : $config;
                $methods = isset($config['methods']) ? $config['methods'] : ['POST', 'GET'];
                if (isset($config['middleware'])) {
                    $this->addMiddleware($nameSpace . '/' . $route, $config['middleware']);
                }
                register_rest_route($nameSpace, $route, [
                    'callback' => [$this, $callback],
                    'methods' => $methods,
                    'permission_callback' => '__return_true'
                ]);
            }
        }
    });
}
```
`https://plugins.trac.wordpress.org/browser/account-switcher/tags/1.0.2/app/PluginHero/BaseAPI.php#L51`

**Root cause at that line:** `permission_callback` is hard-coded for the whole route table,
and authorization is delegated to an **optional** `middleware` key applied through
`rest_pre_dispatch`. Optional means some route will not declare it. The one that did not was
`rememberLogin`, which compares a submitted secret against `asSecret` user meta using `!=`;
for a user who never used "remember me" the meta does not exist, `get_user_meta()` returns
`''`, and an empty submitted secret satisfies `'' != ''` as false — after which the route
calls `wp_set_auth_cookie()` for the named user. Subscriber to Administrator in one request.

**Detection consequences.** First, `register_rest_route(` appears **once** in the source and
registers however many routes the table holds, so a route count taken by grepping
registrations is wrong — find the route table. Second, note the two defaults compounding:
`['POST', 'GET']` when `methods` is unset, and `__return_true` always. Framework defaults are
where this class concentrates, because one decision propagates to everything.

### The comment says it (CVE-2026-2262, 7.5, unauthenticated)

```php
add_action('rest_api_init', function () {
	register_rest_route('wp/v2/eablocks', '/ea_appointments/', [
		'methods'  => 'GET',
		'callback' => 'easy_ea_block_get_appointments',
		'permission_callback' => '__return_true', // Secure this if needed
	]);
});
```
`https://plugins.trac.wordpress.org/browser/easy-appointments/tags/3.12.19/ea-blocks/ea-blocks.php#L190`

**Root cause at that line:** the callback runs a `SELECT *` over the appointments table and
returns full customer records — names, email addresses, phone numbers, IP addresses,
appointment descriptions and prices — to `GET /wp-json/wp/v2/eablocks/ea_appointments/`, with
no authentication and no pagination limit.

Two details worth carrying. First, the namespace is `wp/v2/eablocks`: registering into core's
`wp/v2` namespace makes the route look like core in a route listing and in logs. Grep
`register_rest_route` by *call site*, never by namespace. Second, `// Secure this if needed`
is not an outlier — placeholder `__return_true` with a TODO beside it is a recurring shape.
Grep the lines adjacent to every REST-001 hit for `TODO`, `FIXME`, `for now`, `temporary`,
`if needed`; they mark endpoints the author already knew were unfinished.

### Every route has a permission callback, and it is the wrong one (CVE-2025-4672, 8.8, contributor+)

```php
register_rest_route( $namespace . $version, '/usermeta/(?P<metaKey>[\S]+)/(?P<userId>[\d]+)', array(
    array(
        'methods'         => WP_REST_Server::READABLE,
        'callback'        => array( $this, 'get_usermeta' ),
        'permission_callback' => array( $this, 'get_meta_permissions_check' )
    ),
    array(
        'methods'         => WP_REST_Server::CREATABLE,
        'callback'        => array( $this, 'create_usermeta' ),
        'permission_callback' => array( $this, 'create_meta_permissions_check' )
    ),
    ...
```
`https://plugins.trac.wordpress.org/browser/offsprout-page-builder/tags/2.15.2/api/class-offsprout-api-extensions.php#L32`

```php
public function create_meta_permissions_check( $request ) {
    return current_user_can( 'edit_posts' );
}
```

```php
public function create_usermeta( $request ) {
    $user_id = (int) $request->get_param( 'userId' );
    $meta_key = (string) $request->get_param( 'metaKey' );
    $json_payload = $request->get_json_params();

    $data = update_user_meta( $user_id, $meta_key, $json_payload );
```

**Root cause at that line:** the controller is, by the standards of most plugins, well
written — four method groups, four distinct permission callbacks, and elsewhere in the same
file `options_permissions_check()` correctly returns `current_user_can('manage_options')` and
`edit_users_permissions_check()` correctly returns `current_user_can('edit_users')`. The
`usermeta` routes got `edit_posts`. Both the meta *key* and the *user ID* are route
parameters, so a Contributor writes `wp_capabilities` on their own account and becomes an
administrator.

NVD classifies this CWE-285 (improper authorization) rather than CWE-862 (missing
authorization), and the distinction is the point: **REST-001 through REST-003 score this
file completely clean.** Only REST-004 fires, and only because `edit_posts` happens to be on
its low-capability list. **The audit question is not "does a permission callback exist" — it
is "does the capability match the worst thing the callback can do, and is the object ID
checked".**

### Public route plus request-supplied object ID (CVE-2025-12903, 7.5, unauthenticated)

```php
public function register_routes() {
    register_rest_route(
        $this->rest_uri(),
        'vaulted_nonce',
        array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'get_vaulted_nonce' ),
            'permission_callback' => '__return_true',
        )
    );
}

public function get_vaulted_nonce( $request ) {
    $response = new WP_REST_Response();
    if ( isset( $request['token_id'] ) ) {
        $token = WC_Payment_Tokens::get( $request['token_id'] )->get_token();
```
`https://plugins.trac.wordpress.org/browser/woo-payment-gateway/tags/3.2.78/includes/api/class-wc-braintree-controller-3ds.php#L18`

**Root cause at that line:** `$request['token_id']` names any stored payment token in the
system, and the handler returns a usable payment-method nonce for it. There is no
authentication (`__return_true`) and no ownership check (`WC_Payment_Tokens::get()` does not
compare `user_id`). Enumerating integer token IDs yields nonces for other customers' saved
cards.

**Pattern to internalise:** `__return_true` is at its most dangerous next to a
request-supplied identifier — `token_id`, `order_id`, `user_id`, `booking_id`, `file_id`.
Either alone is often survivable; together they are an unauthenticated enumeration of the
whole table. When triaging REST-001 hits, sort by whether the handler reads an ID out of the
request, and take those first.

## Detection guidance

**What the regexes catch reliably**

- `REST-001` is an exact string match with essentially no parse ambiguity. It also covers the
  three *falsy-but-allowing* helpers (`__return_zero`, `__return_empty_string`,
  `__return_empty_array`) and correctly excludes the two that deny.
- `REST-002` catches the login-only gate, which is the most common "check that isn't one".
- `REST-004` catches a permission callback gated on `read` / `exist` / `level_0`, which
  authorises nothing at all.
- `REST-007` is the counting rule, and counting is how omitted callbacks are found.

**What only the low-confidence rules reach**

`REST-003`, `REST-005`, `REST-007` and `REST-008` all fire on correct code and are worklists
by design — `REST-008` matches the exact line `tests/fixtures/safe.php` presents as a
*correct* permission callback. That is not a defect in the rule; it is the shape of the
class. The two hardest real cases in this file — a named callback whose body is
`return true;` (CVE-2023-3956) and a genuine capability check that is simply the wrong
capability (CVE-2025-4672) — are syntactically indistinguishable from correct code and are
reachable **only** through these worklists plus manual reading. Budget for that: a REST audit
is a read of every permission callback in the plugin, not a grep.

**What the regexes CANNOT catch — read the code**

1. **An omitted `permission_callback`.** There is nothing to match. The only method is to
   count `register_rest_route()` **endpoint groups** and compare against
   `permission_callback` occurrences, then read every route definition where the numbers
   disagree. Remember that one `register_rest_route()` call can define several endpoint
   groups, each needing its own callback.
2. **A named callback whose body returns `true`.** CVE-2023-3956. `REST-003` produces the
   list; you must read the bodies.
3. **Whether the capability matches the impact.** CVE-2025-4672. `manage_options` on a
   settings route is right; `edit_posts` on a user-meta route is a privilege-escalation
   primitive. `REST-008` gives you the list at low confidence — because on a post-scoped
   route the same line is correct — and only reading the handler settles it. Cross-check
   every callback against capability-matrix.md §2.
4. **Object-level authorization.** A correct capability plus a request-supplied ID is still
   IDOR. Every route pattern containing `(?P<id>…)`, and every handler reading
   `$request['…_id']`, needs either a meta capability with that ID or an explicit ownership
   comparison.
5. **Framework and base-class registration.** CVE-2026-6456. Find every wrapper around
   `register_rest_route()` and read its route table before you believe any endpoint count.
6. **Routes registered into `wp/v2` or another core namespace.** They look like core in a
   route listing. Enumerate by call site.
7. **`rest_pre_dispatch` / `rest_authentication_errors` middleware.** Authorization may
   legitimately live in a filter rather than in `permission_callback` — or may be *claimed*
   to and be optional per route. Read the filter, then check which routes opt in.
8. **`?rest_route=` reachability.** Every route is also reachable at
   `/?rest_route=/namespace/route`, so WAF rules and access controls keyed on the
   `/wp-json/` path prefix do not protect it. Never accept "it's blocked at the edge" for a
   `/wp-json/` path pattern.
9. **What `args` does and does not do.** `sanitize_callback` and `validate_callback` run
   **after** `permission_callback` and are data hygiene only. A well-specified `args` block
   next to `__return_true` is not mitigation.
10. **Non-boolean returns in longer callbacks.** `REST-006` catches the one-line cases. A
    twenty-line callback whose last statement is `return $this->cache[ $key ];` has the same
    bug and no regex will find it. Read the final expression of every permission callback and
    ask whether it can be `0`, `''` or `array()`.

## Audit checklist

- [ ] `rg -n "register_rest_route" --type php` and count **endpoint groups**, not calls.
      Compare with `rg -c "permission_callback"`. Any deficit = fully public routes.
- [ ] `rg -n "permission_callback['\"]?\s*=>\s*['\"]__return_(true|zero|empty_string|empty_array)"`
      and triage each hit by what the callback does: writes, reads non-public data, or reads a
      request-supplied identifier.
- [ ] Grep the lines adjacent to each `__return_true` for `TODO`, `FIXME`, `for now`,
      `temporary`, `if needed` — self-documented unfinished endpoints.
- [ ] `rg -n "function\s+\w*[Pp]ermission\w*\s*\("` and **read every body**. Classify:
      unconditional `true` / login-only / capability too low / capability right but no object
      check / correct.
- [ ] Run `REST-004` (high — `read`/`exist`/`level_0` authorise nothing) and `REST-008`
      (low — Contributor/Author primitives); for each `REST-008` hit, decide whether the route
      is post-scoped (often fine) or touches users, options, files or a request-supplied ID
      (finding).
- [ ] For each permission callback, confirm the return value is `true`, `false` or `WP_Error`
      and can never be `0`, `''` or `array()`.
- [ ] For each route, confirm the capability matches the worst thing the handler can do
      (capability-matrix.md §2), not what the route name suggests.
- [ ] For every route pattern with a captured ID, and every handler reading `$request['…id']`,
      confirm a meta capability with the object ID or an explicit ownership check.
- [ ] Confirm each `methods` group has its **own** `permission_callback`; a single callback
      shared by `GET` and `POST` is answering two different questions with one answer.
- [ ] Find every wrapper around `register_rest_route()` (base classes, loaders, route tables)
      and follow it to its data before trusting an endpoint count.
- [ ] Grep `rest_pre_dispatch|rest_authentication_errors|rest_authorization_required_code` for
      middleware-based authorization, and check which routes opt in.
- [ ] For intentionally public routes, verify what authenticates the caller instead: HMAC with
      `hash_equals()`, replay protection, and no request-controlled identifier reaching a
      privileged read.
- [ ] Test the route at `/?rest_route=/namespace/route` as well as `/wp-json/…` before
      accepting any edge-level mitigation.
- [ ] Cross-reference **WP-AUTHZ** for the handler body and **WP-AJAX** for the same operation
      exposed a second time as an AJAX action; plugins commonly ship both, and fixing one
      leaves the other open.
