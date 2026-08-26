---
class_id: WP-IDOR
title: Insecure Direct Object Reference — ownership of the target is never checked
cwe: [CWE-639, CWE-863, CWE-566, CWE-285]
owasp: A01:2021-Broken Access Control
severity_typical: high
auth_required_typical: subscriber+
prevalence_rank: 24
detection:
  - id: IDOR-001
    description: Object loaded directly from a request-supplied identifier
    regex: '\b(get_post|get_page|get_userdata|get_user_by|get_comment|get_term|wc_get_order|wc_get_product|get_post_meta|get_user_meta|get_comment_meta|get_term_meta)\s*\(\s*(\(\s*int\s*\)\s*)?[a-z_]*\s*\(?\s*(\(\s*int\s*\)\s*)?\$_(GET|POST|REQUEST|COOKIE)'
    confidence: medium
    false_positive_notes: >-
      This is a SUSPICIOUS SINK, not a finding. Loading an object by request id is completely
      normal — WordPress is built on it. The finding is the ABSENCE of a check, and absence
      is not greppable. For each hit the triaging agent must answer three questions by
      reading the enclosing function: (a) is there a current_user_can() naming THIS object
      id, or an explicit comparison of an owner column against get_current_user_id(); (b) if
      the object is a post, is its post_status/post_type constrained; (c) is the handler
      reachable below the privilege the object requires. Note the regex deliberately allows
      absint()/intval()/(int) between the sink and the superglobal: casting to an integer is
      input validation and has nothing to do with authorization, and its presence is the
      most common reason a reviewer marks these lines safe.
  - id: IDOR-002
    description: Write or delete keyed on a request-supplied identifier
    regex: '\b(wp_update_post|wp_delete_post|wp_trash_post|wp_update_user|wp_delete_user|wp_update_comment|wp_delete_comment|update_post_meta|update_user_meta|delete_post_meta|delete_user_meta|wp_set_password|wp_delete_attachment)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      Higher confidence than IDOR-001 because the impact is a modification rather than a
      read, and because the core functions listed here do NOT perform capability checks of
      their own — wp_update_post() and wp_update_user() will happily write to any ID they
      are given. wp_update_user() with a request-controlled ID and a user_email field is the
      account-takeover primitive: change the address, then use the normal password-reset
      flow. Safe only if a per-object capability check on the same id appears above.
  - id: IDOR-003
    description: Custom-table read or write keyed on an id column from the request
    regex: '\$wpdb->(update|delete|get_row|get_var|get_results)\s*\([^;]*[''"](id|ID|user_id|post_id|order_id|customer_id|booking_id|entry_id|item_id|ticket_id)[''"]\s*(=>|\]\s*=)'
    confidence: medium
    false_positive_notes: >-
      Plugins that keep bookings, orders, entries, tickets or licences in their own tables
      get no help from map_meta_cap() — there is no meta capability for a row in
      wp_myplugin_bookings, so the ownership check must be written by hand and usually is
      not. A hit is SAFE when the WHERE array also constrains an ownership column, e.g.
      array( 'id' => $id, 'user_id' => get_current_user_id() ). That single extra pair is
      the whole fix, and its absence is the whole bug. Read the array, not the call.
  - id: IDOR-004
    description: Singular meta capability invoked without an object id
    regex: 'current_user_can\s*\(\s*[''"](edit_post|delete_post|read_post|publish_post|edit_page|delete_page|read_page|edit_user|delete_user|remove_user|promote_user|edit_comment|edit_term|delete_term|assign_term|edit_post_meta|delete_post_meta)[''"]\s*\)'
    confidence: high
    false_positive_notes: >-
      These are META capabilities: they only mean anything when an object id is passed as
      the second argument, because map_meta_cap() uses the id to decide which primitive to
      require. Called with one argument they do not fail closed — they fall through to the
      primitive (edit_post -> edit_posts, delete_user -> delete_users), so the check passes
      for anyone holding the generic capability and says nothing about THIS object. See
      kb/reference/capability-matrix.md §4. Near-zero false positives: there is no correct
      reason to call a singular meta cap without an id.
  - id: IDOR-005
    description: Request parameter that names an object — surface mapping
    regex: '\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[''"]([a-zA-Z][a-zA-Z0-9_]*_?)?[iI][dD][''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      Deliberately broad and case-tolerant, so it catches order_id, userId, postID, uid and
      bare id. It also matches words that merely end in "id" (valid, grid, paid) and matches
      benign ids such as a nonce action id. Its job is to enumerate every request-supplied
      object reference so each one can be traced to its sink; the value is completeness of
      the worklist, not precision.
  - id: IDOR-006
    description: REST route whose path contains an object identifier
    regex: 'register_rest_route\s*\([^;]*\(\?P<[a-zA-Z_]*_?[iI][dD]>'
    confidence: medium
    false_positive_notes: >-
      A route of the shape /things/(?P<id>\d+) is an object reference by construction. The
      question is whether its permission_callback receives $request and checks ownership of
      THAT id, or whether it only checks a generic capability — the latter is the majority
      case. Note that a permission_callback which returns a non-boolean falsy value (0, '',
      array()) GRANTS access; see kb/reference/entry-points.md §5.
  - id: IDOR-007
    description: permission_callback that proves at most that the caller is logged in
    regex: '[''"]permission_callback[''"]\s*=>\s*([''"]__return_true[''"]|[''"]is_user_logged_in[''"]|function\s*\([^)]*\)\s*\{?\s*return\s+(true|is_user_logged_in))'
    confidence: high
    false_positive_notes: >-
      __return_true is legitimate for a genuinely public, read-only route over public data.
      is_user_logged_in is legitimate for a route that only ever touches the CURRENT user
      (and then the handler must use get_current_user_id(), never a request id). Anything
      else is an IDOR by construction: every Subscriber on the site reaches the handler, and
      the handler decides which object to act on from the request.
  - id: IDOR-008
    description: Entity array built with a variable ID field
    regex: '[''"]ID[''"]\s*=>\s*\$[a-zA-Z_][a-zA-Z0-9_\[\]''">\-]*'
    confidence: medium
    false_positive_notes: >-
      Matches the argument arrays passed to wp_update_post()/wp_update_user()/wp_insert_user()
      even when the request value reached the variable many lines earlier, which is the shape
      IDOR-002 misses. Deliberately does NOT match 'ID' => get_current_user_id(), which is
      the safe form. Triage by establishing the provenance of the variable; if it descends
      from the request, an ownership check must exist between the two.
  - id: IDOR-009
    description: Generic capability used as the only gate on an object-specific action
    regex: 'current_user_can\s*\(\s*[''"](edit_posts|edit_others_posts|edit_published_posts|publish_posts|upload_files|read|list_users|moderate_comments|manage_woocommerce|edit_shop_orders)[''"]\s*\)'
    confidence: low
    false_positive_notes: >-
      Very common and usually correct — a generic capability is the right gate for a generic
      action (rendering a screen, listing your own items). It becomes a finding when the
      handler goes on to act on an id from the request: "may this user edit posts in general"
      is not "may this user edit post 47". Cross-reference each hit with IDOR-001/002/003 in
      the same function; a handler that matches both and matches neither IDOR-004-with-id nor
      IDOR-010 has no object-level authorization at all.
  - id: IDOR-010
    description: Places the code establishes who the caller is — inverse grep
    regex: '\b(get_current_user_id\s*\(\s*\)|wp_get_current_user\s*\(\s*\))'
    confidence: low
    false_positive_notes: >-
      Not a vulnerability signature — the opposite. Ownership checks are invisible to
      pattern matching, but their ABSENCE becomes visible when you list every place the
      caller's identity is resolved. Run IDOR-001/002/003 to get the sinks, run this to get
      the identity sites, and treat every sink function that contains no identity site as an
      unauthenticated-target handler until proven otherwise. Beware hits that only WRITE the
      identity (update_user_meta( $id, '_author', get_current_user_id() )) without ever
      reading it back — the WCFM case study is exactly that.
fix_apis:
  - current_user_can()
  - map_meta_cap()
  - get_current_user_id()
  - wp_verify_nonce()
  - check_ajax_referer()
  - wc_get_order()
  - rest_authorization_required_code()
  - wp_generate_password()
examples:
  - cve: CVE-2026-9185
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: Tenant-portal AJAX actions registered on nopriv hooks took the tenant identifier straight from the request body and used it to fetch and update that tenant's record upstream, with no session binding of any kind.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-9185
    code_ref: https://plugins.trac.wordpress.org/browser/6storage-rentals/tags/2.20.2/inc/Base/Six_Storage_DashboardController.php#L871
    root_cause: The caller's identity was asserted by the caller — $_POST['userId'] became the path segment of the upstream API call, and nothing compared it to the session.
  - cve: CVE-2024-8290
    year: 2024
    severity: 8.8
    auth: subscriber+
    summary: A customer-management controller accepted a customer ID from the submitted form, cast it with absint(), and passed it to wp_update_user() together with a new email address, allowing any low-privileged user to retarget an administrator account.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-8290
    code_ref: https://plugins.trac.wordpress.org/browser/wc-frontend-manager/tags/6.7.12/controllers/customers/wcfm-controller-customers-manage.php#L63
    root_cause: The ownership column existed and was written on creation, but was never read before the update; absint() was mistaken for an authorization control.
  - cve: CVE-2026-1375
    year: 2026
    severity: 8.1
    auth: subscriber+
    summary: A bulk-action handler verified a nonce and a generic course-editing capability, then deleted or changed the status of every course ID in a comma-separated request parameter without checking who owned them.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-1375
    code_ref: https://plugins.trac.wordpress.org/browser/tutor/tags/3.9.5/classes/Course_List.php#L289
    root_cause: A global capability (edit_tutor_course) was checked once for the request, and no per-object capability was checked for any of the ids the request named.
  - cve: CVE-2026-3453
    year: 2026
    severity: 8.1
    auth: subscriber+
    summary: A checkout handler accepted a subscription ID intended for plan upgrades, loaded that subscription, and cancelled and expired it without verifying that it belonged to the requesting user.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-3453
    code_ref: https://plugins.trac.wordpress.org/browser/wp-user-avatar/tags/4.16.9/src/Membership/Controllers/CheckoutController.php#L237
    root_cause: A verified nonce and an (int) cast stood in for ownership validation on the change_plan_sub_id parameter.
  - cve: CVE-2026-5465
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: A provider self-service profile update merged request fields over the stored record, so the field that maps a provider to a WordPress user ID could be replaced, and the resulting ID was passed to the password-setting and user-update calls.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-5465
    code_ref: https://plugins.trac.wordpress.org/browser/ameliabooking/tags/2.1.3/src/Application/Commands/User/Provider/UpdateProviderCommandHandler.php#L146
    root_cause: The authorization branch corrected which record was loaded but not which WordPress user ID the write targeted; the link field itself was never validated as unchanged.
  - cve: CVE-2026-3360
    year: 2026
    severity: 7.5
    auth: unauthenticated
    summary: A front-end "pay for incomplete order" action verified a nonce, looked up an order by a request-supplied integer ID, and wrote submitted billing fields onto the profile of whichever user owned that order.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-3360
    code_ref: https://plugins.trac.wordpress.org/browser/tutor/tags/3.9.7/ecommerce/CheckoutController.php#L1059
    root_cause: Neither authentication nor ownership was checked before the order id was used; a typed integer parameter and a verified nonce were the only controls.
  - cve: CVE-2026-5396
    year: 2026
    severity: 8.2
    auth: subscriber+
    summary: A submission policy class authorised read, status-change, note and delete actions on form entries using a form ID taken from the query string rather than the form ID of the entry actually being acted on.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-5396
    root_cause: The authorization decision and the object it was supposed to protect were keyed on two different, independently supplied identifiers.
---

## What it is

The handler is authorised. The *target* is not. A logged-in user calls an endpoint they are
entitled to call, changes an id in the request, and the plugin operates on somebody else's
order, booking, submission, attachment or user account. There is no injection, no traversal
and no missing nonce — the request looks exactly like a legitimate one, because it *is* a
legitimate one with a different number in it.

This is the failure mode that survives review most reliably, because everything a reviewer
greps for is present: a nonce check, a `current_user_can()`, an `absint()`. The one thing
that is absent — a comparison between the object's owner and the caller — leaves no trace in
the source at all.

## Why it happens in WordPress

- **`absint()` and `(int)` read as sanitisation and get mistaken for authorization.**
  Casting `../../../etc/passwd` to `0` is meaningful for a path; casting `47` to `47` is
  meaningful for nothing. Every case study below has an integer cast on the vulnerable line.
- **A nonce answers a different question.** `check_ajax_referer()` proves the request came
  from a page the server rendered. It says nothing about *which* object the request names.
  A nonce is per-action, not per-object. See `kb/reference/entry-points.md` §0.
- **Meta capabilities silently degrade when the id is omitted.** `current_user_can( 'edit_post' )`
  does not fail closed. `map_meta_cap()` needs the id to decide which primitive to require;
  without it the check collapses to `edit_posts`, which every Contributor holds. This is the
  single highest-value pattern in the class and is documented in
  `kb/reference/capability-matrix.md` §4.
- **Custom tables get no capability model at all.** `map_meta_cap()` knows about posts,
  users, terms and comments. It knows nothing about `wp_myplugin_bookings`. Any plugin that
  stores its domain objects in its own tables — every booking, LMS, CRM, helpdesk and
  membership plugin — must write the ownership check by hand, and the ownership check is
  exactly what gets forgotten.
- **`'map_meta_cap' => false` on a custom post type.** The default for
  `register_post_type()`. With it, `current_user_can( 'edit_post', $id )` never consults the
  post's author, because the meta-cap mapping that would have done so is disabled. The check
  looks per-object and is not.
- **`wp_update_post()` and `wp_update_user()` do not check capabilities.** They are data
  layer, not policy layer. `wp_update_user( array( 'ID' => 1, 'user_email' => $mine ) )`
  succeeds from a Subscriber-level code path, and the password-reset flow does the rest.
- **Front-end "my account" dashboards duplicate admin functionality** on routes that only
  require `is_user_logged_in()`, and the object id is supplied by the page's own JavaScript
  — which the attacker edits.
- **`wp_ajax_nopriv_` on a portal endpoint** removes even the "is the caller anyone at all"
  question, leaving the request body as the sole source of identity.

## Vulnerable pattern

```php
add_action( 'wp_ajax_example_get_invoice', 'example_get_invoice' );

function example_get_invoice() {
    // A nonce: proves the request came from our page. Says nothing about WHOSE invoice.
    check_ajax_referer( 'example_invoice', 'nonce' );

    // A generic capability: proves the caller is a customer. Says nothing about WHOSE invoice.
    if ( ! is_user_logged_in() ) {
        wp_send_json_error( '', 403 );
    }

    // An integer cast: input validation, not authorization.
    $invoice_id = isset( $_POST['invoice_id'] ) ? absint( $_POST['invoice_id'] ) : 0;

    global $wpdb;
    $invoice = $wpdb->get_row(
        $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}example_invoices WHERE id = %d", $invoice_id )
    );
    // ^ Correctly prepared. Correctly typed. Completely unauthorised.

    wp_send_json_success( $invoice );
}
```

The write variant is the account-takeover primitive:

```php
function example_update_customer() {
    check_ajax_referer( 'example_customer', 'nonce' );

    $customer_id = absint( $_POST['customer_id'] );

    // wp_update_user() performs NO capability check of its own.
    wp_update_user( array(
        'ID'         => $customer_id,          // 1 is the site owner
        'user_email' => sanitize_email( $_POST['user_email'] ),
    ) );

    wp_send_json_success();
}
```

And the shape that defeats review, because the check is right there:

```php
function example_delete_item() {
    // Looks per-object. Is not: with one argument, map_meta_cap() falls through to
    // the primitive 'edit_posts', which every Contributor holds.
    if ( ! current_user_can( 'edit_post' ) ) {
        wp_send_json_error( '', 403 );
    }
    wp_delete_post( absint( $_POST['id'] ), true );
}
```

## Secure pattern

```php
/**
 * Shape 1 — CORE OBJECTS. Pass the id to the capability check. That is the whole fix.
 */
function example_update_post_title() {
    check_ajax_referer( 'example_post', 'nonce' );

    $post_id = isset( $_POST['post_id'] ) ? absint( $_POST['post_id'] ) : 0;
    if ( ! $post_id ) {
        wp_send_json_error( 'bad request', 400 );
    }

    // Constrain the TYPE as well as the id: 'edit_post' on an attachment, a WooCommerce
    // order and a plugin CPT map to different primitives, and an unexpected type is how
    // an object-level check gets bypassed sideways.
    $post = get_post( $post_id );
    if ( ! $post || 'example_doc' !== $post->post_type ) {
        wp_send_json_error( 'not found', 404 );
    }

    // Second argument = the object. map_meta_cap() now consults post_author.
    if ( ! current_user_can( 'edit_post', $post_id ) ) {
        wp_send_json_error( 'forbidden', 403 );
    }

    wp_update_post( array(
        'ID'         => $post_id,
        'post_title' => sanitize_text_field( wp_unslash( $_POST['title'] ) ),
    ) );
    wp_send_json_success();
}
```

```php
/**
 * Shape 2 — CUSTOM TABLES. No meta-cap mapping exists, so the ownership predicate goes
 * into the query itself. Filter, do not fetch-then-compare: a fetch-then-compare that
 * forgets to return leaks the row anyway.
 */
function example_get_invoice() {
    if ( ! is_user_logged_in() ) {
        wp_send_json_error( '', 403 );
    }
    check_ajax_referer( 'example_invoice', 'nonce' );

    $invoice_id = isset( $_POST['invoice_id'] ) ? absint( $_POST['invoice_id'] ) : 0;
    $user_id    = get_current_user_id();

    global $wpdb;
    $invoice = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}example_invoices WHERE id = %d AND user_id = %d",
        $invoice_id,
        $user_id
    ) );

    // A staff role gets a separate, explicit branch — never an OR inside the same query.
    if ( ! $invoice && current_user_can( 'manage_woocommerce' ) ) {
        $invoice = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}example_invoices WHERE id = %d", $invoice_id
        ) );
    }

    if ( ! $invoice ) {
        wp_send_json_error( 'not found', 404 );   // same response for "missing" and "not yours"
    }

    wp_send_json_success( example_public_invoice_fields( $invoice ) );
}
```

```php
/**
 * Shape 3 — SELF-SERVICE. When the endpoint only ever acts on the caller, do not accept an
 * id at all. An id the handler ignores is an id a future refactor will start honouring.
 */
function example_update_my_profile() {
    if ( ! is_user_logged_in() ) { wp_send_json_error( '', 403 ); }
    check_ajax_referer( 'example_profile', 'nonce' );

    wp_update_user( array(
        'ID'         => get_current_user_id(),    // not $_POST['user_id']
        'first_name' => sanitize_text_field( wp_unslash( $_POST['first_name'] ) ),
    ) );
    wp_send_json_success();
}
```

```php
/**
 * Shape 4 — REST. The permission_callback receives $request; use it. Return a real boolean
 * or a WP_Error — a falsy non-boolean (0, '', array()) is treated as ALLOW by dispatch.
 */
register_rest_route( 'example/v1', '/invoices/(?P<id>\d+)', array(
    'methods'             => WP_REST_Server::READABLE,
    'callback'            => 'example_rest_get_invoice',
    'permission_callback' => function ( WP_REST_Request $request ) {
        $invoice = example_load_invoice( (int) $request['id'] );
        if ( ! $invoice ) {
            return new WP_Error( 'not_found', __( 'Not found', 'example' ), array( 'status' => 404 ) );
        }
        return (bool) ( (int) $invoice->user_id === get_current_user_id()
                        || current_user_can( 'manage_woocommerce' ) );
    },
    'args' => array( 'id' => array( 'sanitize_callback' => 'absint' ) ),
) );
```

Four things this class turns on:

- **The capability check must name the object.** `current_user_can( $cap, $id )`, or an
  explicit comparison against `get_current_user_id()`.
- **Constrain the type, not just the id.** An object-level check on the wrong kind of object
  is not an object-level check.
- **Prefer filtering in the query to comparing after the fetch.** The comparison branch is
  what people forget to `return` from.
- **Never let the same handler learn the caller's identity from the request.** If a
  `user_id`, `customer_id` or `token` parameter exists, ask why `get_current_user_id()` is
  not enough.

## Real-world case studies

### Identity asserted by the caller (CVE-2026-9185, 7.5, unauthenticated)

```php
add_action('wp_ajax_six_storage_get_user_info', [$this, 'six_storage_getUserInfo']);
add_action('wp_ajax_nopriv_six_storage_get_user_info', [$this, 'six_storage_getUserInfo']);
...
add_action('wp_ajax_six_storage_update_profile', [$this, 'six_storage_updateProfile']);
add_action('wp_ajax_nopriv_six_storage_update_profile', [$this, 'six_storage_updateProfile']);
```

```php
public function six_storage_getUserInfo()
{
     ...
     $userId = sanitize_text_field($_POST['userId']);
     $isAjax = true;

     $url = $this->six_storage_api_url . 'user/' . $userId;

     $response = wp_remote_post(esc_url_raw($url), array(
          'method'    => 'GET',
          ...
```
`https://plugins.trac.wordpress.org/browser/6storage-rentals/tags/2.20.2/inc/Base/Six_Storage_DashboardController.php#L871`

**Root cause at that line:** `$_POST['userId']` becomes a path segment of the upstream
tenant API call and the response is returned to the caller. There is no nonce, no
capability check, no session lookup — and the handler is on a `_nopriv_` hook, so the caller
need not have an account at all. The sibling `six_storage_updateProfile()` and
`six_storage_updatePassword()` are built the same way, with `$_POST['userId']` reaching
`user/{$userId}/update` and `user/password/{$userId}/update`.

A detail worth carrying forward: a few lines below, the handler writes the upstream
response back into `$_SESSION[$table_prefix . 'userid']`. **A handler that both reads its
subject from the request and writes that subject into the session is an identity-poisoning
primitive**, not just a read — every later endpoint that trusts the session now trusts the
attacker's chosen id. This is the same two-step shape WP-DELETE documents for stored paths,
applied to identity.

### The ownership column exists and is never read (CVE-2024-8290, 8.8, subscriber+)

```php
if( isset($wcfm_customer_form_data['customer_id']) && $wcfm_customer_form_data['customer_id'] != 0 ) {
    $customer_id = absint( $wcfm_customer_form_data['customer_id'] );
    $is_update = true;
}
...
$user_data = array( 'user_login' => ..., 'user_email' => $wcfm_customer_form_data['user_email'], ...
                    'ID'         => $customer_id
                    );
if( $is_update ) {
    unset( $user_data['user_login'] );
    ...
    $customer_id = wp_update_user( $user_data ) ;
} else {
    $customer_id = wp_insert_user( $user_data ) ;

    // Customer Real Author
    update_user_meta( $customer_id, '_wcfm_customer_author', get_current_user_id() );
}
```
`https://plugins.trac.wordpress.org/browser/wc-frontend-manager/tags/6.7.12/controllers/customers/wcfm-controller-customers-manage.php#L63`

**Root cause at that line:** look at what the code *does* know. On creation it records
`_wcfm_customer_author = get_current_user_id()` — the plugin has an explicit ownership
model and stores it. On update it never reads that meta back. `absint()` on line 63 is the
only processing applied to a value that is about to become `'ID'` in a `wp_update_user()`
call, and `wp_update_user()` performs no capability check of its own. Setting
`customer_id=1` with an attacker-controlled `user_email` retargets the site owner's account;
the standard password-reset flow completes the takeover.

Two transferable lessons. First: **`update_user_meta( $id, '_owner', get_current_user_id() )`
is a write, not a check** — `IDOR-010` will show it as an identity site, and the triage step
is to confirm the value is ever read. Second, note the nonce logic at the top of the same
controller:

```php
if( isset( $wcfm_customer_form_data['wcfm_nonce'] ) && !empty( $wcfm_customer_form_data['wcfm_nonce'] ) ) {
    if( !wp_verify_nonce( $wcfm_customer_form_data['wcfm_nonce'], 'wcfm_customers_manage' ) ) {
```

— the verification runs *only if the nonce field is present*. Omitting it entirely skips the
check. That is a WP-CSRF finding in its own right, but it matters here because it removes
the last obstacle to scripting the IDOR.

### One capability check for a whole array of ids (CVE-2026-1375, 8.1, subscriber+)

```php
public function course_list_bulk_action() {

    tutor_utils()->checking_nonce();

    $action   = Input::post( 'bulk-action', '' );
    $bulk_ids = Input::post( 'bulk-ids', '' );

    // Check if user is privileged.
    if ( ! current_user_can( 'administrator' ) ) {
        if ( current_user_can( 'edit_tutor_course' ) ) {
```
`https://plugins.trac.wordpress.org/browser/tutor/tags/3.9.5/classes/Course_List.php#L289`

and the ids go straight through:

```php
public static function bulk_delete_course( $bulk_ids ): bool {
    $bulk_ids = explode( ',', sanitize_text_field( $bulk_ids ) );

    foreach ( $bulk_ids as $post_id ) {
        CourseModel::delete_course( $post_id );
    }
```

```php
public static function update_course_status( string $status, $bulk_ids ): bool {
    ...
    $ids       = array_map( 'intval', explode( ',', $bulk_ids ) );
    $in_clause = QueryHelper::prepare_in_clause( $ids );

    $update = $wpdb->query(
        $wpdb->prepare(
            "UPDATE {$post_table} SET post_status = %s WHERE ID IN ($in_clause)",
            $status
        )
    );
```

**Root cause at those lines:** the authorization decision is made **once, for the request**,
using a capability an Instructor holds by design (`edit_tutor_course`). It is never made
again for any of the ids in `bulk-ids`. Note the defences that *are* present and are
irrelevant: a verified nonce, `sanitize_text_field()`, `array_map( 'intval', ... )`, and a
properly prepared statement. Note also that `update_course_status()` writes directly to
`wp_posts` with no `post_type` predicate — so the id does not even have to be a course.

**This is the archetype of the class**: a per-request capability check standing in for a
per-object one. Bulk endpoints deserve a dedicated sweep, because the per-object check has
to go *inside the loop* and that is a shape developers rarely write.

### The nonce and the cast, with nothing behind them (CVE-2026-3453, 8.1, subscriber+)

```php
$nonce_check = check_ajax_referer('ppress_process_checkout', 'ppress_checkout_nonce', false);

if (false === $nonce_check) {
    throw new \Exception(esc_html__('Error processing checkout. Nonce failed', 'wp-user-avatar'));
}

$_POST = $this->cleanup_posted_data($_POST);

$plan_id = (int)$_POST['plan_id'];

$change_plan_sub_id = (int)$_POST['change_plan_sub_id'];
```
`https://plugins.trac.wordpress.org/browser/wp-user-avatar/tags/4.16.9/src/Membership/Controllers/CheckoutController.php#L237`

and, a hundred lines later:

```php
$sub = SubscriptionFactory::fromId($change_plan_sub_id);

if ($sub->exists()) {
    ...
    $sub->cancel(true);
    $sub->expire();
```

**Root cause at that line:** `$change_plan_sub_id` is a subscription belonging to *whoever
owns it*, and `$sub->exists()` is the only test applied before it is cancelled and expired.
The parameter is intended for "upgrade my existing plan", so the developer's mental model is
"this is my subscription" — an assumption the request does not enforce. The distance between
line 237 and line 334 is the reason `IDOR-001` cannot see this: the sink is a factory call on
a plain variable, and the superglobal is a hundred lines up. **Trace every request-derived
id to every use, not just its first.**

### The check fixed the wrong variable (CVE-2026-5465, 8.8, subscriber+)

```php
$userId = (int)$command->getArg('id');
...
if (
    !$command->getPermissionService()->currentUserCanWrite(Entities::EMPLOYEES) ||
    (
        !$command->getPermissionService()->currentUserCanWriteOthers(Entities::EMPLOYEES) &&
        (
            !$currentUser->getId() ||
            $currentUser->getId()->getValue() !== $userId
        )
    )
) {
    $oldUser = $userAS->getAuthenticatedUser($command->getToken(), false, 'providerCabinet');
```

then the request fields are merged over the loaded record:

```php
$newUserData = array_merge($oldUser->toArray(), $providerData);
...
$newUser = UserFactory::create($newUserData);
```
`https://plugins.trac.wordpress.org/browser/ameliabooking/tags/2.1.3/src/Application/Commands/User/Provider/UpdateProviderCommandHandler.php#L146`

and the WordPress-side writes use a field that came in with that merge:

```php
if ($newUser->getExternalId() && $newUser->getExternalId()->getValue()) {
    add_filter('amelia_user_profile_updated', '__return_true');
    wp_set_password($command->getField('password'), $newUser->getExternalId()->getValue());
```

**Root cause:** there *is* an ownership check, and it works — for the record that gets
loaded. When a provider updates someone else's id, the branch falls back to loading the
provider identified by their own session token, which is correct. What it does not do is
constrain `externalId`, the field that maps the provider record to a **WordPress user ID**.
`array_merge( $oldUser->toArray(), $providerData )` lets the request overwrite it, and the
merged value flows into `wp_set_password()` and `wp_update_user()`.

**The lesson generalises well beyond this plugin:** an ownership check protects the object
it names. If the request can also supply a *link* to a second object — a `user_id`, a
`parent_id`, an `externalId`, a `_wp_attached_file` — that link is a separate reference and
needs its own check, or must be excluded from the writable field set. Audit every
`array_merge`, `wp_parse_args`, `shortcode_atts` and `$model->fill( $request )` that puts
request data over a trusted record, and enumerate exactly which keys survive.

### Unauthenticated, and it writes to the victim's profile (CVE-2026-3360, 7.5, unauthenticated)

```php
public function pay_incomplete_order() {
    $order_id       = Input::post( 'order_id', 0, Input::TYPE_INT );
    $payment_method = Input::post( 'payment_method', '' );
    $request        = Input::sanitize_array( $_POST );

    $billing_model           = new BillingModel();
    $billing_fillable_fields = array_intersect_key( $request, array_flip( $billing_model->get_fillable_fields() ) );

    if ( ! tutor_utils()->is_nonce_verified() ) {
        ...
    }
    if ( $order_id ) {
        $order_model = new OrderModel();
        $order_data  = $order_model->get_order_by_id( $order_id );
```
`https://plugins.trac.wordpress.org/browser/tutor/tags/3.9.7/ecommerce/CheckoutController.php#L1059`

**Root cause at that line:** the handler is wired to a front-end action hook
(`tutor_action_tutor_pay_incomplete_order`), so it runs before any login requirement; the
order is fetched by an id the request supplies; and the billing fields from the same request
are then written against the order's owner. Every control that a scanner recognises is
present — a typed integer parameter (`Input::TYPE_INT`), an array sanitiser, a fillable-field
allowlist, and a verified nonce — and not one of them answers "whose order is this".

Note the fillable-field allowlist in particular: it constrains *which columns* may be
written, and reads exactly like an authorization control. It is not one. **Field allowlists
and object authorization are orthogonal**; a handler needs both.

### Two identifiers, one decision (CVE-2026-5396, 8.2)

A submission-policy class decided whether the caller could read, re-status, annotate or
delete a form entry by looking at a `form_id` **query parameter**, while the action itself
was performed on the entry named by a different parameter. A manager restricted to form A
sent `form_id=A` with an entry id belonging to form B.
`https://nvd.nist.gov/vuln/detail/CVE-2026-5396`

**Root cause:** the authorization decision and the object it protects were keyed on two
independently supplied identifiers. Whenever a permission check reads one request parameter
and the action reads another, the check is decorative — the attacker simply sets them
inconsistently. **The authorization predicate must be derived from the object, never
supplied alongside it:** load the entry, read *its* `form_id`, and authorise against that.

## Detection guidance

**What the regexes catch reliably**

- `IDOR-004` is the one rule here that finds bugs on its own: a singular meta capability
  called without an object id is always wrong, and it *looks* right to a reviewer.
- `IDOR-007` finds the routes where every logged-in user reaches the handler.
- `IDOR-002` finds the account-takeover shape (`wp_update_user` with a request id).

**Everything else is a worklist, and this is inherent, not a limitation of these particular
regexes.** A missing ownership check is the absence of code. There is no line to match. The
workflow this class supports is:

1. Run `IDOR-005` to enumerate every request-supplied object reference.
2. Run `IDOR-001`/`IDOR-002`/`IDOR-003`/`IDOR-008` to enumerate every sink keyed on one.
3. Run `IDOR-010` to enumerate every place the caller's identity is resolved.
4. For each sink function, ask: does an identity site appear in it, and is the identity
   actually *compared* to the object's owner rather than merely stored?

**What no regex can decide — read the code**

1. **Whether an ownership check exists at all.** The core question. Step 4 above is manual.
2. **Whether an existing check names the right object.** CVE-2026-5465: the check was real
   and guarded the wrong variable. CVE-2026-5396: the check read a different parameter than
   the action did. Confirm the predicate is derived from the loaded object.
3. **Whether the check runs per item in a bulk operation.** CVE-2026-1375. The capability
   check is outside the `foreach`. Grep for `explode( ','` and `implode` near an id
   parameter, for `IN (` clauses, and for `bulk` in function names.
4. **Whether a merge lets the request overwrite a foreign-key field.** `array_merge`,
   `wp_parse_args`, `shortcode_atts`, `->fill( $request )`, `$_POST` spread into an update
   array. Enumerate the surviving keys.
5. **Whether the CPT actually maps meta capabilities.** `register_post_type()` defaults to
   `'map_meta_cap' => false`; with it, `current_user_can( 'edit_post', $id )` never consults
   `post_author`. Grep every `register_post_type` for `map_meta_cap` and `capability_type`.
6. **Whether a field allowlist has been mistaken for an authorization control.**
   CVE-2026-3360. "Which columns may be written" and "which rows may be written" are
   different questions.
7. **Whether the identifier is guessable.** Sequential integers are the normal case.
   A UUID or a 32-character random token is *mitigation*, not a fix, but it changes
   exploitability materially — and `uniqid()`, `md5( time() )`, `rand()` and `crc32()` are
   not random (see WP-SECRETS).
8. **Whether the response leaks existence.** Returning 403 for "not yours" and 404 for
   "does not exist" turns the endpoint into an enumeration oracle even when the IDOR itself
   is fixed. Return the same status for both.
9. **Whether the plugin's own router bypasses the hook list.** `task=`, `action=`, `do=`
   dispatchers and REST routes registered in a loop never appear in a `wp_ajax_` grep.
10. **Second-order references.** An id that is legitimate for the caller resolves to a
    parent, an attachment, or a related record that is not. Follow the object graph one hop
    past the id the request supplied.

## Audit checklist

- [ ] Run `IDOR-004` first; every hit is a finding. Add the object id, or replace the meta
      cap with the primitive it was actually intended to be.
- [ ] Run `IDOR-005` to list every request-supplied object reference, then trace each to
      every use — not only its first.
- [ ] Run `IDOR-001`/`IDOR-002`/`IDOR-003`/`IDOR-008` for sinks and `IDOR-010` for identity
      sites; flag every sink function containing no identity site.
- [ ] For each `IDOR-010` hit, confirm the identity is *compared*, not merely stored. A
      `get_current_user_id()` that only ever appears inside an `update_*_meta()` call proves
      an ownership model exists and is unused.
- [ ] For every `$wpdb->update`/`delete`/`get_row` keyed on an id, confirm the WHERE also
      constrains an owner column.
- [ ] For every `current_user_can()` in a handler that acts on a request id, confirm a
      second argument naming that id.
- [ ] For every bulk/batch endpoint, confirm the authorization check is inside the loop.
- [ ] For every `register_post_type()`, check `map_meta_cap` and `capability_type`; a CPT
      with `map_meta_cap => false` has no per-object authorization no matter what the
      handler calls.
- [ ] For every REST route matched by `IDOR-006`, read the `permission_callback`: does it
      take `$request`, does it load the object, does it return a strict boolean or
      `WP_Error`? A falsy non-boolean return grants access.
- [ ] Run `IDOR-007`; for each hit decide whether the route is genuinely public and
      read-only, or genuinely self-scoped (uses only `get_current_user_id()`).
- [ ] Enumerate every `array_merge`/`wp_parse_args`/`->fill()` that puts request data over a
      loaded record and list the keys that survive; reject foreign-key fields explicitly.
- [ ] Confirm "not found" and "not yours" return identical responses.
- [ ] Enumerate the plugin's own request router (`task=`, `action=`, `do=`) before assuming
      the hook list is complete.
