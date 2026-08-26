# Fixes: the WordPress-correct patch per class

Prefer a core API over a hand-rolled check. Core's version is maintained, handles the edge
cases, and a reviewer recognises it. Show the fix as a diff against the real code.

## The guard clause every privileged handler needs

Capability and nonce are **different obligations**. A nonce proves the request was intended
by the user; a capability proves the user is allowed. Privileged state changes need both.

```php
function my_save_handler() {
    if ( ! current_user_can( 'manage_options' ) ) {              // permission
        wp_send_json_error( __( 'Denied', 'td' ), 403 );
    }
    if ( ! check_ajax_referer( 'my_save', 'nonce', false ) ) {    // intent
        wp_send_json_error( __( 'Bad nonce', 'td' ), 403 );
    }
    $value = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );
    update_option( 'my_setting', $value );
    wp_send_json_success();
}
```

Pick the capability that names the action (`manage_options`, `edit_others_posts`,
`upload_files`), never a role name and never `read`.

## WP-SQLI

```php
// wrong - interpolated before prepare sees it
$wpdb->get_results( "SELECT * FROM {$t} WHERE id = " . $_GET['id'] );
// wrong - %s already supplies quotes
$wpdb->prepare( "... WHERE name = '%s'", $name );

// right
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ) );
// identifiers (WP 6.2+)
$wpdb->prepare( "SELECT * FROM %i WHERE %i = %s", $table, $column, $value );
// IN() - one placeholder per element
$ph = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
$wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID IN ($ph)", $ids );
```

`$wpdb->prefix` and `$wpdb->posts` are trusted. `esc_sql()` is not a substitute for
`prepare()`.

## WP-XSS-S / WP-XSS-R — escape at output, by context

| Context | Function |
|---|---|
| HTML text | `esc_html()` |
| Attribute value | `esc_attr()` |
| URL (`href`/`src`) | `esc_url()` |
| Inside a `<script>` literal | `wp_json_encode()` |
| Rich text that must keep tags | `wp_kses_post()` |
| Translated string | `esc_html__()` / `esc_attr__()` |

`wp_localize_script()` runs `html_entity_decode()` over every scalar, so pre-escaping is
undone — pass raw and escape in JS, or use `wp_add_inline_script()` with
`wp_json_encode()`.

## WP-XSS-DOM

Use `.text()` / `textContent` instead of `.html()` / `innerHTML`. When markup is genuinely
required, build nodes with `document.createElement` and set properties, or sanitise
server-side and re-check that the client does not re-parse the result.

## WP-UPLOAD

```php
$overrides = array(
    'test_form' => false,
    'mimes'     => array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png' ),
);
$file = wp_handle_upload( $_FILES['file'], $overrides );
if ( isset( $file['error'] ) ) { /* reject */ }
```

Never trust `$_FILES[..]['type']`. Never build the destination name from
`$_FILES[..]['name']`. Use an allowlist, never a denylist of "bad" extensions.

## WP-LFI / WP-FILEREAD / WP-TRAVERSAL / WP-DELETE

Allowlist when the set is known:

```php
$allowed = array( 'list', 'detail' );
if ( ! in_array( $view, $allowed, true ) ) { return; }
include plugin_dir_path( __FILE__ ) . 'views/' . $view . '.php';
```

Otherwise resolve and confine:

```php
$base = trailingslashit( wp_upload_dir()['basedir'] . '/myplugin' );
$path = realpath( $base . basename( $name ) );
if ( ! $path || strpos( $path, realpath( $base ) ) !== 0 || ! is_file( $path ) ) { return; }
wp_delete_file( $path );
```

## WP-POI

```php
$data = json_decode( $raw, true );                                // preferred
$data = unserialize( $raw, array( 'allowed_classes' => false ) ); // if you must
```

## WP-SSRF

```php
$url = esc_url_raw( $input );
if ( ! wp_http_validate_url( $url ) ) { return new WP_Error( 'bad_url' ); }
$res = wp_safe_remote_get( $url, array( 'timeout' => 5, 'redirection' => 0 ) );
```

Set `redirection => 0`: safety travels with the args, and a redirect can land somewhere the
first check passed. On sites below WP 7.1, also reject `169.254.169.254` explicitly. Never
filter `http_request_host_is_external` to `__return_true`.

## WP-REDIRECT

`wp_safe_redirect()` for anything derived from a request. `wp_redirect()` only for a
hard-coded or already-validated destination; `wp_validate_redirect( $url, $fallback )` to
check one yourself.

## WP-REST

```php
'permission_callback' => function () { return current_user_can( 'edit_posts' ); },
```

Return a strict boolean or `WP_Error`. `__return_true` — and a closure that just returns
`true` — is only acceptable on a genuinely public route, and then the callback must
constrain what it returns (`post_status => 'publish'`, an allowlist of post types).

## WP-AJAX

Register `wp_ajax_nopriv_` only for something the whole internet may do. The handler still
needs its own nonce check and rate consideration; "nopriv" means "no login", not "no rules".

## WP-PRIVESC / WP-OPTIONS

Never let a role, capability, or meta **key** come from the request. Allowlist the key:

```php
$allowed_keys = array( 'first_name', 'last_name', 'billing_phone' );
if ( ! in_array( $key, $allowed_keys, true ) ) { return; }
update_user_meta( $user_id, $key, $value );
```

Guard `set_role()`/`add_cap()` with `current_user_can( 'promote_users' )` and an explicit
allowlist of assignable roles. Treat `users_can_register`, `default_role` and mail settings
as takeover-critical.

## WP-IDOR

```php
$order = wc_get_order( $order_id );
if ( ! $order || $order->get_customer_id() !== get_current_user_id() ) {
    if ( ! current_user_can( 'manage_woocommerce' ) ) { wp_die(); }
}
```

## WP-SECRETS

Keep credentials out of source. Use `wp_generate_password( 32, false )` or
`random_bytes()` for tokens — never `rand`, `mt_rand`, or `uniqid`. Compare secrets with
`hash_equals()`, never `==`.

## WP-XXE

Drop `LIBXML_NOENT`. On PHP 8 the defaults are safe; pass `LIBXML_NONET` to be explicit.

## WP-AUTHBYPASS

Verify the token server-side against the provider, bind the verified identity to a local
account by an immutable id (not a submitted email), compare with `hash_equals()`, and check
the return value of every verification call — `openssl_verify()` returns `-1` on error,
which is truthy.
