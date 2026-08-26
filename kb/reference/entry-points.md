# Reference: Untrusted-Input Entry Points in WordPress

**Audience:** an auditing agent that must enumerate every path by which an
unauthenticated or low-privileged HTTP request reaches plugin/theme code.

**Verified against:** WordPress core `master` (7.2-alpha; current stable release
7.1) — `wp-admin/admin-ajax.php`, `wp-admin/admin-post.php`,
`wp-includes/rest-api.php`, `wp-includes/rest-api/class-wp-rest-server.php`,
`wp-includes/load.php`, `wp-includes/pluggable.php`.

---

## 0. The rule that governs this whole document

> **Registering a callback on a hook grants no authorization whatsoever.**

WordPress hooks are a *dispatch* mechanism, not an *access control* mechanism.
Every hook below will happily invoke plugin code for an anonymous attacker. The
only things that stop them are checks the plugin author writes **inside** the
callback:

| Control | Answers the question | Defeats |
|---|---|---|
| `current_user_can( $cap )` | *May this user do this?* | WP-ACL, WP-PRIVESC, WP-IDOR |
| `wp_verify_nonce` / `check_admin_referer` / `check_ajax_referer` | *Did this user intend this, from our UI?* | WP-CSRF |
| `sanitize_*` on input, `esc_*` on output, `$wpdb->prepare` | *Is the data safe in its sink?* | WP-SQLI, WP-XSS-\*, WP-LFI, WP-RCE |

A handler needs **all three**. Nonce without capability = CSRF-proof privilege
escalation. Capability without nonce = CSRF. Both without sanitization = injection.

---

## 1. `is_admin()` is NOT an authorization check

This single misconception is responsible for a large share of real WordPress
vulnerabilities, so it leads this document.

Core's own definition (`wp-includes/load.php`):

```php
function is_admin() {
	if ( isset( $GLOBALS['current_screen'] ) ) {
		return $GLOBALS['current_screen']->in_admin();
	} elseif ( defined( 'WP_ADMIN' ) ) {
		return WP_ADMIN;
	}
	return false;
}
```

`is_admin()` returns the value of the `WP_ADMIN` constant. Core's own docblock
for the sibling function says it plainly:

> "Does not check if the user is an administrator; use `current_user_can()` for
> checking roles and capabilities."

**`WP_ADMIN` is defined as `true` by both of these files, before any login check:**

- `wp-admin/admin-ajax.php` — `if ( ! defined( 'WP_ADMIN' ) ) { define( 'WP_ADMIN', true ); }`
- `wp-admin/admin-post.php` — same lines.

Therefore `is_admin()` is `true` for a completely anonymous `POST /wp-admin/admin-ajax.php`.

### What `is_admin()` actually means

"The current request is being served by code under `/wp-admin/`, or by
`admin-ajax.php` / `admin-post.php`." It answers *where am I*, not *who are you*.

### The vulnerable pattern to flag

```php
// VULNERABLE — WP-ACL / WP-AUTHBYPASS
function my_delete_thing() {
	if ( ! is_admin() ) {          // <-- true for any anonymous admin-ajax request
		return;
	}
	$wpdb->delete( 'my_table', array( 'id' => $_POST['id'] ) );
}
add_action( 'wp_ajax_nopriv_delete_thing', 'my_delete_thing' );
```

### Related non-checks (all frequently misused as authorization)

| Function | What it really tells you | Authorization value |
|---|---|---|
| `is_admin()` | Request is admin-side / ajax / admin-post | **None** |
| `is_user_logged_in()` | A cookie session exists | Subscriber-level only |
| `wp_doing_ajax()` / `DOING_AJAX` | Request came via admin-ajax.php | **None** |
| `is_user_admin()` | Request is in the *user* admin (multisite `/wp-admin/user/`) | **None** |
| `is_network_admin()` | Request is in the network admin screens | **None** |
| `defined('WP_ADMIN')` | Same as `is_admin()` | **None** |
| `check_admin_referer()` | Nonce/referer matched | CSRF only, **not** capability |
| `$_SERVER['HTTP_REFERER']` | Attacker-controlled header | **None** |
| `is_super_admin()` | *Is* a real check (multisite) | Genuine, but see capability-matrix.md |
| `current_user_can( $cap )` | *Is* the real check | **This is the one** |

> **Audit heuristic:** any `is_admin()` appearing in a conditional that guards a
> state change, a database write, a file operation, or an option update is a
> finding until proven otherwise. `is_admin()` is legitimate only for deciding
> *what to load* (e.g. "only register this admin menu on admin screens").

---

## 2. `admin-ajax.php` — `wp_ajax_nopriv_{action}` and `wp_ajax_{action}`

### Registration signature

```php
add_action( 'wp_ajax_nopriv_' . $action, $callback, $priority = 10, $accepted_args = 1 ); // logged OUT
add_action( 'wp_ajax_'        . $action, $callback, $priority = 10, $accepted_args = 1 ); // logged IN
```

### Reachability

| Hook | URL | Who can reach it |
|---|---|---|
| `wp_ajax_nopriv_{action}` | `POST\|GET /wp-admin/admin-ajax.php?action={action}` | **Anyone on the internet.** No cookie, no nonce, no account. |
| `wp_ajax_{action}` | same URL | **Any logged-in user**, including a brand-new Subscriber from open registration. |

The action name is read from `$_REQUEST['action']`, so it may arrive via **GET or
POST** regardless of which the plugin intended. A handler that only reads
`$_POST` can still be *invoked* by GET.

### Dispatch logic (verbatim shape, from `wp-admin/admin-ajax.php`)

```php
$action = $_REQUEST['action'];

if ( is_user_logged_in() ) {
	if ( ! has_action( "wp_ajax_{$action}" ) ) { wp_die( '0', 400 ); }
	do_action( "wp_ajax_{$action}" );
} else {
	if ( ! has_action( "wp_ajax_nopriv_{$action}" ) ) { wp_die( '0', 400 ); }
	do_action( "wp_ajax_nopriv_{$action}" );
}
```

Note what is **absent**: no nonce check, no capability check, no referer check.
`is_user_logged_in()` is the *only* gate, and it merely selects which of the two
hooks fires.

### Authorization it does NOT provide

- ❌ No capability check of any kind.
- ❌ No nonce / CSRF check.
- ❌ No rate limiting.
- ❌ `wp_ajax_{action}` distinguishes **logged-in from logged-out**, nothing more.
  A Subscriber and an Administrator hit the identical hook.
- ✅ It *does* guarantee the user has *some* account, if and only if you register
  **only** the `wp_ajax_` variant and **not** the `_nopriv_` variant.

### The classic double-registration bug

```php
// VULNERABLE — WP-AJAX / WP-ACL
add_action( 'wp_ajax_export_users',        'my_export_users' );
add_action( 'wp_ajax_nopriv_export_users', 'my_export_users' ); // <-- opens it to the world
```

Registering both hooks to the same callback is nearly always wrong unless the
callback is genuinely public *and* read-only. Flag every `wp_ajax_nopriv_`
registration and demand a justification for it.

### CORS note

`admin-ajax.php` calls `send_origin_headers()`, which honours the
`allowed_http_origins` filter. A plugin that widens that filter turns every AJAX
action into a cross-origin-readable endpoint.

---

## 3. `admin-post.php` — `admin_post_nopriv_{action}` and `admin_post_{action}`

### Registration signature

```php
add_action( 'admin_post_nopriv_' . $action, $callback ); // logged OUT
add_action( 'admin_post_'        . $action, $callback ); // logged IN
add_action( 'admin_post_nopriv',            $callback ); // logged OUT, NO action param supplied
add_action( 'admin_post',                   $callback ); // logged IN,  NO action param supplied
```

The last two are easy to miss: they fire when `$_REQUEST['action']` is **empty**.
Grep for them separately.

### Reachability

`POST` (or `GET`) to `/wp-admin/admin-post.php?action={action}`. Identical trust
model to `admin-ajax.php`: `_nopriv_` = the entire internet, non-`_nopriv_` = any
logged-in user at any level.

The difference from `admin-ajax.php` is only in intent: `admin-post.php` is
designed for **form submissions that redirect**, so its handlers are far more
likely to perform state changes — making a missing nonce or capability check
directly exploitable (WP-CSRF, WP-OPTION, WP-SETTINGS, WP-PRIVESC).

`$action` here is passed through `sanitize_text_field()` by core before hook
dispatch, which is a small difference from `admin-ajax.php` but has no security
significance for the handler.

### Authorization it does NOT provide

Same list as `admin-ajax.php`. No capability, no nonce, no referer check.

---

## 4. `admin_init` — reachable by ANY logged-in user, and by anonymous users

**This is the highest-value misconception in this document after `is_admin()`.**

Developers assume `admin_init` means "an administrator is initialising the admin
area". It does not. `admin_init` fires from **three** places, and two of them are
not the admin screens at all:

| File | Auth performed before `do_action( 'admin_init' )` | Result |
|---|---|---|
| `wp-admin/admin.php` | `auth_redirect()` + `current_user_can()` for the screen | Requires login, and (usually) some admin capability |
| `wp-admin/admin-ajax.php` | **none** | Fires for **anonymous** requests |
| `wp-admin/admin-post.php` | **none** | Fires for **anonymous** requests |

From `wp-admin/admin-ajax.php`, in file order:

```php
define( 'DOING_AJAX', true );
if ( ! defined( 'WP_ADMIN' ) ) { define( 'WP_ADMIN', true ); }
require_once dirname( __DIR__ ) . '/wp-load.php';
send_origin_headers();
...
if ( empty( $_REQUEST['action'] ) || ! is_scalar( $_REQUEST['action'] ) ) { wp_die( '0', 400 ); }
require_once ABSPATH . 'wp-admin/includes/admin.php';
require_once ABSPATH . 'wp-admin/includes/ajax-actions.php';
send_nosniff_header();
nocache_headers();
/** This action is documented in wp-admin/admin.php */
do_action( 'admin_init' );          // <-- NO auth check anywhere above this line
```

`wp-admin/admin-post.php` is the same: `require wp-load.php`, `send_origin_headers()`,
`require admin.php`, `nocache_headers()`, then `do_action( 'admin_init' )` — and
only *after* that does it branch on `is_user_logged_in()`.

### Exploitation shape

```php
// VULNERABLE — WP-OPTION / WP-SETTINGS / WP-PRIVESC
add_action( 'admin_init', function () {
	if ( isset( $_POST['my_plugin_save'] ) ) {          // no cap, no nonce
		update_option( 'my_plugin_settings', $_POST['settings'] );
	}
} );
```

An attacker reaches this with:

```
POST /wp-admin/admin-post.php?action=anything_registered
my_plugin_save=1&settings[...]=...
```

…with **no cookie at all**. `admin_init` runs, the plugin's handler runs, the
option is written. Core's later `wp_die( '', 400 )` for an unregistered action is
irrelevant — the damage happened during `admin_init`.

> **Audit heuristic:** every `add_action( 'admin_init', ... )` whose callback
> inspects `$_GET`/`$_POST`/`$_REQUEST` and performs a state change must contain
> both a capability check and a nonce check inside the callback. Treat the hook
> as fully unauthenticated.

### Related admin-side hooks with the same caveat

`admin_menu`, `admin_enqueue_scripts`, `current_screen`, and `load-{$page_hook}`
do **not** fire on `admin-ajax.php` / `admin-post.php` (they are added by
`wp-admin/admin.php` and the screen loader), so they are genuinely admin-screen
only. But `admin_menu` running only on admin screens still does not mean the
*callback registered by* a menu page is protected — see §5.

### Menu-page callbacks

```php
add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback );
add_submenu_page( $parent, $page_title, $menu_title, $capability, $menu_slug, $callback );
```

The `$capability` argument gates **whether the menu item renders and whether the
screen loads** — core checks it in `user_can_access_admin_page()`. That is a real
check for direct navigation to `/wp-admin/admin.php?page={slug}`. **But:**

- If the plugin also processes `$_POST` inside the page callback, and the page
  callback is *additionally* wired to `admin_init` or `admin-post.php`, the
  capability on the menu registration does nothing for that second path.
- Passing a low capability such as `'read'` (every logged-in user, including
  Subscribers) as `$capability` is a common WP-ACL finding.
- `add_options_page()`, `add_management_page()` etc. have fixed default
  capabilities but the argument is still overridable.

---

## 5. REST API — `register_rest_route`

### Registration signature

```php
register_rest_route(
	string $namespace,   // e.g. 'myplugin/v1'
	string $route,       // e.g. '/things/(?P<id>\d+)'
	array  $args = array(),
	bool   $override = false
);
```

with each endpoint in `$args`:

```php
array(
	'methods'             => WP_REST_Server::READABLE,  // 'GET' | 'POST' | ...
	'callback'            => 'my_handler',
	'permission_callback' => 'my_permission_check',     // REQUIRED — see below
	'args'                => array(
		'id' => array(
			'required'          => true,
			'type'              => 'integer',
			'validate_callback' => 'my_validator',
			'sanitize_callback' => 'absint',
		),
	),
)
```

Routes are registered on the `rest_api_init` hook. Reachable at
`/wp-json/{namespace}/{route}` (or `?rest_route=/{namespace}/{route}` when pretty
permalinks are off — **note this alternate form; WAF rules keyed on `/wp-json/`
miss it**).

### Reachability

**Anyone on the internet**, by default. The REST API is public infrastructure;
core exposes it without authentication and plugins add routes to the same
surface. Authentication (cookie+nonce, application passwords, or a plugin-provided
scheme) is *optional* per request.

### `permission_callback` semantics — verified in core

Since **WordPress 5.5**, `register_rest_route()` emits a `_doing_it_wrong()`
notice when `permission_callback` is absent. From `wp-includes/rest-api.php`:

```php
if ( ! isset( $arg_group['permission_callback'] ) ) {
	_doing_it_wrong(
		__FUNCTION__,
		sprintf(
			__( 'The REST API route definition for %1$s is missing the required %2$s argument. For REST API routes that are intended to be public, use %3$s as the permission callback.' ),
			'<code>' . $clean_namespace . '/' . trim( $route, '/' ) . '</code>',
			'<code>permission_callback</code>',
			'<code>__return_true</code>'
		),
		'5.5.0'
	);
}
```

> ⚠️ **CRITICAL — the notice does not block anything.** `_doing_it_wrong()` is a
> developer notice. It is *silent* unless `WP_DEBUG` is on, the route is still
> registered, and the request still executes. Enforcement in
> `WP_REST_Server::dispatch()` is:
>
> ```php
> if ( ! is_wp_error( $response ) && ! empty( $handler['permission_callback'] ) ) {
> 	$permission = call_user_func( $handler['permission_callback'], $request );
> 	if ( is_wp_error( $permission ) ) {
> 		$response = $permission;
> 	} elseif ( false === $permission || null === $permission ) {
> 		$response = new WP_Error( 'rest_forbidden', ..., array( 'status' => rest_authorization_required_code() ) );
> 	}
> }
> ```
>
> `! empty( $handler['permission_callback'] )` — **a missing, `null`, `false`, or
> empty-string `permission_callback` means the block is skipped entirely and the
> endpoint executes for anonymous callers.** "Required" is documentation, not
> enforcement. Never assume WP 5.5+ closed these holes.

#### Return-value trap in `permission_callback`

The rejection test is `false === $permission || null === $permission` — **strict
comparison**. Consequences an auditor must encode:

| Callback returns | Result |
|---|---|
| `true` | Allowed |
| `false` | Denied (403/401) |
| `null` (including *falling off the end of the function*) | Denied — fails closed ✅ |
| `WP_Error` | Denied, with your error surfaced |
| `0`, `'0'`, `''`, `array()`, `0.0` | **ALLOWED** — falsy but not `false`/`null` ⚠️ |

So `'permission_callback' => fn( $r ) => get_current_user_id()` **grants access to
anonymous users**, because `get_current_user_id()` returns `int 0` when logged
out, and `0 !== false`. Likewise any callback returning a count, an ID, or a
`strpos()` result. Flag `permission_callback` bodies whose final expression is not
clearly boolean.

> Separately note that `rest_send_allow_header()` (which builds the `Allow`
> header) uses `true === $permission`, i.e. *stricter* than dispatch. The two are
> inconsistent; only dispatch controls access.

### Authorization `register_rest_route` does NOT provide

- ❌ No default authentication — routes are public unless `permission_callback` says otherwise.
- ❌ No CSRF protection *of its own*. See below.
- ❌ `'methods' => 'POST'` is not a security control.
- ❌ `args` `sanitize_callback` runs **after** `permission_callback`; it is data hygiene, not access control.

### REST and CSRF

The REST API's CSRF story is different from admin-ajax:

- **Cookie authentication** to the REST API *requires* the `X-WP-Nonce` header (or
  `_wpnonce` param) carrying a `wp_rest` nonce. Core enforces this in
  `rest_cookie_check_errors()`. So a cookie-authenticated REST request is
  CSRF-protected **by core**, and a plugin does *not* need its own nonce.
- **Application passwords / OAuth / other non-cookie auth** are not
  cookie-riding, so CSRF does not apply.
- ⚠️ Therefore: adding `check_ajax_referer()` inside a REST callback is usually
  redundant, but **removing** `permission_callback` because "the nonce protects
  it" is a serious error — the nonce only applies when the caller chose cookie
  auth. An anonymous, cookie-less request skips `rest_cookie_check_errors()`
  entirely.

---

## 6. Front-end request hooks that inspect `$_GET` / `$_POST`

These fire on **every front-end page load**, for **anonymous visitors**, with no
auth of any kind. A plugin that inspects superglobals inside them has created an
unauthenticated endpoint at *every URL on the site*.

| Hook | Fires on | Notes |
|---|---|---|
| `plugins_loaded` | Every request (front, admin, ajax, REST, cron) | Runs before the user is even resolved; `current_user_can()` here is unreliable — see §11 |
| `init` | Every request of every kind | The single most common place an accidental unauthenticated endpoint appears |
| `wp_loaded` | Every request, after `init` | Same exposure as `init` |
| `parse_request` | Front-end + REST; receives the `WP` object | Often used to build "pretty" custom endpoints |
| `request` (filter) | Front-end query var assembly | Attacker-controlled query vars |
| `send_headers` | Front-end | |
| `wp` | Front-end, after query is set up | |
| `template_redirect` | Front-end page rendering only | Very common for "custom endpoint" / download handlers |
| `pre_get_posts` | Any `WP_Query` | Attacker-influenced query args |

### The pattern to flag

```php
// VULNERABLE — WP-LFI / WP-ACL, reachable by anyone at any front-end URL
add_action( 'template_redirect', function () {
	if ( isset( $_GET['download_file'] ) ) {
		readfile( WP_CONTENT_DIR . '/private/' . $_GET['download_file'] );
		exit;
	}
} );
```

```php
// VULNERABLE — WP-PRIVESC, fires for anonymous visitors on every page
add_action( 'init', function () {
	if ( isset( $_GET['make_me_admin'] ) ) {
		$u = new WP_User( get_current_user_id() );
		$u->set_role( 'administrator' );
	}
} );
```

> **Audit heuristic:** grep for `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`,
> `$_COOKIE`, `$_SERVER` inside callbacks attached to `init`, `wp_loaded`,
> `template_redirect`, `parse_request`, and `plugins_loaded`. Each hit is an
> unauthenticated entry point until a capability + nonce check is found.

---

## 7. Shortcodes

### Registration signature

```php
add_shortcode( string $tag, callable $callback );
// $callback( array|string $atts, string|null $content, string $tag )
```

### Reachability and trust model

Shortcodes execute when `do_shortcode()` runs over content — by default via the
`the_content` filter on the front end. The attacker's lever is **who can put a
shortcode into rendered content**:

| Vector | Required privilege | Notes |
|---|---|---|
| Shortcode in a post/page | **Contributor+** (`edit_posts`) | Contributor can save a draft containing arbitrary shortcodes with arbitrary attributes; a preview renders it, and an Editor previewing it renders it in *their* session |
| Shortcode in a widget / block | Editor+ / Admin | |
| Shortcode in a comment | Only if the plugin/theme added `do_shortcode` to `comment_text` | Not core default — but check for it |
| Shortcode in usermeta / profile field rendered via `do_shortcode` | Subscriber+ | |
| Shortcode attributes reflected from `$_GET` by the shortcode itself | **Unauthenticated** | e.g. `[my_search term="..."]` that falls back to `$_GET['s']` |

**Attributes are attacker-controlled strings.** `shortcode_atts()` merges
defaults; it does **not** sanitize. Core lowercases attribute *names* but leaves
*values* untouched.

```php
// VULNERABLE — WP-XSS-S (Contributor+) and WP-SQLI
add_shortcode( 'user_card', function ( $atts ) {
	$a = shortcode_atts( array( 'id' => 0, 'class' => '' ), $atts );
	$row = $GLOBALS['wpdb']->get_row( "SELECT * FROM t WHERE id = {$a['id']}" ); // WP-SQLI
	return '<div class="' . $a['class'] . '">' . $row->name . '</div>';          // WP-XSS-S
} );
```

Shortcode output is **echoed into `the_content` after `wp_kses` has already run**,
so `wp_kses_post` filtering of the post body does *not* sanitize what a shortcode
callback returns. This is why Contributor-authored shortcode attributes produce
real stored XSS even on sites where post content is KSES-filtered.

Note also: **`unfiltered_html` does not gate shortcodes.** A Contributor without
`unfiltered_html` still gets their shortcode *executed*; KSES strips raw
`<script>` from their post body but the shortcode tag itself survives KSES and
the callback's return value is inserted unfiltered.

---

## 8. Blocks — `render_callback`

### Registration signature

```php
register_block_type( $block_type, array(
	'attributes'     => array( 'url' => array( 'type' => 'string' ) ),
	'render_callback' => 'my_render',   // $attributes, $content, $block
) );
// or via block.json:  "render": "file:./render.php"
```

### Reachability and trust model

Structurally identical to shortcodes: `$attributes` come from the serialized block
comment in post content, so they are controlled by **whoever can edit the post
(Contributor+)**.

Extra traps specific to blocks:

- The `attributes` schema in `block.json` provides `type` coercion for
  *registered* attributes only. **Unregistered attributes present in the block
  comment are still passed through** in many code paths — do not treat the schema
  as a whitelist.
- Dynamic blocks rendered via `render_callback` output **after** KSES, exactly like
  shortcodes (WP-XSS-S).
- `render_callback` also runs for the **REST block-renderer endpoint**
  `/wp-json/wp/v2/block-renderer/{name}`, which requires `edit_posts` — meaning a
  Contributor can invoke your `render_callback` with **fully arbitrary attributes**
  directly, without ever saving a post. This is a cleaner exploit path than post
  preview and auditors should assume it exists for every dynamic block.

---

## 9. WP-Cron and scheduled events

### Registration signature

```php
wp_schedule_event( $timestamp, $recurrence, $hook, $args = array() );
wp_schedule_single_event( $timestamp, $hook, $args = array() );
add_action( $hook, $callback );          // the actual handler
```

### Reachability — a nuanced case

Cron **callbacks** are not directly attacker-invocable with arbitrary arguments;
`$args` are whatever was passed at scheduling time. But:

- **`wp-cron.php` is web-accessible and unauthenticated by default.** Anyone can
  `GET /wp-cron.php?doing_wp_cron` to force the queue to run. This makes cron an
  attacker-controlled *trigger* — useful for timing, for racing, and for
  converting a "stored" payload into execution on demand.
- If the plugin **schedules an event with attacker-influenced `$args`** (e.g. a
  URL submitted by an anonymous form), the cron callback becomes a deferred
  unauthenticated sink — a very common WP-SSRF pattern.
- Cron callbacks run with **no user context**: `get_current_user_id()` is `0` and
  `current_user_can()` is meaningless. Do not add capability checks inside cron
  callbacks expecting them to pass; validate at *scheduling* time instead.
- `DISABLE_WP_CRON` only stops the front-end spawn; `wp-cron.php` remains
  reachable unless blocked at the web-server level.

**Audit action:** trace what data flows into `wp_schedule_*_event()` `$args`. If it
originates from a request, the cron callback inherits that taint.

---

## 10. Other entry points

### XML-RPC (`xmlrpc.php`)

```php
add_filter( 'xmlrpc_methods', function ( $methods ) {
	$methods['my.method'] = 'my_callback';   // $args from the XML payload
	return $methods;
} );
```

- **Unauthenticated reachability:** `xmlrpc.php` is public. Most core methods take
  username/password as the first args and authenticate per call, but **the method
  dispatch itself is anonymous**, and a plugin-registered method authenticates
  only if the plugin writes that code.
- Historically significant for credential brute-forcing (`system.multicall`
  amplification) and for pingback-driven SSRF.
- The `xmlrpc_enabled` filter disables only the *authenticated* methods, not the
  endpoint. Plugin-added methods keep working.
- Treat every `xmlrpc_methods` entry as an unauthenticated entry point.

### Webhook / third-party callback endpoints

Plugins that receive payment, form, or integration callbacks typically expose them
via one of the mechanisms above (usually `wp_ajax_nopriv_`, `init` +
`$_GET['my_webhook']`, or a REST route with `permission_callback => '__return_true'`).

These are **legitimately unauthenticated** — the remote service has no WordPress
cookie. That does **not** make them unauthorized. The correct control is
payload authentication, and an auditor must check for it:

| Control | Look for |
|---|---|
| HMAC signature verification | `hash_hmac()` + **`hash_equals()`** (not `==` / `!==` on strings) |
| Shared secret in the payload | Compared with `hash_equals()`, and not logged |
| Source IP allowlist | Weak alone; check it does not trust `X-Forwarded-For` |
| Replay protection | Timestamp window + nonce/event-ID de-duplication |
| TLS + verified provider certificate | `sslverify` not set to `false` |

A webhook that "authenticates" by checking a secret passed in the **URL query
string** (`?key=...`) leaks it via logs, referers, and analytics — flag as WP-INFO
plus weak authentication. A webhook with **no** verification is WP-AUTHBYPASS.

### WP-CLI — **not attacker-reachable**

```php
WP_CLI::add_command( 'my-plugin thing', 'My_Command_Class' );
```

WP-CLI runs from a shell on the server. Reaching it already requires OS-level
access, at which point the WordPress trust model is moot.

- ✅ Missing `current_user_can()` in a WP-CLI command is **not** a vulnerability.
- ✅ Missing nonce checks in WP-CLI commands are **not** a vulnerability (there is
  no browser, so no CSRF).
- ⚠️ **But:** SQL injection in a WP-CLI command *is* still a bug if the parameters
  can come from anywhere but the operator, and code shared between a CLI command
  and a web handler must be judged by the *web* handler's trust level.
- ⚠️ `WP_CLI::runcommand()` / `shell_exec` in a plugin's **web** path is WP-RCE.

Guard with `if ( defined( 'WP_CLI' ) && WP_CLI )` and confirm the code is genuinely
unreachable from HTTP before down-rating a finding.

### Other non-HTTP contexts with no user

`wp_mail` filters, `save_post` from an importer, `wp_insert_post` during a
migration, and cron all run with **no current user**. Capability checks placed
there silently fail (or silently pass, if inverted). Validate at the point where
the request enters, not deep in a hook chain.

---

## 11. Hook timing vs. user availability

A capability check is only meaningful once WordPress knows who the user is.
`current_user_can()` triggers user resolution, but on very early hooks the
pluggable auth functions and the current user may not be settled, and plugins that
filter authentication may not have loaded.

| Hook | Current user reliable? | Notes |
|---|---|---|
| `muplugins_loaded` | ❌ | Far too early |
| `plugins_loaded` | ⚠️ | Pluggable functions defined, but auth plugins may not have hooked yet |
| `after_setup_theme` | ⚠️ | |
| `set_current_user` | ✅ | The user is now determined |
| `init` | ✅ | First hook where `current_user_can()` is dependable |
| `wp_loaded`, `admin_init`, `template_redirect`, `rest_api_init` | ✅ | |

Do **not** perform authorization on `plugins_loaded` or earlier. Do the work on
`init` or later — or, better, inside the request handler itself.

---

## 12. Auditor's enumeration checklist

Run this against any plugin/theme to build the entry-point inventory before
looking for any specific vulnerability class.

```bash
# 1. AJAX
rg -n "add_action\s*\(\s*['\"]wp_ajax_nopriv_" --type php     # UNAUTHENTICATED
rg -n "add_action\s*\(\s*['\"]wp_ajax_"        --type php     # any logged-in user

# 2. admin-post
rg -n "add_action\s*\(\s*['\"]admin_post_nopriv" --type php   # UNAUTHENTICATED
rg -n "add_action\s*\(\s*['\"]admin_post"        --type php

# 3. REST
rg -n "register_rest_route" --type php
rg -n "permission_callback" --type php                        # then diff counts against routes
rg -n "permission_callback['\"]?\s*=>\s*['\"]__return_true"  --type php

# 4. admin_init and friends
rg -n "add_action\s*\(\s*['\"]admin_init" --type php

# 5. Front-end request hooks
rg -n "add_action\s*\(\s*['\"](init|wp_loaded|template_redirect|parse_request|plugins_loaded)['\"]" --type php

# 6. Shortcodes and blocks
rg -n "add_shortcode|register_block_type|render_callback" --type php

# 7. Cron and XML-RPC
rg -n "wp_schedule_event|wp_schedule_single_event|xmlrpc_methods" --type php

# 8. The misconception detectors
rg -n "if\s*\(\s*!?\s*is_admin\s*\(\s*\)" --type php
rg -n "if\s*\(\s*!?\s*is_user_logged_in\s*\(\s*\)" --type php
rg -n "current_user_can" --type php                            # compare count to entry-point count
```

For each entry point found, record:

1. **Hook / registration** and file:line.
2. **Minimum privilege to reach it** — unauthenticated / subscriber+ / contributor+ / author+ / editor+ / admin+.
3. **Capability check present?** — which capability, and does it match the action's impact?
4. **Nonce check present?** — and is it checked *before* any side effect?
5. **Input handling** — which superglobals, sanitized how, reaching which sink.
6. **Side effects** — DB write, option write, file write/read/delete, HTTP request, user/role change, email.

An entry point missing #3 or #4 while having a side effect in #6 is a finding.
Rate it using the privilege from #2 — see `capability-matrix.md`.

---

## 13. Quick-reference table

| Entry point | Registration | Minimum privilege to reach | Auth provided by core |
|---|---|---|---|
| `wp_ajax_nopriv_{a}` | `add_action` | **Unauthenticated** | None |
| `wp_ajax_{a}` | `add_action` | Any logged-in user (Subscriber) | Login only |
| `admin_post_nopriv_{a}` / `admin_post_nopriv` | `add_action` | **Unauthenticated** | None |
| `admin_post_{a}` / `admin_post` | `add_action` | Any logged-in user (Subscriber) | Login only |
| `register_rest_route` | `rest_api_init` | **Unauthenticated** | **None unless `permission_callback` is set AND returns `false`/`null`/`WP_Error`** |
| `admin_init` | `add_action` | **Unauthenticated** (via admin-ajax.php / admin-post.php) | None |
| `add_menu_page` callback | `admin_menu` | The `$capability` argument — *for direct screen access only* | Capability, for that path only |
| `init` / `wp_loaded` / `template_redirect` / `parse_request` | `add_action` | **Unauthenticated** | None |
| `plugins_loaded` | `add_action` | **Unauthenticated** | None; user not yet reliable |
| Shortcode callback | `add_shortcode` | Contributor+ (content), or unauthenticated if atts come from `$_GET` | None |
| Block `render_callback` | `register_block_type` | Contributor+ (incl. direct via `/wp-json/wp/v2/block-renderer/`) | None |
| Cron callback | `wp_schedule_event` | Trigger is unauthenticated (`/wp-cron.php`); args set at schedule time | None; no user context |
| XML-RPC method | `xmlrpc_methods` filter | **Unauthenticated** dispatch | None for plugin methods |
| Webhook endpoint | usually one of the above | **Unauthenticated** by design | None — plugin must verify signature |
| WP-CLI command | `WP_CLI::add_command` | **Not attacker-reachable** (shell access required) | N/A — do not report missing caps/nonces |

---

## See also

- `wp-security-apis.md` — the correct sanitize/escape/prepare/authz API for each sink.
- `capability-matrix.md` — turning "minimum privilege to reach" into a severity rating.
- `secure-handler-template.md` — the correct complete shape of each handler type.
