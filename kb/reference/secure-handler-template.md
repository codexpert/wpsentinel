# Reference: Secure Handler Templates

**Audience:** an auditing agent producing a fix. These are the *complete, correct*
shapes of the five handler types that account for most WordPress plugin
vulnerabilities. Copy the structure, not just the individual calls — most real
bugs are a **missing step**, not a wrong function.

**Verified against:** WordPress core `master` (7.2-alpha; current stable 7.1).
Every API used here was checked against current core source; version-gated
features are marked inline.

**Class IDs referenced:** WP-ACL, WP-AJAX, WP-REST, WP-CSRF, WP-SQLI, WP-XSS-R,
WP-XSS-S, WP-UPLOAD, WP-LFI, WP-DELETE, WP-POI, WP-RCE, WP-SSRF, WP-OPTION,
WP-PRIVESC, WP-AUTHBYPASS, WP-IDOR, WP-INFO, WP-REDIRECT, WP-SETTINGS.

---

## 0. The universal handler skeleton

Every state-changing handler, regardless of entry point, has the same five phases
**in this order**. Order is load-bearing.

```
1. AUTHENTICATE the request   → nonce / signature      (defeats WP-CSRF)
2. AUTHORIZE  the actor       → current_user_can()     (defeats WP-ACL, WP-PRIVESC, WP-AUTHBYPASS)
3. VALIDATE + SANITIZE input  → sanitize_* / allowlist (defeats WP-SQLI, WP-LFI, WP-POI, WP-SSRF)
4. AUTHORIZE the OBJECT       → current_user_can($cap, $id) (defeats WP-IDOR)
5. ACT, then ESCAPE on output → $wpdb->prepare / esc_* (defeats WP-SQLI, WP-XSS-R, WP-XSS-S)
```

Phase 4 is separate from phase 2 on purpose: you cannot check "may this user edit
**post 42**" until you have safely parsed `42` out of the request. A handler that
does 2 but not 4 is the classic WP-IDOR.

**Fail closed, and fail early.** Every guard must `wp_die()`, `wp_send_json_error()`,
`return new WP_Error()`, or `return` — never merely log and continue.

---

## (a) Authenticated AJAX handler

Defeats: **WP-AJAX, WP-ACL, WP-CSRF, WP-IDOR, WP-XSS-S, WP-SQLI**

```php
<?php
/**
 * Register the AJAX action.
 *
 * SECURITY: We register ONLY `wp_ajax_` and deliberately NOT
 * `wp_ajax_nopriv_`. Registering the nopriv_ variant would expose this
 * handler to the entire internet with no account at all.
 *   -> Defeats WP-AJAX / WP-AUTHBYPASS.
 *
 * NOTE: `wp_ajax_` alone still only proves the caller is logged in — a
 * brand-new Subscriber from open registration hits the same hook as an
 * Administrator. The capability check below is what actually authorizes.
 */
add_action( 'wp_ajax_myplugin_rename_thing', 'myplugin_ajax_rename_thing' );

function myplugin_ajax_rename_thing() {

	/* ---- PHASE 1: AUTHENTICATE THE REQUEST (CSRF) ------------------------ */

	/*
	 * SECURITY: Verifies the `wp_rest`-style nonce tying this request to this
	 * user's session AND to this specific action. With $stop = true (default)
	 * core calls wp_die( -1, 403 ) on failure, so execution stops here.
	 *
	 * Always pass an explicit action string. check_ajax_referer() with no
	 * argument defaults to $action = -1, which core flags via
	 * _doing_it_wrong() and which weakens the check to near-uselessness.
	 *   -> Defeats WP-CSRF.
	 *
	 * NOTE: nonces are NOT authorization. Official core docs: "Nonces should
	 * never be relied on for authentication, authorization, or access control."
	 */
	check_ajax_referer( 'myplugin_rename_thing', '_ajax_nonce' );

	/* ---- PHASE 2: AUTHORIZE THE ACTOR ----------------------------------- */

	/*
	 * SECURITY: The real access control. Check a CAPABILITY, never a role
	 * name and never a user level — membership and e-commerce plugins rename
	 * and remap roles constantly, so roles are not a stable contract.
	 *
	 * Choose the capability that matches the IMPACT of the action, not the
	 * lowest one that makes your UI work. `'read'` would let every logged-in
	 * user through.
	 *   -> Defeats WP-ACL / WP-PRIVESC.
	 */
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error(
			array( 'message' => __( 'You are not allowed to do that.', 'my-plugin' ) ),
			403
		);
	}

	/* ---- PHASE 3: VALIDATE AND SANITIZE INPUT ---------------------------- */

	/*
	 * SECURITY: wp_unslash() FIRST (WordPress adds magic-quote-style slashes
	 * to $_POST/$_GET/$_REQUEST/$_COOKIE), THEN sanitize. Order matters.
	 *
	 * absint() for any ID: it yields a non-negative integer and cannot carry
	 * SQL metacharacters.
	 *   -> Defeats WP-SQLI at the source.
	 */
	$post_id = isset( $_POST['post_id'] )
		? absint( wp_unslash( $_POST['post_id'] ) )
		: 0;

	if ( ! $post_id ) {
		wp_send_json_error(
			array( 'message' => __( 'Missing or invalid post ID.', 'my-plugin' ) ),
			400
		);
	}

	/*
	 * SECURITY: sanitize_text_field() strips tags, normalises whitespace and
	 * removes percent-encoded characters. It is the right default for a
	 * single-line free-text field.
	 *
	 * Use sanitize_textarea_field() instead when newlines must survive —
	 * sanitize_text_field() destroys them.
	 *
	 * NOTE: sanitizing on input does NOT license echoing later. Output is
	 * still escaped at the sink (phase 5).
	 *   -> Defeats WP-XSS-S.
	 */
	$new_title = isset( $_POST['title'] )
		? sanitize_text_field( wp_unslash( $_POST['title'] ) )
		: '';

	if ( '' === $new_title ) {
		wp_send_json_error(
			array( 'message' => __( 'Title cannot be empty.', 'my-plugin' ) ),
			400
		);
	}

	/*
	 * SECURITY: Validation beats sanitization wherever the value has a known
	 * shape. An allowlist with STRICT comparison is the only safe way to
	 * handle a value that becomes a column name, ORDER BY direction,
	 * callback name, class name, or file path segment — sinks for which no
	 * escaping function exists.
	 *   -> Defeats WP-SQLI, WP-LFI, WP-RCE.
	 */
	$allowed_statuses = array( 'draft', 'pending', 'publish' );
	$status           = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : 'draft';

	if ( ! in_array( $status, $allowed_statuses, true ) ) {
		wp_send_json_error(
			array( 'message' => __( 'Invalid status.', 'my-plugin' ) ),
			400
		);
	}

	/* ---- PHASE 4: AUTHORIZE THE OBJECT ---------------------------------- */

	/*
	 * SECURITY: THIS IS THE STEP MOST OFTEN MISSING.
	 *
	 * `edit_posts` (plural, primitive) is held by Contributor and up and
	 * carries NO ownership, status, or post-type check. Only the singular
	 * `edit_post` META capability — with the object ID as the second argument
	 * — runs map_meta_cap()'s author/status logic and resolves to
	 * edit_others_posts / edit_published_posts / edit_private_posts.
	 *
	 * Without this line a Contributor passes phase 2 and then edits ANYONE's
	 * published post.
	 *   -> Defeats WP-IDOR.
	 *
	 * Meta caps that REQUIRE an object ID: edit_post, delete_post, read_post,
	 * publish_post, edit_comment, edit_term, delete_term, assign_term, and
	 * the *_post_meta / *_term_meta / *_comment_meta / *_user_meta families.
	 */
	if ( ! current_user_can( 'edit_post', $post_id ) ) {
		wp_send_json_error(
			array( 'message' => __( 'You are not allowed to edit this post.', 'my-plugin' ) ),
			403
		);
	}

	/*
	 * SECURITY: Confirm the object actually exists and is the type you expect,
	 * so an attacker cannot pivot to an unrelated post type whose caps happen
	 * to be looser.
	 *   -> Defeats WP-IDOR.
	 */
	$post = get_post( $post_id );
	if ( ! $post || 'my_plugin_thing' !== $post->post_type ) {
		wp_send_json_error(
			array( 'message' => __( 'Not found.', 'my-plugin' ) ),
			404
		);
	}

	/* ---- PHASE 5: ACT, THEN ESCAPE ON OUTPUT ---------------------------- */

	/*
	 * SECURITY: wp_update_post() runs core's own sanitization and capability
	 * plumbing. Prefer core CRUD APIs over direct $wpdb writes; they are
	 * parameterised for you.
	 *   -> Defeats WP-SQLI.
	 */
	$result = wp_update_post(
		array(
			'ID'          => $post_id,
			'post_title'  => $new_title,
			'post_status' => $status,
		),
		true // return WP_Error instead of 0 on failure
	);

	if ( is_wp_error( $result ) ) {
		/*
		 * SECURITY: Do not leak internal error text, SQL, or paths to the
		 * client. Log server-side; return something generic.
		 *   -> Defeats WP-INFO.
		 */
		wp_send_json_error(
			array( 'message' => __( 'Could not update the item.', 'my-plugin' ) ),
			500
		);
	}

	/*
	 * SECURITY: wp_send_json_success() sets Content-Type: application/json and
	 * JSON-encodes, so values are not interpreted as HTML by the browser.
	 * Escape anyway for any value the client will inject into the DOM, and
	 * escape in the JS with textContent rather than innerHTML.
	 *
	 * If you ever echo an HTML fragment from an AJAX handler, esc_html() /
	 * esc_attr() / esc_url() it exactly as you would in a template.
	 *   -> Defeats WP-XSS-S / WP-XSS-R.
	 *
	 * wp_send_json_* calls wp_die() internally, so nothing runs after this.
	 */
	wp_send_json_success(
		array(
			'post_id' => $post_id,
			'title'   => $new_title,
		)
	);
}
```

### The matching enqueue — where the nonce comes from

```php
add_action( 'admin_enqueue_scripts', 'myplugin_enqueue' );

function myplugin_enqueue() {
	wp_enqueue_script(
		'myplugin-admin',
		plugins_url( 'js/admin.js', __FILE__ ),
		array( 'wp-i18n' ),
		'1.0.0',   // explicit version — cache busting
		true       // explicit in_footer
	);

	/*
	 * SECURITY: wp_localize_script() JSON-encodes the data, so values cannot
	 * break out of the <script> block. Never build inline JS by string
	 * concatenation — use this, wp_add_inline_script(), or wp_json_encode().
	 *   -> Defeats WP-XSS-R.
	 *
	 * The nonce action string MUST match the one in check_ajax_referer().
	 */
	wp_localize_script(
		'myplugin-admin',
		'myPluginData',
		array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'myplugin_rename_thing' ),
		)
	);
}
```

> ⚠️ **If you genuinely need a public endpoint**, `wp_ajax_nopriv_` is correct —
> but understand that `check_ajax_referer()` gives you **no CSRF protection**
> there. Core generates the **same nonce for every anonymous visitor** (the hash
> input includes `$uid = 0` and an empty session token), so an attacker simply
> fetches a valid nonce from any public page. A public endpoint must be **safe by
> design**: read-only, rate-limited, and non-enumerating. See
> `entry-points.md` §2.

---

## (b) REST route with a real `permission_callback`

Defeats: **WP-REST, WP-ACL, WP-IDOR, WP-SQLI, WP-XSS-S**

```php
<?php
add_action( 'rest_api_init', 'myplugin_register_routes' );

function myplugin_register_routes() {

	register_rest_route(
		'myplugin/v1',                 // namespace — always vendor-prefixed
		'/things/(?P<id>[\d]+)',       // regex constrains id to digits (defence in depth)
		array(
			array(
				'methods'  => WP_REST_Server::EDITABLE,   // POST, PUT, PATCH
				'callback' => 'myplugin_rest_update_thing',

				/*
				 * SECURITY: THE MOST IMPORTANT LINE IN ANY REST ROUTE.
				 *
				 * Since WP 5.5 core emits a _doing_it_wrong() notice when this
				 * key is absent — but THE NOTICE DOES NOT BLOCK ANYTHING. It is
				 * silent unless WP_DEBUG is on, the route still registers, and
				 * the request still executes. Enforcement in
				 * WP_REST_Server::dispatch() is guarded by
				 * `! empty( $handler['permission_callback'] )`, so a missing,
				 * null, false, or empty-string value means NO CHECK RUNS AT ALL
				 * and the endpoint is open to anonymous callers.
				 *
				 * "Required" is documentation, not enforcement. Never assume
				 * WP 5.5+ closed these holes.
				 *   -> Defeats WP-REST / WP-ACL / WP-AUTHBYPASS.
				 */
				'permission_callback' => 'myplugin_rest_update_permission',

				/*
				 * SECURITY: The args schema runs validate_callback then
				 * sanitize_callback BEFORE your callback executes — but AFTER
				 * permission_callback. It is data hygiene, not access control.
				 *   -> Defeats WP-SQLI / WP-XSS-S at the source.
				 */
				'args' => array(
					'id' => array(
						'required'          => true,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
						'validate_callback' => static function ( $value ) {
							return is_numeric( $value ) && (int) $value > 0;
						},
					),
					'title' => array(
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'status' => array(
						'required' => false,
						'type'     => 'string',
						'default'  => 'draft',
						/*
						 * SECURITY: `enum` is a core-enforced allowlist —
						 * strictly better than sanitizing a free string.
						 */
						'enum'     => array( 'draft', 'pending', 'publish' ),
					),
					'homepage' => array(
						'required'          => false,
						'type'              => 'string',
						'format'            => 'uri',
						/*
						 * SECURITY: sanitize_url() (canonical name; esc_url_raw()
						 * is its alias as of WP 6.1) filters the protocol
						 * allowlist, blocking javascript: and data:.
						 *   -> Defeats WP-XSS-S.
						 */
						'sanitize_callback' => 'sanitize_url',
					),
				),
			),
		)
	);
}

/**
 * The permission callback.
 *
 * SECURITY — RETURN-VALUE CONTRACT (verified in WP_REST_Server::dispatch):
 *
 *     if ( ! is_wp_error( $response ) && ! empty( $handler['permission_callback'] ) ) {
 *         $permission = call_user_func( $handler['permission_callback'], $request );
 *         if ( is_wp_error( $permission ) ) {
 *             $response = $permission;
 *         } elseif ( false === $permission || null === $permission ) {
 *             $response = new WP_Error( 'rest_forbidden', ... );
 *         }
 *     }
 *
 * The rejection test is STRICT. Only `false`, `null`, and WP_Error deny.
 *
 *   true                          -> allowed
 *   false                         -> denied
 *   null (incl. falling off end)  -> denied  (fails closed)
 *   WP_Error                      -> denied, with your message
 *   0, '0', '', array(), 0.0      -> ALLOWED  <-- falsy but not false/null!
 *
 * So `'permission_callback' => fn( $r ) => get_current_user_id()` GRANTS ACCESS
 * TO ANONYMOUS USERS, because get_current_user_id() returns int 0 when logged
 * out and 0 !== false. Always return a real boolean or a WP_Error.
 *   -> Defeats WP-REST / WP-AUTHBYPASS.
 *
 * @param WP_REST_Request $request
 * @return true|WP_Error
 */
function myplugin_rest_update_permission( WP_REST_Request $request ) {

	/*
	 * SECURITY: Check the capability, not is_user_logged_in(). Official REST
	 * handbook guidance: "Where possible, you should always use
	 * current_user_can; instead of checking if the user is logged in
	 * (authentication), check whether they can perform the action
	 * (authorization)."
	 *   -> Defeats WP-ACL.
	 */
	if ( ! current_user_can( 'edit_posts' ) ) {
		return new WP_Error(
			'rest_forbidden',
			__( 'Sorry, you are not allowed to do that.', 'my-plugin' ),
			/*
			 * SECURITY: rest_authorization_required_code() returns 401 when
			 * logged out and 403 when logged in — the semantically correct
			 * status without leaking whether the object exists.
			 *   -> Defeats WP-INFO.
			 */
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/*
	 * SECURITY: Object-level authorization belongs here when the object ID is
	 * already in the route. Doing it in permission_callback rather than in the
	 * main callback means core returns a clean 403 and your handler never runs.
	 *   -> Defeats WP-IDOR.
	 */
	$post_id = absint( $request['id'] );
	$post    = get_post( $post_id );

	if ( ! $post || 'my_plugin_thing' !== $post->post_type ) {
		return new WP_Error(
			'rest_not_found',
			__( 'Not found.', 'my-plugin' ),
			array( 'status' => 404 )
		);
	}

	if ( ! current_user_can( 'edit_post', $post_id ) ) {
		return new WP_Error(
			'rest_forbidden',
			__( 'Sorry, you are not allowed to edit this item.', 'my-plugin' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	return true;   // explicit boolean true — never a truthy non-boolean
}

/**
 * The main callback. Runs ONLY if permission_callback returned true.
 *
 * @param WP_REST_Request $request
 * @return WP_REST_Response|WP_Error
 */
function myplugin_rest_update_thing( WP_REST_Request $request ) {

	/*
	 * Values are already sanitized by the args schema. Reading them off the
	 * request object (not $_POST) keeps that guarantee.
	 */
	$post_id = absint( $request['id'] );
	$title   = $request['title'];
	$status  = $request['status'];

	$result = wp_update_post(
		array(
			'ID'          => $post_id,
			'post_title'  => $title,
			'post_status' => $status,
		),
		true
	);

	if ( is_wp_error( $result ) ) {
		/*
		 * SECURITY: Return a generic message; do not forward internal error
		 * strings, SQL, or filesystem paths.
		 *   -> Defeats WP-INFO.
		 */
		return new WP_Error(
			'rest_update_failed',
			__( 'Could not update the item.', 'my-plugin' ),
			array( 'status' => 500 )
		);
	}

	/*
	 * SECURITY: REST responses are JSON-encoded by core, so no HTML escaping
	 * is needed here — but only return fields the caller is entitled to see.
	 * Do not echo the whole row: emails, hashes, private meta, and internal
	 * IDs leak this way.
	 *   -> Defeats WP-INFO.
	 */
	return rest_ensure_response(
		array(
			'id'     => $post_id,
			'title'  => get_the_title( $post_id ),
			'status' => get_post_status( $post_id ),
		)
	);
}
```

### Notes on REST and CSRF

- A **cookie-authenticated** REST request is CSRF-protected **by core**:
  `rest_cookie_check_errors()` requires the `X-WP-Nonce` header (or `_wpnonce`)
  carrying a `wp_rest` nonce. You do **not** need your own nonce check.
- ⚠️ That protection applies **only** when the caller chose cookie auth. An
  anonymous, cookie-less request never reaches `rest_cookie_check_errors()`. So
  the nonce is **not** a substitute for `permission_callback`.
- Routes are also reachable as `?rest_route=/myplugin/v1/things/1` when pretty
  permalinks are off. WAF rules keyed on `/wp-json/` miss this form.
- For a genuinely public route, be explicit:
  `'permission_callback' => '__return_true'`. Silence is not intent.

---

## (c) `admin-post.php` form handler

Defeats: **WP-CSRF, WP-ACL, WP-SETTINGS, WP-OPTION, WP-PRIVESC, WP-REDIRECT, WP-XSS-R**

### The form

```php
<?php
function myplugin_render_settings_form() {

	/*
	 * SECURITY: Gate the RENDER too. Without this, the form (and any data in
	 * it) is disclosed to users who cannot submit it.
	 *   -> Defeats WP-INFO / WP-ACL.
	 */
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die(
			esc_html__( 'You do not have permission to access this page.', 'my-plugin' ),
			403
		);
	}
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">

		<?php
		/*
		 * SECURITY: Emits the hidden _wpnonce field AND the _wp_http_referer
		 * field. The action string must match check_admin_referer() exactly.
		 *   -> Defeats WP-CSRF.
		 */
		wp_nonce_field( 'myplugin_save_settings', '_wpnonce' );
		?>

		<?php
		/*
		 * The action value selects the admin_post_{action} hook.
		 * NOTE: this is routing, not security.
		 */
		?>
		<input type="hidden" name="action" value="myplugin_save_settings" />

		<label for="myplugin_api_url"><?php esc_html_e( 'API URL', 'my-plugin' ); ?></label>
		<input
			type="url"
			id="myplugin_api_url"
			name="api_url"
			<?php
			/*
			 * SECURITY: esc_url() for a URL inside an attribute — esc_attr()
			 * would let `javascript:` through. esc_attr() for the plain-text
			 * field. And the attribute is QUOTED: esc_attr() does not protect
			 * an unquoted attribute.
			 *   -> Defeats WP-XSS-R / WP-XSS-S.
			 */
			?>
			value="<?php echo esc_url( get_option( 'myplugin_api_url', '' ) ); ?>"
		/>

		<label for="myplugin_mode"><?php esc_html_e( 'Mode', 'my-plugin' ); ?></label>
		<select id="myplugin_mode" name="mode">
			<?php foreach ( array( 'live', 'test' ) as $mode ) : ?>
				<option
					value="<?php echo esc_attr( $mode ); ?>"
					<?php selected( get_option( 'myplugin_mode' ), $mode ); ?>
				>
					<?php echo esc_html( $mode ); ?>
				</option>
			<?php endforeach; ?>
		</select>

		<?php submit_button(); ?>
	</form>
	<?php
}
```

### The handler

```php
<?php
/*
 * SECURITY: Register ONLY the authenticated hook. `admin_post_nopriv_*` would
 * expose this settings writer to the entire internet.
 *   -> Defeats WP-AUTHBYPASS / WP-SETTINGS.
 *
 * Remember: `admin_post_{action}` fires for ANY logged-in user, including a
 * Subscriber. The capability check below is the real gate.
 */
add_action( 'admin_post_myplugin_save_settings', 'myplugin_handle_save_settings' );

function myplugin_handle_save_settings() {

	/* ---- PHASE 1: AUTHENTICATE THE REQUEST (CSRF) ------------------------ */

	/*
	 * SECURITY: Verifies _wpnonce against the action string and calls
	 * wp_nonce_ays() + die() on failure, so execution stops here.
	 *
	 * ALWAYS pass an explicit action. With the default $action = -1, core
	 * falls back to:
	 *
	 *     if ( ! $result && ! ( -1 === $action && str_starts_with( $referer, $adminurl ) ) )
	 *
	 * i.e. a request whose attacker-influenced Referer header merely starts
	 * with the admin URL PASSES WITHOUT A VALID NONCE.
	 *   -> Defeats WP-CSRF.
	 */
	check_admin_referer( 'myplugin_save_settings', '_wpnonce' );

	/* ---- PHASE 2: AUTHORIZE THE ACTOR ----------------------------------- */

	/*
	 * SECURITY: manage_options is the correct capability for site-wide
	 * settings. The nonce above proves intent, NOT permission — a Subscriber
	 * viewing a page that renders a nonce still gets a valid one.
	 *   -> Defeats WP-ACL / WP-PRIVESC / WP-SETTINGS.
	 */
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die(
			esc_html__( 'You do not have permission to do this.', 'my-plugin' ),
			403
		);
	}

	/* ---- PHASE 3: VALIDATE AND SANITIZE INPUT ---------------------------- */

	/*
	 * SECURITY: sanitize_url() for a URL going into the database — it filters
	 * the protocol allowlist without HTML-encoding ampersands. Never store
	 * esc_url() output; that is the display form.
	 *   -> Defeats WP-XSS-S / WP-SSRF.
	 */
	$api_url = isset( $_POST['api_url'] )
		? sanitize_url( wp_unslash( $_POST['api_url'] ) )
		: '';

	/*
	 * SECURITY: Additionally validate the URL is externally fetchable and not
	 * pointed at internal infrastructure, since this value later feeds an
	 * outbound request.
	 *   -> Defeats WP-SSRF.
	 */
	if ( '' !== $api_url && ! wp_http_validate_url( $api_url ) ) {
		wp_die( esc_html__( 'Invalid API URL.', 'my-plugin' ), 400 );
	}

	/*
	 * SECURITY: Strict allowlist for the enumerated field.
	 *   -> Defeats WP-SETTINGS / WP-SQLI.
	 */
	$allowed_modes = array( 'live', 'test' );
	$mode          = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'test';

	if ( ! in_array( $mode, $allowed_modes, true ) ) {
		$mode = 'test';
	}

	/* ---- PHASE 4/5: ACT ------------------------------------------------- */

	/*
	 * SECURITY: HARDCODE the option names. Never do:
	 *     update_option( $_POST['option_name'], $_POST['option_value'] );
	 *
	 * Arbitrary option write is CRITICAL, not medium: `default_role` is an
	 * unvalidated option, so setting default_role=administrator together with
	 * users_can_register=1 yields anonymous self-service admin creation.
	 * `siteurl`, `home`, and `admin_email` are equally abusable.
	 *   -> Defeats WP-OPTION / WP-PRIVESC.
	 */
	update_option( 'myplugin_api_url', $api_url );
	update_option( 'myplugin_mode', $mode );

	/*
	 * SECURITY: wp_safe_redirect() runs wp_validate_redirect(), which allows
	 * only http/https schemes and only hosts in `allowed_redirect_hosts`
	 * (default: this site), falling back to admin_url(). Plain wp_redirect()
	 * would happily send the user to an attacker's domain.
	 *   -> Defeats WP-REDIRECT.
	 *
	 * NEVER redirect to a raw $_GET['redirect_to'] / $_POST['return_url'].
	 * If you must honour a return URL, pass it through wp_validate_redirect()
	 * with an explicit local fallback.
	 */
	$redirect = add_query_arg(
		array(
			'page'             => 'myplugin-settings',
			'myplugin_updated' => '1',
		),
		admin_url( 'admin.php' )
	);

	wp_safe_redirect( $redirect );

	/*
	 * SECURITY: wp_redirect()/wp_safe_redirect() DO NOT terminate execution.
	 * Without exit, everything below keeps running — including code the
	 * redirect was meant to skip.
	 *   -> Defeats WP-ACL / WP-AUTHBYPASS.
	 */
	exit;
}
```

> **Do not roll your own settings page if the Settings API will do.**
> `register_setting( $group, $name, array( 'sanitize_callback' => ... ) )` +
> `settings_fields( $group )` + `options.php` gives you nonce handling, capability
> gating, and per-option sanitization from core. Use the template above only when
> you genuinely need a custom endpoint.

---

## (d) File-upload handler

Defeats: **WP-UPLOAD, WP-RCE, WP-ACL, WP-CSRF, WP-LFI, WP-XSS-S**

```php
<?php
add_action( 'admin_post_myplugin_upload', 'myplugin_handle_upload' );

function myplugin_handle_upload() {

	/* ---- PHASE 1: CSRF --------------------------------------------------- */
	check_admin_referer( 'myplugin_upload', '_wpnonce' );

	/* ---- PHASE 2: AUTHORIZE --------------------------------------------- */

	/*
	 * SECURITY: upload_files is the capability that gates uploading. Note that
	 * Contributor does NOT have it — Author and up do. Requiring a lower
	 * capability here would hand file-write to Contributors.
	 *   -> Defeats WP-ACL / WP-UPLOAD.
	 */
	if ( ! current_user_can( 'upload_files' ) ) {
		wp_die( esc_html__( 'You are not allowed to upload files.', 'my-plugin' ), 403 );
	}

	/* ---- PHASE 3: VALIDATE ---------------------------------------------- */

	if ( empty( $_FILES['myplugin_file'] ) || ! isset( $_FILES['myplugin_file']['error'] ) ) {
		wp_die( esc_html__( 'No file was uploaded.', 'my-plugin' ), 400 );
	}

	if ( UPLOAD_ERR_OK !== (int) $_FILES['myplugin_file']['error'] ) {
		wp_die( esc_html__( 'Upload failed.', 'my-plugin' ), 400 );
	}

	/*
	 * wp_handle_upload() lives in wp-admin/includes/file.php. It is already
	 * loaded on admin-post.php and admin-ajax.php (both require
	 * wp-admin/includes/admin.php), but include it explicitly so the handler
	 * is safe to call from any context.
	 */
	if ( ! function_exists( 'wp_handle_upload' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	/*
	 * SECURITY: An EXPLICIT MIME ALLOWLIST is the core control. Keys are
	 * extension regexes, values are the expected MIME types.
	 *
	 * Narrow this to exactly what the feature needs. Do NOT fall back to the
	 * site-wide get_allowed_mime_types() unless the feature really accepts
	 * everything the media library does.
	 *
	 * NEVER allow: php, php3, php4, php5, php7, phtml, phar, pht, htaccess,
	 * html, htm, shtml, js, svg (SVG carries script and yields stored XSS).
	 *   -> Defeats WP-UPLOAD / WP-RCE / WP-XSS-S.
	 */
	$allowed_mimes = array(
		'jpg|jpeg|jpe' => 'image/jpeg',
		'png'          => 'image/png',
		'gif'          => 'image/gif',
		'webp'         => 'image/webp',
		'pdf'          => 'application/pdf',
	);

	$overrides = array(
		/*
		 * SECURITY: test_form defaults to TRUE, which requires
		 * $_POST['action'] === 'wp_handle_upload'. Our action is
		 * 'myplugin_upload', so we must disable that specific test.
		 *
		 * This is NORMAL and is NOT a vulnerability — we have our own nonce
		 * (phase 1) and capability check (phase 2). Do not confuse it with
		 * test_type below.
		 */
		'test_form' => false,

		/*
		 * SECURITY: test_type MUST stay true. Core:
		 *
		 *     if ( ( ! $type || ! $ext ) && ! current_user_can( 'unfiltered_upload' ) ) {
		 *         return $upload_error_handler( $file, 'Sorry, you are not allowed to upload this file type.' );
		 *     }
		 *
		 * With test_type => false, wp_check_filetype_and_ext() is never called
		 * and ANY file — including .php — is written to the uploads directory.
		 * This is the single most common WP-UPLOAD finding.
		 *   -> Defeats WP-UPLOAD / WP-RCE.
		 */
		'test_type' => true,

		'test_size' => true,
		'mimes'     => $allowed_mimes,
	);

	/*
	 * SECURITY: wp_handle_upload() is the correct API. It:
	 *   - verifies is_uploaded_file() (blocks path-injection into $_FILES)
	 *   - runs wp_check_filetype_and_ext(), which inspects real file CONTENT,
	 *     not just the filename (blocks polyglots and double extensions)
	 *   - runs sanitize_file_name() and wp_unique_filename()
	 *   - writes only inside wp_upload_dir()
	 *
	 * NEVER use move_uploaded_file() with a user-supplied destination path —
	 * that is WP-UPLOAD + WP-LFI + WP-RCE in one line.
	 */
	$movefile = wp_handle_upload( $_FILES['myplugin_file'], $overrides );

	if ( ! $movefile || isset( $movefile['error'] ) ) {
		/*
		 * SECURITY: Generic message. $movefile['error'] can contain server
		 * paths and configuration details.
		 *   -> Defeats WP-INFO.
		 */
		wp_die( esc_html__( 'Upload rejected.', 'my-plugin' ), 400 );
	}

	/*
	 * SECURITY: Belt-and-braces re-check of the resulting extension against
	 * our allowlist, in case an upload_mimes filter elsewhere widened things.
	 *   -> Defeats WP-UPLOAD / WP-RCE.
	 */
	$check = wp_check_filetype( $movefile['file'], $allowed_mimes );

	if ( empty( $check['ext'] ) || empty( $check['type'] ) ) {
		wp_delete_file( $movefile['file'] );
		wp_die( esc_html__( 'Disallowed file type.', 'my-plugin' ), 400 );
	}

	/*
	 * SECURITY: Registering the file as an attachment is preferable to
	 * tracking a raw path in your own option/meta — it keeps the file inside
	 * WordPress's own lifecycle and lets you reference it by ID rather than
	 * by path, which removes an entire class of traversal bugs.
	 *   -> Defeats WP-LFI / WP-DELETE.
	 */
	$attachment_id = wp_insert_attachment(
		array(
			'post_mime_type' => $check['type'],
			'post_title'     => sanitize_file_name( basename( $movefile['file'] ) ),
			'post_content'   => '',
			'post_status'    => 'inherit',
		),
		$movefile['file']
	);

	if ( is_wp_error( $attachment_id ) || ! $attachment_id ) {
		wp_delete_file( $movefile['file'] );
		wp_die( esc_html__( 'Could not register the upload.', 'my-plugin' ), 500 );
	}

	if ( ! function_exists( 'wp_generate_attachment_metadata' ) ) {
		require_once ABSPATH . 'wp-admin/includes/image.php';
	}

	wp_update_attachment_metadata(
		$attachment_id,
		wp_generate_attachment_metadata( $attachment_id, $movefile['file'] )
	);

	/*
	 * SECURITY: Store the ID, never the path. Later reads become
	 * get_attached_file( absint( $id ) ) — no user-controlled path anywhere.
	 *   -> Defeats WP-LFI / WP-DELETE / WP-IDOR.
	 */
	update_post_meta( $attachment_id, '_myplugin_owner', get_current_user_id() );

	wp_safe_redirect( admin_url( 'admin.php?page=myplugin&uploaded=1' ) );
	exit;
}
```

### Serving a stored file back — the WP-LFI-safe read

```php
<?php
function myplugin_serve_file() {
	check_admin_referer( 'myplugin_download', '_wpnonce' );

	if ( ! is_user_logged_in() ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	/*
	 * SECURITY: Accept an ID, never a path. This is the single most effective
	 * WP-LFI defence — there is no attacker-controlled path to traverse.
	 *   -> Defeats WP-LFI.
	 */
	$attachment_id = isset( $_GET['file_id'] ) ? absint( wp_unslash( $_GET['file_id'] ) ) : 0;

	if ( ! $attachment_id || 'attachment' !== get_post_type( $attachment_id ) ) {
		wp_die( esc_html__( 'Not found.', 'my-plugin' ), 404 );
	}

	/*
	 * SECURITY: Object-level authorization — otherwise any logged-in user
	 * enumerates every attachment ID on the site.
	 *   -> Defeats WP-IDOR.
	 */
	$owner = (int) get_post_meta( $attachment_id, '_myplugin_owner', true );

	if ( $owner !== get_current_user_id() && ! current_user_can( 'edit_others_posts' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	$path = get_attached_file( $attachment_id );

	/*
	 * SECURITY: Defence in depth — resolve with realpath() and confirm the
	 * result is genuinely inside the uploads directory.
	 *
	 * NOTE: validate_file() is NOT sufficient on its own. Core's own docblock:
	 * "absolute POSIX paths such as /etc/passwd are *not* rejected, and never
	 * have been." It also returns 0 (OK) for an empty string. The realpath()
	 * prefix check below is the load-bearing control.
	 *   -> Defeats WP-LFI.
	 */
	$uploads = wp_upload_dir();
	$base    = realpath( $uploads['basedir'] );
	$real    = $path ? realpath( $path ) : false;

	if ( ! $base || ! $real || ! str_starts_with( $real, $base . DIRECTORY_SEPARATOR ) ) {
		wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
	}

	$type = get_post_mime_type( $attachment_id );

	/*
	 * SECURITY: Force download and block content sniffing so a stored file
	 * cannot execute as HTML/JS in the site's origin.
	 *   -> Defeats WP-XSS-S.
	 *
	 * basename() + sanitize_file_name() prevent CR/LF header injection via
	 * the filename.
	 */
	nocache_headers();
	header( 'Content-Type: ' . ( $type ? $type : 'application/octet-stream' ) );
	header( 'X-Content-Type-Options: nosniff' );
	header(
		'Content-Disposition: attachment; filename="'
		. sanitize_file_name( basename( $real ) ) . '"'
	);
	header( 'Content-Length: ' . filesize( $real ) );

	readfile( $real );
	exit;
}
```

---

## (e) `$wpdb` query with `prepare()`

Defeats: **WP-SQLI, WP-IDOR, WP-INFO**

```php
<?php
/**
 * Fetch a page of rows with a search term, an ID filter, and a sort.
 *
 * @param string $search   Free-text search.
 * @param int[]  $ids      Optional ID filter.
 * @param string $orderby  Column to sort by (attacker-influenced).
 * @param string $order    ASC|DESC (attacker-influenced).
 * @param int    $per_page Page size.
 * @param int    $page     1-based page number.
 * @return array
 */
function myplugin_query_things( $search = '', $ids = array(), $orderby = 'created', $order = 'DESC', $per_page = 20, $page = 1 ) {

	global $wpdb;

	/*
	 * SECURITY: The table name is built from $wpdb->prefix, which is server
	 * configuration and NOT user input. Interpolating it is safe and idiomatic.
	 * Do not let a linter warning push you into "fixing" this incorrectly.
	 */
	$table = $wpdb->prefix . 'myplugin_things';

	/* ---- ORDER BY: no placeholder exists for a column name --------------- */

	/*
	 * SECURITY: ORDER BY columns and directions CANNOT be parameterised with
	 * %s/%d — they are identifiers and keywords, not values. A strict
	 * allowlist is the correct control.
	 *
	 * As of WP 6.2, %i handles identifiers (see below), but an allowlist is
	 * still preferable when the legal set is small and known: it also prevents
	 * LOGICAL access to columns the feature was never meant to expose, which
	 * %i does not.
	 *   -> Defeats WP-SQLI / WP-INFO.
	 */
	$allowed_orderby = array( 'id', 'name', 'created', 'status' );

	if ( ! in_array( $orderby, $allowed_orderby, true ) ) {
		$orderby = 'created';
	}

	$order = ( 'ASC' === strtoupper( $order ) ) ? 'ASC' : 'DESC';

	/* ---- WHERE: every VALUE goes through a placeholder ------------------- */

	$where  = array( '1=1' );
	$params = array();

	if ( '' !== $search ) {
		/*
		 * SECURITY: TWO separate concerns.
		 *
		 * 1. $wpdb->esc_like() escapes the LIKE metacharacters _ % and \ so a
		 *    user cannot turn a search into a full table scan or a wildcard
		 *    match. Core's docblock: "The output is not SQL safe. Call
		 *    wpdb::prepare() or wpdb::_real_escape() next."
		 *
		 * 2. prepare() with %s handles the SQL injection. esc_like() ALONE is
		 *    NOT injection protection.
		 *
		 * The wildcards live in the ARGUMENT, never in the query string —
		 * prepare() rejects % in the query except as %%.
		 *
		 * NOTE: like_escape() is deprecated (WP 4.0). Never recommend it.
		 *   -> Defeats WP-SQLI.
		 */
		$where[]  = 'name LIKE %s';
		$params[] = '%' . $wpdb->esc_like( $search ) . '%';
	}

	if ( ! empty( $ids ) ) {
		/*
		 * SECURITY: An IN() clause needs one placeholder per element,
		 * generated to match the array length. Casting through absint() first
		 * means even a placeholder mistake cannot inject.
		 *
		 * NOTE: %i cannot be used inside IN().
		 *   -> Defeats WP-SQLI.
		 */
		$ids = array_filter( array_map( 'absint', (array) $ids ) );

		if ( ! empty( $ids ) ) {
			$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			$where[]      = "id IN ( $placeholders )";
			$params       = array_merge( $params, $ids );
		}
	}

	/*
	 * SECURITY: Object-level scoping. Without it, any caller reads every row.
	 *   -> Defeats WP-IDOR.
	 */
	if ( ! current_user_can( 'edit_others_posts' ) ) {
		$where[]  = 'owner_id = %d';
		$params[] = get_current_user_id();
	}

	/* ---- LIMIT / OFFSET ------------------------------------------------- */

	$per_page = min( 100, max( 1, absint( $per_page ) ) );   // clamp: no DoS via huge page size
	$offset   = ( max( 1, absint( $page ) ) - 1 ) * $per_page;

	$params[] = $per_page;
	$params[] = $offset;

	/*
	 * SECURITY: $orderby and $order are interpolated ONLY because they were
	 * just constrained to a hardcoded allowlist above. Every remaining
	 * attacker-controlled value is a placeholder.
	 *
	 * All placeholders are UNQUOTED — prepare() adds the quotes for %s.
	 * Writing '%s' is a classic bug that breaks the escaping.
	 *   -> Defeats WP-SQLI.
	 */
	$sql = "SELECT id, name, status, created
	          FROM {$table}
	         WHERE " . implode( ' AND ', $where ) . "
	      ORDER BY {$orderby} {$order}
	         LIMIT %d OFFSET %d";

	/*
	 * SECURITY: prepare() is called ONCE, on the query TEMPLATE, with all
	 * arguments. Never call prepare() on an already-concatenated string —
	 * by then the injection has happened and prepare() has nothing to escape.
	 *
	 * Args may be passed variadically OR as a single array, never a mix.
	 */
	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $sql is a template; all values are placeholders.
	$prepared = $wpdb->prepare( $sql, $params );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	return $wpdb->get_results( $prepared );
}
```

### Dynamic table/column names with `%i` (WordPress 6.2+)

```php
<?php
function myplugin_count_rows( $table_suffix, $column ) {

	global $wpdb;

	/*
	 * SECURITY: %i is the identifier placeholder, added in WP 6.2. Core
	 * escapes the value by doubling backticks and wrapping in backticks:
	 *
	 *     private function _escape_identifier_value( $identifier ) {
	 *         return str_replace( '`', '``', $identifier );
	 *     }
	 *
	 * This is the modern fix for the previously-unparameterizable
	 * table/column-name problem.
	 *   -> Defeats WP-SQLI.
	 *
	 * Rules:
	 *   - Leave %i UNQUOTED. '%i', "%i", and `%i` are all wrong.
	 *   - %i cannot be used inside an IN() clause.
	 *   - One argument may not serve as both %i and %s in the same query.
	 */
	if ( ! $wpdb->has_cap( 'identifier_placeholders' ) ) {
		/*
		 * SECURITY: %i is unavailable below WP 6.2. If the plugin's
		 * "Requires at least:" header is < 6.2, %i is NOT a valid fix —
		 * fall back to a strict allowlist.
		 */
		$allowed_columns = array( 'id', 'name', 'status' );

		if ( ! in_array( $column, $allowed_columns, true ) ) {
			return 0;
		}

		return (int) $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $column is allowlisted above.
			"SELECT COUNT({$column}) FROM {$wpdb->prefix}myplugin_things"
		);
	}

	$table = $wpdb->prefix . 'myplugin_' . sanitize_key( $table_suffix );

	return (int) $wpdb->get_var(
		$wpdb->prepare(
			'SELECT COUNT(%i) FROM %i',
			$column,
			$table
		)
	);
}
```

### Writes — prefer the helper methods

```php
<?php
function myplugin_insert_thing( $name, $status, $owner_id ) {

	global $wpdb;

	/*
	 * SECURITY: $wpdb->insert() / update() / delete() / replace() prepare the
	 * VALUES for you — no manual prepare() needed.
	 *
	 * BUT: the $table argument and the ARRAY KEYS (column names) are NOT
	 * escaped. Both must be literals or allowlisted. Passing a user-controlled
	 * table name or column key here is WP-SQLI.
	 *
	 * Always pass explicit $format arrays: they force the type and stop a
	 * string sneaking into a numeric column.
	 *   -> Defeats WP-SQLI.
	 */
	$ok = $wpdb->insert(
		$wpdb->prefix . 'myplugin_things',          // literal table
		array(                                       // literal column keys
			'name'     => sanitize_text_field( $name ),
			'status'   => in_array( $status, array( 'draft', 'live' ), true ) ? $status : 'draft',
			'owner_id' => absint( $owner_id ),
			'created'  => current_time( 'mysql' ),
		),
		array( '%s', '%s', '%d', '%s' )              // explicit formats
	);

	if ( false === $ok ) {
		/*
		 * SECURITY: Never echo $wpdb->last_error or $wpdb->last_query to the
		 * client — they leak schema, paths, and query structure. Log instead.
		 *   -> Defeats WP-INFO.
		 */
		return new WP_Error( 'myplugin_db_error', __( 'Could not save.', 'my-plugin' ) );
	}

	return (int) $wpdb->insert_id;
}
```

> **`$wpdb` escaping summary**
>
> | Method | Escapes values for you? |
> |---|---|
> | `insert` / `update` / `delete` / `replace` | ✅ values only — **not** `$table`, **not** column keys |
> | `query` / `get_var` / `get_row` / `get_col` / `get_results` | ❌ **you must call `prepare()`** |
>
> `esc_sql()` is a last resort: it does **not** add quotes, gives no identifier
> protection, and since WP 4.8.3 replaces `%` with an internal placeholder, so its
> output must never be reused outside the immediate query.

---

## (f) Bonus: outbound HTTP (WP-SSRF)

```php
<?php
function myplugin_fetch_remote( $url ) {

	/*
	 * SECURITY: sanitize_url() enforces the protocol allowlist;
	 * wp_http_validate_url() additionally rejects credentials in the URL and
	 * private/reserved IPv4 ranges.
	 *   -> Defeats WP-SSRF.
	 */
	$url = sanitize_url( $url );

	if ( ! $url || ! wp_http_validate_url( $url ) ) {
		return new WP_Error( 'myplugin_bad_url', __( 'Invalid URL.', 'my-plugin' ) );
	}

	/*
	 * SECURITY: wp_safe_remote_get() re-validates the URL AND EVERY REDIRECT
	 * TARGET through wp_http_validate_url(). Plain wp_remote_get() does not,
	 * and neither do file_get_contents() or curl_*().
	 *   -> Defeats WP-SSRF.
	 *
	 * Never set 'sslverify' => false, and never filter
	 * 'http_request_host_is_external' to true — both re-open SSRF.
	 *
	 * KNOWN LIMITS of core's validator (still worth an allowlist for
	 * high-value integrations): it is IPv4-only, it SKIPS the IP-range check
	 * when the host equals the site's own host, and DNS is resolved twice
	 * (validation, then request), so rebinding is not prevented.
	 */
	$response = wp_safe_remote_get(
		$url,
		array(
			'timeout'     => 10,
			'redirection' => 3,
			'user-agent'  => 'MyPlugin/1.0; ' . home_url( '/' ),
		)
	);

	if ( is_wp_error( $response ) ) {
		return $response;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		return new WP_Error( 'myplugin_http_error', __( 'Remote request failed.', 'my-plugin' ) );
	}

	$body = wp_remote_retrieve_body( $response );

	/*
	 * SECURITY: NEVER unserialize() a remote or user-supplied string — that is
	 * WP-POI (PHP object injection). Use JSON.
	 *   -> Defeats WP-POI / WP-RCE.
	 */
	$data = json_decode( $body, true );

	if ( null === $data && JSON_ERROR_NONE !== json_last_error() ) {
		return new WP_Error( 'myplugin_bad_json', __( 'Invalid response.', 'my-plugin' ) );
	}

	return $data;
}
```

---

## (g) Bonus: webhook receiver (legitimately unauthenticated)

```php
<?php
/*
 * SECURITY: A webhook has no WordPress cookie, so nopriv is correct here.
 * Unauthenticated is NOT the same as unauthorized — the payload itself must
 * be authenticated.
 *   -> Defeats WP-AUTHBYPASS.
 */
add_action( 'wp_ajax_nopriv_myplugin_webhook', 'myplugin_handle_webhook' );
add_action( 'wp_ajax_myplugin_webhook', 'myplugin_handle_webhook' );

function myplugin_handle_webhook() {

	$payload   = file_get_contents( 'php://input' );
	$signature = isset( $_SERVER['HTTP_X_MYPLUGIN_SIGNATURE'] )
		? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_MYPLUGIN_SIGNATURE'] ) )
		: '';

	$secret = myplugin_get_webhook_secret();   // from wp-config constant or an option

	if ( ! $secret || '' === $signature || '' === $payload ) {
		wp_send_json_error( array( 'message' => 'Bad request' ), 400 );
	}

	$expected = hash_hmac( 'sha256', $payload, $secret );

	/*
	 * SECURITY: hash_equals() is a TIMING-SAFE comparison. Using == or ===
	 * on a secret leaks it byte-by-byte through response timing.
	 *
	 * Also note the secret arrives in a HEADER, never a query string —
	 * query strings leak via access logs, Referer headers, and analytics.
	 *   -> Defeats WP-AUTHBYPASS / WP-INFO.
	 */
	if ( ! hash_equals( $expected, $signature ) ) {
		wp_send_json_error( array( 'message' => 'Invalid signature' ), 403 );
	}

	$data = json_decode( $payload, true );   // never unserialize() -- WP-POI

	if ( null === $data && JSON_ERROR_NONE !== json_last_error() ) {
		wp_send_json_error( array( 'message' => 'Invalid payload' ), 400 );
	}

	/*
	 * SECURITY: Replay protection — a valid signature is replayable forever
	 * without it. Reject stale timestamps and de-duplicate on event ID.
	 */
	$event_id  = isset( $data['id'] ) ? sanitize_key( $data['id'] ) : '';
	$timestamp = isset( $data['timestamp'] ) ? absint( $data['timestamp'] ) : 0;

	if ( '' === $event_id || abs( time() - $timestamp ) > 5 * MINUTE_IN_SECONDS ) {
		wp_send_json_error( array( 'message' => 'Stale or malformed event' ), 400 );
	}

	if ( get_transient( 'myplugin_evt_' . $event_id ) ) {
		wp_send_json_success( array( 'message' => 'Already processed' ) );
	}

	set_transient( 'myplugin_evt_' . $event_id, 1, DAY_IN_SECONDS );

	myplugin_process_webhook_event( $data );

	wp_send_json_success();
}
```

---

## Anti-pattern quick reference

Each row is a finding. The fix is the corresponding template above.

| Anti-pattern | Class | Fix |
|---|---|---|
| `if ( is_admin() )` as an authorization check | WP-ACL, WP-AUTHBYPASS | `current_user_can( $cap )` |
| `if ( is_user_logged_in() )` guarding a privileged action | WP-ACL | `current_user_can( $cap )` |
| `add_action( 'wp_ajax_nopriv_x', ... )` on a state change | WP-AJAX | Drop the nopriv registration |
| Nonce check but no capability check | WP-ACL, WP-PRIVESC | Add `current_user_can()` |
| Capability check but no nonce check | WP-CSRF | Add `check_admin_referer()` / `check_ajax_referer()` |
| `check_admin_referer()` with no action argument | WP-CSRF | Pass an explicit action string |
| `wp_verify_nonce( ... ) === true` | WP-CSRF | It returns `1`/`2`/`false` — use `! wp_verify_nonce(...)` |
| Nonce as the only control on a `_nopriv_` endpoint | WP-CSRF | Anonymous nonces are identical site-wide — redesign |
| `register_rest_route` with no `permission_callback` | WP-REST | Add one; `__return_true` only if truly public |
| `permission_callback` returning a non-boolean | WP-REST | Only `false`/`null`/`WP_Error` deny |
| `current_user_can( 'edit_posts' )` then acting on `$_POST['id']` | WP-IDOR | `current_user_can( 'edit_post', $id )` |
| `current_user_can( 'edit_post' )` with no ID | WP-ACL | Broken feature — pass the object ID |
| `in_array( 'administrator', $user->roles )` | WP-ACL | Check a capability |
| String interpolation in `$wpdb->query()` | WP-SQLI | `$wpdb->prepare()` |
| `$wpdb->prepare( "... '%s'", $v )` | WP-SQLI | Leave placeholders unquoted |
| `$wpdb->prepare( $already_built_string )` | WP-SQLI | Prepare the template, not the result |
| User input as a table/column name | WP-SQLI | `%i` (WP 6.2+) or an allowlist |
| `esc_like()` without `prepare()` | WP-SQLI | Both |
| `like_escape()` | WP-SQLI | Deprecated — `$wpdb->esc_like()` |
| `echo $var` in a template | WP-XSS-R/S | `esc_html()` / `esc_attr()` / `esc_url()` |
| `esc_attr()` or `esc_html()` on a URL in `href` | WP-XSS-R | `esc_url()` |
| `esc_attr()` on an **unquoted** attribute | WP-XSS-R | Quote the attribute |
| `_e()` / `echo __()` | WP-XSS-R | `esc_html_e()` / `esc_html__()` |
| `esc_js()` inside a `<script>` block | WP-XSS-R | `wp_json_encode()` |
| `'test_type' => false` in upload overrides | WP-UPLOAD, WP-RCE | Keep it `true`, pass a `mimes` allowlist |
| `move_uploaded_file()` with a user-supplied path | WP-UPLOAD, WP-RCE | `wp_handle_upload()` |
| `php`/`phtml`/`svg`/`html` in an `upload_mimes` filter | WP-UPLOAD, WP-RCE, WP-XSS-S | Remove |
| `include`/`require`/`readfile` on a request path | WP-LFI, WP-RCE | Accept an ID; `realpath()` prefix check |
| `validate_file()` treated as an absolute-path guard | WP-LFI | It does not reject `/etc/passwd` — add `realpath()` |
| `unlink()` on a request path | WP-DELETE | ID lookup + ownership check |
| `unserialize()` on request/remote data | WP-POI, WP-RCE | `json_decode()` |
| `eval()`, `create_function()`, `assert()`, `extract()` | WP-RCE | Remove |
| `call_user_func( $_POST['cb'] )` | WP-RCE | Allowlist of callables |
| `wp_remote_get( $user_url )` | WP-SSRF | `wp_safe_remote_get()` |
| `'sslverify' => false` | WP-SSRF | Remove |
| `wp_redirect( $_GET['url'] )` | WP-REDIRECT | `wp_safe_redirect()` |
| Redirect without `exit;` | WP-ACL, WP-AUTHBYPASS | Add `exit;` |
| `update_option( $_POST['name'], $_POST['value'] )` | WP-OPTION, WP-PRIVESC | Hardcode option names |
| `$user->set_role( $_POST['role'] )` | WP-PRIVESC | Allowlist + `promote_users` check |
| `==` / `===` comparing a secret or HMAC | WP-AUTHBYPASS | `hash_equals()` |
| `rand()` / `mt_rand()` / `uniqid()` for a token | WP-AUTHBYPASS | `wp_generate_password()` / `random_bytes()` |
| Echoing `$wpdb->last_error` or a stack trace | WP-INFO | Generic message; log server-side |
| Secret in a URL query string | WP-INFO | Use a header or POST body |

---

## See also

- `entry-points.md` — which template applies to which entry point.
- `wp-security-apis.md` — the full API tables behind each control.
- `capability-matrix.md` — choosing the right capability, and rating what you find.
