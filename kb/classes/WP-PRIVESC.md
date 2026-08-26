---
class_id: WP-PRIVESC
title: Privilege escalation via role, capability and account manipulation
cwe: [CWE-269, CWE-266, CWE-268]
owasp: A01:2021-Broken Access Control
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 5
detection:
  - id: PRIVESC-001
    description: Role name taken from the request and handed to a user-creation or user-update call
    regex: '[''"]role[''"]\s*=>\s*[^,;)]*\$_(POST|GET|REQUEST|COOKIE)'
    confidence: high
    false_positive_notes: >-
      Near-zero false positives. wp_insert_user()/wp_update_user() apply NO capability check to
      the 'role' key — core simply calls WP_User::set_role() with whatever it is given — so a
      request-supplied role is an unconditional finding unless an allowlist intercepts the value
      before this line. Note that a sanitiser on the same line (sanitize_text_field, sanitize_key)
      is not an allowlist: 'administrator' survives all of them intact.
  - id: PRIVESC-002
    description: set_role()/add_role()/add_cap() called with a variable rather than a literal
    regex: '->(set_role|add_role|add_cap)\s*\(\s*\$'
    confidence: medium
    false_positive_notes: >-
      Common in legitimate membership and e-commerce code, so triage by provenance of the
      variable. WP_User::set_role() performs no authorization of its own; it writes the
      capabilities meta directly. A get_role( $x ) or role_exists( $x ) guard upstream is NOT
      sufficient because 'administrator' is a registered role — the guard must be a positive
      allowlist of roles this feature may assign, plus a promote_users check on the caller.
  - id: PRIVESC-003
    description: Direct write to the capabilities / user_level meta key
    regex: '\b(update|add|delete)_user_meta\s*\([^;]*([''"][A-Za-z0-9_]*(capabilities|user_level)[''"]|prefix\s*\.\s*[''"](capabilities|user_level)[''"])'
    confidence: high
    false_positive_notes: >-
      Legitimate code has essentially no reason to write this key by hand — set_role()/add_role()
      exist for it. Covers both the hardcoded 'wp_capabilities' form and the correct-but-still-
      dangerous $wpdb->prefix . 'capabilities' form. Treat every hit as a role assignment and ask
      what capability guards it. Also matches the denylist-construction case, which is exactly
      what PRIVESC-008 wants you to look at.
  - id: PRIVESC-004
    description: update_user_meta()/add_user_meta() whose META KEY is a variable — the sink that lets an attacker name wp_capabilities
    regex: '\b(update|add)_user_meta\s*\(\s*[^,]+,\s*\$[^,;)]+,'
    confidence: medium
    false_positive_notes: >-
      The highest-value rule in this class and the noisiest. A variable meta key is only safe if
      it came from a hardcoded allowlist. Where it is derived from $_POST/$_GET, from an option
      an attacker can write, or from a loop over a request array, the attacker names the key —
      and 'wp_capabilities' is a valid key. Trace the second argument to its origin; do not
      dismiss a hit because the value looks harmless, since the key is the payload.
  - id: PRIVESC-005
    description: Target user identified by the request in an account-modifying call
    regex: '([''"]ID[''"]\s*=>\s*[^,;)]*\$_(POST|GET|REQUEST|COOKIE)|\b(wp_set_password|wp_update_user|wp_delete_user)\s*\([^;]*\$_(POST|GET|REQUEST|COOKIE))'
    confidence: high
    false_positive_notes: >-
      Changing another account's email address is account takeover even when no role changes,
      because the attacker then drives core's own password-reset flow. The only safe forms are
      get_current_user_id() or an ID that has been through an ownership check —
      current_user_can( 'edit_user', $id ) is NOT such a check when $id is the caller's own.
  - id: PRIVESC-006
    description: Handler hooked to a user-profile lifecycle action, which any Subscriber can trigger for themselves
    regex: 'add_action\s*\(\s*[''"](personal_options_update|edit_user_profile_update|profile_update|user_register|user_profile_update_errors)[''"]'
    confidence: medium
    false_positive_notes: >-
      Not a defect by itself; it is a reachability signal. personal_options_update fires when a
      user saves their OWN profile, so a Subscriber reaches the callback with a valid nonce that
      core printed on their own profile page. Any role or capability write inside such a callback
      must be gated on promote_users, never on edit_user. user_register fires during open
      registration and is therefore unauthenticated-reachable when users_can_register is on.
  - id: PRIVESC-007
    description: A capability check that every logged-in or low-privileged user passes
    regex: 'current_user_can\s*\(\s*[''"](edit_user|read|edit_posts|upload_files|edit_pages)[''"]\s*[,)]'
    confidence: low
    false_positive_notes: >-
      Rated low deliberately: these capabilities are correct in most contexts, so the rule
      fires on correct code (it hits the legitimate current_user_can( 'edit_posts' )
      permission_callback in tests/fixtures/safe.php). Use it as a worklist that is only
      meaningful when cross-referenced with PRIVESC-002/003/004/006 in the same handler.
      Correct in its own context and catastrophic in a role-writing one. current_user_can(
      'edit_user', $user_id ) with $user_id equal to the caller is always true — every user may
      edit their own profile — so it authorizes nothing about role changes. 'read' is held by
      every logged-in user; 'edit_posts' is Contributor and up; 'upload_files' is Author and up.
      Grade each hit against kb/reference/capability-matrix.md §2 "Choosing the right capability".
  - id: PRIVESC-008
    description: A denylist of protected user fields — check it for case, prefix and multisite evasion
    regex: '\b(in_array|unset|array_diff|array_key_exists|array)\s*\([^;]*[''"][A-Za-z0-9_]*(capabilities|user_level)[''"]'
    confidence: medium
    false_positive_notes: >-
      A hit means the author knew the key was dangerous and chose a denylist. Denylists in this
      class fail three ways, all seen in the wild: case (the comparison runs before sanitize_key()
      lowercases), multisite prefix (blocking wp_capabilities while wp_2_capabilities reaches the
      same sink on subsite 2), and completeness (blocking wp_capabilities but not wp_user_level,
      or the reverse). Convert to an allowlist rather than extending the denylist.
  - id: PRIVESC-009
    description: Password-reset and credential primitives — the exhaustive worklist
    regex: '\b(get_password_reset_key|reset_password|wp_set_password|wp_generate_password|retrieve_password|check_password_reset_key)\s*\('
    confidence: low
    false_positive_notes: >-
      Matches correct code by design. For each hit establish: which account the operation targets
      and how that account was chosen; whether the reset token is unpredictable and single-use;
      and where the resulting link or code is delivered. A reset flow that lets the requester
      choose the destination address, or that reuses a publicly visible identifier as the token,
      is account takeover on every account including the administrator's.
fix_apis:
  - current_user_can( 'promote_users' )
  - current_user_can( 'edit_users' )
  - current_user_can( 'manage_options' )
  - WP_User::set_role()
  - get_editable_roles()
  - wp_insert_user()
  - wp_update_user()
  - check_admin_referer()
  - check_ajax_referer()
  - wp_check_password()
examples:
  - cve: CVE-2026-7284
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A front-end registration AJAX handler placed the request-supplied role directly into the wp_insert_user() array, so an anonymous visitor could register as administrator.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-7284
    code_ref: https://plugins.trac.wordpress.org/browser/easy-elements/tags/1.4.0/widgets/login-register/class.login-register.php#L62
    root_cause: No allowlist on the role assigned at registration; wp_insert_user() applies no capability check to the 'role' key.
  - cve: CVE-2026-9018
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: After the role parameter was fixed to a server-chosen safe value, the same registration handler still looped an attacker-controlled meta array into update_user_meta(), letting wp_capabilities be overwritten immediately after the safe role was assigned.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-9018
    code_ref: https://plugins.trac.wordpress.org/browser/easy-elements/tags/1.4.5/widgets/login-register/class.login-register.php#L128
    root_cause: An unfiltered foreach over a request array into update_user_meta() gives the attacker the meta KEY, which defeats any control placed on the role VALUE.
  - cve: CVE-2026-12415
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: An account-edit AJAX action registered for anonymous callers passed a request-supplied user ID and email straight to wp_update_user(), enabling any account's address to be replaced and then reset through core's own password flow.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12415
    code_ref: https://plugins.trac.wordpress.org/browser/invoice-creator/trunk/lib/user-manage-function.php#L184
    root_cause: wp_ajax_nopriv_ registration with no authentication, no ownership check and no nonce; the target account is named by the request.
  - cve: CVE-2026-7106
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: A role-management handler hooked to the profile-save actions verified a nonce and checked current_user_can('edit_user', $user_id) — a capability every user holds over their own account — before assigning the request-supplied role.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-7106
    code_ref: https://plugins.trac.wordpress.org/browser/highland-software-custom-role-manager/tags/1.0.0/includes/user-ui.php#L199
    root_cause: The wrong capability. A role change requires promote_users; edit_user on one's own ID authorizes editing a profile, not granting privileges.
  - cve: CVE-2026-11616
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: An RSVP AJAX handler used a request-supplied string as the user-meta key, so posting type=wp_capabilities and postid=administrator wrote an administrator entry into the caller's own capabilities meta.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-11616
    code_ref: https://plugins.trac.wordpress.org/browser/events-for-geodirectory/tags/2.3.28/includes/class-geodir-event-ayi.php#L357
    root_cause: strip_tags(esc_sql()) applied to a meta KEY with no allowlist; WP_User::get_role_caps() then treats the 'administrator' array key as an active role.
  - cve: CVE-2026-3629
    year: 2026
    severity: 8.1
    auth: unauthenticated
    summary: A CSV-driven profile-field feature wrote every configured column to user meta and its restricted-fields list omitted the capabilities key entirely.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-3629
    code_ref: https://plugins.trac.wordpress.org/browser/import-users-from-csv-with-meta/tags/1.29.7/classes/helper.php#L146
    root_cause: A denylist that did not list wp_capabilities, guarding a sink whose meta key is chosen from stored configuration rather than from code.
  - cve: CVE-2026-7641
    year: 2026
    severity: 8.8
    auth: subscriber+
    summary: The repaired denylist blocked the current site's capabilities and user_level keys but not the equivalents for other subsites in a multisite network, so wp_2_capabilities passed the check and escalated on subsite 2.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-7641
    code_ref: https://plugins.trac.wordpress.org/browser/import-users-from-csv-with-meta/tags/2.0.6/classes/helper.php#L150
    root_cause: The denylist was built from $wpdb->prefix, which names only the current blog; WP_User's cap_key is $wpdb->get_blog_prefix( $site_id ) . 'capabilities', so every other subsite has a differently-named key reaching the same sink.
  - cve: CVE-2025-4631
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: A generic object-save endpoint accepted a datatype of 'users' with no capability check and wrote arbitrary strings directly into the capabilities meta field of an existing or newly created account.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-4631
    code_ref: https://plugins.trac.wordpress.org/browser/profitori/tags/2.1.1.3/profitori.php#L2698
    root_cause: A generic data-layer endpoint treated the user table as just another datatype, so the capabilities column inherited the same "any field, any value" contract as ordinary business data.
  - cve: CVE-2026-13439
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A password-recovery flow used the publicly visible form session identifier as the reset token, alongside a public endpoint that issued valid REST nonces to anonymous visitors.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-13439
    code_ref: https://plugins.trac.wordpress.org/browser/easy-form-builder/trunk/includes/class-Emsfb-public.php#L5060
    root_cause: The reset token was not a secret — it was scraped from the rendered login form — so any account's password could be set by anyone who knew the account's email address.
  - cve: CVE-2026-8206
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A custom password-reset form accepted an arbitrary email address alongside a username, and sent the reset link for the named account to the attacker-supplied address.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-8206
    code_ref: https://plugins.trac.wordpress.org/browser/kirki/tags/6.0.4/ComponentLibrary/controller/CompLibFormHandler.php#L330
    root_cause: The account to reset and the address to notify were taken from two independent request fields and never required to match, so the delivery channel became attacker-chosen.
---

## What it is

A user, or an anonymous visitor, ends a request holding more privilege than they started with.
In WordPress that almost always means one of four concrete writes: a role assigned from
attacker-controlled data, a direct write to the `wp_capabilities` user-meta key, a change of
another account's email or password, or a password-reset flow whose token or delivery address
the attacker controls.

This class has the **highest average CVSS in the corpus — 9.03** — despite being only 2.17% of
records, because the outcome is not "data exposed" or "site broken" but "attacker is now the
administrator", and an administrator on a default single-site install holds `edit_plugins`,
`install_plugins` and `activate_plugins`, i.e. arbitrary PHP execution.

## Why WordPress makes this easy: the three mechanisms

Everything in this class routes through machinery in `wp-includes/class-wp-user.php`, and the
machinery has no opinion about who is calling it.

**1. `set_role()` performs no authorization at all.**

```php
	public function set_role( $role ) {
		...
		if ( ! empty( $role ) ) {
			$this->caps[ $role ] = true;
			$this->roles         = array( $role => true );
		} else {
			$this->roles = array();
		}

		update_user_meta( $this->ID, $this->cap_key, $this->caps );
		$this->get_role_caps();
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/class-wp-user.php` (lines 620–640)

There is no `current_user_can()` anywhere in it. `wp_insert_user()` and `wp_update_user()` call
it directly whenever the `role` key is present, so `'role' => $_POST['role']` is a complete
exploit on its own. The capability check is entirely the plugin's job.

**2. A role is just a key in a meta array, and only the key is examined.**

```php
			foreach ( $this->caps as $key => $value ) {
				if ( $wp_roles->is_role( $key ) ) {
					$this->roles[] = $key;
				}
			}

		// Build $allcaps from role caps, overlay user's $caps.
		$this->allcaps = array();
		foreach ( (array) $this->roles as $role ) {
			$the_role      = $wp_roles->get_role( $role );
			$this->allcaps = array_merge( (array) $this->allcaps, (array) $the_role->capabilities );
		}
		$this->allcaps = array_merge( (array) $this->allcaps, (array) $this->caps );
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/class-wp-user.php` (lines 511–538)

Two consequences that drive real exploits:

- `$value` is **never inspected**. `array( 'administrator' => 'administrator' )`,
  `array( 'administrator' => 1 )` and even `array( 'administrator' => false )` all make
  `administrator` an active role, because only `is_role( $key )` is consulted. This is why
  CVE-2026-11616 works with `postid=administrator` — a value that was never meant to be a role.
- `$allcaps` is the role's capabilities **overlaid with `$this->caps`**, so a direct meta write
  does not even need a role name: `array( 'manage_options' => true )` grants the capability with
  no role change and no entry in `$user->roles` to notice during review.

**3. The meta key is site-scoped, and the scope is not what a denylist usually assumes.**

```php
			$this->cap_key = $wpdb->get_blog_prefix( $this->site_id ) . 'capabilities';
```
`https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/class-wp-user.php` (line 488)

On the main site of a network — and on every single-site install — that is `wp_capabilities`. On
subsite 2 it is `wp_2_capabilities`. A denylist built from `$wpdb->prefix` names only the blog
the request happens to be running on. Every other subsite's key is a different string that
reaches the same sink; that is CVE-2026-7641 exactly.

## Why it happens in WordPress

- **The role is just another form field.** Registration and profile forms carry `role`
  alongside `first_name`. Nothing in the framework distinguishes them, and no sanitiser does
  either: `sanitize_text_field( 'administrator' )` is `'administrator'`.
- **`current_user_can( 'edit_user', $user_id )` reads like an ownership check and is not a
  privilege check.** Every user may edit their own profile, so the check passes for a Subscriber
  editing themselves — which is precisely the request in which a role field is submitted. The
  capability a role change needs is `promote_users`; see
  `kb/reference/capability-matrix.md` §2.
- **`get_role( $x )` / `role_exists( $x )` are validity checks, not allowlists.**
  `administrator` is a perfectly valid role. Code that rejects `superuser` and accepts
  `administrator` looks validated and is not.
- **Profile hooks are Subscriber-reachable with a valid nonce.**
  `personal_options_update` fires when a user saves their *own* profile at
  `/wp-admin/profile.php` — a page every logged-in user can load, complete with the nonce core
  printed on it. A nonce check on such a handler proves nothing about privilege.
- **`user_register` is unauthenticated-reachable** whenever `users_can_register` is on — which
  a WP-OPTIONS finding can turn on. The two classes chain: arbitrary option write enables open
  registration, and a role-manipulation bug in the registration path then grants administrator.
- **Meta writes are generic.** Plugins expose "save my custom fields" endpoints that loop a
  request array into `update_user_meta()`. The loop is written to be extensible, which is the
  same thing as being unconstrained.
- **Email change is account takeover.** Changing an administrator's `user_email` requires no
  role write at all: set the address, then use core's own "lost password" flow. Any handler that
  lets you name someone else's user ID in a `wp_update_user()` call is a 9.8.
- **Denylists sit upstream of normalisation.** Compare-then-normalise loses to case changes
  (`WP_CAPABILITIES` → `sanitize_key()` → `wp_capabilities`) and to prefix variants. Compare
  after normalisation, or better, allowlist.

## Vulnerable pattern

```php
// 1. The role is a request field.
add_action( 'wp_ajax_nopriv_example_register', 'example_register' );
function example_register() {
    $user_id = wp_insert_user( array(
        'user_login' => sanitize_user( $_POST['user_login'] ),
        'user_email' => sanitize_email( $_POST['user_email'] ),
        'user_pass'  => $_POST['user_pass'],
        'role'       => sanitize_text_field( $_POST['role'] ),   // 'administrator' survives this
    ) );
}

// 2. The role was fixed -- but the meta loop was not.
$user_id = wp_insert_user( $user_data );          // 'role' => $safe_role, correctly
foreach ( $custom_meta as $key => $value ) {      // $custom_meta comes from $_POST
    update_user_meta( $user_id, $key, $value );   // custom_meta[wp_capabilities][administrator]=1
}

// 3. The capability checked is not the capability needed.
add_action( 'personal_options_update', 'example_save_user_roles' );   // Subscriber, own profile
function example_save_user_roles( $user_id ) {
    if ( ! current_user_can( 'edit_user', $user_id ) ) {  // always TRUE for one's own account
        return;
    }
    check_admin_referer( 'example_save_user_roles', 'example_nonce' ); // nonce is on that page
    $roles = array_map( 'sanitize_key', wp_unslash( $_POST['example_roles'] ) );
    $user  = new WP_User( $user_id );
    if ( get_role( $roles[0] ) ) {                       // 'administrator' is a valid role
        $user->set_role( $roles[0] );
    }
}

// 4. The meta KEY is attacker-chosen.
$type = strip_tags( esc_sql( $_POST['type'] ) );          // no allowlist
$pid  = strip_tags( esc_sql( $_POST['postid'] ) );
update_user_meta( $current_user->ID, $type, array( $pid => $pid ) );
// type=wp_capabilities&postid=administrator

// 5. The account is chosen by the request.
$args = array( 'ID' => $_POST['user_id'], 'user_email' => esc_attr( $_POST['user_email'] ) );
wp_update_user( $args );      // then drive core's lost-password flow against the new address
```

Shapes 3 and 4 are the ones that survive review, because both contain a nonce check and shape 3
also contains a `current_user_can()`. Neither answers the question "may this user grant
privilege".

## Secure pattern

Three separate obligations: the right capability, an allowlist on the role, and never letting
the request name the meta key or the target account.

```php
add_action( 'wp_ajax_example_set_role', 'example_set_role' );
// No wp_ajax_nopriv_ counterpart. Privilege grants are never anonymous.

function example_set_role() {
    // 1. INTENT.
    check_ajax_referer( 'example_set_role', 'nonce' );

    // 2. PERMISSION -- the capability the OPERATION needs, not the one the screen needs.
    //    promote_users is the capability WordPress itself gates role changes on, and unlike
    //    install_plugins it survives on multisite, so it is a genuine takeover-equivalent.
    if ( ! current_user_can( 'promote_users' ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    $target = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
    $role   = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';

    // 3. ALLOWLIST the role. get_role()/role_exists() are validity checks, not allowlists;
    //    get_editable_roles() applies core's editable_roles filter, and the explicit
    //    array_key_exists() keeps this feature from ever assigning administrator.
    $assignable = array_intersect_key(
        get_editable_roles(),
        array_flip( array( 'subscriber', 'contributor', 'customer' ) )
    );
    if ( ! array_key_exists( $role, $assignable ) ) {
        wp_send_json_error( array( 'message' => 'role not assignable' ), 400 );
    }

    // 4. Do not let a caller act on an account above their own level.
    $user = get_userdata( $target );
    if ( ! $user || ! current_user_can( 'edit_user', $target ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }
    if ( user_can( $user, 'manage_options' ) && ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
    }

    $user->set_role( $role );
    wp_send_json_success();
}
```

For the "save my profile fields" shape, the fix is an allowlist of **keys**, built in code:

```php
function example_save_profile_meta( $user_id ) {
    if ( ! current_user_can( 'edit_user', $user_id ) ) {   // fine HERE: no privilege is granted
        return;
    }
    check_admin_referer( 'update-user_' . $user_id );

    // The keys are a constant. Nothing the request sends can add to this list, so
    // wp_capabilities / wp_2_capabilities / wp_user_level can never be named.
    $allowed = array( 'example_phone', 'example_company', 'example_bio' );

    foreach ( $allowed as $key ) {
        if ( isset( $_POST[ $key ] ) ) {
            update_user_meta( $user_id, $key, sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) );
        }
    }
}
```

Non-negotiables: `promote_users` (or `edit_users`) guards any role or capability write; the role
is checked against a positive list of assignable roles, never merely `get_role()`; meta keys come
from a hardcoded array, never from the request or from stored configuration an attacker can
influence; the target user ID is `get_current_user_id()` or has passed an ownership check that is
meaningful for a *different* account; and a caller may never modify an account that outranks them.

## Real-world case studies

### The role field, and the fix that missed the second sink (CVE-2026-7284 → CVE-2026-9018)

Version 1.4.4 of a registration widget put the request's role straight into `wp_insert_user()`,
a 9.8 unauthenticated escalation
(`https://plugins.trac.wordpress.org/browser/easy-elements/tags/1.4.0/widgets/login-register/class.login-register.php#L62`).
The fix replaced it with a server-chosen role — and the very next release was still vulnerable:

```php
        $custom_meta = !empty($_POST['custom_meta'])
        ? map_deep( wp_unslash( $_POST['custom_meta'] ), 'sanitize_text_field' )
        : [];
...
        $safe_role = $this->easyel_get_safe_registration_role();

        $user_data = [
            ...
            'role'          => $safe_role,
        ];
...
        $user_id = wp_insert_user( $user_data );

        if ( is_wp_error( $user_id ) ) {
            return wp_send_json_error( ['msg' => $user_id->get_error_message()] );
        }

        // Save meta
        foreach ( $custom_meta as $key => $value ) {
            update_user_meta( $user_id, $key, $value );
        }
```
`https://plugins.trac.wordpress.org/browser/easy-elements/tags/1.4.5/widgets/login-register/class.login-register.php#L128`

**Root cause at that line:** `'role' => $safe_role` is now correct, and it is irrelevant.
`custom_meta[wp_capabilities][administrator]=1` reaches `update_user_meta( $user_id,
'wp_capabilities', array( 'administrator' => '1' ) )` three lines later and overwrites the safe
role that `wp_insert_user()` just assigned. `map_deep( ..., 'sanitize_text_field' )` sanitises
the *values* and leaves the *keys* untouched, which is the wrong half.

Two more details from the same function that generalise:

- The handler's only gate is `wp_verify_nonce( $posted_nonce, 'easy_elements_nonce' )`, and the
  advisory records that this nonce is published in the DOM of any page carrying the
  login/register widget. A nonce a public page hands out is not a control — see **WP-CSRF**,
  rule CSRF-007.
- The function ends with `wp_set_current_user( $user_id ); wp_set_auth_cookie( $user_id, ... );`,
  so the attacker is logged into the account they just escalated within the same request.

**The lesson to carry into every audit: constraining the role VALUE is worthless while any
sink in the same request lets the attacker choose a meta KEY.** Audit `role` and `update_user_meta`
together, never separately.

### The wrong capability, with a nonce for camouflage (CVE-2026-7106, 8.8, subscriber+)

```php
add_action('personal_options_update', 'hscrm_save_user_roles');
add_action('edit_user_profile_update', 'hscrm_save_user_roles');
add_action('user_register', 'hscrm_save_user_roles');

function hscrm_save_user_roles($user_id) {

    /**
     * SECURITY: Capability check
     */
    if (!current_user_can('edit_user', $user_id)) {
        return;
    }

    /**
     * SECURITY: Nonce verification
     */
    if (
        !isset($_POST['hscrm_roles_nonce']) ||
        !wp_verify_nonce(
            sanitize_text_field(wp_unslash($_POST['hscrm_roles_nonce'])),
            'hscrm_save_user_roles'
            )
    ) {
        return;
    }
...
    if (!get_role($primary_role)) {
        $primary_role = $default_role;
    }

    $user->set_role($primary_role);
```
`https://plugins.trac.wordpress.org/browser/highland-software-custom-role-manager/tags/1.0.0/includes/user-ui.php#L199`

**Root cause at that line:** every control here is real and none of them is the right one.

- `current_user_can( 'edit_user', $user_id )` is `true` for a Subscriber editing their own
  profile — `map_meta_cap()`'s self-edit shortcut. It authorizes editing a profile, not granting
  privilege. The capability needed is `promote_users`.
- The nonce is genuine and correctly verified — and it is printed by the plugin's own
  `wp_nonce_field()` onto `/wp-admin/profile.php`, a page the Subscriber loads legitimately.
- `if ( ! get_role( $primary_role ) )` is a validity check, and `administrator` is valid, so it
  passes the value through untouched.

The handler is registered on `personal_options_update`, so the whole chain is: Subscriber loads
their own profile, reads the nonce core printed there, POSTs `hscrm_roles[]=administrator`.
This is the shape PRIVESC-006 plus PRIVESC-007 exist to find together — neither is a finding
alone, and the pair almost always is.

### The attacker names the meta key (CVE-2026-11616, 8.8, subscriber+)

```php
	public static function ajax_ayi_action() {
		check_ajax_referer('geodir-ayi-nonce', 'geodir_ayi_nonce');
		//set variables
		$action = strip_tags(esc_sql($_POST['btnaction']));
		$type = strip_tags(esc_sql($_POST['type']));
		$post_id = strip_tags(esc_sql($_POST['postid']));
...
			update_user_meta( $current_user->ID, $rsvp_args['type'], $posts );
```
`https://plugins.trac.wordpress.org/browser/events-for-geodirectory/tags/2.3.28/includes/class-geodir-event-ayi.php#L357`

**Root cause at that line:** `$type` is a request string with no allowlist and it is the *meta
key*. `esc_sql()` escapes for SQL and `strip_tags()` removes markup; neither restricts the value
to the two or three keys this RSVP feature actually uses. Posting `type=wp_capabilities` and
`postid=administrator` produces `array( 'administrator' => 'administrator' )` in the caller's own
capabilities meta, and — per `get_role_caps()` above — the array *key* is all WordPress inspects.

Note that the write targets `$current_user->ID`, so this is self-escalation rather than
takeover of another account. That is still a full compromise: an attacker registers a Subscriber
account (or already has one on any membership site) and returns as an administrator. A rule that
only looks for writes to *other* users' meta misses the entire shape.

The `check_ajax_referer()` at the top is correct and irrelevant — a logged-in Subscriber has
every nonce the front end issues them.

### Denylist, twice (CVE-2026-3629 → CVE-2026-7641)

The first version's restricted-fields list did not mention the capabilities key at all. The
repaired version does:

```php
    function get_restricted_fields(){
        global $wpdb;

        $wp_users_fields = $this->get_wp_users_fields();
        $wp_min_fields = array( "Username", "Email", "role", $wpdb->prefix . 'capabilities', $wpdb->prefix . 'user_level' );
        $acui_restricted_fields = array_merge( $wp_users_fields, $wp_min_fields );

        return apply_filters( 'acui_restricted_fields', $acui_restricted_fields );
    }
```
`https://plugins.trac.wordpress.org/browser/import-users-from-csv-with-meta/tags/2.0.6/classes/helper.php#L150`

and the sink it guards:

```php
	function save_extra_user_profile_fields( $user_id ){
		if( !current_user_can( 'edit_user', $user_id ) )
			return;
...
		$headers = get_option("acui_columns");
		$acui_restricted_fields = ACUIHelper()->get_restricted_fields();
...
			foreach ( $headers as $column ){
				if( in_array( strtolower( $column ), array_map( 'strtolower', $acui_restricted_fields ) ) )
					continue;
...
                    update_user_meta( $user_id, $column, $post_filtered[ $column_sanitized ] );
```
`https://plugins.trac.wordpress.org/browser/import-users-from-csv-with-meta/tags/2.0.6/classes/columns.php#L221`

**Root cause at that line:** `$wpdb->prefix` is the prefix of the blog handling the request. On
the main site it yields `wp_capabilities` and `wp_user_level` — and `WP_User::$cap_key` for
subsite 2 is `wp_2_capabilities`, a string this list never contains. Submitting that column name
passes `in_array()` and writes straight through.

Three things generalise from this pair:

1. **The denylist got one revision and was still incomplete.** Denylists in this class are
   revised, not fixed. The correct shape is the inverse: an allowlist of the keys this feature
   owns.
2. **The `strtolower()` on both sides is the right instinct** — it closes the case-evasion route
   that WP-DELETE's CVE-2026-8095 exploited — and it does nothing about a prefix variant. Case
   normalisation and namespace completeness are independent problems.
3. **The capability check is the same self-edit trap as CVE-2026-7106.** The meta keys reaching
   the sink come from `get_option( 'acui_columns' )`, i.e. from stored state written by an
   earlier CSV import — so no superglobal appears near the dangerous key, exactly the
   stored-state pattern WP-DELETE's DELETE-008 describes.

### Anonymous account-takeover by email swap (CVE-2026-12415, 9.8, unauthenticated)

```php
function pravel_invoice_edit_account(){
	$user_id = sanitize_text_field($_POST['user_id']);
	...
	$user_email = sanitize_text_field($_POST['user_email']);
	...
	$args = array(
		'ID'         => $user_id,
		'user_email' => esc_attr( $user_email )
	);
	wp_update_user( $args );
	...
}

add_action( 'wp_ajax_nopriv_pravel_invoice_edit_account', 'pravel_invoice_edit_account' );
add_action( 'wp_ajax_pravel_invoice_edit_account', 'pravel_invoice_edit_account' );
```
`https://plugins.trac.wordpress.org/browser/invoice-creator/trunk/lib/user-manage-function.php#L184`

**Root cause at that line:** the target account is `$_POST['user_id']` and nothing establishes
that the caller owns it — there is no `is_user_logged_in()`, no `current_user_can()`, no nonce,
and the handler is registered on `wp_ajax_nopriv_`. No role is ever written, which is exactly why
this shape evades role-focused review: set user 1's email to your own address, then click
"Lost your password?" on `wp-login.php` and let core hand you the reset link.

**Any handler that accepts a user ID from the request and reaches `wp_update_user()`,
`wp_set_password()` or `wp_delete_user()` is a privilege-escalation finding regardless of whether
the word "role" appears.** That is what PRIVESC-005 exists for.

### Password resets whose token or destination is not a secret (CVE-2026-13439 and CVE-2026-8206)

Two variants of the same failure at opposite ends of the reset flow:

- The **token is public.** A recovery flow stored the form's session identifier — a value
  rendered into the published login form and readable by any visitor — as the password-reset
  token, and a separate public REST endpoint issued valid `wp_rest` nonces to anonymous callers.
  Scrape the identifier, request recovery for a known administrator address, then set an
  arbitrary password.
  `https://plugins.trac.wordpress.org/browser/easy-form-builder/trunk/includes/class-Emsfb-public.php#L5060`
- The **destination is chosen by the attacker.** A custom reset form accepted a username *and* an
  arbitrary email address, and sent the reset link for the named account to whichever address the
  request supplied. The token stayed unpredictable; it was simply delivered to the wrong person.
  `https://plugins.trac.wordpress.org/browser/kirki/tags/6.0.4/ComponentLibrary/controller/CompLibFormHandler.php#L330`

**Root cause in both:** a reset is a privilege grant, and it rests on exactly two secrets — the
unpredictability of the token and the fact that only the account owner can read the mailbox it is
sent to. Custom flows routinely reuse an existing identifier as the token (breaking the first) or
take the delivery address from the request (breaking the second). Core's own
`get_password_reset_key()` / `check_password_reset_key()` / `retrieve_password()` get both right;
a plugin that reimplements them is the finding. This is what PRIVESC-009 is for.

### The user table as generic data (CVE-2025-4631, 9.8, unauthenticated)

A generic "save object" endpoint dispatched on a `_datatype` parameter, and `users` was one of
the accepted datatypes; the handler then wrote arbitrary strings into the account's capabilities
field with no capability check on the caller.
`https://plugins.trac.wordpress.org/browser/profitori/tags/2.1.1.3/profitori.php#L2698`

**Root cause:** a data-abstraction layer that treats every table identically inherits its weakest
authorization decision for its most dangerous table. When you find a generic
`save_object`/`update_record`/`sync_entity` endpoint, enumerate the datatypes it accepts and check
whether `users`, `usermeta` or `options` are among them — that single question converts a
"generic CRUD endpoint" finding into a 9.8.

## Detection guidance

**What the regexes catch reliably**

- `PRIVESC-001` is the cleanest rule in the class: `'role' => $_POST[...]` has no benign form,
  because core applies no capability check to that key.
- `PRIVESC-003` catches hand-written capability-meta writes, which legitimate code has almost no
  reason to perform.
- `PRIVESC-005` catches the account-takeover-without-role-change shape, which role-focused review
  reliably misses.
- `PRIVESC-006` plus `PRIVESC-007` are most valuable **as a pair**: a profile-lifecycle hook whose
  handler checks `edit_user` and writes a role is the CVE-2026-7106 shape exactly, and neither
  rule alone would justify a finding.

**What the regexes CANNOT catch — read the code**

1. **Where a variable role or meta key came from.** `PRIVESC-002` and `PRIVESC-004` produce
   candidates, not findings. Trace each argument back to a hardcoded array (safe), a request
   (finding), or stored configuration (finding if any endpoint can write that configuration —
   the CVE-2026-3629 shape, where `get_option('acui_columns')` supplies the key).
2. **Whether an allowlist is really an allowlist.** `get_role( $x )`, `role_exists( $x )`,
   `wp_roles()->is_role( $x )` and `in_array( $x, array_keys( wp_roles()->roles ) )` all accept
   `administrator`. Only a list this feature owns is an allowlist.
3. **Whether the capability is the right one.** No regex can decide that. Take every
   `current_user_can()` guarding a privilege write to
   `kb/reference/capability-matrix.md` §2 and answer: does this capability imply the authority to
   grant privilege? `edit_user` on one's own ID, `read`, `edit_posts`, `edit_pages` and
   `manage_woocommerce` do not.
4. **Horizontal escalation into an outranking account.** `promote_users` alone lets an
   Administrator act on a Super Admin's account on multisite, and a plugin-defined "manager" role
   frequently carries plugin capabilities that let it create administrators — CVE-2026-15312 is
   that shape. Ask what the *lowest* role holding the checked capability is.
5. **The second sink in the same handler.** CVE-2026-9018's role parameter was correct. Read the
   whole function, not the `wp_insert_user()` call.
6. **Capability writes with no role name.** `array( 'manage_options' => true )` written into the
   capabilities meta grants the capability with no role change, so `$user->roles` looks normal in
   any admin listing.
7. **Escalation through stored state.** The dangerous key can come from an option, post meta, a
   CSV import, or a settings row. Find the sink first, identify the storage key, then audit every
   writer of that key — the same two-step this KB documents under WP-DELETE (DELETE-008).
8. **Multisite key variants.** `wp_2_capabilities`, `wp_2_user_level`, and the same for every
   subsite. Any denylist built from `$wpdb->prefix` is incomplete on a network.
9. **Custom role tables and capability filters.** Plugins that implement their own role systems
   often bridge back to `WP_User` at some point; find the bridge. Also check
   `add_filter( 'user_has_cap', ... )` and `add_filter( 'map_meta_cap', ... )` — a plugin can
   grant capabilities from a filter with no meta write at all.
10. **Reset-flow secrecy.** Whether a token is unpredictable, single-use and bound to the account,
    and whether the delivery address is server-resolved, are all semantic questions.

## Audit checklist

- [ ] Run `PRIVESC-001` and `PRIVESC-003` first — their hits are findings, not candidates.
- [ ] Run `PRIVESC-005`; for every hit, establish how the target account is chosen. Anything other
      than `get_current_user_id()` or a genuine ownership check is account takeover.
- [ ] Run `PRIVESC-002` and `PRIVESC-004` and trace every variable to its origin: hardcoded array,
      request, or stored state. Treat stored state as attacker-controlled until you have audited
      every writer of that key.
- [ ] Cross-reference `PRIVESC-006` and `PRIVESC-007`. A profile-lifecycle hook whose handler
      checks `edit_user`/`read`/`edit_posts` and writes a role or capability is a finding.
- [ ] For every role assignment, confirm the guard is `promote_users` (or `edit_users` with an
      explicit rank comparison) — not `edit_user`, not `manage_options` alone, and never a role
      name test such as `in_array( 'administrator', $user->roles )`.
- [ ] For every role assignment, confirm the value is checked against a positive list this feature
      owns. `get_role()`/`role_exists()` accept `administrator`.
- [ ] Read the whole handler after any `wp_insert_user()` / `wp_update_user()` call and look for a
      second sink — a meta loop, a `set_role()` in a callback, a `do_action` that other code hooks.
- [ ] Run `PRIVESC-008` and, for each denylist, test three evasions: case, multisite prefix
      (`wp_2_capabilities`), and sibling keys (`wp_user_level`, `wp_2_user_level`). Recommend
      converting it to an allowlist.
- [ ] Grep for `add_filter( 'user_has_cap'` and `add_filter( 'map_meta_cap'` — capabilities can be
      granted without any meta write.
- [ ] Run `PRIVESC-009`; for each reset primitive, verify the token is unpredictable, single-use
      and account-bound, and that the delivery address is resolved from the account rather than
      taken from the request.
- [ ] Enumerate generic data endpoints (`save_object`, `update_record`, `sync_*`, `import_*`,
      `/wp-json/*/data`) and list the datatypes/tables they accept. `users`, `usermeta` and
      `options` in that list are 9.8 candidates.
- [ ] Check whether any WP-OPTIONS finding in the same codebase can set `users_can_register` or
      `default_role` — that pair alone is anonymous administrator creation, and it also opens the
      `user_register` hook to unauthenticated callers, chaining into every finding above.
- [ ] Verify each fix does all three: right capability, role allowlist, hardcoded meta-key list.
      A fix that only constrains the role value is the CVE-2026-9018 shape and is still exploitable.
