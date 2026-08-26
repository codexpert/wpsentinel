# Reference: WordPress Capability Matrix and Privilege-Severity Model

**Audience:** an auditing agent that must (a) decide which capability a handler
*should* require, and (b) convert "who can reach this flaw" into a defensible
severity rating.

**Verified against:** WordPress core `master` (7.2-alpha; current stable 7.1) —
`wp-includes/capabilities.php`, `wp-includes/class-wp-user.php`,
`wp-admin/includes/schema.php` (`populate_roles*`), `wp-includes/load.php`,
`wp-includes/user.php`, `wp-includes/ms-functions.php` — plus
`wordpress.org/documentation/article/roles-and-capabilities/` and
`developer.wordpress.org/apis/wp-config-php/`. The `unfiltered_html` logic was
cross-checked against the 6.8 and 6.9 tags and is identical.

---

## 0. The structural fact that governs everything below

There are **two independent layers**, and conflating them produces wrong
conclusions:

1. **Stored role capabilities** — the `wp_user_roles` option, seeded by
   `populate_roles()`. This is what `get_role( 'administrator' )->capabilities`
   and `$user->allcaps` return.
2. **`map_meta_cap()` runtime gating** — runs on *every* `current_user_can()` /
   `user_can()` call and can return `'do_not_allow'` regardless of what the stored
   role array says.

> **A capability present in the stored role array can still be denied at runtime.**

Any check that reads role caps from the database and concludes "Administrator has
`unfiltered_html`" will be **wrong on multisite** and wrong on hardened single
sites. **Always evaluate through `user_can()` / `current_user_can()`, never
through `get_role()`.**

---

## 1. The six roles

| Role | Purpose | Legacy levels | Registration reachable? |
|---|---|---|---|
| **Subscriber** | Read + manage own profile | `level_0` | ✅ **Yes** — the default `default_role` for open registration |
| **Contributor** | Write own drafts; cannot publish; cannot upload | `level_0`–`level_1` | Common on multi-author / guest-post sites |
| **Author** | Publish and manage own posts; can upload | `level_0`–`level_2` | Common |
| **Editor** | Manage all content by anyone | `level_0`–`level_7` | Trusted staff |
| **Administrator** | Full single-site control | `level_0`–`level_10` | Site owner |
| **Super Admin** | Network-wide control (multisite only) | — | Network owner |

**Subscriber's actual stored capabilities are exactly two:** `read` and `level_0`
(from `populate_roles_160()`; no later `populate_roles_*` touches the subscriber
role). The official docs list only `read`, which is accurate in spirit but
incomplete — `level_0` is a real entry in `$user->allcaps` and in the
`wp_capabilities` usermeta array.

Two further capabilities are granted at runtime by `WP_User::has_cap()` to any
existing user: `exist` ("Everyone is allowed to exist"), and `do_not_allow` is
unconditionally unset from the map.

---

## 2. Security-relevant capability matrix

Legend: **A** = Administrator, **E** = Editor, **Au** = Author, **C** = Contributor,
**S** = Subscriber, **SA** = Super Admin. Super Admin holds everything by
definition unless explicitly denied.

### Site-takeover-equivalent capabilities

Holding **any** of these is functionally equivalent to full site compromise,
because each one allows arbitrary PHP execution or arbitrary privilege grants.
This is the key insight for the severity model in §6.

| Capability | Stored on | Runtime gate | Effective holders | Why it is takeover |
|---|---|---|---|---|
| `edit_plugins` | A | `DISALLOW_FILE_EDIT`; `DISALLOW_FILE_MODS`; multisite non-SA denied | A (single site), SA | Write arbitrary PHP via the file editor |
| `edit_themes` | A | same | A (single site), SA | Same |
| `edit_files` | A | same | A (single site), SA | Docs mark it "no longer used" |
| `install_plugins` | A | `DISALLOW_FILE_MODS`; multisite non-SA denied | A (single site), SA | Upload a ZIP containing arbitrary PHP |
| `upload_plugins` / `upload_themes` | A | same | A (single site), SA | Same |
| `install_themes` | A | same | A (single site), SA | Same |
| `update_core` | A | same | A (single site), SA | Arbitrary code via update source |
| `activate_plugins` | A | multisite: also needs `manage_network_plugins` unless network `menu_items['plugins']` is set | A (single site); conditional on multisite | Activate already-uploaded malicious PHP |
| `unfiltered_upload` | A | Denied unless `ALLOW_UNFILTERED_UPLOADS`; multisite SA-only | **Nobody by default** | Upload `.php` directly |
| `promote_users` | A | **none** — passes through even on multisite | A, SA | Make yourself/anyone an Administrator |
| `edit_users` | A | multisite: needs `manage_network_users` | A (single site), SA | Change any user's password/role |
| `manage_options` | A | none | A, SA | Rewrite `default_role`, `users_can_register`, `siteurl`, etc. |

### Content and moderation capabilities

| Capability | A | E | Au | C | S | Notes |
|---|---|---|---|---|---|---|
| `read` | ✅ | ✅ | ✅ | ✅ | ✅ | Everyone. **Passing `'read'` as a menu-page capability = every logged-in user.** |
| `edit_posts` | ✅ | ✅ | ✅ | ✅ | ❌ | **Primitive.** No ownership/status check. Contributor+ |
| `delete_posts` | ✅ | ✅ | ✅ | ✅ | ❌ | Primitive |
| `publish_posts` | ✅ | ✅ | ✅ | ❌ | ❌ | |
| `edit_published_posts` | ✅ | ✅ | ✅ | ❌ | ❌ | |
| `upload_files` | ✅ | ✅ | ✅ | ❌ | ❌ | **Contributor cannot upload** |
| `edit_others_posts` | ✅ | ✅ | ❌ | ❌ | ❌ | |
| `moderate_comments` | ✅ | ✅ | ❌ | ❌ | ❌ | |
| `manage_categories` | ✅ | ✅ | ❌ | ❌ | ❌ | |
| `unfiltered_html` | ✅ | ✅ | ❌ | ❌ | ❌ | **Single site only** — see §3 |
| `list_users` | ✅ | ❌ | ❌ | ❌ | ❌ | |
| `export` / `import` | ✅ | ❌ | ❌ | ❌ | ❌ | |
| `edit_theme_options` | ✅ | ❌ | ❌ | ❌ | ❌ | |
| `customize` | ✅ | ❌ | ❌ | ❌ | ❌ | **Not stored on any role** — meta cap aliasing `edit_theme_options` |
| `edit_dashboard` | ✅ | ❌ | ❌ | ❌ | ❌ | |

> ⚠️ `customize` is a pure meta capability:
> `case 'customize': $caps[] = 'edit_theme_options'; break;`
> Scanning role arrays for it always returns nothing. Do not conclude "nobody can
> customize".

### Choosing the right capability for a handler

| The handler… | Require |
|---|---|
| changes a site-wide setting / option | `manage_options` |
| creates, edits, or deletes users or roles | `edit_users` / `promote_users` / `delete_users` |
| lists users or exposes user data | `list_users` |
| edits a **specific** post | `edit_post`, **`$post_id`** |
| deletes a **specific** post | `delete_post`, **`$post_id`** |
| reads a **specific** private post | `read_post`, **`$post_id`** |
| edits any post generally (menu gating only) | `edit_posts` |
| edits others' content | `edit_others_posts` |
| uploads a file | `upload_files` |
| moderates comments | `moderate_comments` |
| touches theme settings | `edit_theme_options` |
| installs/activates plugins | `install_plugins` / `activate_plugins` |
| is network-wide (multisite) | `manage_network_options` / `manage_network` |

---

## 3. `unfiltered_html` — the capability that changes XSS severity

Verbatim from `wp-includes/capabilities.php` (identical in 6.8, 6.9, and trunk):

```php
case 'edit_css':
case 'unfiltered_html':
	// Disallow unfiltered_html for all users, even admins and super admins.
	if ( defined( 'DISALLOW_UNFILTERED_HTML' ) && DISALLOW_UNFILTERED_HTML ) {
		$caps[] = 'do_not_allow';
	} elseif ( is_multisite() && ! is_super_admin( $user_id ) ) {
		$caps[] = 'do_not_allow';
	} else {
		$caps[] = 'unfiltered_html';
	}
	break;
```

| Environment | Who effectively has `unfiltered_html` |
|---|---|
| **Single site** | **Administrator and Editor** |
| **Multisite** | **Super Admins only** — a site Administrator does **not** have it, even though the stored role array still lists it |
| `DISALLOW_UNFILTERED_HTML` defined truthy | **Nobody**, including Super Admins |

The Super Admin denial is real: `WP_User::has_cap()` short-circuits with
*"Multisite super admin has all caps by definition, Unless specifically denied"*
and returns `false` when `do_not_allow` is in `$caps`.

- ⚠️ **`edit_css` is an undocumented alias** sharing the same case block. A
  hardening check that greps only for `unfiltered_html` misses it.
- ⚠️ **Documentation bug to be aware of:** the capability-vs-role table on
  `wordpress.org/documentation/article/roles-and-capabilities/` contains **two
  contradictory `unfiltered_html` rows** — one marked "yes (single site)" and one
  marked plain "yes". The **"yes (single site)" row is correct**; the other
  contradicts both the page's own prose note and the source. The same table also
  lists `delete_site` as unconditionally available to Administrators, but the
  source makes it multisite-only.

### Why this matters for rating XSS

`unfiltered_html` is *permission to inject HTML and JavaScript into content*. So:

- A user who **has** `unfiltered_html` cannot meaningfully "achieve" stored XSS —
  they are authorized to post scripts. **Editor+ stored XSS on single site is
  usually not a vulnerability.**
- ⚠️ **But on multisite, an Editor — and even a site Administrator — does NOT have
  `unfiltered_html`.** The same "Editor+ stored XSS" is therefore a **genuine
  vulnerability on multisite**, where it lets a site admin escalate to Super
  Admin. Always state the environment assumption when down-rating on this basis.
- A user **without** it (Subscriber, Contributor, Author) achieving stored XSS
  **has crossed a real boundary** — see §6.
- ⚠️ **`unfiltered_html` does not gate shortcodes or block `render_callback`s.**
  A Contributor's shortcode attributes reach the callback and its return value is
  inserted into the page *after* KSES has already run. This is why
  "Contributor+ stored XSS" is real even on KSES-filtered sites.

---

## 4. Meta capabilities vs. primitive capabilities

**Primitive** capabilities are stored on roles (`edit_posts`, `manage_options`).
**Meta** capabilities are per-object and are resolved by `map_meta_cap()` into one
or more primitives (`edit_post` + a post ID → `edit_others_posts`,
`edit_published_posts`, …).

### The fail-open bug — flag this loudest

```php
if ( current_user_can( 'edit_posts' ) ) { /* then edit $_POST['post_id'] */ }  // ❌ WP-IDOR
if ( current_user_can( 'edit_post', $post_id ) ) { /* correct */ }             // ✅
```

`edit_posts` (plural, primitive) is held by **Contributor and up** and carries
**no ownership, status, or post-type check whatsoever**. Only the singular
`edit_post` meta capability resolves author/status logic:

```php
if ( $post->post_author && $user_id === (int) $post->post_author ) {
	if ( in_array( $post->post_status, array( 'publish', 'future' ), true ) ) {
		$caps[] = $post_type->cap->edit_published_posts;
	} // ... else edit_posts
} else {
	$caps[] = $post_type->cap->edit_others_posts;
	if ( in_array( $post->post_status, array( 'publish', 'future' ), true ) ) {
		$caps[] = $post_type->cap->edit_published_posts;
	} elseif ( 'private' === $post->post_status ) {
		$caps[] = $post_type->cap->edit_private_posts;
	}
}
```

**This is the canonical WP-IDOR enabler.** A Contributor passes
`current_user_can( 'edit_posts' )` and then edits *anyone's* published post.

### The fail-closed bug — a broken feature, not an escalation

`current_user_can( 'edit_post' )` **without** the post ID:

- On **WP ≥ 6.1**, `map_meta_cap()` emits `_doing_it_wrong( ..., '6.1.0' )` —
  *"When checking for the `edit_post` capability, you must always check it against
  a specific post."* — and appends `do_not_allow`. `WP_User::has_cap()` then
  returns **`false` for every user, including Super Admins**. Fail-closed: the
  feature silently breaks for everyone. The `_doing_it_wrong` notice is invisible
  without `WP_DEBUG`, so in production it presents as "the button disappeared".
- ⚠️ On **WP ≤ 6.0** the guard did not exist: `get_post( $args[0] )` with an
  undefined index called `get_post( null )`, **which returns the global `$post`**.
  The check silently evaluated against whatever post was in the loop — a genuine
  wrong-object bug. **Severity depends on the target's minimum WP version.**

### Meta caps WITH a missing-ID guard (fail closed on WP 6.1+)

`delete_post`, `delete_page`, `edit_post`, `edit_page`, `read_post`, `read_page`,
`publish_post`, `edit_comment`, `edit_term`, `delete_term`, `assign_term`, and the
`*_post_meta`, `*_comment_meta`, `*_term_meta`, `*_user_meta` families.

### ⚠️ Meta caps WITHOUT a guard — these fall through to their primitive

The blanket claim "all meta caps fail closed without an ID" is **false**:

| Cap | Behavior with no object ID |
|---|---|
| `edit_user` | Self-edit shortcut skipped; **single site → maps to primitive `edit_users`**, so an Administrator passes. On multisite it evaluates `is_super_admin( $args[0] )` with an undefined key, and `is_super_admin( null )` falls back to *the current user*. |
| `delete_user` | `$args` never read → maps to `delete_users` |
| `promote_user` / `add_users` | `$args` never read → maps to `promote_users` |
| `remove_user` | Falls back to `remove_users`, losing the "can't remove yourself" protection |
| App-password caps (`create_app_password`, `edit_app_password`, …) | Call `map_meta_cap( 'edit_user', $user_id, $args[0] )` with an undefined key |

### Other non-obvious mappings worth encoding

- `edit_comment` recurses into `map_meta_cap( 'edit_post', $user_id, $comment->comment_post_ID )`. An **orphaned comment** (post deleted) falls back to primitive `edit_posts`.
- `edit_post` / `delete_post` on the **privacy policy page** additionally require `manage_privacy_options`.
- `delete_post` on `page_for_posts` or `page_on_front` requires `manage_options`.
- `delete_term` on a taxonomy's **default term** is hardcoded `do_not_allow`.
- `manage_post_tags`, `edit_categories`, `edit_post_tags`, `delete_categories`, `delete_post_tags` → `manage_categories`. But `assign_categories` / `assign_post_tags` → **`edit_posts`**, i.e. **Contributors can assign terms**.
- Block caps (`edit_blocks`, `publish_blocks`, …) are string-rewritten `_blocks` → `_posts`.
- ⚠️ **Custom post types registered with `'map_meta_cap' => false` bypass all ownership/status logic** — `$caps[] = $post_type->cap->$cap` directly. **High-signal audit finding in plugin code.**

### Never check roles

```php
if ( in_array( 'administrator', (array) $user->roles, true ) )   // ❌
if ( $user->user_level >= 8 )                                    // ❌ deprecated since WP 3.0
if ( current_user_can( 'manage_options' ) )                      // ✅
```

Membership, LMS, and e-commerce plugins rename, clone, and remap roles constantly.
Capabilities are the stable contract. WPCS `WordPress.WP.Capabilities` flags roles
passed where a capability belongs (`RoleFound`) and deprecated user levels
(`Deprecated`).

---

## 5. Multisite

### `is_super_admin()` — a major gotcha

```php
function is_super_admin( $user_id = false ) {
	if ( ! $user_id ) { $user = wp_get_current_user(); }
	else { $user = get_userdata( $user_id ); }
	if ( ! $user || ! $user->exists() ) { return false; }
	if ( is_multisite() ) {
		$super_admins = get_super_admins();
		if ( is_array( $super_admins ) && in_array( $user->user_login, $super_admins, true ) ) { return true; }
	} elseif ( $user->has_cap( 'delete_users' ) ) {
		return true;
	}
	return false;
}
```

- ⚠️ **On single site, `is_super_admin()` returns `true` for anyone holding
  `delete_users`** — every Administrator, *and any custom role a plugin granted
  `delete_users` to*. It is not a "network owner" test.
- ⚠️ It matches on **`user_login` (string), not user ID**. Renaming a user
  silently revokes Super Admin.
- ⚠️ `get_super_admins()` falls back to `get_site_option( 'site_admins', array( 'admin' ) )`.
  If the `site_admins` network option is missing or corrupted, **a user named
  `admin` becomes Super Admin**.
- `grant_super_admin()` / `revoke_super_admin()` return `false` immediately on
  single site, or when `$GLOBALS['super_admins']` is defined in `wp-config.php`
  (hardcoded-list mode, in which the DB option is ignored entirely). Hooks
  `granted_super_admin` / `revoked_super_admin` are good audit-log anchors.

### `manage_network*` capabilities

`create_sites`, `delete_sites`, `manage_network`, `manage_sites`,
`manage_network_users`, `manage_network_plugins`, `manage_network_themes`,
`manage_network_options`, `upgrade_network` are **unmapped pass-throughs** — held
by **no default role**. They are satisfied only by the blanket super-admin bypass
in `WP_User::has_cap()`, or if a plugin explicitly adds them to a role.

Related: `setup_network` → `manage_network_options` (multisite) / `manage_options`
(single). `manage_privacy_options`, `export_others_personal_data`,
`erase_others_personal_data` → `manage_network` (multisite) / `manage_options`.

### What a site Administrator LOSES on multisite

Hard `do_not_allow` for non-Super-Admins:

`install_plugins`, `update_plugins`, `delete_plugins`, `upload_plugins`,
`install_themes`, `update_themes`, `delete_themes`, `upload_themes`,
`update_core`, `update_php`, `update_https`, `edit_files`, `edit_plugins`,
`edit_themes`, **`unfiltered_html`**, `edit_css`, `unfiltered_upload`,
`install_languages`, `update_languages`, `delete_users`/`delete_user`,
`edit_users`/`edit_user` (requires `manage_network_users`),
`view_site_health_checks`.

Conditional:

- `create_users` — only if the network option `add_new_users` is truthy. **Default
  is `'0'`.**
- `activate_plugins` / `deactivate_plugins` — additionally requires
  `manage_network_plugins` unless the network option `menu_items['plugins']` is
  set. ⚠️ **`menu_items` is absent from the default `populate_network_meta()`
  sitemeta**, so on a fresh network **site Administrators cannot activate plugins
  at all** until a Super Admin enables Network Admin → Settings → Enable
  administration menus → Plugins.

**Retained:** `manage_options`, `promote_users`, `remove_users`, `list_users`,
`switch_themes`, `edit_theme_options`, `customize`, `edit_dashboard`, `export`,
`import`, `moderate_comments`, `manage_categories`, all post/page caps,
`delete_site` (→ `manage_options`), plus `resume_plugins` / `resume_themes`.

> **Auditing consequence:** on multisite, a site Administrator is a genuinely
> *restricted* role. "Admin+" findings that would be low-severity on single site
> (SQLi, file read, option write) can be **real privilege escalation to Super
> Admin** on multisite. Always state which model you are rating under.

### Registration on multisite

Network signups are controlled by the network option `registration` (default
`'none'`), **not** `users_can_register`. And `wpmu_create_user()` explicitly
deletes the caps `wp_insert_user()` just wrote:

```php
// Newly created users have no roles or caps until they are added to a blog.
delete_user_option( $user_id, 'capabilities' );
delete_user_option( $user_id, 'user_level' );
```

So auditing `default_role` on a multisite network install is largely meaningless
for network signups; the per-site role is assigned later by `add_user_to_blog()`.

---

## 6. THE SEVERITY MODEL

### 6.1 Why required privilege drives severity

Severity is **impact × reachability**. Reachability in WordPress is dominated by
one question:

> **Does exploiting this flaw give the attacker power they did not already have?**

If the privilege required to reach a flaw already confers equal-or-greater power,
the flaw is not a meaningful boundary crossing. This is not leniency — it is the
same reasoning that says "root can read `/etc/shadow`" is not a vulnerability.

### 6.2 The privilege ladder and its real-world population

| Tier | Who | How common on real sites | Attacker cost to obtain |
|---|---|---|---|
| **Unauthenticated** | Anyone | Universal | **Zero** |
| **Subscriber+** | Any logged-in account | Very common — open registration, WooCommerce customers, membership sites, LMS students, forum members | **Near zero** where registration is open; one signup form |
| **Contributor+** | Can write drafts, cannot publish, cannot upload | Common — multi-author blogs, guest-post programs, editorial workflows, news sites | Low — social engineering, or open on guest-post sites |
| **Author+** | Can publish own posts, can upload | Moderately common | Low-moderate |
| **Editor+** | Manages all content | Uncommon as an attacker tier | Moderate — a trusted staff account |
| **Admin+** (single site) | Full control | The site owner | **Already total** |
| **Super Admin** (multisite) | Network control | Network owner | Already total |

### 6.3 Severity matrix

Base ratings. Adjust with §6.6.

| Vulnerability class | Unauth | Subscriber+ | Contributor+ | Author+ | Editor+ | Admin+ (single site) |
|---|---|---|---|---|---|---|
| **WP-RCE** (remote code execution) | Critical | Critical | Critical | Critical | High | **Low/Info** |
| **WP-SQLI** | Critical | High | High | High | Medium | **Low/Info** |
| **WP-AUTHBYPASS** / **WP-PRIVESC** | Critical | Critical | Critical | High | High | **N/A** |
| **WP-UPLOAD** (arbitrary file upload) | Critical | Critical | Critical | High | High | **Low/Info** |
| **WP-DELETE** (arbitrary file delete) | Critical | High | High | High | Medium | **Low/Info** |
| **WP-LFI** (local file read/include) | High/Critical | High | High | Medium | Medium | **Low/Info** |
| **WP-OPTION** (arbitrary option update) | Critical | Critical | High | High | Medium | **N/A** |
| **WP-SETTINGS** (unauthorized settings change) | High | High | Medium | Medium | Low | **N/A** |
| **WP-ACL** (missing capability check) | *rate as the action it exposes* | | | | | |
| **WP-XSS-S** (stored) | High | High | **Medium/High** | Medium | **Low/Info** ⚠️ | **Info** ⚠️ |
| **WP-XSS-R** (reflected) | Medium | Medium | Medium | Medium | Medium | Medium |
| **WP-CSRF** | *rate as the action it triggers* | | | | | |
| **WP-SSRF** | High | Medium | Medium | Medium | Low | **Low/Info** |
| **WP-IDOR** | High | High | Medium | Medium | Low | **Low/Info** |
| **WP-REDIRECT** (open redirect) | Low/Medium | Low | Low | Low | Low | Low |
| **WP-INFO** (information disclosure) | Low/Medium | Low | Low | Low | Info | **Info** |
| **WP-POI** (PHP object injection) | Critical | Critical | High | High | Medium | **Low/Info** |

⚠️ The Editor+/Admin+ stored-XSS ratings assume **single site**. On **multisite**,
neither role has `unfiltered_html`, so raise both by two steps — see §6.5.

### 6.4 Why "Contributor+ Stored XSS" IS a genuine vulnerability

This is the rating most often disputed, so the reasoning is spelled out.

**1. The Contributor tier is genuinely populated.**
Contributor is the standard role for guest authors, editorial interns, and
community writers. Many sites accept guest posts by design. Combined with open
registration and plugins that auto-assign Contributor, obtaining the tier is
frequently trivial and sometimes a published, advertised process.

**2. A Contributor does NOT have `unfiltered_html`.**
Only Administrator and Editor do (single site), and neither does on multisite.
Core deliberately runs Contributor content through KSES precisely **because
Contributors are not trusted to inject HTML.** A flaw that lets them do it anyway
defeats a control core actively enforces. That is the definition of a
vulnerability.

**3. The escalation path is short, reliable, and well-trodden.**
Contributor stored XSS → an Administrator previews or reviews the pending draft →
the payload executes **in the Administrator's authenticated session** → the script
uses the admin's own nonces to create a new Administrator, install a plugin, or
write to the theme editor → **full site compromise**. Contributor workflow
*guarantees* an Administrator or Editor will review the content. The victim
interaction is not incidental; it is the feature.

**4. The block-renderer path makes it worse than "draft preview".**
`/wp-json/wp/v2/block-renderer/{name}` requires only `edit_posts`, so a
Contributor can invoke any dynamic block's `render_callback` with **fully
arbitrary attributes** without ever saving a post.

**5. It is a real privilege boundary crossing.**
Contributor cannot publish, cannot upload, cannot edit others' posts. Stored XSS
grants all of that transitively. **Rate Contributor+ stored XSS as Medium to High**
depending on how certain the admin-views-it step is.

The same reasoning applies with **more** force to Subscriber+ and Author+ stored
XSS: neither has `unfiltered_html` either, and Subscriber has no content
privileges at all, so the boundary crossed is even larger.

### 6.5 Why "Admin+ SQLi" is usually rated Low

**1. An Administrator already has equal-or-greater power.**
On single site an Administrator holds `edit_plugins`, `edit_themes`,
`install_plugins`, and `unfiltered_html`. They can write arbitrary PHP through the
theme/plugin editor — which is **strictly more powerful than SQL injection**,
because PHP execution subsumes database access. Exploiting SQLi to read the
database is a *harder path to a lesser outcome* than what the role already
authorizes.

**2. There is no privilege boundary to cross.**
The severity question is "what does the attacker gain?" An Administrator gains
nothing. There is no escalation.

**3. It is still worth reporting — as a code-quality/defence-in-depth issue.**
Report it as **Low** or **Informational**, with the fix, because:
- It becomes serious the moment the entry point's capability check is loosened.
- It is often the *same code path* reachable at a lower tier elsewhere.
- It is a **real vulnerability on multisite** (§6.6).
- Hardened sites define `DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS`, which removes
  the "admin already has RCE" premise (§6.6).

**Do not use this reasoning to dismiss:**
- ❌ **Admin+ *privilege escalation to Super Admin* on multisite** — a real boundary.
- ❌ **Admin+ flaws reachable via CSRF** — the *victim* is the Administrator; the
  *attacker* is unauthenticated. Rate it by the attacker's tier, not the victim's.
  This is the single most common mis-rating.
- ❌ **Admin+ flaws in code also reachable at a lower tier** by a second path.
- ❌ **Stored XSS that fires for *other* users**, where the payload author is an
  admin but the audience is broader.

### 6.6 Severity modifiers

Apply after the base rating.

**Escalate (+1 or more):**

| Condition | Why |
|---|---|
| **Reachable via CSRF from unauthenticated** | Effective attacker tier collapses to unauthenticated |
| **Multisite** and the finding is Admin+/Editor+ | Site admins lack `unfiltered_html`, file-edit, and install caps — a real boundary exists |
| Target hardened with `DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS` | "Admin already has RCE" premise no longer holds |
| No user interaction required | |
| Reachable on **every** page load (`init`, `template_redirect`) | Trivial to find and hit |
| Chains into RCE or account takeover | Rate the chain, not the link |
| Payload executes in a **higher-privileged** user's session | The Contributor-XSS argument |
| CPT registered with `'map_meta_cap' => false` | Ownership logic bypassed entirely |
| Plugin grants a takeover-equivalent cap to a low role | Effective tier is lower than it appears |

**De-escalate (−1 or more):**

| Condition | Why |
|---|---|
| Required capability already confers equal/greater power | The §6.5 argument |
| Requires a non-default, uncommon configuration | Reduced population |
| Requires winning a tight race | Reliability |
| Exploitation is read-only, non-sensitive | Impact |
| The role holding the cap is inherently trusted for this action | e.g. Editor+ stored XSS **on single site only** |

### 6.7 Rating CSRF and missing-capability findings

**WP-CSRF and WP-ACL have no intrinsic severity.** Rate them by the action they
expose:

- CSRF on "update plugin settings" → rate as WP-SETTINGS at **unauthenticated**
  tier (the attacker is anonymous; the admin is the vehicle).
- CSRF on "delete all posts" → rate as WP-DELETE at unauthenticated tier.
- Missing capability check on an endpoint that updates `default_role` → rate as
  WP-PRIVESC at whatever tier reaches the endpoint.

For a **missing nonce**, the effective attacker tier is **unauthenticated**, and
the *victim's* privilege determines the impact. This inversion is the most common
severity mistake in WordPress auditing.

### 6.8 The two-option escalation pair — always flag together

```php
update_option( 'users_can_register', 1 );
update_option( 'default_role', 'administrator' );
```

Defaults are `users_can_register => 0` and `default_role => 'subscriber'`
(`populate_options()`). ⚠️ **`default_role` is a plain, unvalidated option** —
nothing in `wp_insert_user()`'s path restricts it to a low-privilege role:

```php
if ( isset( $userdata['role'] ) )      { $user->set_role( $userdata['role'] ); }
elseif ( ! $update )                   { $user->set_role( get_option( 'default_role' ) ); }
```

Individually benign; together they yield **anonymous self-service Administrator
creation**. Any WP-OPTION finding that permits writing arbitrary option
names/values is therefore **Critical**, not Medium — because `default_role`,
`users_can_register`, `siteurl`, `home`, and `admin_email` are all reachable
through it. Rate arbitrary-option-write as privilege escalation.

---

## 7. Hardening constants

### `DISALLOW_FILE_EDIT`

Official wording:

> "Occasionally you may wish to disable the plugin or theme file editor to prevent
> overzealous users from being able to edit sensitive files and potentially crash
> the site. Disabling these also provides an additional layer of security if a
> hacker gains access to a well-privileged user account."

**Strips exactly three capabilities:** `edit_files`, `edit_plugins`, `edit_themes`.

The docs also warn plugin authors directly:

> "The functionality of some plugins may be affected by the use of
> `current_user_can('edit_plugins')` in their code. Plugin authors should avoid
> checking for this capability…"

### `DISALLOW_FILE_MODS`

Official wording:

> "This will block users being able to use the plugin and theme
> installation/update functionality from the WordPress admin area. Setting this
> constant also disables the Plugin and Theme File editor (i.e. you don't need to
> set `DISALLOW_FILE_MODS` and `DISALLOW_FILE_EDIT`, as on its own
> `DISALLOW_FILE_MODS` will have the same effect)."

Mechanism:

```php
function wp_is_file_mod_allowed( $context ) {
	return apply_filters( 'file_mod_allowed', ! defined( 'DISALLOW_FILE_MODS' ) || ! DISALLOW_FILE_MODS, $context );
}
```

**Strips 16 capabilities across four contexts:**

| Context | Capabilities stripped |
|---|---|
| `capability_edit_themes` | `edit_files`, `edit_plugins`, `edit_themes` ← **the mechanical proof that `DISALLOW_FILE_MODS` implies `DISALLOW_FILE_EDIT`** |
| `capability_update_core` | `update_plugins`, `delete_plugins`, `install_plugins`, `upload_plugins`, `update_themes`, `delete_themes`, `install_themes`, `upload_themes`, `update_core` |
| `can_install_language_pack` | `install_languages`, `update_languages` |
| `automatic_updater` | ⚠️ **All background auto-updates disabled** |

Transitively also blocked: `update_php`, `update_https`.

### ⚠️ Commonly assumed but false

- **`DISALLOW_FILE_MODS` does NOT block `activate_plugins` / `deactivate_plugins`.**
  Those live in a separate case with no file-mod gate. A compromised admin can
  still activate an already-installed malicious plugin.
- **`DISALLOW_FILE_MODS` silently kills security auto-updates.** Recommending it
  as blanket hardening trades one risk for another. Say so when recommending it.
- **Both constants are enforced only inside `map_meta_cap()`.** Plugin code that
  writes files *without* a capability check is entirely unaffected. These
  constants are not a filesystem sandbox.
- **The `file_mod_allowed` filter (since WP 4.8) lets any plugin re-enable file
  mods per-context.** Presence of the constant in `wp-config.php` is **not** proof
  the restriction is in force.
- `DISALLOW_FILE_EDIT` is checked **before** `wp_is_file_mod_allowed()`, so a
  `file_mod_allowed` filter can undo `DISALLOW_FILE_MODS` but **not**
  `DISALLOW_FILE_EDIT`.

### `DISALLOW_UNFILTERED_HTML`

Strips `unfiltered_html` and `edit_css` from **everyone, including Super Admins**.
When set, **all** stored XSS findings become genuine regardless of the author's
role — no down-rating on the `unfiltered_html` argument is available.

---

## 8. Auditor's capability checklist

1. **Enumerate entry points** (see `entry-points.md`) and record the minimum
   privilege to reach each.
2. **For each, find the capability check.** Missing → WP-ACL, rated by the action.
3. **Is the capability appropriate to the impact?** `current_user_can( 'read' )`
   guarding an option write is effectively no check — every logged-in user passes.
4. **Is it a meta capability?** If so, is the **object ID** passed? Missing ID on a
   post/term/comment cap = broken feature (WP ≥ 6.1) or wrong-object bug (≤ 6.0);
   missing ID on a **user** cap falls through to the primitive.
5. **Is a primitive used where a meta cap belongs?** `edit_posts` guarding an
   operation on `$_POST['post_id']` = **WP-IDOR, fail-open**.
6. **Is a role checked instead of a capability?** → finding.
7. **Does the plugin grant capabilities?** Grep `add_cap`, `add_role`,
   `->add_cap(`, `map_meta_cap` filters, `user_has_cap` filters. A plugin granting
   `unfiltered_html`, `unfiltered_upload`, `edit_plugins`, `install_plugins`, or
   `promote_users` to a low role has created a privilege-escalation path — and it
   **lowers the effective tier of every other finding in the plugin**.
8. **Does it register a CPT with `'map_meta_cap' => false`?** → ownership logic
   bypassed.
9. **Rate using §6**, and **state the environment assumption** (single site vs.
   multisite; hardened vs. default) whenever it changes the answer.

### Grep starters

```bash
rg -n "current_user_can|user_can|author_can" --type php
rg -n "add_cap|remove_cap|add_role|remove_role" --type php
rg -n "map_meta_cap|user_has_cap" --type php           # capability filters
rg -n "in_array\s*\(\s*['\"](administrator|editor|author|contributor|subscriber)" --type php
rg -n "user_level|level_10|level_[0-9]" --type php     # deprecated
rg -n "unfiltered_html|unfiltered_upload|edit_plugins|install_plugins|promote_users" --type php
rg -n "map_meta_cap['\"]?\s*=>\s*false" --type php     # CPT ownership bypass
rg -n "default_role|users_can_register" --type php     # the escalation pair
rg -n "is_super_admin" --type php                      # true for any single-site admin
```

---

## See also

- `entry-points.md` — determining the minimum privilege that reaches a handler.
- `wp-security-apis.md` — `current_user_can` semantics and the nonce API.
- `secure-handler-template.md` — correct capability checks in context.
