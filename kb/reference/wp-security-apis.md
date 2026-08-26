# Reference: WordPress Security API Tables

**Audience:** an auditing agent that has found a flaw and must now write the
*correct* fix. Choosing the wrong API here is itself a bug — `esc_html()` on a URL
in an `href` does not stop `javascript:`, and `esc_attr()` on data destined for
SQL does nothing at all.

**Verified against:** WordPress core `master` (7.2-alpha; current stable 7.1) —
`wp-includes/formatting.php`, `wp-includes/class-wpdb.php`,
`wp-includes/pluggable.php`, `wp-includes/functions.php`, `wp-includes/http.php`,
`wp-admin/includes/file.php` — plus the Common APIs Security chapter on
developer.wordpress.org.

---

## 0. The golden rule

> ### Sanitize on input. Escape on output. Escape as late as possible.

Core's own wording, from the Security chapter:

> "Always make sure to *validate* and *sanitize* user input before using it, and to
> *escape* on output."
>
> "Escape as late as possible."
>
> "Never trust user input."

### Why each clause exists

| Clause | Rationale |
|---|---|
| **Sanitize on input** | Bounds what can ever be stored. Limits blast radius if some downstream sink later forgets to escape. |
| **Escape on output** | Safety depends on the *destination*, and the destination is not known at input time. The same stored string is safe in `<p>`, dangerous in `href`, and differently dangerous in `<script>`. Only the output site knows which. |
| **Escape as late as possible** | An escaped value that travels is a value that gets re-processed, concatenated, double-escaped, or passed to a second sink with the wrong encoding. Escaping at the `echo` makes the correctness of every call site locally verifiable. |

### Corollary rules an auditor should apply

- **Validation beats sanitization.** Core: *"Validation is preferred over
  sanitization because validation is more specific."* If the value must be one of
  five strings, use `in_array( $v, $allowed, true )` — do not `sanitize_text_field()`
  it and hope.
- **Sanitizing is not escaping.** `sanitize_text_field()` on input does **not**
  license `echo $value;` later. It strips tags, but escaping is still required at
  the sink — and it is the wrong tool for URL, JS, and attribute contexts.
- **Escaping is not sanitizing.** `esc_attr()` before `INSERT` gives you HTML
  entities in your database and no SQL protection whatsoever.
- **Never escape twice.** Double-escaping is a correctness bug that also masks
  the real fix. If a value arrives already escaped, fix the producer.
- **`wp_unslash()` first.** WordPress adds magic-quote-style slashes to `$_GET`,
  `$_POST`, `$_REQUEST`, and `$_COOKIE`. Read them as
  `sanitize_text_field( wp_unslash( $_POST['x'] ) )`. Omitting `wp_unslash()` is
  what WPCS reports as `WordPress.Security.ValidatedSanitizedInput.MissingUnslash`;
  it is a data-corruption bug (accumulating backslashes) more than a security one,
  but its presence reliably indicates input handling nobody reviewed.
  **Order matters: unslash *then* sanitize.**

---

## 1. Escaping — organized by OUTPUT CONTEXT

Pick the row by **where the value lands**, never by what the value "is".

| Output context | Use | Notes / failure mode if wrong |
|---|---|---|
| Text between HTML tags — `<p>HERE</p>` | `esc_html()` | Escapes `& < > " '`. The default choice for plain text. |
| HTML attribute value — `<div title="HERE">` | `esc_attr()` | **Always quote the attribute.** `esc_attr()` does not protect an unquoted attribute — an attacker supplies `x onmouseover=alert(1)` with no quotes needed. |
| URL in `href` / `src` / `action` | `esc_url()` | Whitelists protocols via `wp_allowed_protocols()`; strips `javascript:`, `data:`, `vbscript:`. **`esc_attr()` here is a vulnerability** — it happily passes `javascript:alert(1)`. |
| URL being **stored** or redirected to | `sanitize_url()` (canonical) / `esc_url_raw()` (alias) | Same protocol filtering, but does **not** convert `&` to `&amp;`. Never put `esc_url()` output in the DB. |
| `<textarea>HERE</textarea>` | `esc_textarea()` | `esc_html()` also works but `esc_textarea()` is the documented intent. |
| Inline JS in an attribute — `onclick='HERE'` | `esc_js()` | ⚠️ Core docblock: *"Escapes text strings for echoing in JS. It is intended to be used for inline JS (in a tag attribute, for example `onclick="..."`). Note that the strings have to be in **single quotes**."* Only escapes `' " < > &` and fixes line endings. |
| Value inside a `<script>` block | **`wp_json_encode()`**, not `esc_js()` | `esc_js()` does **not** escape `</script>`, backslashes, or U+2028/U+2029. `echo 'var x = ' . wp_json_encode( $v ) . ';';` is the correct construction. Better still: `wp_add_inline_script()` / `wp_localize_script()`. |
| Rich text that must keep some HTML | `wp_kses( $html, $allowed )` | You supply the allowed tags/attributes array. The only safe way to permit markup. |
| Rich text in post-content contexts | `wp_kses_post()` | Allows exactly what post content allows. |
| Rich text in comment contexts | `wp_kses_data()` | Narrower than `wp_kses_post()`. |
| CSS class name | `sanitize_html_class()` | Then `esc_attr()` at output. |
| XML / feed output | `esc_xml()` | |
| Plain-text email body, HTTP header, log line | **No `esc_*` applies** | Use context-appropriate validation. For headers, reject `\r` and `\n` (header injection). |
| SQL | **None of the above** — use `$wpdb->prepare()` | See §3. Escaping functions provide zero SQL safety. |
| Shell command | **None of the above** | `escapeshellarg()`, and prefer not executing shells at all (WP-RCE). |
| Filesystem path | **None of the above** | See §6. |

### i18n variants — use these whenever the string is translated

Translated strings are data too: `.po`/`.mo` files can be supplied by a
third-party language pack, and translator placeholders interpolate untrusted
values.

| Plain | Echoes | Returns | With context |
|---|---|---|---|
| `__()` (**not escaped**) | `_e()` (**not escaped**) | — | `_x()` |
| `esc_html__()` | `esc_html_e()` | ✅ returns | `esc_html_x()` |
| `esc_attr__()` | `esc_attr_e()` | ✅ returns | `esc_attr_x()` |

- ❌ `_e( 'text', 'domain' )` echoes **unescaped**. Prefer `esc_html_e()`.
- ❌ `echo __( 'text', 'domain' )` — same problem. Use `esc_html__()`.
- ⚠️ `esc_html( __( 'x', 'd' ) )` is correct but non-idiomatic; WPCS's
  `WordPress.CodeAnalysis.EscapedNotTranslated` flags the adjacent mistake
  `esc_html( 'x', 'd' )` — two args to `esc_html()` means the author meant
  `esc_html__()` and the text domain is being silently discarded.
- For `printf`-style: escape the **interpolated values**, then the format string
  separately — `printf( esc_html__( 'Hello %s', 'd' ), esc_html( $name ) )` is
  double-escaping the name; prefer
  `printf( /* translators: %s: name */ esc_html__( 'Hello %s', 'd' ), $name )`
  only when `$name` is already known safe, otherwise
  `echo esc_html( sprintf( __( 'Hello %s', 'd' ), $name ) );`.

### Version note (WP 6.9+)

`esc_url()` and `esc_url_raw()`/`sanitize_url()` now **prepend `https://`** when
the URL has no scheme and the first entry in `$protocols` is `https`. Code that
relied on scheme-relative or bare-host inputs surviving unchanged may behave
differently. Confirm the target WP version before asserting old behavior.

### Escaping functions are not interchangeable — the four common mix-ups

```php
echo '<a href="' . esc_html( $url ) . '">';        // ❌ WP-XSS-R: javascript: survives
echo '<a href="' . esc_attr( $url ) . '">';        // ❌ WP-XSS-R: javascript: survives
echo '<div class=' . esc_attr( $c ) . '>';         // ❌ WP-XSS-R: unquoted attribute
echo "<script>var u='" . esc_js( $s ) . "';</script>"; // ⚠️ '</script>' in $s breaks out
```

```php
echo '<a href="' . esc_url( $url ) . '">' . esc_html( $text ) . '</a>';  // ✅
echo '<div class="' . esc_attr( $c ) . '">';                             // ✅
echo '<script>var u = ' . wp_json_encode( $s ) . ';</script>';           // ✅
```

---

## 2. Sanitization — on INPUT

Sanitizers coerce a value toward a shape. They **do not** make a value safe for an
arbitrary sink. Apply at the moment untrusted data enters, after `wp_unslash()`.

| Function | Produces | Use for | Caveats |
|---|---|---|---|
| `sanitize_text_field( $s )` | Single-line plain text | The default for short free-text `$_POST` fields | Core: checks invalid UTF-8, converts lone `<` to entity, **strips all tags**, removes line breaks/tabs/extra whitespace, strips percent-encoded characters. **Destroys newlines** — wrong for multi-line input. |
| `sanitize_textarea_field( $s )` | Multi-line plain text | `<textarea>` input | Same as above but preserves newlines. |
| `sanitize_email( $s )` | Email or `''` | Email fields | Returns empty string on failure — **check the result**, don't assume. Pair with `is_email()` for validation. |
| `sanitize_file_name( $s )` | Safe filename | Any user-supplied filename | Strips path separators and dangerous chars. **Not a path-traversal guard on its own** — see §6. Does not stop a `.php` extension by itself. |
| `sanitize_key( $s )` | `[a-z0-9_\-]` lowercase | Option names, meta keys, array indices, action/slug identifiers | Excellent for anything used as an identifier. Very restrictive by design. |
| `sanitize_title( $s )` | URL slug | Slugs, permalink parts | Applies `sanitize_title` filter; result may be empty. |
| `sanitize_user( $s, $strict )` | Username | Usernames | Pass `$strict = true` to limit to `a-z A-Z 0-9 _ . - @ space`. |
| `sanitize_html_class( $s )` | CSS class token | `class="..."` values | Still escape with `esc_attr()` at output. |
| `sanitize_hex_color( $s )` | `#rgb` / `#rrggbb` or `null` | Color pickers | Returns **`null`** (not `''`) when invalid — test explicitly. `sanitize_hex_color_no_hash()` for the un-prefixed form. |
| `sanitize_mime_type( $s )` | MIME type string | MIME handling | Format only; asserts nothing about actual file content. |
| `sanitize_option( $option, $value )` | Per-option sanitized value | Values written to core options | Dispatches to the right sanitizer for known core options. |
| `sanitize_meta( $key, $value, $type )` | Per-meta sanitized value | Meta values | Honours `register_meta()` sanitize callbacks. |
| `sanitize_sql_orderby( $s )` | Validated ORDER BY clause or `false` | `ORDER BY` fragments | ⚠️ Returns `false` on failure — `if ( ! $x ) reject;`. Prefer an explicit allowlist (§3). |
| `absint( $v )` | Non-negative integer | IDs, counts, offsets | `abs( intval( $v ) )`. **The right choice for post/user/term IDs.** |
| `intval( $v )` | Integer (may be negative) | Signed numerics | `intval( '12abc' ) === 12` and `intval( 'abc' ) === 0` — a `0` result is indistinguishable from a legitimate `0`. Validate range separately. |
| `floatval( $v )` | Float | Prices, coordinates | Locale-independent; validate range. |
| `wp_kses( $h, $allowed )` | HTML limited to `$allowed` | User-supplied rich text | The tag/attr array is the security boundary — review it. |
| `wp_kses_post( $h )` | Post-content-safe HTML | Rich text stored as content | Allows a broad tag set including `<iframe>` for some roles — not a minimal allowlist. |
| `wp_kses_data( $h )` | Comment-safe HTML | Comment-like rich text | Narrower than `wp_kses_post()`. |
| `sanitize_url( $u )` | Storable URL | URLs written to the DB / used in redirects | Canonical name. `esc_url_raw()` is an **alias** for it as of WP 6.1. |
| `wp_parse_id_list( $s )` | `int[]` | Comma/array lists of IDs | Ideal before building an `IN (...)` clause. |

### Validation helpers (prefer these where the value has a known shape)

| Function | Returns |
|---|---|
| `is_email( $s )` | Email or `false` |
| `wp_http_validate_url( $u )` | URL or `false` (SSRF-aware — see §6) |
| `in_array( $v, $allowed, true )` | The allowlist pattern — **strict comparison mandatory** |
| `array_key_exists( $v, $map )` | Allowlist-by-key |
| `wp_is_uuid( $s )` | bool |
| `rest_is_valid_*` / `rest_sanitize_*` | REST schema validators, usable outside REST |

### The allowlist pattern, which beats every sanitizer

```php
$allowed = array( 'asc', 'desc' );
$order   = in_array( strtolower( $_GET['order'] ?? '' ), $allowed, true )
	? strtoupper( $_GET['order'] )
	: 'ASC';
```

Use this for anything that becomes a **column name, table name, ORDER BY
direction, callback name, file path segment, or class name** — the sinks where no
escaping function exists.

---

## 3. Database — `$wpdb`

### `$wpdb->prepare()`

```php
$wpdb->prepare( string $query, mixed ...$args );
```

| Placeholder | Substitutes | Quoting |
|---|---|---|
| `%s` | String | **Auto-quoted** — write it bare |
| `%d` | Integer | Bare |
| `%f` | Float | Bare |
| `%i` | **Identifier** (table / column name) | **Auto-quoted with backticks** — write it bare |

Core's docblock:

> "All placeholders MUST be left unquoted in the query string. A corresponding
> argument MUST be passed for each placeholder."

```php
// ✅ correct
$wpdb->get_results( $wpdb->prepare(
	"SELECT * FROM {$wpdb->prefix}things WHERE status = %s AND user_id = %d",
	$status,
	$user_id
) );

// ❌ WP-SQLI — quotes around %s
$wpdb->prepare( "WHERE status = '%s'", $status );

// ❌ WP-SQLI — interpolation, prepare() does nothing here
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM t WHERE id = $id" ) );

// ❌ WP-SQLI — prepare() called on an already-built string
$sql = "SELECT * FROM t WHERE id = " . $_GET['id'];
$wpdb->get_results( $wpdb->prepare( $sql ) );
```

#### `%i` for identifiers — the modern fix for the table/column problem (WP 6.2+)

Before WP 6.2 there was **no** placeholder for identifiers, so dynamic table and
column names had to be handled with a hand-written allowlist. As of **WordPress
6.2**, `%i` does it correctly:

```php
$wpdb->prepare(
	"SELECT * FROM %i WHERE %i = %s",
	$table,
	$field,
	$value
);
```

Core escapes the value by doubling backticks (`_escape_identifier_value()`) and
wrapping in backticks.

Version-gating notes an auditor must respect:

- `@since 6.2.0 Added %i for identifiers`. If the plugin's `Requires at least:`
  header is **below 6.2**, `%i` is not a valid fix — recommend an allowlist
  instead, or a bumped minimum.
- Support is detectable at runtime: `$wpdb->has_cap( 'identifier_placeholders' )`.
- `%i` **cannot be used inside an `IN()` clause** (WPCS error
  `IdentifierWithinIN`).
- `%i` must be **unquoted** in the query string — `'%i'`, `"%i"`, and `` `%i` ``
  are all wrong (WPCS `QuotedIdentifierPlaceholder`).
- An argument may not be used as both `%i` and `%s` in the same query — core
  raises `_doing_it_wrong` (`6.2.0`).

Even with `%i`, an allowlist is still preferable when the set of legal
tables/columns is small and known — it prevents *logical* access to tables the
feature was never meant to touch, which `%i` does not.

#### The positional-placeholder trap

Core docblock:

> "Note: There is one exception to the above: for compatibility with old
> behavior, numbered or formatted string placeholders (eg, `%1$s`, `%5s`) will not
> have quotes added by this function, so should be passed with appropriate quotes
> around them."

So `%1$s` is **not auto-quoted**. Mixing `%s` and `%1$s` in one query silently
changes quoting behavior. Flag any `prepare()` containing `%1$s`-style
placeholders for manual review.

#### Other `prepare()` facts

- Literal `%` must be written `%%`.
- LIKE wildcards **cannot** be placed in the query string; build the whole LIKE
  argument and pass it as `%s` (see `esc_like` below).
- Args may be passed variadically **or** as one array — never a mix.
- `prepare()` with a query containing **no placeholders** raises
  `_doing_it_wrong` and is a strong signal the author misunderstood the API.

### `$wpdb->esc_like()` — for LIKE, always combined with `prepare()`

`like_escape()` is **deprecated** (since WP 4.0) and must not be recommended. Use:

```php
$like = '%' . $wpdb->esc_like( $search ) . '%';
$wpdb->get_results( $wpdb->prepare(
	"SELECT * FROM {$wpdb->posts} WHERE post_content LIKE %s",
	$like
) );
```

`esc_like()` is `addcslashes( $text, '_%\\' )`. Core's own docblock:

> "The output is not SQL safe. Call `wpdb::prepare()` or `wpdb::_real_escape()`
> next."

`esc_like()` **alone is not SQL injection protection** — it only neutralises LIKE
wildcards. Using it without `prepare()` is still WP-SQLI.

### `esc_sql()` — last resort only

```php
$ids = implode( ',', array_map( 'absint', $id_list ) );   // ✅ preferred for IN()
$sql = "SELECT * FROM t WHERE id IN ($ids)";
```

`esc_sql( $data )` calls `$wpdb->_escape()` and accepts strings or arrays. It
exists for spot-escaping, e.g. building an `IN` clause. Caveats:

- ⚠️ Since **WP 4.8.3**, `%` characters are replaced with an internal placeholder
  string. Core: *"This change in behavior may cause issues for code that expects
  the return value of `esc_sql()` to be usable for other purposes."* Never reuse
  `esc_sql()` output outside the immediate query.
- ⚠️ `esc_sql()` does **not** add quotes. `WHERE name = " . esc_sql( $n )` is still
  injectable — you need `'" . esc_sql( $n ) . "'`. This is exactly why `prepare()`
  is preferred: it cannot be got wrong this way.
- ⚠️ `esc_sql()` provides no protection for identifiers. Use `%i` or an allowlist.

### `$wpdb` methods that prepare for you (and those that don't)

| Method | Escapes automatically? |
|---|---|
| `$wpdb->insert( $table, $data, $format )` | ✅ Yes — `$data` values are prepared |
| `$wpdb->update( $table, $data, $where, ... )` | ✅ Yes — `$data` and `$where` values |
| `$wpdb->delete( $table, $where, $where_format )` | ✅ Yes — `$where` values |
| `$wpdb->replace( ... )` | ✅ Yes |
| `$wpdb->get_var/get_row/get_col/get_results/query` | ❌ **No** — you must call `prepare()` |

⚠️ For `insert`/`update`/`delete`, the **`$table` argument and the `$data`/`$where`
array *keys* (column names) are NOT escaped**. Passing a user-controlled table
name or column key to these methods is WP-SQLI. Always use a literal table name
built from `$wpdb->prefix`, and literal column keys.

### Table prefixes

```php
$table = $wpdb->prefix . 'my_table';        // per-site table
$table = $wpdb->base_prefix . 'my_table';   // network-wide table (multisite)
$wpdb->posts, $wpdb->users, $wpdb->usermeta, $wpdb->options, $wpdb->postmeta  // core tables
```

`{$wpdb->prefix}` interpolated into a query string is safe — it is server
configuration, not user input. Do not let a linter's interpolation warning push
you into "fixing" it incorrectly.

---

## 4. Authentication and authorization

### Capability checks — the actual access control

```php
current_user_can( string $capability, ...$args ): bool
current_user_can_for_blog( int $blog_id, string $capability, ...$args ): bool
user_can( int|WP_User $user, string $capability, ...$args ): bool
author_can( int|WP_Post $post, string $capability, ...$args ): bool
```

**Meta capabilities require the object ID as the second argument.** These are
resolved per-object by `map_meta_cap()`:

```php
current_user_can( 'edit_post',   $post_id );    // ✅
current_user_can( 'delete_post', $post_id );    // ✅
current_user_can( 'read_post',   $post_id );    // ✅
current_user_can( 'edit_user',   $user_id );    // ✅
current_user_can( 'edit_comment', $comment_id ); // ✅
current_user_can( 'edit_term',   $term_id );    // ✅

current_user_can( 'edit_post' );                // ❌ WP-ACL / WP-IDOR — no object
```

A meta capability called **without** its object ID cannot be resolved to a real
primitive capability, and the result is meaningless. This is the canonical
**IDOR** enabler: the check "passes" generically while the handler then operates
on an arbitrary `$_POST['post_id']`.

**Never check roles instead of capabilities:**

```php
if ( in_array( 'administrator', $user->roles, true ) )   // ❌ brittle, bypasses caps
if ( current_user_can( 'manage_options' ) )               // ✅
```

Roles are relabelled, cloned, and remapped constantly by membership and
e-commerce plugins; capabilities are the stable contract. WPCS ships
`WordPress.WP.Capabilities` (added in WPCS 3.0) which flags roles passed where a
capability is expected (`RoleFound`), deprecated user levels (`Deprecated`), and
unrecognised capability strings (`Unknown`).

**Also never use user levels** — `level_10` and friends were deprecated in WP 3.0.

See `capability-matrix.md` for which capability to require for which action.

### Nonces — CSRF only, never authorization

Official guidance, verbatim from the Security chapter:

> "Nonces should never be relied on for authentication, authorization, or access
> control."
>
> "Protect your functions using `current_user_can()`, always assume Nonces can be
> compromised."

| Function | Signature | Behavior on failure |
|---|---|---|
| `wp_create_nonce( $action )` | Returns a 10-char token | — |
| `wp_nonce_field( $action, $name = '_wpnonce', $referer = true, $display = true )` | Prints/returns hidden inputs | — |
| `wp_nonce_url( $url, $action, $name = '_wpnonce' )` | URL with nonce appended | — |
| `wp_verify_nonce( $nonce, $action )` | **`1`**, **`2`**, or **`false`** | Returns; caller must act |
| `check_admin_referer( $action = -1, $query_arg = '_wpnonce' )` | `1`/`2`/`false` | **`wp_nonce_ays()` + `die()`** |
| `check_ajax_referer( $action = -1, $query_arg = false, $stop = true )` | `1`/`2`/`false` | **`wp_die( -1, 403 )`** when `$stop` |

#### Verified return-value semantics — a real trap

`wp_verify_nonce()` returns:

- **`1`** — valid, generated 0–12 hours ago
- **`2`** — valid, generated 12–24 hours ago
- **`false`** — invalid

It **never returns `true`**. Therefore:

```php
if ( wp_verify_nonce( $n, 'a' ) === true )  // ❌ ALWAYS FALSE — endpoint is dead or fails open
if ( ! wp_verify_nonce( $n, 'a' ) ) { wp_die(); }   // ✅
if ( false === wp_verify_nonce( $n, 'a' ) ) { wp_die(); }  // ✅
```

#### Nonce lifetime

Default `nonce_life` is `DAY_IN_SECONDS`. The tick is `nonce_life / 2`, so a
nonce is accepted for **between 12 and 24 hours**. Nonces are **not one-time** —
core does not track use, so they do not stop replay.

#### ⚠️ Nonces for logged-out users are worthless as CSRF protection

`wp_create_nonce()` / `wp_verify_nonce()` hash
`$tick . '|' . $action . '|' . $uid . '|' . $token`. For an anonymous visitor
`$uid` is `0` and `wp_get_session_token()` is empty, so **every anonymous visitor
on the site receives the identical nonce for a given action**. Official docs
confirm this and recommend the `nonce_user_logged_out` filter plus a custom
session mechanism.

Consequence for auditing: a `wp_ajax_nopriv_` handler that "protects" itself with
`check_ajax_referer()` has **no CSRF protection at all** against an
unauthenticated attacker, who simply fetches a valid nonce from any public page
first. It is not a fix — do not accept it as one.

#### ⚠️ `check_admin_referer()` with no action

```php
if ( ! $result && ! ( -1 === $action && str_starts_with( $referer, $adminurl ) ) ) {
	wp_nonce_ays( $action ); die();
}
```

When `$action` is left at its default `-1`, a request whose **`Referer` header**
merely starts with the admin URL **passes without a valid nonce**. Since
`Referer` is attacker-influenced, `check_admin_referer()` called with no argument
is close to useless. Core emits `_doing_it_wrong` for it. Always pass a specific
action string. Same for `check_ajax_referer( -1 )`.

### Other auth primitives

| Function | Meaning | Authorization value |
|---|---|---|
| `is_user_logged_in()` | A session exists | Subscriber-level only — **not** an authorization check |
| `wp_get_current_user()` / `get_current_user_id()` | Current user (`0` if anonymous) | Informational |
| `is_super_admin( $user_id )` | Multisite network admin | Genuine check, multisite semantics |
| `wp_check_password( $pw, $hash, $user_id )` | Password verification | Use `wp_authenticate()` for login flows |
| `hash_equals( $known, $given )` | **Timing-safe** string comparison | **Mandatory** for tokens, HMACs, and secrets. `==`/`===` on secrets is a finding. |
| `wp_generate_password( $len, $special, $extra )` | CSPRNG-backed random string | Good for tokens |
| `wp_rand()` / `random_bytes()` / `wp_generate_uuid4()` | Randomness | ❌ Never `rand()`, `mt_rand()`, or `uniqid()` for security tokens |

---

## 5. REST-specific APIs

| Function | Purpose |
|---|---|
| `register_rest_route( $ns, $route, $args, $override )` | Route registration — `permission_callback` is mandatory in practice |
| `__return_true` | The documented, explicit way to mark a route public |
| `rest_authorization_required_code()` | Returns `401` when logged out, `403` when logged in — use in your `WP_Error` |
| `wp_verify_nonce( $n, 'wp_rest' )` | The REST nonce action, if you check it manually |
| `rest_ensure_response( $r )` | Normalise a return value |
| `current_user_can()` | The real check, inside `permission_callback` |

Canonical shape:

```php
'permission_callback' => static function ( WP_REST_Request $request ) {
	if ( ! current_user_can( 'edit_posts' ) ) {
		return new WP_Error(
			'rest_forbidden',
			__( 'Sorry, you are not allowed to do that.', 'my-plugin' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}
	return true;
},
```

⚠️ **Return strictly `true` or `false`/`WP_Error`.** Core rejects only on
`false === $permission || null === $permission`. A callback returning `0`, `''`,
or `array()` **grants access**. See `entry-points.md` §5.

---

## 6. Filesystem, uploads, HTTP

### Uploads

| Function | Purpose | Traps |
|---|---|---|
| `wp_handle_upload( &$file, $overrides, $time )` | The correct entry point for `$_FILES` handling | See below |
| `wp_handle_sideload( &$file, $overrides, $time )` | Same, for files already on disk | Uses `is_readable()` instead of `is_uploaded_file()` |
| `media_handle_upload( $file_id, $post_id )` | Upload **and** create an attachment post | Applies the same checks |
| `wp_check_filetype( $filename, $mimes )` | Extension → MIME mapping | **Filename only** — does not read the file |
| `wp_check_filetype_and_ext( $file, $filename, $mimes )` | Real content check | Returns `ext`/`type`/`proper_filename`; if the file does not exist it silently degrades to `wp_check_filetype()` |
| `wp_upload_dir( $time )` | Upload paths/URLs | Use it; never hardcode `wp-content/uploads` |
| `wp_unique_filename( $dir, $name, $cb )` | Collision-free filename | |
| `sanitize_file_name( $name )` | Filename hygiene | Not a traversal guard by itself |
| `wp_mkdir_p( $dir )` | Recursive mkdir | |

**`$overrides` keys that matter for security** (from `_wp_handle_upload()`):

```php
$test_form = $overrides['test_form'] ?? true;
$test_size = $overrides['test_size'] ?? true;
$test_type = $overrides['test_type'] ?? true;   // "If you override this, you must provide $ext and $type!!"
$mimes     = $overrides['mimes']     ?? null;
```

- ⚠️ **`'test_type' => false` disables all MIME/extension validation.** This is the
  single most common WP-UPLOAD finding. Never recommend it.
- `'test_form' => true` (the default) requires `$_POST['action']` to equal
  `'wp_handle_upload'`. AJAX handlers that set a different action must pass
  `'test_form' => false` — **this is normal and not itself a vulnerability**, as
  long as a nonce and capability check exist in the handler. Do not confuse it
  with `test_type`.
- `'mimes' => array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png' )` is the
  correct way to **narrow** the allowed set. Pass an explicit allowlist.
- The `upload_mimes` filter widens the site-wide set — a plugin adding
  `php`, `phtml`, `svg`, or `html` there is a finding (RCE and stored XSS).

**The `unfiltered_upload` escape hatch:**

```php
if ( ( ! $type || ! $ext ) && ! current_user_can( 'unfiltered_upload' ) ) {
	return $upload_error_handler( $file, __( 'Sorry, you are not allowed to upload this file type.' ) );
}
```

A user with `unfiltered_upload` bypasses MIME validation entirely. By default
**nobody** has it — core grants it only when `ALLOW_UNFILTERED_UPLOADS` is defined
and truthy, and on multisite only to Super Admins:

```php
case 'unfiltered_upload':
	if ( defined( 'ALLOW_UNFILTERED_UPLOADS' ) && ALLOW_UNFILTERED_UPLOADS
		&& ( ! is_multisite() || is_super_admin( $user_id ) ) ) { ... }
```

A plugin granting `unfiltered_upload` to a role is effectively granting RCE.

### Path validation

`validate_file( string $file, array $allowed_files = array() ): int`

Returns **`0` = OK**, non-zero = problem:

| Return | Meaning |
|---|---|
| `0` | Nothing wrong |
| `1` | Contains a disallowed `../` construction |
| `2` | Absolute **Windows** path (drive path, UNC share, or `//./` `//?/` device namespace) |
| `3` | Not in `$allowed_files` |

> ⚠️ **Verified trap, stated in core's own docblock:** *"Note that absolute POSIX
> paths such as `/etc/passwd` are **not** rejected, and never have been. Callers
> that must reject them are responsible for their own check. The convention in
> core is to concatenate the validated value onto a trusted base directory and
> then confirm the result exists, rather than to treat this function as an
> absolute-path guard."*

Further verified quirks:

- `validate_file( '' )` and any non-scalar returns **`0`** — it **fails open** on
  empty input.
- A single trailing `../` is permitted; only `../` alone, more than one `../`, or
  a `../` not at the end returns `1`.
- The `@since 7.2.0` widening of return `2` to UNC/device paths is **newer than
  current stable 7.1** — do not rely on it for sites on 7.1 or below.

Because of all this, `validate_file()` is **necessary but not sufficient**. The
correct WP-LFI defence:

```php
$base = realpath( wp_upload_dir()['basedir'] . '/my-plugin' );
$path = realpath( $base . '/' . $user_supplied );

if ( false === $path || ! str_starts_with( $path, $base . DIRECTORY_SEPARATOR ) ) {
	wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}
```

`realpath()` + prefix check is the load-bearing control; `validate_file()` and
`sanitize_file_name()` are defence in depth. Better still, never accept a path:
accept an **ID** and look the path up server-side.

### Outbound HTTP — SSRF

| Function | SSRF-validated? |
|---|---|
| `wp_safe_remote_get/post/head/request()` | ✅ **Yes** — URL and every redirect target validated by `wp_http_validate_url()` |
| `wp_remote_get/post/head/request()` | ❌ **No** — arbitrary URLs, arbitrary protocols |
| `wp_http_validate_url( $url )` | The validator itself; returns URL or `false` |
| `file_get_contents()`, `curl_*()`, `fopen()` on a URL | ❌ No validation; also flagged by WPCS `WordPress.WP.AlternativeFunctions` |

**Rule: any URL that originates from a request must go through `wp_safe_remote_*`.**

`wp_http_validate_url()` verified behavior:

- Only `http` and `https` (via `wp_kses_bad_protocol`).
- Rejects URLs with `user`/`pass` components, and hosts containing `: # ? [ ]`.
- Resolves the host with `gethostbyname()` and rejects private/reserved IPv4
  ranges, subject to the `http_request_host_is_external` filter.

Documented limitations an auditor must still flag:

- ⚠️ **IPv4 only.** The literal-IP regex and `gethostbyname()` do not cover IPv6,
  so `http://[::1]/` style targets are not caught by the IP-range check.
- ⚠️ **Same-host bypass.** If the host equals the site's own `home` host, the IP
  range check is **skipped entirely**.
- ⚠️ **TOCTOU / DNS rebinding.** Validation resolves the name; the subsequent
  request resolves it again.
- ⚠️ A plugin filtering `http_request_host_is_external` to `true`, or setting
  `'reject_unsafe_urls' => false`, re-opens SSRF.
- ⚠️ `'sslverify' => false` in the args array disables certificate validation —
  always a finding.

### Redirects — open redirect (WP-REDIRECT)

| Function | Safe? |
|---|---|
| `wp_safe_redirect( $location, $status, $x_redirect_by )` | ✅ Runs `wp_validate_redirect()` with an `admin_url()` fallback |
| `wp_validate_redirect( $location, $fallback_url )` | ✅ The validator |
| `wp_redirect( $location, ... )` | ❌ **No validation** — WPCS `WordPress.Security.SafeRedirect` warns on it |
| `header( 'Location: ' . $url )` | ❌ No validation, and no `\r\n` filtering |

Verified `wp_validate_redirect()` behavior: allows only `http`/`https` schemes
(so `data:`, `javascript:` are rejected), normalises a leading `//` to `http://`
(because browsers treat it as protocol-relative), rejects malformed URLs and
host/user/pass components containing `: / ? # @`, and finally requires the host to
be in `allowed_redirect_hosts` (default: the site's own host).

⚠️ Plugins widening `allowed_redirect_hosts` re-introduce open redirect.

**Both `wp_redirect()` and `wp_safe_redirect()` must be followed by `exit;`** —
they do not terminate. A missing `exit` means the handler keeps running and the
"protected" code below still executes.

---

## 7. WPCS sniff cross-reference

For static pre-screening. Verified against WPCS **3.4.1**.

| Sniff | Catches | In `WordPress-Extra`? |
|---|---|---|
| `WordPress.Security.EscapeOutput` | Unescaped output (XSS) | ✅ |
| `WordPress.Security.NonceVerification` | Missing CSRF nonce | ✅ |
| `WordPress.Security.ValidatedSanitizedInput` | Unsanitized superglobals, missing `wp_unslash` | ❌ **No — must be added explicitly** |
| `WordPress.Security.SafeRedirect` | `wp_redirect()` instead of `wp_safe_redirect()` | ✅ |
| `WordPress.Security.PluginMenuSlug` | `__FILE__` as menu slug (path disclosure) | ✅ |
| `WordPress.DB.PreparedSQL` | Interpolated SQL | ✅ (also in `-Core`) |
| `WordPress.DB.PreparedSQLPlaceholders` | Wrong placeholder use, incl. `%i` rules | ✅ (also in `-Core`) |
| `WordPress.DB.DirectDatabaseQuery` | Direct `$wpdb` use / no caching | ❌ **No — must be added explicitly** |
| `WordPress.WP.Capabilities` | Roles or user levels passed where a capability belongs | ✅ |
| `WordPress.PHP.DontExtract` | `extract()` | ✅ (also in `-Core`) |
| `WordPress.PHP.RestrictedPHPFunctions` | `create_function()` etc. | ✅ (also in `-Core`) |
| `WordPress.WP.AlternativeFunctions` | `file_get_contents`, `curl_*`, `unlink`, `chmod` | ✅ |
| `WordPress.WP.GlobalVariablesOverride` | Clobbering core globals | ✅ |

Practical notes:

- ⚠️ **`WordPress-Extra` silently omits `ValidatedSanitizedInput` and
  `DirectDatabaseQuery`** — two of the most important security sniffs. Either use
  the full `WordPress` ruleset or add them explicitly.
- `NonceVerification` reports `$_POST`/`$_FILES` as **errors** (`Missing`) but
  `$_GET`/`$_REQUEST` only as **warnings** (`Recommended`) — do not let default
  warning-suppression hide `$_GET`-driven CSRF.
- `PreparedSQLPlaceholders` understands `%i` (WPCS 3.0+) and only complains when
  `minimum_wp_version` is set below `6.2`. The current default
  `minimum_wp_version` is `6.7`, so `%i` passes out of the box.
- ⚠️ WPCS **3.4.1 is a security release**: `WordPress.WP.EnqueuedResourceParameters`
  could achieve arbitrary command execution on the *scanning host* when run over
  untrusted PHP, and the sniff is reachable from both `WordPress` and
  `WordPress-Extra`. **Any tool that lints third-party plugin code must be on
  ≥ 3.4.1.**
- WPCS 3.0 removed the legacy `// WPCS: xxx ok` annotations entirely. In older
  plugin code these are now **inert**, so previously-suppressed findings will
  reappear — that is correct behavior, not a false positive.

---

## 8. Quick decision table

| I have… | …going to | Use |
|---|---|---|
| `$_POST` text | a variable | `sanitize_text_field( wp_unslash( $_POST['x'] ) )` |
| `$_POST` multi-line text | a variable | `sanitize_textarea_field( wp_unslash( $_POST['x'] ) )` |
| `$_GET` id | a query | `absint( $_GET['id'] )` |
| a string | `<p>` | `esc_html()` |
| a string | `attr="…"` | `esc_attr()` (quote the attribute) |
| a URL | `href` / `src` | `esc_url()` |
| a URL | the database | `sanitize_url()` |
| a URL | `wp_safe_redirect()` | `sanitize_url()`, then `wp_safe_redirect()` |
| a URL | an outbound HTTP request | `wp_safe_remote_get()` |
| a string | `<textarea>` | `esc_textarea()` |
| a string | `<script>` | `wp_json_encode()` |
| a string | `onclick='…'` | `esc_js()` (single quotes only) |
| rich text | the page | `wp_kses_post()` or `wp_kses( $h, $allowed )` |
| any value | a SQL value | `$wpdb->prepare()` with `%s` / `%d` / `%f` |
| any value | a SQL table/column | `%i` (WP 6.2+) **or** an allowlist |
| any value | a LIKE clause | `$wpdb->esc_like()` **inside** `prepare()` with `%s` |
| a filename | the filesystem | `sanitize_file_name()` + `realpath()` prefix check |
| a path | `include`/`readfile` | allowlist / ID lookup; `validate_file()` is not sufficient |
| `$_FILES` | disk | `wp_handle_upload()` with an explicit `mimes` allowlist, **never** `test_type => false` |
| a secret | a comparison | `hash_equals()` |
| an action | permission | `current_user_can( $cap, $object_id )` |
| a state change | CSRF safety | `check_admin_referer()` / `check_ajax_referer()` with an explicit action |

---

## See also

- `entry-points.md` — how untrusted input arrives in the first place.
- `capability-matrix.md` — which capability to require, and how privilege maps to severity.
- `secure-handler-template.md` — these APIs assembled into complete, correct handlers.
