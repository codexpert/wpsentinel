---
class_id: WP-SQLI
title: SQL Injection via unprepared $wpdb queries
cwe: [CWE-89]
owasp: A03:2021-Injection
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 6
detection:
  - id: SQLI-001
    description: >-
      A PHP variable interpolated directly into the string literal handed to a raw $wpdb read/write
      method. The $wpdb-> prefix properties ($wpdb->prefix, $wpdb->posts, $wpdb->users ...) are
      excluded from the match because they are server configuration, not user input.
    regex: '\$wpdb->(?:query|get_results|get_var|get_row|get_col)\s*\(\s*(?:"[^"]*|\x27[^\x27]*)\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: high
    false_positive_notes: >-
      Safe only when the interpolated variable is a compile-time constant the request cannot reach
      (a hard-coded table suffix, an allowlisted column). It cannot be made safe by escaping the
      value beforehand with esc_sql() unless the author also added the surrounding quotes by hand --
      see SQLI-009. The rule is line-oriented, so a query built across several lines is invisible to
      it; SQLI-006 and SQLI-007 exist to cover that case.
  - id: SQLI-002
    description: String concatenation of a variable into a raw $wpdb read/write method call - the `"... WHERE id = " . $x` shape, including the `'".$x."'` form where the author added quotes but no escaping.
    regex: '\$wpdb->(?:query|get_results|get_var|get_row|get_col)\([^;]*["\x27]\s*\.\s*\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: high
    false_positive_notes: >-
      The $wpdb-> prefix properties are excluded from the match, so the safe idiom
      `$wpdb->query( "DROP TABLE " . $wpdb->prefix . "x" )` does not fire. What remains as a possible
      false positive is a class constant or a locally derived literal concatenated in
      (`" LIMIT " . $this->page_size`). Check what is on the right of the dot: a superglobal, a
      function argument or a row value is a finding; a value that traces to a literal is not.
  - id: SQLI-003
    description: >-
      $wpdb->prepare() called with a single string argument and no substitution arguments. Core
      raises _doing_it_wrong for this, and it is a reliable tell that the author believes prepare()
      sanitises an already-built query string rather than performing substitution.
    regex: '->prepare\s*\(\s*(?:"[^"]*"|\x27[^\x27]*\x27)\s*\)'
    confidence: high
    false_positive_notes: >-
      A genuinely constant query wrapped in a pointless prepare() is harmless but still wrong; it
      will be flagged. Read the string: if it contains an interpolated variable the finding is live,
      if it is fully literal the finding is only a code-quality issue. The variant
      `$wpdb->prepare( $sql )` where $sql was assembled earlier is NOT caught here - grep separately
      for `prepare( $` followed by a bare variable.
  - id: SQLI-004
    description: A variable concatenated into the *query string* passed to prepare(). prepare() substitutes placeholders in the string it receives; anything already concatenated into that string is raw SQL by the time prepare() sees it.
    regex: '->prepare\s*\(\s*["\x27][^"\x27]*["\x27]\s*\.\s*\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: high
    false_positive_notes: >-
      The common safe form is a pre-built placeholder list -
      `prepare( "... IN (" . implode( ",", array_fill( 0, count( $ids ), "%d" ) ) . ")", $ids )`.
      Distinguish by looking at what the concatenated variable holds: a list of %d/%s tokens is the
      correct fix, a list of values is the bug. Class properties holding table names
      ($this->table, $this->tb_posts) also match and are usually safe.
  - id: SQLI-005
    description: >-
      A placeholder wrapped in quotes or backticks inside prepare(). %s supplies its own single
      quotes and %i its own backticks, so \x27%s\x27 produces a doubly quoted, corrupt value and
      \x60%i\x60 is rejected outright by WPCS (QuotedIdentifierPlaceholder).
    regex: '->prepare\s*\([^;]*[\x27"\x60]\s*%[sdifSDIF]\s*[\x27"\x60]'
    confidence: high
    false_positive_notes: >-
      Rare false positives where a literal quote happens to sit next to a placeholder for reasons
      unrelated to quoting, e.g. `LIKE %s` inside a longer string containing apostrophes. Also flags
      numbered placeholders written as \x27%1$s\x27, which are a separate trap: core does NOT add
      quotes to %1$s-style placeholders, so those genuinely need hand-written quotes and are still
      worth reading.
  - id: SQLI-006
    description: An interpolated variable in identifier position - after FROM, JOIN, ORDER BY or GROUP BY. Identifiers could not be parameterised at all before WP 6.2 and are the single most common reason a developer abandons prepare().
    regex: '(?:ORDER\s+BY|GROUP\s+BY|FROM|JOIN)\s+[^\x27";]{0,40}\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: low
    false_positive_notes: >-
      Reclassified low by scripts/test_rules.py: this fires on correct code in
      tests/fixtures/safe.php, and kb/SCHEMA.md reserves high/medium for rules that stay
      silent there. No coverage is lost - the high-confidence rules in this class still
      cover the unambiguous shapes; this one is the worklist that needs triage.
      Noisy by design and the noisiest rule in this class. On a plugin that keeps table names in
      class properties ("FROM {$this->tb_posts}") it fires on nearly every query, and it also fires
      on `ORDER BY x {$order}` where $order is a locally derived \x27ASC\x27/\x27DESC\x27. Treat it
      as a worklist, not a finding list: for each hit, find where the variable is assigned and stop
      as soon as you reach a literal. The hits that matter are the ones whose variable traces back
      to $_GET/$_POST, a shortcode attribute, a REST parameter or a stored option.
  - id: SQLI-007
    description: >-
      An interpolated variable on the value side of a comparison inside WHERE/AND/OR/SET/HAVING/LIMIT.
      Matches inside a multi-line heredoc-style query string, which is where SQLI-001 and SQLI-002
      go blind. Also matches the quoted form \x27{$var}\x27, which developers frequently believe is safe.
    regex: '(?:WHERE|AND|OR|SET|HAVING|LIMIT|OFFSET)\s+[^\x27";]{0,60}[=<>]\s*[\x27"\x60]?\{?\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: medium
    false_positive_notes: >-
      Fires on SQL fragments that are never executed (documentation blocks, README samples, .sql
      migration text embedded in PHP) and on WP_Query/meta_query array code that merely contains the
      word AND. It cannot tell whether the surrounding statement ends up in $wpdb->prepare(), so
      correlate hits with the nearest enclosing $wpdb call before judging.
  - id: SQLI-008
    description: An IN() list built by interpolation or concatenation rather than by generating one placeholder per element.
    regex: '\bIN\s*\(\s*(?:[\x27"]\s*\.\s*|\{)?\$(?:[A-Za-vx-z_]|w[^p]|wp[^d]|wpd[^b]|wpdb[0-9A-Za-z_])'
    confidence: low
    false_positive_notes: >-
      Reclassified low by scripts/test_rules.py: this fires on correct code in
      tests/fixtures/safe.php, and kb/SCHEMA.md reserves high/medium for rules that stay
      silent there. No coverage is lost - the high-confidence rules in this class still
      cover the unambiguous shapes; this one is the worklist that needs triage.
      The *correct* fix also matches: `"... WHERE id IN( {$placeholders} )"` where
      $placeholders = implode( ",", array_fill( 0, count( $ids ), "%d" ) ) and $ids is passed to
      prepare() as the argument array. Read one line up. If the interpolated variable holds
      placeholder tokens the code is right; if it holds values (even esc_sql\x27d or absint\x27d
      ones) it is a finding, because %i is not permitted inside IN() and an integer cast is the only
      other thing that closes it.
  - id: SQLI-009
    description: Any use of esc_sql(). Per core, esc_sql() is spot-escaping of last resort - it adds no quotes, offers no identifier protection, and since WP 4.8.3 rewrites % characters, so its output is unsafe to reuse.
    regex: '(?:^|[^_A-Za-z0-9>:])esc_sql\s*\('
    confidence: medium
    false_positive_notes: >-
      esc_sql() used on a value that the author then wrapped in literal single quotes inside the
      query is technically correct, and esc_sql() applied to an array before an insert is common.
      Both still deserve a read. The two shapes that are always findings are
      `WHERE x = " . esc_sql( $v )` (no quotes added, so any numeric-context payload walks straight
      in) and `esc_sql( implode( ",", $ids ) )` (identifier/list context, where escaping does nothing).
fix_apis:
  - $wpdb->prepare()
  - '%i identifier placeholder (WP 6.2+)'
  - $wpdb->has_cap('identifier_placeholders')
  - $wpdb->esc_like()
  - $wpdb->insert()
  - $wpdb->update()
  - $wpdb->delete()
  - absint()
  - in_array($v, $allowed, true)
  - esc_sql()
examples:
  - cve: CVE-2024-1071
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A member-directory AJAX endpoint took a sort key from POST, ran it through sanitize_text_field(), and interpolated the result into both a JOIN condition and an ORDER BY clause.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-1071
    code_ref: https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.2/includes/core/class-member-directory-meta.php#L666
    root_cause: sanitize_text_field() was treated as SQL escaping; it strips tags and control characters but leaves quotes intact, and the value landed in identifier position where no placeholder existed before WP 6.2.
  - cve: CVE-2024-4434
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A course query built an IN() list by joining term IDs into a string, escaping it with esc_sql(), and passing the finished string to prepare() with no substitution arguments.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-4434
    code_ref: https://plugins.trac.wordpress.org/browser/learnpress/tags/4.2.6.5/inc/Databases/class-lp-course-db.php#L508
    root_cause: prepare() was called on an already-assembled query string containing zero placeholders, so it had nothing to substitute and performed no escaping; esc_sql() on a comma-joined list neither quotes the values nor constrains them.
  - cve: CVE-2024-2804
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A multisite category listing interpolated a category id straight into a multi-line get_col() query with no prepare() anywhere in the call.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-2804
    code_ref: https://plugins.trac.wordpress.org/browser/network-summary/trunk/includes/class-network-summary.php#L225
    root_cause: A raw $wpdb->get_col() with the parameter interpolated into the WHERE clause - the base case of the class, made harder to grep because the query spans five lines.
  - cve: CVE-2016-15040
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A statistics AJAX handler registered on wp_ajax_nopriv_ used a POST parameter as the selected column name in SELECT, GROUP BY and ORDER BY simultaneously.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2016-15040
    code_ref: https://plugins.trac.wordpress.org/browser/kento-post-view-counter/trunk/index.php#L216
    root_cause: A request parameter used as a column identifier with no allowlist, on a handler reachable without authentication; the only validation was an empty() check that supplied a default.
  - cve: CVE-2024-8436
    year: 2024
    severity: 9.9
    auth: subscriber+
    summary: An image-edit AJAX handler verified a nonce, called stripslashes_deep() over the whole POST array, then concatenated an element of it into a DELETE statement between hand-written single quotes.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-8436
    code_ref: https://plugins.trac.wordpress.org/browser/wp-easy-gallery/trunk/wp-easy-gallery.php#L730
    root_cause: stripslashes_deep() on $_POST removed the only escaping present before the value was concatenated into a raw $wpdb->query(); the adjacent $wpdb->update() call in the same loop was safe, which is why the flaw survived review.
  - cve: CVE-2024-7854
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: Five wp_ajax_nopriv_ handlers each read the same record id from POST, passed it through sanitize_text_field(), and interpolated it into a get_row() query against a hard-coded, unprefixed table name.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-7854
    code_ref: https://plugins.trac.wordpress.org/browser/woo-inquiry/trunk/includes/functions.php?rev=2088873#L307
    root_cause: sanitize_text_field() used as SQL protection on an unauthenticated route, with the same unprepared query duplicated across every handler in the file.
  - cve: CVE-2024-6265
    year: 2024
    severity: 9.8
    auth: unauthenticated
    summary: A user-directory sort parameter was escaped with esc_sql() and strip_tags() and then used to build the ORDER BY clause of the users query.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-6265
    code_ref: https://plugins.trac.wordpress.org/browser/userswp/tags/1.2.10/admin/settings/class-uwp-settings-user-sorting.php#L45
    root_cause: esc_sql() applied to an identifier - it escapes quote characters for string context and provides no protection at all in ORDER BY, where the injection needs no quotes.
---

## What it is

`$wpdb` does not escape anything on its own. `$wpdb->query()`, `get_var()`, `get_row()`,
`get_col()` and `get_results()` send the string they are given to MySQL verbatim. The escaping
happens in exactly one place — `$wpdb->prepare()` — and only for values that are still
*placeholders* at the moment prepare() runs. WP-SQLI is the family of bugs where request-controlled
data becomes part of the SQL text rather than part of the parameters: by interpolation, by
concatenation, by being handed to prepare() already baked into the query string, or by sitting in a
position (`ORDER BY`, `IN (...)`, a table name) where the author believed no placeholder existed.

At 340 records in the Wordfence prevalence sample and an average CVSS of 7.15, this is the
highest-impact *common* class in the WordPress ecosystem. Its signatures are unusually
recognisable, which is why grep-based auditing works well here.

## Why it happens in WordPress

1. **`$wpdb` looks like an ORM and is not one.** `insert()`, `update()`, `delete()` and `replace()`
   *do* escape their value arrays, so a developer who starts with those and later drops down to
   `get_results()` for a join carries over the expectation that `$wpdb` "handles it". It does not.
   In the wp-easy-gallery case below, one loop contains a safe `$wpdb->update()` and an injectable
   `$wpdb->query()` three lines apart.

2. **`sanitize_*` is input sanitisation, not SQL escaping.** `sanitize_text_field()` strips tags,
   octets and line breaks. It does not touch `'`, `"`, `\`, `--`, `/*` or `)`. Four of the seven
   cases below "sanitised" the parameter and still shipped an injection. The reference table in
   `kb/reference/wp-security-apis.md` is explicit: for a SQL destination, **none** of the `esc_*` or
   `sanitize_*` families apply — only `prepare()`.

3. **Identifiers had no placeholder until WordPress 6.2.** Sortable columns, dynamic table names and
   `GROUP BY` targets genuinely could not be parameterised, so the ecosystem grew a habit of
   hand-escaping them. `%i` (WP 6.2+) fixed the language problem but not the habit, and a plugin
   whose `Requires at least:` header is below 6.2 still cannot use it — for those, an allowlist is
   the only correct fix.

4. **`prepare()` is misread as a sanitiser.** The mental model "wrap the query in prepare() and it
   becomes safe" produces `$wpdb->prepare( $sql )` and
   `$wpdb->prepare( 'AND id IN (' . $list . ')' )`. Both compile, both run, both do nothing. Core
   raises `_doing_it_wrong` when a prepared query contains no placeholders, but that notice is
   invisible on a production site.

5. **`%s` brings its own quotes.** Core's docblock: *"All placeholders MUST be left unquoted in the
   query string."* Writing `'%s'` yields `''value''`. Writing `` `%i` `` is likewise wrong. Both are
   WPCS errors, and both appear in the wild because the author tested against a value with no
   quotes in it and saw the query "work".

6. **`esc_sql()` adds no quotes.** `WHERE id = " . esc_sql( $v )` is fully injectable for any
   numeric-context payload, because the attacker never needs to break out of a string. Since
   WP 4.8.3 `esc_sql()` also rewrites `%` into an internal placeholder token, so its output is not
   safe to reuse anywhere else. Core positions it as spot-escaping of last resort.

7. **`$wpdb->prefix` confusion cuts both ways.** `{$wpdb->prefix}` interpolated into a query is
   *safe* — it is server configuration — and a linter warning about it must not be "fixed" by
   wrapping the query in a placeholder-free `prepare()`. In the other direction, hard-coding a table
   name without the prefix (`FROM woo_wpinq_requests`) is a correctness bug that also tells you the
   author was not thinking about `$wpdb` semantics at all; treat it as a smell that predicts
   injection elsewhere in the same file.

8. **`wp_ajax_nopriv_*`, public REST routes and shortcodes run before any capability check.** The
   sink is only half the finding; the hook registration decides whether it is a 9.8 or a 7.2. See
   `kb/reference/entry-points.md`.

## Vulnerable pattern

```php
// 1. Interpolation into a raw read method. The base case.
$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}things WHERE id = $id" );

// 2. Concatenation, with hand-written quotes that provide no protection.
$_POST = stripslashes_deep( $_POST );                       // removes the only escaping present
$wpdb->query( "DELETE FROM $wpdb->easyImages WHERE Id = '" . $editImageId . "'" );

// 3. prepare() with nothing to substitute.
$list = esc_sql( join( ',', $term_ids ) );
$where[] = $wpdb->prepare( 'AND tx.term_id IN (' . $list . ')' );   // zero placeholders

// 4. prepare() on an already-assembled string.
$sql = "SELECT * FROM t WHERE id = " . $_GET['id'];
$wpdb->get_results( $wpdb->prepare( $sql ) );

// 5. Quoted placeholders.
$wpdb->prepare( "WHERE status = '%s'", $status );           // becomes ''publish''
$wpdb->prepare( "SELECT * FROM `%i`", $table );             // WPCS QuotedIdentifierPlaceholder

// 6. Identifier injection: the sanitiser runs, the injection still works.
$sortby = ! empty( $_POST['sorting'] ) ? sanitize_text_field( $_POST['sorting'] ) : 'user_login';
$joins[] = "LEFT JOIN {$wpdb->prefix}um_metadata umm ON ( umm.um_key = '{$sortby}' )";
$order   = " ORDER BY u.{$sortby} ASC ";

// 7. Column name straight from the request, on an unauthenticated route.
add_action( 'wp_ajax_nopriv_pvc_top_geo', 'pvc_top_geo' );
function pvc_top_geo() {
    $geo = $_POST['pvc_geo'];
    $wpdb->get_results( "SELECT $geo FROM $table GROUP BY $geo ORDER BY COUNT($geo) DESC LIMIT 10" );
}

// 8. esc_sql() without quotes: numeric context needs no quote to break out.
$sql = "SELECT * FROM t WHERE id = " . esc_sql( $id );
```

## Secure pattern

```php
// 1. Values: placeholders, unquoted, one argument each.
$rows = $wpdb->get_results( $wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}things WHERE status = %s AND user_id = %d",
    $status,
    $user_id
) );

// 2. IN(): generate one placeholder per element. %i is NOT allowed inside IN().
$ids          = array_map( 'absint', (array) $ids );
$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
$wpdb->query( $wpdb->prepare(
    "UPDATE {$wpdb->prefix}contacts SET unsubscribed = %d WHERE id IN ( {$placeholders} )",
    array_merge( array( $unsubscribed ), $ids )
) );
// For integers an absint() map alone is also sufficient, and is the form core's own
// esc_sql() docs recommend:
$ids = implode( ',', array_map( 'absint', $id_list ) );
$sql = "SELECT * FROM t WHERE id IN ($ids)";

// 3. Identifiers on WP 6.2+: %i, written bare, never quoted or backticked.
$q = $wpdb->prepare( "SELECT * FROM %i WHERE %i = %s", $table, $column, $value );

// 4. Identifiers when the plugin must support < 6.2, or when the legal set is small:
//    an allowlist. This is preferable to %i even on 6.2+, because %i escapes the name
//    but does not stop the feature reaching a table it was never meant to touch.
$allowed = array( 'user_login', 'display_name', 'user_registered' );
$sortby  = in_array( $requested, $allowed, true ) ? $requested : 'user_login';
$order   = ( 'DESC' === strtoupper( $requested_dir ) ) ? 'DESC' : 'ASC';
$sql     = "SELECT * FROM {$wpdb->users} ORDER BY {$sortby} {$order}";
// Runtime-detect %i support if you need both branches:
if ( $wpdb->has_cap( 'identifier_placeholders' ) ) { /* %i path */ }

// 5. LIKE: esc_like() *inside* prepare(), never instead of it.
$like = '%' . $wpdb->esc_like( $search ) . '%';
$wpdb->get_results( $wpdb->prepare(
    "SELECT * FROM {$wpdb->posts} WHERE post_content LIKE %s",
    $like
) );

// 6. Where a helper method fits, use it - the value array is prepared for you.
//    NOTE: the $table argument and the array *keys* are NOT escaped; keep both literal.
$wpdb->update(
    $wpdb->prefix . 'my_table',
    array( 'title' => $title ),          // values: escaped
    array( 'id' => $id ),                // where values: escaped
    array( '%s' ),
    array( '%d' )
);

// 7. Gate the route as well as the query.
add_action( 'wp_ajax_myplugin_edit', 'myplugin_edit' );   // no _nopriv_ variant
function myplugin_edit() {
    check_ajax_referer( 'myplugin_edit' );
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_send_json_error( '', 403 );
    }
    // ... prepared query ...
}
```

Two rules cover almost every case: **placeholders are written bare**, and **anything that is not a
value needs an allowlist or `%i`, never an escaper**.

## Real-world case studies

### A sanitiser standing in for an escaper, in identifier position (CVE-2024-1071)

Ultimate Member's member directory, tag 2.8.2 of
`includes/core/class-member-directory-meta.php`:

```php
$sortby = ! empty( $_POST['sorting'] ) ? sanitize_text_field( $_POST['sorting'] ) : $directory_data['sortby'];   // L666
...
$this->joins[] = "LEFT JOIN {$wpdb->prefix}um_metadata umm_sort ON ( umm_sort.user_id = u.ID AND umm_sort.um_key = '{$sortby}' )";  // L704
...
$this->sql_order = " ORDER BY u.{$sortby} {$order} ";   // L820
```

**Root cause at L666:** `sanitize_text_field()` is a *text* sanitiser. It removes tags, invalid
UTF-8, octets and newlines; it leaves `'`, `"` and `\` untouched. The value then reaches two
distinct sinks — a quoted string inside a `JOIN` condition (L704) and a bare identifier in
`ORDER BY` (L820). The L820 path is the harder one to fix retroactively because it needs no quote
to break out at all. Note the shape of the guard: the code carefully checks `! empty()` and supplies
a default, which *reads* like validation while validating nothing about the content.

The scanning lesson: this file produces 15 SQLI-006 hits and 4 SQLI-007 hits, of which two lines
matter. That ratio is normal for identifier rules and is why SQLI-006 is `medium`.

### prepare() with nothing to prepare (CVE-2024-4434)

LearnPress, tag 4.2.6.5 of `inc/Databases/class-lp-course-db.php`, lines 507–512:

```php
$term_ids_format = esc_sql( join( ',', $filter->term_ids ) );
$filter->where[] = $this->wpdb->prepare( 'AND tx.term_id IN (' . $term_ids_format . ')' );
} else {
    $term_all        = $this->recursion_sub_categories( $filter->term_ids );
    $term_ids_format = esc_sql( join( ',', $term_all ) );
    $filter->where[] = "AND tx.term_id IN ($term_ids_format)";
}
```

**Root cause at L508:** three separate failures stacked in one statement.
`join( ',', $term_ids )` flattens the list into SQL text; `esc_sql()` escapes quote characters,
which is irrelevant because the payload lives in numeric context; and `prepare()` receives a
finished string with **zero placeholders and zero arguments**, so it has nothing to substitute and
returns the string essentially unchanged. Line 512 drops even the pretence of `prepare()`.

Compare line 498 in the same file, which is correct:
`$this->wpdb->prepare( 'AND p.post_status IN (' . $post_status_format . ')', $filter->post_status )`
— there `$post_status_format` is a generated list of `%s` tokens and the values are passed as an
argument. **Both lines match SQLI-004.** Telling them apart requires reading one line up to see
what the concatenated variable holds. That distinction — placeholder list versus value list — is
the entire triage rule for `IN()` findings.

### The base case, hidden by line breaks (CVE-2024-2804)

`includes/class-network-summary.php`, lines 225–232:

```php
public function get_sites_per_category( $category_id, $show_only_shared = false ) {
    global $wpdb;
    $result = $wpdb->get_col(
        "SELECT blogs.blog_id
         FROM $wpdb->blogs blogs
         JOIN $wpdb->site_categories_relationships rel ON blogs.blog_id = rel.blog_id
         WHERE rel.category_id = $category_id
         ORDER BY blog_id ASC" );
```

**Root cause at L231:** a function parameter interpolated into `WHERE` with no `prepare()` anywhere
in the statement. What makes it worth including is the formatting: the `$wpdb->get_col(` token and
the injected variable are six lines apart, so SQLI-001 (which requires both on one line) misses it
entirely. SQLI-007 catches it because it anchors on the SQL keyword rather than on the `$wpdb` call.
Note also that `$wpdb->blogs` and `$wpdb->site_categories_relationships` on the neighbouring lines
are *safe* interpolations — a reviewer skimming for `$` in the query has to distinguish them, which
is exactly what the `$wpdb`-exclusion in the rules automates.

### A column name from an unauthenticated POST (CVE-2016-15040)

`kento-post-view-counter/trunk/index.php`, lines 216–229 and 297–298:

```php
function kento_pvc_top_geo() {
    if ( isset( $_POST['kento_pvc_geo'] ) ) {
        $geo = $_POST['kento_pvc_geo'];
    }
    if ( empty( $geo ) ) { $geo = "country"; }
    ...
    $result = $wpdb->get_results( "SELECT $geo FROM $table GROUP BY $geo ORDER BY COUNT($geo) DESC LIMIT 10", ARRAY_A );
}
add_action( 'wp_ajax_kento_pvc_top_geo', 'kento_pvc_top_geo' );
add_action( 'wp_ajax_nopriv_kento_pvc_top_geo', 'kento_pvc_top_geo' );
```

**Root cause at L229:** the raw POST value is used as a *column identifier* in three positions of
one query, with no sanitiser at all and no allowlist. The `empty()` default is the only control and
it only fires when the parameter is absent. The `wp_ajax_nopriv_` registration at L298 is what makes
this a 9.8: no nonce, no capability, no login. The correct fix here is an allowlist
(`in_array( $geo, array( 'country', 'city' ), true )`), not `%i` — the set of legal columns is two.

### stripslashes_deep() removing the accidental protection (CVE-2024-8436)

`wp-easy-gallery/trunk/wp-easy-gallery.php`, the AJAX handler at L730 and its sink at L747:

```php
public function wpeg_edit_images() {
    check_ajax_referer( 'wp_easy_gallery', 'security' );

    $_POST = stripslashes_deep( $_POST );

    $editImageIds = $_POST['edit_imageId'];
    ...
    foreach ( $editImageIds as $editImageId ) {
        if ( in_array( $editImageId, $deleteIds ) ) {
            $wpdb->query( "DELETE FROM $wpdb->easyImages WHERE Id = '" . $editImageId . "'" );
        }
        else {
            $imageEdited = $wpdb->update( $wpdb->easyImages, array( ... ), array( 'Id' => $editImageId ) );
        }
    }
```

**Root cause at L747:** the `'` characters around the concatenation are hand-written, so the value
is in string context with no escaping — and `stripslashes_deep( $_POST )` three lines earlier has
already removed the magic-quote-style backslashes that would otherwise have neutralised a quote.
Two things make this case instructive. First, a nonce **is** verified: `check_ajax_referer()`
proves intent but says nothing about the data, and there is no `current_user_can()` at all, so a
subscriber can reach it. Second, the safe call and the unsafe call sit in the same `foreach`: the
`$wpdb->update()` on the next branch escapes `Id` automatically, which is precisely why the
`$wpdb->query()` beside it never looked wrong.

### The same unprepared query duplicated across five public endpoints (CVE-2024-7854)

`woo-inquiry/trunk/includes/functions.php` at r2088873, lines 292 and 307 (and again at 335/352,
524/529, 593/599):

```php
add_action( 'wp_ajax_nopriv_woo_wpinq_times_up', 'woo_wpinq_times_up' );
function woo_wpinq_times_up() {
    $dbid = sanitize_text_field( $_POST['dbid'] );
    ...
    $item_requests = $wpdb->get_row( "SELECT * FROM  woo_wpinq_requests WHERE id = $dbid" );
```

**Root cause at L307:** `sanitize_text_field()` again standing in for `prepare()`, on a handler
registered with `wp_ajax_nopriv_` and with no nonce — scored 10.0 because it is unauthenticated and
the scope changes. Note the table name: `woo_wpinq_requests`, hard-coded with no `$wpdb->prefix`.
That is a separate correctness bug, but it is a useful tell for an auditor: a file that ignores
`$wpdb->prefix` is a file where nobody read the `$wpdb` documentation, and the same page documents
`prepare()`. When you find one, grep the whole file rather than the one reported line — here the
identical sink appears five times.

### esc_sql() applied to an identifier (CVE-2024-6265)

UsersWP, tag 1.2.10 of `admin/settings/class-uwp-settings-user-sorting.php`, line 45:

```php
public function pre_user_query( $vars ) {
    ...
    if ( isset( $_GET['uwp_sort_by'] ) && $_GET['uwp_sort_by'] != '' ) {
        $sort_by = strip_tags( esc_sql( $_GET['uwp_sort_by'] ) );
    }
```

**Root cause at L45:** `esc_sql()` escapes characters that matter inside a quoted string literal.
`$sort_by` is subsequently decomposed into a meta key and an ORDER BY direction and interpolated
into the users query in *identifier* position, where the payload requires no quote and therefore
meets no escaping. `strip_tags()` compounds the false sense of safety by looking like a second layer
of defence. This is the canonical demonstration that **escaping is destination-specific**: the same
`esc_sql()` call that would be adequate (if quoted) for a value is worth nothing for a column name.
The fix for an ORDER BY is always an allowlist or `%i`.

## Detection guidance

**Triage order that works:** SQLI-002 and SQLI-001 first (highest precision, and they name the
`$wpdb` call directly), then SQLI-003/004/005 (prepare misuse — small hit counts, near-100 %
worth reading), then SQLI-008 (`IN()`), then SQLI-006 and SQLI-007 last, because those two produce
the bulk of the noise and are most useful as a *worklist* once the obvious cases are cleared.

**What the regexes catch:**

- SQLI-001/002 — the direct sinks: interpolation and concatenation into `query`, `get_results`,
  `get_var`, `get_row`, `get_col`, with `$wpdb->prefix`-style properties excluded so the common safe
  form does not drown the report.
- SQLI-003/004/005 — the three ways `prepare()` is neutralised: no placeholders, a variable
  concatenated into the query string, and quoted placeholders.
- SQLI-006/007 — identifier position and value position respectively, anchored on SQL keywords so
  they still work on multi-line queries and on query *fragments* assembled into arrays.
- SQLI-008 — `IN()` lists.
- SQLI-009 — every `esc_sql()`, since core positions it as a last resort.

**What they MISS — read code manually when you see these:**

- **Wrapper methods.** `$this->db->get( $sql )`, `Helper::query()`, `MyPlugin_DB::run()`. None of
  the rules fire on a wrapper's call sites, only inside the wrapper itself. After any `$wpdb` hit
  in a class named `*_DB`, `*_Query`, `*_Model` or `*Repository`, grep for calls to that class.
- **Query fragments assembled into arrays.** The LearnPress and Ultimate Member cases both build
  `$filter->where[]` / `$this->joins[]` arrays that are `implode()`d into a query hundreds of lines
  away. SQLI-006/007 catch the fragment; nothing links it to the eventual `$wpdb` call. When you see
  `$where[] =` or `$joins[] =`, find the `implode` and read the final assembly.
- **`$wpdb->prepare( $sql )` with a bare variable.** SQLI-003 requires a literal string. Grep
  separately for `prepare\(\s*\$` — a prepare whose first argument is a variable is *always* worth
  reading, because the query text was built elsewhere.
- **The table argument of `insert()`/`update()`/`delete()`/`replace()`.** These methods escape the
  data and where-clause *values* but not the `$table` argument and not the array *keys*. A
  request-controlled table name or column key passed to them is injectable and matches none of these
  rules. Grep for `->insert(\s*\$`, `->update(\s*\$`, `->delete(\s*\$` and inspect the first
  argument.
- **`$wpdb->get_results( $sql, ARRAY_A )` where `$sql` was built far above.** All the value rules
  anchor on either the `$wpdb` call or an SQL keyword; a query assembled through ten `.=` statements
  and executed at the end will only surface via SQLI-006/007 on the individual fragments.
- **Second-order injection.** A value that is safely stored and later read back and interpolated.
  The write side may be perfectly parameterised; the read side is the bug. Nothing in a
  line-oriented rule can see this. Treat option values, post meta, custom-table columns and
  transients as untrusted input for the purposes of the read-side query.
- **`%1$s`-style numbered placeholders.** Core does **not** add quotes to these, so they behave
  differently from `%s` in the same query. SQLI-005 will flag `'%1$s'` but the underlying trap —
  mixing numbered and unnumbered placeholders — needs a human. Flag any `prepare()` containing
  `%1$`, `%2$` etc. for manual review.
- **`prepare()` argument-count mismatches.** Passing args variadically *and* as an array, or fewer
  args than placeholders, produces a `_doing_it_wrong` at runtime and often a query that does not do
  what the author intended. Not regex-detectable; rely on WPCS
  `WordPress.DB.PreparedSQLPlaceholders`.
- **`LIKE` built with wildcards in the query string.** `"LIKE '%$term%'"` is both an injection and a
  wildcard bug. SQLI-007 may catch it via the `=`/`<`/`>` anchor only by accident; grep `LIKE` and
  check every hit for `esc_like()` *inside* a `prepare()`.

**Static-analysis backstop.** WPCS `WordPress.DB.PreparedSQL` and
`WordPress.DB.PreparedSQLPlaceholders` catch most of SQLI-001 through SQLI-005 with better precision
than any regex, and `PreparedSQLPlaceholders` understands `%i` from WPCS 3.0. They are not enabled
by default in every ruleset — `WordPress.DB.DirectDatabaseQuery` in particular must be added
explicitly. Run them where the codebase permits, and use these rules for the cases WPCS suppresses
via `// phpcs:ignore`, which is itself a high-yield grep.

## Audit checklist

- [ ] Enumerate every `$wpdb->` call site in the tree, including `vendor/` and any bundled library.
      Record which are `insert`/`update`/`delete`/`replace` (values auto-escaped) and which are
      `query`/`get_*` (nothing auto-escaped).
- [ ] Run SQLI-001 and SQLI-002. Every hit whose interpolated value is not a literal or a
      `$wpdb->` property is a finding until the taint path proves otherwise.
- [ ] Run SQLI-003. For each hit, read the string: an interpolated variable makes it live, a fully
      literal query makes it a code-quality note. Then separately grep `prepare\(\s*\$` for the
      variable-first-argument form the rule cannot see.
- [ ] Run SQLI-004 and, for each hit, read the line above to determine whether the concatenated
      variable holds **placeholder tokens** (correct) or **values** (finding).
- [ ] Run SQLI-005. Remove the quotes/backticks around `%s`/`%d`/`%f`/`%i`. Separately grep `%1$`,
      `%2$` and flag numbered placeholders for manual review — they are not auto-quoted.
- [ ] Run SQLI-006. For each hit, trace the variable to its assignment. Stop at the first literal.
      Anything reaching `$_GET`/`$_POST`/`$_REQUEST`, a shortcode attribute, a REST parameter or a
      stored option is a finding.
- [ ] For every identifier finding, choose the fix by the plugin's `Requires at least:` header:
      `%i` if 6.2 or higher, an **allowlist** otherwise. Prefer the allowlist either way when the
      legal set is small — `%i` escapes the name but does not restrict which tables the feature can
      reach.
- [ ] Confirm `%i` usages are written **bare**. `'%i'`, `"%i"` and `` `%i` `` are all wrong, `%i` is
      not permitted inside `IN()`, and one argument may not be used as both `%i` and `%s` in the
      same query.
- [ ] Run SQLI-008. Verify each `IN()` list is built as `array_fill( 0, count( $ids ), '%d' )` with
      the values passed to `prepare()`, or as `implode( ',', array_map( 'absint', $ids ) )`.
      An `esc_sql( implode(...) )` is a finding.
- [ ] Run SQLI-009. For each `esc_sql()`, answer two questions: does the query add quotes around it,
      and is the destination a value rather than an identifier? A "no" to either is a finding.
- [ ] Check the first argument of every `insert`/`update`/`delete`/`replace`, and the *keys* of the
      data and where arrays. Those are not escaped.
- [ ] Grep for `LIKE` and confirm `$wpdb->esc_like()` is used **inside** a `prepare()` with the
      wildcards attached to the argument, not written into the query string. `like_escape()` is
      deprecated and must not be recommended as a fix.
- [ ] Trace every confirmed sink back to its entry point and record the gate: `wp_ajax_nopriv_*`,
      `wp_ajax_*`, `register_rest_route` `permission_callback`, `admin_post_nopriv_*`, shortcode,
      widget, `init`, `pre_get_posts`, cron. Record `unauthenticated` if no capability check runs.
- [ ] Where a nonce is present but `current_user_can()` is not, do **not** downgrade: a nonce proves
      intent, not permission, and any logged-in subscriber can obtain one.
- [ ] Grep for `phpcs:ignore` and `@codingStandardsIgnore` on or near `$wpdb` lines. Suppressed
      warnings are a high-yield source of real findings.
- [ ] For each finding, check whether the same statement is duplicated elsewhere in the file — an
      unprepared query is very often copy-pasted across every handler in the module.
- [ ] Verify any claimed fix actually parameterises the value. A patch that adds `sanitize_text_field()`,
      `strip_tags()`, `esc_sql()` or a nonce narrows exploitation but leaves the injection intact;
      report it as partially fixed.
