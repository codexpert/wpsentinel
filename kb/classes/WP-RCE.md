---
class_id: WP-RCE
title: Remote code execution via eval, dynamic callables and shell commands
cwe: [CWE-94, CWE-95, CWE-78, CWE-77]
owasp: A03:2021-Injection
severity_typical: critical
auth_required_typical: unauthenticated
prevalence_rank: 9
detection:
  - id: RCE-001
    description: >-
      Any call to eval() or assert(). In a WordPress plugin or theme neither has a defensible use:
      eval() is the language\x27s own code-injection primitive, and assert() executed a string
      argument as PHP on every version before 8.0. Read every hit.
    regex: '(?:^|[^_A-Za-z0-9$])@?(?:eval|assert)\s*\('
    confidence: high
    false_positive_notes: >-
      Matches assert() used in its modern, safe expression form (PHP 7+ with zend.assertions off) and
      matches method declarations or calls named eval()/assert() - `$engine->eval( $tpl )` is a
      template-engine wrapper, which is itself worth reading because it usually hides the real sink.
      Also fires on the literal string "eval(" inside JavaScript embedded in a PHP heredoc; confirm
      the hit is PHP, not an inline <script> block.
  - id: RCE-002
    description: A request superglobal used directly as the callable argument of a dispatch function, optionally through one wrapping call such as urldecode() or sanitize_text_field().
    regex: '(?:call_user_func(?:_array)?|array_map|array_filter|array_walk|usort|uasort|uksort|register_shutdown_function|forward_static_call(?:_array)?|iterator_apply)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)'
    confidence: high
    false_positive_notes: >-
      Essentially none as a *finding*. The only ambiguity is reachability - which hook registers the
      handler and what capability check runs first. Note that array_map/array_filter/array_walk are
      included because their first argument is a callable exactly as much as call_user_func\x27s is;
      `array_map( $_GET[\x27f\x27], $items )` is a full arbitrary-function-call primitive.
  - id: RCE-003
    description: A dispatch function whose callable argument is a variable rather than a literal - the shape that survives after the request value has been copied into a local, a property or an options array.
    regex: '(?:call_user_func(?:_array)?|forward_static_call(?:_array)?)\s*\(\s*\$'
    confidence: low
    false_positive_notes: >-
      Downgraded to low after integration testing: this fired on the canonical SAFE
      allowlist dispatch in tests/fixtures/safe.php. No coverage is lost -- RCE-002
      (high) already catches the unambiguous case where a superglobal is the callable.
      This rule is the broader variable-shaped variant and needs assignment tracing,
      which is a triage step by construction.
      The safe idiom matches too: `call_user_func( $allowed[ $key ], $data )` where $allowed is a
      hard-coded map. Triage by finding the assignment of the callable variable. If it traces to a
      literal array, a class constant or a hook registration it is fine; if it traces to a request
      parameter, a shortcode attribute, a block attribute, a post meta value or a plugin option, it
      is a finding. A `function_exists()` or `is_callable()` guard is NOT an allowlist and does not
      downgrade the finding.
  - id: RCE-004
    description: Variable variables ($$name) and dynamic property/variable braces (${$key}). Rare, and almost always a sign that a name is being taken from data rather than written by the developer.
    regex: '\$\$[A-Za-z_]|\$\{\s*\$[A-Za-z_]'
    confidence: high
    false_positive_notes: >-
      Legitimate uses exist in old templating and extract()-style code, and `${$var}` also appears in
      string interpolation contexts where it is inert. Low volume in practice, so read every hit
      rather than filtering. Frequently found next to extract(), which turns a request array into
      local variables and is worth grepping for alongside this rule.
  - id: RCE-005
    description: Variable function invocation - $fn( ... ). The bare-syntax equivalent of call_user_func(), and the form that grep-based reviews miss most often because it contains no function name at all.
    regex: '(?:^|[^A-Za-z0-9_>$\x27"])\$[A-Za-z_][A-Za-z0-9_]*\s*\('
    confidence: medium
    false_positive_notes: >-
      Matches every closure invocation, which in modern PHP is common: `$callback( $x )` where
      $callback was assigned a `function () {}` two lines up is entirely safe. Does not match method
      calls ($obj->m()), static calls (C::m()) or array-element calls ($map[\x27k\x27]()). Triage by
      locating the assignment: an inline closure or a literal string is fine, anything derived from
      input is a finding. Expect a high hit count on codebases that use closures heavily; run it
      after RCE-002 and RCE-003.
  - id: RCE-006
    description: Any OS command execution primitive. WordPress core never shells out, so a plugin that does is doing something the platform deliberately avoids and every call deserves review regardless of how the argument is built.
    regex: '(?:^|[^_A-Za-z0-9>:$])@?(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|expect_popen)\s*\('
    confidence: high
    false_positive_notes: >-
      The word `exec` is a common method name, so `->exec(` and `::exec(` are deliberately excluded
      by the leading character class; a database or HTTP client wrapper named exec() would otherwise
      dominate the results. That exclusion means a genuine `$shell->exec( $cmd )` wrapper is missed -
      see RCE-007 and the guidance below. Also matches availability probes such as
      `shell_exec( \x27echo test\x27 )`, which are inert but tell you the plugin has a shell path.
  - id: RCE-007
    description: A shell primitive whose argument list contains a variable - i.e. the command is assembled rather than constant. This is the subset of RCE-006 where injection is actually possible.
    regex: '(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\([^;]*\$'
    confidence: medium
    false_positive_notes: >-
      Cannot see whether the variable was built with escapeshellarg(). A fully escaped command still
      matches, and a command where eight of nine arguments are escaped also matches - which is the
      point, because that is the shape of most real command-injection bugs. For each hit, read the
      construction of the command string argument by argument and identify the one that is not
      wrapped. Unlike RCE-006 this rule has no leading-character exclusion, so it does catch
      `$shell->exec( $cmd )` style wrappers.
  - id: RCE-008
    description: The backtick shell operator - PHP\x27s syntactic shorthand for shell_exec(), with a variable interpolated into it. Contains no function name, so a function-name-based audit will never see it.
    regex: '=\s*@?\x60[^\x60\n]*\$[A-Za-z_]'
    confidence: medium
    false_positive_notes: >-
      Backticks appear in SQL identifier quoting inside PHP strings, so a line like
      $sql = "SELECT \x60{$col}\x60 FROM t" can match. Distinguish by whether the backtick opens a
      bare expression (shell) or sits inside a quoted string (SQL). The anchor on `=` keeps the
      volume low; drop it to a bare backtick-plus-variable search if the codebase is small enough to
      read all the hits.
  - id: RCE-009
    description: Legacy code-execution constructs - create_function(), and preg_replace() with the /e modifier, which evaluated the replacement string as PHP.
    regex: 'create_function\s*\(|preg_replace\s*\(\s*[\x27"][^\x27"]*[/#~!%|][a-zA-Z]{0,6}e[a-zA-Z]{0,6}[\x27"]'
    confidence: high
    false_positive_notes: >-
      The /e branch can misfire on a pattern whose trailing modifier list legitimately contains an
      `e` that is not the eval modifier - there is no such standard PCRE modifier, so in practice the
      only misfires come from a delimiter character appearing inside the pattern body. Both
      constructs are removed from modern PHP (create_function() removed in 8.0, /e removed in 7.0),
      so a hit means either dead legacy code or a plugin that still targets PHP 5, and both are worth
      recording.
fix_apis:
  - in_array($callable, $allowed, true)
  - a hard-coded dispatch map (array literal of permitted callables)
  - do_action()
  - apply_filters()
  - escapeshellarg()
  - escapeshellcmd()
  - preg_replace_callback()
  - json_decode()
  - sanitize_key()
  - absint()
  - current_user_can()
  - check_ajax_referer()
  - wp_remote_get()
  - WP_Filesystem()
examples:
  - cve: CVE-2023-5843
    year: 2023
    severity: 9.8
    auth: unauthenticated
    summary: A public AJAX handler passed the entire $_REQUEST array into a renderer whose argument list included a callback function name, which was then invoked with call_user_func_array().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5843
    code_ref: https://plugins.trac.wordpress.org/browser/ads-by-datafeedrcom/tags/1.1.3/inc/dfads.class.php#L34
    root_cause: A request-supplied function name reached call_user_func_array() guarded only by function_exists() - an existence check, not an allowlist - on a handler registered with wp_ajax_nopriv_.
  - cve: CVE-2023-5201
    year: 2023
    severity: 8.8
    auth: subscriber+
    summary: A shortcode passed its own body straight to eval() after a capability check evaluated against the displayed post's author rather than against whoever supplied the content.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5201
    code_ref: https://plugins.trac.wordpress.org/browser/thesis-openhook/tags/4.3.0/inc/shortcodes.php#L28
    root_cause: eval() on shortcode content, authorised by author_can( get_the_ID(), ... ) - a check on the post's author, which says nothing about the identity of the actor who introduced the shortcode.
  - cve: CVE-2025-2303
    year: 2025
    severity: 8.8
    auth: contributor+
    summary: The plugin added a free-text attribute to every registered block type and evaluated that attribute as a PHP expression on the render_block filter.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2303
    code_ref: https://plugins.trac.wordpress.org/browser/block-logic/tags/1.0.8/block-logic.php#L127
    root_cause: eval() on a block attribute that any user able to save a post could set; the surrounding try/catch handles Error but does nothing about what the evaluated code does first.
  - cve: CVE-2024-8268
    year: 2024
    severity: 8.8
    auth: subscriber+
    summary: Four request handlers each read a callable name out of $_REQUEST and dispatched to it, one of them after urldecode().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-8268
    code_ref: https://plugins.trac.wordpress.org/browser/frontend-dashboard/tags/2.2.4/route/class-fed-request.php#L29
    root_cause: A nonce was verified and the input was passed through a text sanitiser, but no allowlist constrained which functions or methods the request could name.
  - cve: CVE-2026-9834
    year: 2026
    severity: 7.2
    auth: admin+
    summary: A mysqldump command built with escapeshellarg() around every argument except one - a list of excluded table names read from an option that a settings POST could write.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-9834
    code_ref: https://plugins.trac.wordpress.org/browser/wp-database-backup/tags/7.10/includes/admin/class-wpdb-admin.php#L2644
    root_cause: One concatenated argument omitted escapeshellarg(); sanitize_text_field() on the way into the option does not remove ; | & $( or backticks, so the shell metacharacters survived the round trip.
  - cve: CVE-2023-7002
    year: 2023
    severity: 7.2
    auth: admin+
    summary: A migration endpoint interpolated a POST-supplied URL into a shell command inside hand-written double quotes and ran it with exec().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-7002
    code_ref: https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.9/includes/ajax.php#L1518
    root_cause: Quoting an argument by hand instead of calling escapeshellarg() - the quotes are part of the command string, so the payload only has to close them.
---

## What it is

WP-RCE covers every route by which attacker-influenced data becomes *executed instructions* rather
than data. Three mechanisms dominate in the WordPress ecosystem, and they need different fixes:

1. **PHP code injection** (CWE-94/95) — `eval()`, `assert()` with a string, `create_function()`,
   `preg_replace()` with `/e`. The input is parsed as PHP.
2. **Dynamic callables** — `call_user_func()`, `call_user_func_array()`, `array_map()`, `$fn()`,
   `$$var`. The input does not have to be PHP source; it only has to be the *name* of something the
   process already has, which is enough for `system`, `assert`, `file_put_contents`, `wp_delete_user`
   and several thousand other functions.
3. **OS command injection** (CWE-77/78) — `exec`, `shell_exec`, `system`, `passthru`, `popen`,
   `proc_open` and backticks. The input reaches `/bin/sh`.

At 58 records in the Wordfence prevalence sample this class is uncommon, but its average CVSS of
8.86 is among the highest of any class: when it lands, it lands at the top of the impact scale.
The signatures are also short and distinctive, which makes it one of the cheapest classes to scan
for.

## Why it happens in WordPress

1. **"Let the user extend it" is a WordPress cultural default.** Plugins routinely expose a callback
   name, a template hook, a snippet field or a conditional expression as a *setting*, because that
   is how the platform itself behaves. The difference between a hook name and a callable is
   invisible in a settings form and enormous at runtime: `do_action( $name )` fires whatever is
   registered on that hook, while `call_user_func( $name )` calls anything in the process.

2. **`function_exists()` and `is_callable()` read like validation.** They answer "does this exist",
   never "is this allowed". A guard of `if ( function_exists( $this->args['callback_function'] ) )`
   admits every function in core, in the active theme, in all 25 installed plugins and in every
   bundled `vendor/` tree. Two of the six cases below shipped exactly that guard.

3. **Shortcodes and block attributes are a code path from contributor to render.** A shortcode body
   or block attribute is authored by whoever wrote the post, evaluated when the post is displayed,
   and — critically — the capability check usually available at render time describes the *post*,
   not the person who supplied the content. `author_can( get_the_ID(), $cap )` and `is_admin()` are
   both common and both wrong here (see `kb/reference/entry-points.md` §1 on `is_admin()`).

4. **"Snippet" and "conditional logic" features are eval() by design.** Some plugins genuinely
   intend to run administrator-authored PHP. That intent is not a defence once the field is
   reachable by a contributor, a block attribute, a REST route or an imported template — and the
   feature is usually reachable by at least one of those, because the whole point was to make it
   editable from the UI.

5. **WordPress core never shells out, so shell code in a plugin has no house style to copy.**
   Backup, image-optimisation, migration and diagnostics plugins build command lines by string
   concatenation, and correctness there is all-or-nothing: escaping eight of nine arguments is
   equivalent to escaping none.

6. **`escapeshellarg()` and `escapeshellcmd()` are not interchangeable, and one of them is nearly
   always the wrong choice.**
   - `escapeshellarg( $v )` wraps `$v` in single quotes and escapes any embedded quote. It makes
     the value **one shell argument**. This is the correct tool for a parameter.
   - `escapeshellcmd( $cmd )` escapes shell metacharacters across a *whole command line* but leaves
     quotes able to pair up, and it explicitly does not make an argument safe. Applying it to a
     single argument is a well-known bypass surface.
   - Wrapping the argument in your own quotes — `' "' . $url . '" '` — and then not escaping is the
     single most common command-injection shape, because the quotes make it *look* handled.
   - `escapeshellarg()` output must not itself be re-quoted: `'"' . escapeshellarg( $v ) . '"'`
     produces a nested mess and reintroduces the problem.

7. **Second-order paths hide the taint.** Request → `update_option()` → later read → `shell_exec()`
   is a complete chain in which no single line contains both a superglobal and a sink. Two of the
   cases below have exactly that shape.

8. **`wp_ajax_nopriv_*`, public REST routes, shortcodes and `render_block` all run before any
   capability check.** As always, the sink decides the impact and the hook decides the score.

## Vulnerable pattern

```php
// 1. eval() on content that arrives with the post.
public function php( $atts, $content = null ) {
    if ( author_can( get_the_ID(), $this->auth_level ) ) {   // checks the POST's author, not the actor
        ob_start();
        eval( "?>$content<?php " );
        return ob_get_clean();
    }
}

// 2. eval() on a block attribute, added to every block type in the site.
add_action( 'wp_loaded', function () {
    foreach ( WP_Block_Type_Registry::get_instance()->get_all_registered() as $block ) {
        $block->attributes['blockLogic'] = array( 'type' => 'string' );
    }
}, 999 );
add_filter( 'render_block', function ( $content, $block ) {
    $logic = stripslashes( trim( $block['attrs']['blockLogic'] ) );
    if ( stristr( $logic, 'return' ) === false ) {
        $logic = 'return (' . html_entity_decode( $logic ) . ');';
    }
    return eval( $logic ) ? $content : '';     // try/catch around it changes nothing
}, 10, 2 );

// 3. A callable name straight out of the request.
public function ajax_request() {
    $request = my_sanitize_text_field( $_REQUEST );
    my_verify_nonce( $request );                           // intent, not permission
    if ( isset( $request['action_hook_fn'] ) ) {
        my_call_function_method( array(
            'callable'  => $request['action_hook_fn'],     // no allowlist
            'arguments' => $request,
        ) );
    }
}

// 4. function_exists() used as though it were an allowlist.
if ( function_exists( $this->args['callback_function'] ) ) {
    return call_user_func_array( $this->args['callback_function'], array( $ads, $this->args ) );
}

// 5. Hand-written quotes instead of escapeshellarg().
$url = $this->post['url'];
@exec( BMI_CLI . ' -f "' . $handler . '" quick_migration "' . $url . '" > /dev/null &', $res );

// 6. Escaping everything except one argument.
$cmd  = escapeshellarg( $mysqldump );
$cmd .= ' -u ' . escapeshellarg( DB_USER );
$cmd .= ' -h ' . escapeshellarg( $host );
foreach ( get_option( 'exclude_table' ) as $t ) {
    $cmd .= ' --ignore-table=' . DB_NAME . '.' . $t;      // the one that is not escaped
}
$cmd .= ' ' . escapeshellarg( DB_NAME );
$stderr = shell_exec( $cmd );

// 7. Legacy constructs.
$out = preg_replace( '/\{(\w+)\}/e', 'lookup("$1")', $tpl );  // removed in PHP 7
$fn  = create_function( '$a', 'return ' . $expr . ';' );       // removed in PHP 8
$out = `convert $file out.png`;                                // backticks == shell_exec
```

## Secure pattern

```php
// 1. Dispatch through a hard-coded map. The request selects a KEY, never a callable.
$views = array(
    'summary' => 'myplugin_render_summary',
    'detail'  => 'myplugin_render_detail',
);
$key = isset( $_POST['view'] ) ? sanitize_key( wp_unslash( $_POST['view'] ) ) : 'summary';
if ( ! isset( $views[ $key ] ) ) {
    wp_send_json_error( 'unknown view', 400 );
}
call_user_func( $views[ $key ], $data );

// 2. If third parties must be able to extend, use the hook system - that is what it is for.
//    do_action() can only reach callbacks someone deliberately registered in PHP.
do_action( 'myplugin_render_' . sanitize_key( $key ), $data );

// 3. Conditional logic without eval(): parse a small grammar, or compare declared values.
$rules = json_decode( $stored_rules, true );   // data, never code
$show  = ( isset( $rules['field'], $rules['value'] )
    && get_post_meta( $post_id, sanitize_key( $rules['field'] ), true ) === (string) $rules['value'] );

// 4. Text substitution without /e.
$out = preg_replace_callback(
    '/\{(\w+)\}/',
    static function ( $m ) use ( $lookup ) {
        return isset( $lookup[ $m[1] ] ) ? $lookup[ $m[1] ] : '';
    },
    $tpl
);

// 5. Shell: escape EVERY argument, and never add your own quotes around the result.
$cmd = escapeshellarg( $binary );
foreach ( $args as $arg ) {
    $cmd .= ' ' . escapeshellarg( $arg );       // no surrounding "..." - escapeshellarg quotes it
}
$out = shell_exec( $cmd );

// 6. Better: pick the argument from an allowlist so the shell never sees free text at all.
$tables    = array_intersect( (array) $requested, $this->known_table_names() );
foreach ( $tables as $t ) {
    $cmd .= ' --ignore-table=' . escapeshellarg( DB_NAME . '.' . $t );
}

// 7. Best: do not shell out. WordPress ships equivalents for most of what plugins shell out for.
$response = wp_remote_get( esc_url_raw( $url ), array( 'timeout' => 15 ) );
WP_Filesystem();
global $wp_filesystem;
$wp_filesystem->copy( $from, $to, true );

// 8. Gate the route as well as the sink - all three controls, every time.
add_action( 'wp_ajax_myplugin_run', 'myplugin_run' );   // note: no _nopriv_ variant
function myplugin_run() {
    check_ajax_referer( 'myplugin_run' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( '', 403 );
    }
    // ...
}
```

The single rule that covers the callable half of this class: **the request may choose from a list
you wrote; it may never supply the name itself.** The single rule that covers the shell half:
**every argument goes through `escapeshellarg()`, and you never add quotes of your own.**

## Real-world case studies

### $_REQUEST into a renderer whose arguments include a callback name (CVE-2023-5843)

The entry point, in `dfads.php` (tag 1.1.3), is three lines long:

```php
function dfads_ajax_load_ads(){
    echo dfads( $_REQUEST );
    die;
}
add_action('wp_ajax_nopriv_dfads_ajax_load_ads', 'dfads_ajax_load_ads');
add_action('wp_ajax_dfads_ajax_load_ads', 'dfads_ajax_load_ads');
```

`dfads( $_REQUEST )` merges the request array over the renderer's default argument list, one member
of which is `callback_function`. The sink is `inc/dfads.class.php` lines 33–34:

```php
if ( function_exists( $this->args['callback_function'] ) ) {
    return call_user_func_array($this->args['callback_function'], array( $ads, $this->args ));
}
```

**Root cause at L33/L34:** `function_exists()` is an *existence* test. Every function loaded into
the request — core, theme, every active plugin, every bundled library — passes it. The advisory
scores this AC:H rather than AC:L precisely because the attacker does not control the two arguments
passed, which narrows but does not close the primitive. Two auditing lessons: passing a whole
superglobal into a function (`dfads( $_REQUEST )`) is itself a finding-shaped event because it makes
*every* internal option request-settable; and the sink and the entry point live in different files,
so neither file alone looks alarming.

### eval() authorised by the wrong principal (CVE-2023-5201)

`inc/shortcodes.php` at tag 4.3.0, lines 20–31:

```php
public function php( $atts, $content = null ) {
    global $openhook;

    # Only process this shortcode if the author of the post has the authority
    if ( author_can( get_the_ID(), $openhook->auth_level ) ) {
        ob_start();

        eval( "?>$content<?php " );

        return ob_get_clean();
```

**Root cause at L24/L28:** the comment states the design exactly — *"the author of the post"*. The
authorisation is a property of the post being rendered, not of the actor who supplied `$content`.
Any path that runs `do_shortcode()` over lower-privileged content in the context of a
high-privileged post satisfies the check while letting somebody else choose the code. The advisory
records subscriber-level access as sufficient. Note also that `eval( "?>$content<?php " )` is the
"template" idiom: the `?>` escapes to HTML mode first, so the payload does not even need PHP tags
stripped — it needs them *added*, which the attacker is happy to do.

### A free-text attribute grafted onto every block in the site (CVE-2025-2303)

`block-logic.php` at tag 1.0.8. The attribute is registered globally at L30–L43:

```php
foreach ($registered_blocks as $name => $block) {
    $block->attributes['blockLogic'] = ['type' => 'string'];
}
```

and evaluated on render at L108–L134:

```php
function block_logic_check_logic($logic)
{
    $logic = stripslashes(trim($logic));
    $logic = apply_filters('block_logic_eval_override', $logic);
    ...
    if (stristr($logic, 'return') === false) {
        $logic = 'return (' . html_entity_decode($logic, ENT_COMPAT | ENT_HTML401 | ENT_QUOTES) . ');';
    }

    try {
        $show_block = eval($logic); // phpcs:ignore
    } catch (Error $e) {
```

**Root cause at L127:** `eval()` on a value that reaches the function from
`$block['attrs']['blockLogic']` via the `render_block` filter, for any block on any post. Because
the attribute was added to *every registered block type*, the write side is "anyone who can save a
post" — contributor level. Three details worth internalising: the `try { } catch (Error $e)`
handles a parse failure and provides no security value whatsoever, because the payload has already
run by the time anything is thrown; `stripslashes()` and `html_entity_decode()` actively *help* the
payload by reconstituting quotes; and the `// phpcs:ignore` on the eval line is a reliable marker —
grep for suppressed static-analysis warnings first.

### A callable name in $_REQUEST, four handlers deep (CVE-2024-8268)

`route/class-fed-request.php` at tag 2.2.4, lines 19–52:

```php
add_action( 'wp_ajax_fed_ajax_request', array( $this, 'ajax_request' ) );
add_action( 'wp_ajax_fed_api_ajax_request', array( $this, 'ajax_api_request' ) );
add_action( 'admin_post_fed_request', array( $this, 'request' ) );
add_action( 'admin_post_fed_api_request', array( $this, 'api_request' ) );
...
public function ajax_request() {
    $request = fed_sanitize_text_field( $_REQUEST );
    fed_verify_nonce( $request );
    ...
    if ( isset( $request['fed_action_hook'] ) ) {
        fed_execute_method_by_string( urldecode( $request['fed_action_hook'] ), $request );
    }
    if ( isset( $request['fed_action_hook_fn'] ) && ... ) {
        fed_ajax_call_function_method( array(
            'callable'  => $request['fed_action_hook_fn'],
            'arguments' => $request,
        ) );
    }
```

**Root cause at L29/L40/L47:** a nonce is verified and a text sanitiser is applied, and neither
constrains *which* function may be named. The same block is repeated in all four handlers (L64,
L98, L129), so the same primitive is exposed on `wp_ajax_*` and `admin_post_*` alike. Note that
`urldecode()` on L40 runs *after* sanitisation, which is the classic validate-then-normalise
ordering bug — anything the sanitiser would have removed can be smuggled percent-encoded. The names
`fed_execute_method_by_string` and `fed_ajax_call_function_method` are wrappers, so RCE-002 and
RCE-003 do not fire on these lines: the sink lives one file away. Always chase wrapper names.

### Eight arguments escaped, one not (CVE-2026-9834)

`includes/admin/class-wpdb-admin.php` at tag 7.10. The write side, L215–L216:

```php
if ( isset( $_POST['wp_db_exclude_table'] ) ) {
    update_option( 'wp_db_exclude_table', $this->recursive_sanitize_text_field( wp_unslash( $_POST['wp_db_exclude_table'] ) ) , false); // phpcs:ignore
```

The read side, L2608–L2654:

```php
$cmd  = escapeshellarg( $this->get_mysqldump_command_path() );
$cmd .= ' --no-create-db';
$cmd .= ' -u ' . escapeshellarg( DB_USER );
$cmd .= ' -h ' . escapeshellarg( $host );
$cmd .= ' -r ' . escapeshellarg( $sql_filename );

$wp_db_exclude_table = get_option( 'wp_db_exclude_table' );
if ( ! empty( $wp_db_exclude_table ) ) {
    foreach ( $wp_db_exclude_table as $wp_db_exclude_table ) {
        $cmd .= ' --ignore-table=' . DB_NAME . '.' . $wp_db_exclude_table;    // L2644
    }
}
$cmd .= ' ' . escapeshellarg( DB_NAME );
$stderr = shell_exec( $cmd );                                                 // L2654
```

**Root cause at L2644:** every other argument in this command is wrapped in `escapeshellarg()`. This
one is not, and that is sufficient — `sanitize_text_field()` on the way into the option removes tags
and control characters but leaves `;`, `|`, `&`, `` ` `` and `$(` completely intact. The flow is
second-order: `$_POST` → `update_option()` → `get_option()` → `shell_exec()`, so no single line
contains both a superglobal and the sink, and a taint-tracking scan limited to one file finds
nothing. The consistent use of `escapeshellarg()` on the surrounding lines is what makes this so
easy to miss in review; the eye reads the pattern and skips the exception. When auditing a shell
call, count the arguments and check them individually.

### Hand-written quotes instead of escapeshellarg() (CVE-2023-7002)

`includes/ajax.php` at tag 1.3.9, lines 1503 and 1518:

```php
$url = $this->post['url'];
...
@exec(BMI_CLI_EXECUTABLE . ' -f "' . $cliHandler . '" bmi_quick_migration "' . $url . '" > /dev/null &', $res);
```

**Root cause at L1518:** the `"` characters around `$url` are part of the command string the author
wrote, so escaping them is the attacker's entire job — `" ; curl … ; echo "` closes the quote, runs
a command, and reopens it. Note `$cliHandler` on the same line *is* derived from a
`sanitize_text_field( BMI_INCLUDES )` a few lines up, which shows the author was thinking about
input handling and still reached for the wrong tool. `escapeshellarg( $url )` — with the manual
quotes deleted — is the whole fix. The `@` suppression operator is a useful secondary grep: code
that silences errors around a shell call is code nobody expects to inspect.

## Detection guidance

**Triage order that works:** RCE-001 and RCE-009 first (tiny hit counts, near-100 % worth reading),
then RCE-002 (unambiguous), then RCE-006 (enumerate every shell path in the codebase before
analysing any of them), then RCE-007 (argument-by-argument reading), then RCE-003, RCE-004 and
RCE-008, and RCE-005 last because it is the noisiest.

**What the regexes catch:**

- RCE-001/009 — the direct PHP-execution primitives, current and legacy.
- RCE-002 — superglobal straight into a dispatch function, including the `array_map`/`usort` family
  whose first argument is a callable just as much as `call_user_func`'s is.
- RCE-003/005 — the same primitive after the value has been copied into a variable or property.
- RCE-004 — variable variables, which have no function name to grep for.
- RCE-006/007/008 — every shell path, and the subset of it where the command is assembled.

**What they MISS — read code manually when you see these:**

- **Wrapper functions, which are the norm in this class.** `fed_execute_method_by_string()`,
  `Helper::run()`, `$this->call()`, `$engine->render()`. The Frontend Dashboard case is invisible to
  RCE-002 and RCE-003 for exactly this reason. After any RCE hit, grep for the *enclosing function's
  name* to find its callers, and grep for suspicious wrapper names directly:
  `function .*execute`, `function .*call`, `function .*run`, `function .*eval`, `function .*shell`.
- **Second-order flows.** Request → option/meta/custom table → later read → sink. Two of the six
  cases above have this shape. No line-oriented rule can bridge it. Once you have located a sink,
  work *backwards*: for each variable in the command or callable, find every write path to it.
- **Template engines.** Twig, Blade, Smarty, Mustache and hand-rolled `{{ }}` renderers all compile
  templates to PHP. A request-controlled *template string* (as opposed to template *variables*) is
  server-side template injection and reaches code execution without any token in these rules.
  Several of the highest-scoring WordPress RCEs of recent years are SSTI. Grep for
  `createTemplate`, `->render(`, `Twig`, `Environment(`, `->parse(` with a variable argument.
- **`include`/`require` on a request-controlled path.** That is code execution too, and it is
  tracked as `WP-LFI`; the two classes overlap and a finding in one should prompt a scan for the
  other.
- **Deserialization gadget chains.** `unserialize()` reaching `call_user_func` through a magic
  method is `WP-POI`, and no RCE rule sees it. Cross-reference.
- **`extract()` and `${$k} = $v` loops over request arrays.** These turn request keys into local
  variable names, which frequently *creates* the variable that a later `$fn()` uses. RCE-004 catches
  the brace form; grep `extract\s*\(` separately.
- **`array_map`/`usort` with the callable in second position.** `usort( $arr, $_GET['cmp'] )` is a
  callable sink but the superglobal is not the first argument, so RCE-002 misses it. Grep the
  callable-taking function names generally and check every argument position.
- **String-concatenated function names.** `$fn = 'sys' . 'tem'; $fn( $c );` and
  `call_user_func( base64_decode( $x ) )`. RCE-003/005 catch the invocation; nothing catches the
  construction.
- **Disabled-function probes as a signal.** `ini_get( 'disable_functions' )`,
  `shell_exec( 'echo test' )`, `function_exists( 'proc_open' )` — code that checks whether shell
  execution is available always has a shell path somewhere. Treat a probe as a pointer.
- **`// phpcs:ignore` and `@codingStandardsIgnore` near any of these constructs.** Both of the
  eval-based cases above carry one. This is the highest-yield single grep in the class.

**On judging shell code.** `escapeshellarg()` on *some* arguments is worth exactly nothing; count
them. `escapeshellcmd()` on a single argument is a finding, not a fix. Manual quotes around an
argument are a finding whether or not escaping is also present. And a command whose *binary path* is
configurable (`cli_path`, `mysqldump_path`, `imagemagick_path` settings) is command execution by
design — the escaping question is secondary to who can write that setting.

## Audit checklist

- [ ] Run RCE-001 across the whole tree including `vendor/`, `lib/` and any bundled template engine.
      Read every hit. Record the argument's origin, not just the presence of the call.
- [ ] Run RCE-009. `create_function()` and `/e` mean the code targets PHP 5; note the whole plugin
      as legacy and widen the audit.
- [ ] Run RCE-002. Treat every hit as critical until the hook registration proves otherwise.
- [ ] Run RCE-003 and RCE-005. For each hit, trace the callable variable to its assignment and stop
      at the first literal or hard-coded map. Anything reaching a request parameter, shortcode
      attribute, block attribute, post meta, option or imported file is a finding.
- [ ] Treat `function_exists()`, `is_callable()`, `method_exists()` and `class_exists()` guards as
      **absent** controls. Note them; do not downgrade the finding.
- [ ] Run RCE-004, then grep `extract\s*\(` separately and check what array it is applied to.
- [ ] Run RCE-006 to enumerate every shell path in the codebase before analysing any of them. A
      plugin with one shell call usually has five.
- [ ] For each shell call, reconstruct the command string argument by argument and confirm **every**
      variable argument is wrapped in `escapeshellarg()`. One unwrapped argument is a finding.
- [ ] Flag any argument that the code wraps in its own quotes, whether or not it is also escaped.
      Flag any `escapeshellcmd()` applied to a single argument.
- [ ] Identify who can write each configurable binary path or option that reaches a shell call.
      Second-order flows (`$_POST` → `update_option` → `get_option` → `shell_exec`) count.
- [ ] Run RCE-008 and separate SQL backtick-quoting from shell backticks by checking whether the
      backtick opens a bare expression or sits inside a quoted string.
- [ ] Grep for wrapper names — `function .*execute`, `function .*call`, `function .*run`,
      `function .*eval`, `function .*cmd`, `function .*shell` — and then for calls to each one found.
- [ ] Grep for `phpcs:ignore`, `@codingStandardsIgnore` and `@` error suppression on or near any hit
      from these rules.
- [ ] Grep for template-engine entry points (`->render(`, `createTemplate`, `Twig`, `->parse(`,
      `Environment(`) with a variable first argument, and treat a request-controlled *template* as
      an RCE finding even though no rule here matches it.
- [ ] Trace every confirmed sink to its entry point and record the gate: `wp_ajax_nopriv_*`,
      `wp_ajax_*`, `admin_post_nopriv_*`, `register_rest_route` `permission_callback`, shortcode,
      `render_block`, widget, `init`, cron. Record `unauthenticated` if no capability check runs.
- [ ] Where a nonce is present but `current_user_can()` is not, do **not** downgrade — a nonce
      proves intent, not permission.
- [ ] For shortcode and block-attribute sinks, identify the lowest role that can write the content,
      and check whether the capability test examines the *actor* or merely the post being rendered.
- [ ] Confirm any claimed fix replaces the primitive: an allowlist or hook dispatch for callables,
      `escapeshellarg()` on every argument for shell, `preg_replace_callback()` for `/e`. A patch
      that only adds a nonce, a capability check or an input sanitiser reduces reachability and
      leaves the sink intact — report it as partially fixed.
