---
class_id: WP-XSS-R
title: Reflected XSS via request data echoed without context-correct escaping
cwe: [CWE-79, CWE-80]
owasp: A03:2021-Injection
severity_typical: medium
auth_required_typical: unauthenticated
prevalence_rank: 3
detection:
  - id: XSSR-001
    description: echo/print of a superglobal directly, with no escaping wrapper
    regex: '\b(echo|print)\s+\$_(GET|POST|REQUEST|SERVER|COOKIE)\s*\['
    confidence: high
    false_positive_notes: >-
      Zero hits across 256k LOC of five mature audited plugins, so a hit is almost
      always real. The only benign shapes are echoing a value the caller already
      hardened (rare, because the superglobal is being read inline here) and echoing
      into a context where the payload cannot execute (a comment, a Content-Type
      that is not HTML). Confirm the output context before deciding which escaper
      to recommend - do not assume esc_html.
  - id: XSSR-002
    description: Short echo tag printing a superglobal
    regex: '<\?=\s*\$_(GET|POST|REQUEST|SERVER|COOKIE)\s*\['
    confidence: high
    false_positive_notes: >-
      Same profile as XSSR-001. `<?=` is always an echo, so there is no wrapper.
      Note that short_open_tag is irrelevant - `<?=` is always available since PHP 5.4.
  - id: XSSR-003
    description: >-
      echo/print of a bare variable that is not wrapped in any function call
      (the token right after the echo keyword is `$`, not an identifier)
    regex: '\b(echo|print)\s+\$[A-Za-z_][A-Za-z0-9_]*\s*(;|\?>|\.\s)'
    confidence: medium
    false_positive_notes: >-
      203 hits per 256k LOC (0.79/KLOC) versus 3489 for a naive "echo with a
      variable" pattern - a 94% noise reduction, but the residue is real and must
      be triaged. Dominant benign case: the value was escaped on a previous line
      and stored (`$safe = esc_html($x); echo $safe;`), which the WordPress docs
      explicitly sanction when the variable is suffixed `_escaped`, `_safe` or
      `_clean`. Second benign case: the value is a constant, an integer counter,
      or plugin-authored markup. Triage rule for a reviewing agent - walk back to
      the assignment of that variable; if the assignment is a literal, a cast, or
      an esc_*/wp_kses* call, drop it; if the assignment traces to $_GET/$_POST/
      $_REQUEST/$_SERVER/$_COOKIE or to a database read, keep it and then judge the
      output context.
  - id: XSSR-004
    description: >-
      Output of add_query_arg()/remove_query_arg() with no escaping wrapper - these
      default to $_SERVER['REQUEST_URI'] when no URL argument is supplied
    regex: '\b(echo|print)\s+(add_query_arg|remove_query_arg)\s*\('
    confidence: high
    false_positive_notes: >-
      0 hits across the 256k LOC negative corpus, while `esc_url( add_query_arg( ... ) )`
      appeared 48 times in the same corpus - the correct form is what maintained code
      actually contains, so the bare form stands out cleanly. Do NOT add `return` to
      the keyword alternation - `return add_query_arg(...)` is a transport, not an
      output sink, and adding it took this rule from 0 hits to 47 on the same corpus.
      Flag only at the point of emission.
  - id: XSSR-005
    description: Superglobal concatenated into a string that is being built as markup
    regex: '\.\s*\$_(GET|POST|REQUEST|SERVER|COOKIE)\s*\['
    confidence: medium
    false_positive_notes: >-
      10 hits per 256k LOC. Fires on string building regardless of whether the
      string is ever echoed - a value concatenated into a log line, a SQL string,
      or an HTTP header is not reflected XSS (though it may well be another class).
      Check what happens to the assembled variable.
  - id: XSSR-006
    description: >-
      Use of the server variables that carry attacker-controlled request text -
      REQUEST_URI, PHP_SELF, QUERY_STRING, HTTP_REFERER
    regex: '\$_SERVER\s*\[\s*[''"](REQUEST_URI|PHP_SELF|QUERY_STRING|HTTP_REFERER)[''"]\s*\]'
    confidence: low
    false_positive_notes: >-
      A presence check, not a vulnerability check. These variables are legitimately
      read for routing, caching keys, canonical URLs and nonce actions. Its value is
      as an inventory - enumerate every site that touches them, then check each one
      for an output path. Modern browsers percent-encode the path portion of
      REQUEST_URI, which is why several CVEs in this family carry the NVD qualifier
      "in old web browsers"; the query string, and PHP_SELF under PATH_INFO-style
      server configs, are not encoded, so treat the qualifier as narrowing severity,
      not eliminating it.
  - id: XSSR-007
    description: printf/vprintf whose first argument variable is passed unescaped
    regex: '\b(printf|vprintf)\s*\([^;]*,\s*\$[A-Za-z_]'
    confidence: low
    false_positive_notes: >-
      22 hits per 256k LOC, most of them benign because the corresponding format
      specifier is numeric (`%d`, `%u`) and therefore casts the argument. Read the
      format string - only `%s` positions matter. This rule exists because printf
      output is invisible to every echo-anchored rule, and at least one real CVE in
      this class emitted its payload through `printf('%s', $url)`.
  - id: XSSR-008
    description: >-
      Inline PHP echo of a bare variable or superglobal directly inside a quoted
      HTML attribute value
    regex: '=\s*["''][^"'']*<\?(php\s+echo|=)\s+\$'
    confidence: high
    false_positive_notes: >-
      49 hits per 256k LOC. Precise because `value="<?php echo esc_attr($x); ?>"`
      does not match - the token after `echo` is an identifier, not `$`. Every hit
      is an attribute-context output with no wrapper, so the correct fix is nearly
      always esc_attr(), or esc_url() when the attribute is href/src/action/formaction.
      Residual noise is the same "escaped on an earlier line" case as XSSR-003.
  - id: XSSR-009
    description: >-
      Double-quoted PHP string with variable interpolation being echoed, where the
      string contains an HTML attribute assignment
    regex: '\b(echo|print)\s+"[^"]*=\s*.?\$\{?[A-Za-z_]'
    confidence: medium
    false_positive_notes: >-
      Interpolation hides the value from every wrapper-anchored rule because there is
      no function call to look for. Benign when the interpolated variable is an
      integer, a plugin constant, or an already-escaped variable. Heredoc bodies use
      the same interpolation and are NOT matched by this rule - grep separately for
      `<<<` if the codebase uses them.
fix_apis:
  - esc_html()
  - esc_attr()
  - esc_url()
  - esc_js()
  - esc_textarea()
  - esc_xml()
  - wp_kses()
  - wp_kses_post()
  - absint()
  - sanitize_text_field()
examples:
  - cve: CVE-2025-2165
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: A GET parameter was echoed straight into the value attribute of a hidden form input on an admin screen.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2165
    code_ref: https://plugins.trac.wordpress.org/browser/sh-email-alert/tags/1.0/manage.php#L156
    root_cause: Missing esc_attr() on a $_GET value printed inside a double-quoted HTML attribute.
  - cve: CVE-2025-2481
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: One GET parameter was echoed twice on the same screen - once into an input value attribute and once into an href query string.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2481
    code_ref: https://plugins.trac.wordpress.org/browser/mediaview/tags/1.1.2/inc/forms/addMedia.inc.php#L48
    root_cause: Missing esc_attr() in the attribute context and missing esc_url() in the URL context - two different escapers needed for one input.
  - cve: CVE-2025-2269
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: A request parameter was echoed inside a JavaScript string literal within an inline script block on an admin view.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2269
    code_ref: https://plugins.trac.wordpress.org/browser/photo-gallery/tags/1.8.34/admin/views/Editimage.php#L39
    root_cause: HTML escaping would not have helped - the value needed absint()/esc_js()/wp_json_encode() because the context was JavaScript, not HTML.
  - cve: CVE-2024-12466
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: A POST parameter was passed through sanitize_text_field() on input and then printed into an HTML attribute without escaping.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-12466
    code_ref: https://plugins.trac.wordpress.org/browser/proofreading/tags/1.2.1.1/admin/partials/proofreading-admin-display.php#L103
    root_cause: sanitize_text_field() neutralises "<" but leaves quote characters intact, so the attribute could still be broken out of; esc_attr() was required at the output site.
  - cve: CVE-2024-9208
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: remove_query_arg()/add_query_arg() were called with no URL argument, so they rebuilt REQUEST_URI, and the result was echoed into an href on one link while an adjacent link escaped it.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9208
    code_ref: https://plugins.trac.wordpress.org/browser/enable-accessibility/tags/1.4.1/includes/accessibility-attachments-alt.php#L62
    root_cause: Missing esc_url()/esc_attr() around an add_query_arg() result that silently defaults to $_SERVER['REQUEST_URI'].
  - cve: CVE-2024-11375
    year: 2025
    severity: 6.1
    auth: unauthenticated
    summary: The same add_query_arg-defaults-to-REQUEST_URI pattern, but the value was emitted with printf('%s', ...) rather than echo, and appeared in both an href and the link text.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-11375
    code_ref: https://plugins.trac.wordpress.org/browser/wc1c-main/tags/0.23.0/views/promo/activation.php#L25
    root_cause: No escaping at either output site; the href needed esc_url() and the link text needed esc_html(), and printf hid both from echo-anchored review.
  - cve: CVE-2023-0937
    year: 2023
    severity: 6.1
    auth: unauthenticated
    summary: $_SERVER['REQUEST_URI'] was output into an HTML attribute without escaping.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-0937
    root_cause: Missing esc_url()/esc_attr() on a server variable that carries raw request text.
  - cve: CVE-2024-12595
    year: 2025
    severity: 4.7
    auth: unauthenticated
    summary: $_SERVER['REQUEST_URI'] was output into an HTML attribute without escaping - an independent rediscovery of the same pattern two years later.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-12595
    root_cause: Missing esc_url()/esc_attr() on a server variable that carries raw request text.
  - cve: CVE-2024-10815
    year: 2025
    severity: 4.2
    auth: unauthenticated
    summary: $_SERVER['REQUEST_URI'] was output into an HTML attribute without escaping.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-10815
    root_cause: Missing esc_url()/esc_attr() on a server variable that carries raw request text.
---

## What it is

Reflected XSS is when data that arrives with the current HTTP request is written
back into the response without being encoded for the place it lands in. The payload
never touches the database; the attacker delivers it in a crafted link, the victim's
browser sends it, and the page hands it straight back as executable markup or script.

In WordPress this is overwhelmingly an *admin-side* problem. The typical victim is a
logged-in administrator who clicks a link, and the typical payoff is an authenticated
request made in that administrator's session - creating a user, installing a plugin,
writing an option. That is why CVSS vectors for this class are almost always
`AV:N/AC:L/PR:N/UI:R/S:C` - no privileges to launch, but user interaction required,
and a scope change because the script executes in the admin origin.

Measured across five consecutive 120-day NVD publication windows (2023-01-01 through
2024-08-26), reflected XSS accounted for 281 WordPress CVE records against 1828 for
stored XSS - common, but roughly one-sixth as common as its stored sibling.

## Why it happens in WordPress

**WordPress does not escape on output for you.** `the_title()`, `the_content()` and a
handful of other template tags apply filters, but a plugin's own admin screens, list
tables, settings pages and notices are raw PHP writing raw HTML. There is no
auto-escaping template layer. Escaping is entirely the plugin author's job, at every
single output site.

**The escaping API is context-indexed, and picking the wrong index still looks like
escaping.** `esc_attr()` on a value that lands in a `<script>` string literal, or
`esc_html()` on a value that lands in an `href`, produces code that passes a
"did they escape it?" review and is still exploitable. Correctness is a property of
the pair (function, destination), never of the function alone.

**`add_query_arg()` and `remove_query_arg()` default to `$_SERVER['REQUEST_URI']`.**
This is the single most WordPress-specific trap in the class. Called without an
explicit URL argument, they rebuild the current request URI - which is attacker
controlled - and return it. Authors read `add_query_arg( 'page', 'settings' )` as
"build me an internal link" and echo the result without `esc_url()`. It generated an
entire wave of CVEs in this class; four of the nine examples above are this exact
shape.

**`$_SERVER['REQUEST_URI']` and `$_SERVER['PHP_SELF']` look like server data.** They
are named like configuration but they are request input. `PHP_SELF` in particular is
not percent-encoded by browsers under PATH_INFO-style routing, and neither is the
query-string portion of `REQUEST_URI`.

**Sanitising on input is not escaping on output.** `sanitize_text_field()` strips
tags but leaves `"` and `'` untouched, so a sanitised value still breaks out of a
quoted attribute. The developer handbook states the rule plainly: "You always want to
escape when you echo, not before."

**Admin notices are a reflection surface.** The `admin_notices` /
`network_admin_notices` hooks run on every admin page load, and the common idiom is
to read a status parameter off the URL and print a message. If the message text or a
"go back" link in that notice is built from `$_GET`, the notice is a reflected XSS
that fires on a page an administrator visits by clicking a link.

## Vulnerable pattern

```php
<?php
// 1. Superglobal into a text node.
echo $_GET['q'];

// 2. Superglobal into an attribute. sanitize_text_field() does NOT save this:
//    it leaves the quote characters alone, so `" autofocus onfocus=alert(1) x="`
//    still breaks out.
$nonce = sanitize_text_field( wp_unslash( $_POST['nonce'] ) );
?>
<input type="hidden" name="nonce" value="<?php echo $nonce ?>" />

<?php
// 3. Server variable into an attribute.
?>
<form action="<?php echo $_SERVER['REQUEST_URI']; ?>" method="post">

<?php
// 4. The WordPress-specific trap: no URL argument means "use REQUEST_URI".
$query_string = remove_query_arg( array( 'filter', 'paged' ) );
?>
<a href="<?php echo add_query_arg( 'filter', 'unread', $query_string ); ?>">Unread</a>

<?php
// 5. Same value, emitted through printf - invisible to any echo-anchored grep.
$activation_url = get_home_url( '', add_query_arg( array( 'section' => 'settings' ) ) );
?>
<a href="<?php printf( '%s', $activation_url ); ?>"><?php printf( '%s', $activation_url ); ?></a>

<script>
  // 6. JavaScript context. HTML escaping is the wrong tool here.
  var target = "item_<?php echo $_GET['image_id']; ?>";
</script>

<?php
// 7. Admin notice reflection.
add_action( 'admin_notices', function () {
    if ( isset( $_GET['message'] ) ) {
        echo '<div class="notice notice-error"><p>' . $_GET['message'] . '</p></div>';
    }
} );
```

## Secure pattern

```php
<?php
// 1. Text node -> esc_html().
echo esc_html( $_GET['q'] );

// 2. Attribute -> esc_attr(), applied at the echo, not at the assignment.
$nonce = sanitize_text_field( wp_unslash( $_POST['nonce'] ) );
?>
<input type="hidden" name="nonce" value="<?php echo esc_attr( $nonce ); ?>" />

<?php
// 3. A form that posts to itself does not need REQUEST_URI at all. Name the
//    destination explicitly; if a raw URL really is required, esc_url() it.
?>
<form action="<?php echo esc_url( admin_url( 'admin.php?page=my-plugin' ) ); ?>" method="post">

<?php
// 4. Pass an explicit base URL so nothing derives from REQUEST_URI, and escape
//    the result for the href context.
$base = admin_url( 'admin.php?page=my-plugin' );
?>
<a href="<?php echo esc_url( add_query_arg( 'filter', 'unread', $base ) ); ?>">Unread</a>

<?php
// 5. printf: escape per placeholder, and note the two placeholders need
//    DIFFERENT escapers because they land in different contexts.
$activation_url = admin_url( 'admin.php?page=my-plugin&section=settings' );
printf(
    '<a href="%1$s">%2$s</a>',
    esc_url( $activation_url ),
    esc_html( $activation_url )
);
?>

<script>
  // 6a. Numeric id -> cast. Cheapest and strongest.
  var target = "item_<?php echo absint( $_GET['image_id'] ); ?>";

  // 6b. Arbitrary string inside a quoted JS literal -> esc_js().
  var label = '<?php echo esc_js( $label ); ?>';

  // 6c. Best for structured data: emit JSON and do not supply the quotes.
  var config = <?php echo wp_json_encode( $config ); ?>;
</script>

<?php
// 7. Admin notice: never reflect free text. Map a key to a fixed message.
add_action( 'admin_notices', function () {
    $codes = array(
        'saved'  => __( 'Settings saved.', 'my-plugin' ),
        'failed' => __( 'Could not save settings.', 'my-plugin' ),
    );
    $key = isset( $_GET['message'] ) ? sanitize_key( wp_unslash( $_GET['message'] ) ) : '';
    if ( isset( $codes[ $key ] ) ) {
        printf(
            '<div class="notice notice-error"><p>%s</p></div>',
            esc_html( $codes[ $key ] )
        );
    }
} );

// If the message genuinely must carry HTML, allow-list it and remember that
// wp_kses_post() output is safe as a TEXT NODE only - never drop it into an
// attribute without esc_attr().
echo '<div class="notice">' . wp_kses_post( $rich_message ) . '</div>';

// Textarea bodies need their own escaper.
?>
<textarea name="bio"><?php echo esc_textarea( $bio ); ?></textarea>
```

### Escaper selection table

| Where the value lands | Use | Do not use |
| --- | --- | --- |
| Text between tags (`<p>HERE</p>`) | `esc_html()` | - |
| Any attribute value (`class`, `value`, `data-*`, `title`, `alt`) | `esc_attr()` | `esc_html()` (leaves quotes usable in some encodings and is not the documented control) |
| `href`, `src`, `action`, `formaction`, `poster` | `esc_url()` | `esc_attr()` alone - it does not strip `javascript:` |
| Storing a URL in the DB / passing to an HTTP client | `esc_url_raw()` | never as an output escaper |
| Inside a quoted JavaScript string literal | `esc_js()` | `esc_html()`, `esc_attr()` |
| A whole JavaScript value | `wp_json_encode()` (emit without surrounding quotes) | string concatenation |
| Inside `<textarea>` | `esc_textarea()` | `esc_html()` (mangles entities on round-trip) |
| XML / RSS node | `esc_xml()` | - |
| HTML that must survive (rich text) | `wp_kses_post()` / `wp_kses()` | `esc_html()` (destroys the markup) |
| A numeric id | `absint()` / `(int)` | anything else - a cast is stronger than an escaper |
| Inline CSS value | `esc_attr()` plus a strict allow-list | escaping alone; CSS `expression()`/`url()` need validation |

## Real-world case studies

### The `add_query_arg()` default (CVE-2024-9208)

`https://plugins.trac.wordpress.org/browser/enable-accessibility/tags/1.4.1/includes/accessibility-attachments-alt.php#L62`

```php
<?php $query_string = remove_query_arg( array( 'oc-filter', 'paged' ) ); ?>          // line 62
<a href="<?php echo esc_attr( add_query_arg( 'oc-filter', "all", $query_string ) ); ?>"   // line 64
<a href="<?php echo add_query_arg( 'oc-filter', "to-fix", $query_string ); ?>"            // line 70
```

`remove_query_arg()` at line 62 is called with a single argument. With no `$query`
supplied it falls back to `$_SERVER['REQUEST_URI']`, so `$query_string` is the current
request URI with two parameters stripped - fully attacker controlled. Line 64 escapes
it. Line 70, eight lines later and inside the same `<ul>`, does not. Lines 146, 152
and 155 repeat the unescaped form inside a pagination loop.

This is the most instructive snippet in the class for two reasons. First, it shows the
WordPress-specific trap: a function whose name says "build a link" silently sources
attacker input. Second, it destroys the heuristic "this file uses `esc_attr`, so the
author knew about escaping". Escaping is per-output-site. A scanner must decide per
line, and a reviewing agent must not discount a hit because neighbouring lines are
clean.

### Sanitising is not escaping (CVE-2024-12466)

`https://plugins.trac.wordpress.org/browser/proofreading/tags/1.2.1.1/admin/partials/proofreading-admin-display.php#L103`

```php
$nonce = sanitize_text_field( wp_unslash( $_POST['nonce'] ) );   // line 50
...
<input type="hidden" name="nonce" value="<?php echo $nonce ?>" />   // line 103
```

`_sanitize_text_fields()` handles `<` (via `wp_pre_kses_less_than()` and
`wp_strip_all_tags()`), removes invalid UTF-8 and percent-encoded octets, and trims.
It never touches `"` or `'`. A payload of `" autofocus onfocus=alert(1) x="` contains
no `<` at all, passes through untouched, and breaks out of the `value` attribute at
line 103. The fix is `esc_attr( $nonce )` at line 103 - the input-side sanitiser can
stay, but it was never the control that mattered.

### Wrong context, right-looking code (CVE-2025-2269)

`https://plugins.trac.wordpress.org/browser/photo-gallery/tags/1.8.34/admin/views/Editimage.php#L39`

```php
$image_id = WDWLibrary::get('image_id', '0');                                              // line 28
...
var file_type = window.parent.document.getElementById("input_filetype_<?php echo $image_id; ?>").value;   // line 39
```

The value lands inside a double-quoted JavaScript string, inside a `<script>` block.
Reaching for `esc_html()` here - the reflex answer - would be wrong: it does not
escape backslashes and it does not stop `</script>` from terminating the block early.
The correct fixes are `absint()` (the value is an id), `esc_js()` (for a genuinely
free-form JS string literal), or `wp_json_encode()` emitting the quotes itself. The
same parameter is reused at lines 40 and 45.

### printf hides the sink (CVE-2024-11375)

`https://plugins.trac.wordpress.org/browser/wc1c-main/tags/0.23.0/views/promo/activation.php#L25`

```php
$activation_url = get_home_url('', add_query_arg(['section' => 'settings', 'do_settings' => 'activation']));   // line 3
...
<a href="<?php printf('%s', $activation_url); ?>"><?php printf('%s', $activation_url); ?></a>                  // line 25
```

Same `add_query_arg`-defaults-to-`REQUEST_URI` root cause as CVE-2024-9208, but the
output keyword is `printf`, so every `echo`-anchored rule misses it. Line 25 also
shows one value needing two different escapers: `esc_url()` for the `href` and
`esc_html()` for the visible link text.

### The minimal attribute case (CVE-2025-2165, CVE-2025-2481)

`https://plugins.trac.wordpress.org/browser/sh-email-alert/tags/1.0/manage.php#L156`

```php
<input type="hidden" name="mid" value="<?php echo $_GET['mid']; ?>">
```

`https://plugins.trac.wordpress.org/browser/mediaview/tags/1.1.2/inc/forms/addMedia.inc.php#L48`

```php
<input type="hidden" name="key" value="<?php echo $_GET['id']; ?>"/>                              // line 48
<a href="?page=mediaview&view=viewshortcode&id=<?php echo $_GET['id']; ?>" class="mv-cancel">     // line 50
```

The second file is worth reading twice: one parameter, two output sites, two
different escapers required. Line 48 needs `esc_attr()`; line 50 needs the whole URL
built with `add_query_arg()` against an explicit base and then run through
`esc_url()`. Fixing only the obvious one leaves the bug.

### The REQUEST_URI-into-attribute family (CVE-2023-0937, CVE-2024-12595, CVE-2024-10815)

Three independent records, disclosed roughly two years apart, with word-for-word
identical descriptions: the code "does not escape the `$_SERVER['REQUEST_URI']`
parameter before outputting it back in an attribute". No trac line anchors were
published for these, so no source was read - they are recorded as evidence that the
pattern recurs independently rather than as line-level case studies. NVD qualifies
them "in old web browsers" because current browsers percent-encode the path portion
of `REQUEST_URI`; that narrows the severity but does not remove the bug, since the
query string is not encoded and `PHP_SELF` is not encoded at all.

## Detection guidance

### The controlling idea: anchor on the token after the output keyword

`echo esc_html( $x );` and `echo $x;` differ in exactly one character position - the
one right after `echo` and its whitespace. If it is `$`, no function wrapped the
value. If it is an identifier, *something* wrapped it and the question changes from
"is this escaped?" to "was that the right escaper for this context?".

That reframing is what makes this class scannable. On a 256k-LOC corpus of five
large, actively maintained, heavily audited plugins - a corpus where essentially
every hit should be a false positive:

| Pattern | Hits |
| --- | ---: |
| naive `echo` anywhere on a line with a `$` | **3489** |
| `echo`/`print` immediately followed by `$var` (XSSR-003) | **203** |
| `echo`/`print` immediately followed by a superglobal (XSSR-001) | **0** |
| `echo`/`print` immediately followed by `add_query_arg`/`remove_query_arg` (XSSR-004) | **0** |
| `esc_url( add_query_arg( ... ) )` in the same corpus | 48 |

A 94% noise reduction, with no loss on the fixture true positives, and it needs no
lookahead - which matters because ripgrep's Rust regex engine has none. Crucially,
the escaping allow-list never has to appear inside the regex; it only appears in the
second, human/agent stage where the wrapper that *was* found is judged against the
output context.

### How a reviewing agent should triage the residue

For each XSSR-003 / XSSR-008 / XSSR-009 hit, in this order:

1. **Walk back to the assignment.** Literal, `(int)`/`absint()`, or an `esc_*`/
   `wp_kses*` call in the assignment - drop it. The handbook-sanctioned `_escaped`,
   `_safe`, `_clean` suffixes are a legitimate marker of the pre-escaped case.
2. **Trace to a source.** If the chain reaches `$_GET`/`$_POST`/`$_REQUEST`/
   `$_SERVER`/`$_COOKIE`, or `add_query_arg`/`remove_query_arg` with no URL argument,
   keep it. If it reaches a database read, this is WP-XSS-S, not this class.
3. **Identify the output context** (text node / attribute / href / JS / textarea /
   CSS). This determines which escaper the fix needs and is not derivable from the
   regex hit alone.
4. **Check for a suppression comment.** `// phpcs:ignore WordPress.Security.EscapeOutput`
   means the author considered it. Not proof of safety, but strong evidence to weight
   the hit down; its absence in a codebase that uses such annotations elsewhere is
   evidence to weight it up.

### What these regexes MISS - read code manually when you see these

- **Escaping through a project wrapper** (`$this->e( $x )`, `Plugin::out( $x )`,
  `render( $tpl, $vars )`). Reads as unescaped. Grep the codebase for a helper that
  wraps `esc_*` and add it to the triage allow-list before reviewing hits.
- **Escaping applied on an earlier line.** The main source of XSSR-003's residue.
  Regex cannot do dataflow.
- **Heredoc and nowdoc bodies.** `{$var}` interpolation inside `<<<HTML ... HTML;`
  is a real sink and is matched by none of these rules. Grep `<<<` separately.
- **Non-PHP files.** At least one CVE in this family has its trac line anchor inside a
  `.js` file. A PHP-only sweep misses payloads reflected by client-side templating,
  `document.write`, `.innerHTML =`, and `wp_add_inline_script()` payload building.
- **`wp_localize_script()` / `wp_add_inline_script()`** where request data is folded
  into the emitted JS object.
- **`wp_kses_post()` output placed in an attribute.** Syntactically escaped,
  semantically the wrong context - a broken-out attribute is still XSS.
- **Second-order reflection** where the request value is written into a transient or
  option in one request and echoed in the next. That is WP-XSS-S by mechanism even
  though it feels reflected.
- **Escaping that is present but wrong for the context.** `esc_attr()` around a value
  in a `<script>` string literal will never appear in any "missing escape" scan. Only
  a context-aware read finds it.

## Audit checklist

- [ ] Run XSSR-001, XSSR-002, XSSR-004 and XSSR-008 first. They are near-zero-noise
      on maintained code; treat every hit as a finding until disproved.
- [ ] Run XSSR-003 and triage with the four-step walk-back above. Expect roughly
      0.8 hits per KLOC; budget accordingly.
- [ ] Grep for a project-local output helper that wraps `esc_*` and add it to the
      triage allow-list before reading any XSSR-003 results.
- [ ] Grep `add_query_arg\s*\(` and `remove_query_arg\s*\(` and check the argument
      count of every call. One or two arguments to `add_query_arg`, or one to
      `remove_query_arg`, means the URL came from `$_SERVER['REQUEST_URI']`.
- [ ] Grep `\$_SERVER\s*\[` and inventory every use of `REQUEST_URI`, `PHP_SELF`,
      `QUERY_STRING`, `HTTP_REFERER`, `HTTP_HOST`. Follow each to an output site.
- [ ] Grep `<<<` for heredocs and read every interpolated variable in the body.
- [ ] Grep `printf|vprintf|sprintf` and check each `%s` position for an unescaped
      argument; `%d`/`%u` positions are safe.
- [ ] Grep the `admin_notices`, `network_admin_notices` and `all_admin_notices`
      hooks and confirm no notice body or link is built from request data.
- [ ] For each confirmed sink, name the output context before naming the fix, then
      check the fix against the escaper selection table above.
- [ ] Re-check existing `esc_*` calls for *wrong-context* escaping: `esc_attr()` or
      `esc_html()` inside `<script>` blocks, `esc_attr()` alone on `href`/`src`,
      `esc_html()` inside `<textarea>`.
- [ ] Sweep `.js` and template files for `innerHTML`, `document.write`, and jQuery
      `.html()` fed from `location.search` / `location.hash`.
- [ ] Confirm every reported fix escapes at the point of emission, not at assignment
      - the handbook rule is "escape when you echo, not before".
