---
class_id: WP-XSS-DOM
title: DOM-based XSS in plugin and theme JavaScript
cwe: [CWE-79, CWE-83]
owasp: A03:2021-Injection
severity_typical: medium
auth_required_typical: contributor+
prevalence_rank: 21
detection:
  - id: XSSD-001
    description: >-
      A jQuery HTML-parsing sink (.html/.append/.prepend/.after/.before/
      .replaceWith/.wrap*) is fed a string built by concatenation or a template
      literal with an interpolation.
    regex: '\.\s*(html|append|prepend|after|before|replaceWith|wrapInner|wrapAll)\s*\(\s*([''"][^''"]*[''"]\s*\+|`[^`]*\$\{)'
    confidence: high
    false_positive_notes: >-
      49 hits per 1.07M lines of non-minified JavaScript (0.05/KLOC) across seven
      mature plugins. Nearly every hit is a real HTML string being assembled from
      runtime values; the only benign case is one where every interpolated value is
      provably plugin-authored (a translated constant, a loop index, a generated
      class name). Because these methods parse their argument as HTML, the fix is
      never "escape the string" - it is to build a node and set .text()/.textContent,
      or to escape each interpolated value with wp.escapeHtml()/_.escape() before
      concatenation.
  - id: XSSD-002
    description: >-
      The same jQuery HTML-parsing sinks fed a bare variable or property, where the
      value's provenance is not visible on the line.
    regex: '\.\s*(html|append|prepend|after|before|replaceWith)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$.\[\]''"]*\s*\)'
    confidence: medium
    false_positive_notes: >-
      657 hits per 1.07M JS LOC (0.61/KLOC) - the noisiest rule here, because
      `.append( $node )` with an already-constructed jQuery object or DOM node is
      both extremely common and completely safe. Triage by asking what the argument
      IS: a jQuery object or an Element is safe; a string is a sink. jQuery only
      parses a *string* as HTML, and only when it starts with `<`. Note that
      `.append( someString )` where someString came from `.data()`, `JSON.parse`,
      an AJAX response, or a template literal assigned on an earlier line is a real
      finding that this rule is the only one to catch.
  - id: XSSD-003
    description: >-
      Native HTML-parsing sinks - innerHTML/outerHTML assignment,
      insertAdjacentHTML(), document.write().
    regex: '\.(innerHTML|outerHTML)\s*=[^=]|\.insertAdjacentHTML\s*\(|\bdocument\.write(ln)?\s*\('
    confidence: medium
    false_positive_notes: >-
      145 hits per 1.07M JS LOC (0.14/KLOC). The dominant benign shape is
      `el.innerHTML = ''` (a clear) and `el.innerHTML = '<static markup>'`. The
      `[^=]` guard stops the rule matching `===` and `!==` comparisons on a property
      named innerHTML, which is what a naive `innerHTML\s*=` matches. Read the
      right-hand side: a literal is fine, anything else is a sink. Remember that
      innerHTML does not execute a plain `<script>` tag but does fire
      `<img onerror=...>`, `<svg onload=...>` and friends, so "no script tag" is not
      a defence.
  - id: XSSD-004
    description: >-
      DOM sources - the browser-side equivalents of a superglobal. Fires on
      location.search/hash/href/pathname, document.URL/documentURI/referrer and
      URLSearchParams.
    regex: '(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|URLSearchParams)'
    confidence: low
    false_positive_notes: >-
      355 hits per 1.07M JS LOC (0.33/KLOC). A presence check, not a vulnerability
      check - these are read legitimately for routing, analytics, canonical links,
      "current page" highlighting and cache keys. Its value is as an inventory: list
      every site that touches a DOM source, then join that list against the sink
      rules above. A file that contains both a XSSD-004 hit and a XSSD-001/003 hit
      is where you start reading. Note that `location.hash` is never sent to the
      server, so a hash-sourced payload leaves no trace in access logs and is
      invisible to a WAF.
  - id: XSSD-005
    description: >-
      A window "message" listener is registered. postMessage handlers receive data
      from ANY origin unless the handler checks event.origin itself.
    regex: 'addEventListener\s*\(\s*[''"]message[''"]'
    confidence: low
    false_positive_notes: >-
      32 hits per 1.07M JS LOC (0.03/KLOC). Cheap enough to read every one. The
      rule deliberately cannot tell a safe handler from an unsafe one, because the
      check that makes it safe (`if (event.origin !== expected) return;`) is usually
      on a different line from the registration; on the fixture the one-line safe
      form is reported as a hit and that is expected. Triage is a three-line read of
      the callback body: (1) is event.origin compared against an allow-list?
      (2) is event.source compared against the frame you created? (3) does the
      payload reach a sink? Missing (1) plus present (3) is a finding regardless of
      what the payload looks like.
  - id: XSSD-006
    description: >-
      A navigation sink - window.open(), location.href/assign/replace - is given a
      variable rather than a literal. A `javascript:` URL here is script execution,
      not a redirect.
    regex: '(window\.open|location\.href|location\.assign|location\.replace)\s*(=|\()\s*[A-Za-z_$][A-Za-z0-9_$.]*\s*[\[;,)]'
    confidence: medium
    false_positive_notes: >-
      111 hits per 1.07M JS LOC (0.10/KLOC). Benign when the variable was built
      from a same-origin base (`new URL(path, location.origin)`) or came from a
      server-rendered admin_url(). A finding when the value traces to a DOM source,
      a data attribute, a postMessage payload, or an AJAX response. The control is
      a scheme allow-list - `/^https?:\/\//` or a same-origin URL comparison -
      not escaping; there is no escaper that makes `javascript:` safe.
  - id: XSSD-007
    description: >-
      Triple-brace interpolation in a wp.template / Underscore template. In
      WordPress's template settings `{{{ }}}` is the UNESCAPED interpolation and
      `{{ }}` is the escaped one, so every triple brace is a raw HTML write.
    regex: '\{\{\{\s*[A-Za-z_$]'
    confidence: medium
    false_positive_notes: >-
      385 hits per 1.47M lines of PHP (0.26/KLOC) - templates live inside PHP files
      as often as in .html ones, so run this over both. Every hit is genuinely an
      unescaped write; whether it is a vulnerability depends entirely on whether the
      interpolated member is user-controlled. Values that are plugin-generated URLs,
      enum-like status strings or pre-escaped `*_html` members are fine. Values that
      trace to a display name, a title, a caption or any editable setting are not.
      Beware the near-miss: `{{{ }}}` and `{{ }}` differ by one character and are
      routinely mixed within a single template - see CVE-2024-2123.
  - id: XSSD-008
    description: >-
      Server-to-client data channel built from PHP variables -
      wp_add_inline_script() or wp_localize_script() whose payload is not a literal.
    regex: '\b(wp_add_inline_script|wp_localize_script)\s*\([^;]*("[^"]*\$|\.\s*\$[A-Za-z_]|=>\s*\$[A-Za-z_]|,\s*\$[A-Za-z_])'
    confidence: medium
    false_positive_notes: >-
      24 hits per 1.47M LOC of PHP (0.02/KLOC). Neither function is itself an XSS
      sink - wp_localize_script() JSON-encodes with JSON_HEX_TAG, which protects the
      surrounding script block - so a hit is not a finding on its own. It is a
      handoff: the value crosses into JavaScript here, and the question moves to
      what the JavaScript does with it. Two things make this worth flagging anyway.
      First, WP_Scripts::localize() runs html_entity_decode( (string) $value,
      ENT_QUOTES, 'UTF-8' ) over every SCALAR value, so any esc_html()/esc_attr()
      applied first is silently undone (non-scalar members are skipped by that loop
      and pass through untouched). Second, wp_add_inline_script() does NOT
      JSON-encode anything - it emits your string verbatim into the script block, so
      a `</script>` in an interpolated value ends the block.
  - id: XSSD-009
    description: >-
      A value is read back out of an HTML data attribute with .data() or
      .attr('data-...') - the standard channel by which contributor-stored settings
      reach page-builder JavaScript.
    regex: '\.\s*(data|attr)\s*\(\s*[''"][A-Za-z0-9_-]+[''"]\s*\)'
    confidence: low
    false_positive_notes: >-
      811 hits per 1.07M JS LOC (0.76/KLOC), the highest rate in this file, because
      reading a data attribute is ordinary and usually harmless. It is included
      because in the WordPress ecosystem this is the dominant STORED DOM-XSS channel
      - the plugin escapes the value correctly with esc_attr() on the way into the
      attribute, and the escaping is irrelevant once the browser hands the decoded
      string back to jQuery. Treat it as the second half of a join: a file with both
      a XSSD-009 hit and a XSSD-001/002/003 hit deserves a read. Note that .data()
      auto-parses JSON, so a data attribute can deliver a whole object graph, and
      that base64 or JSON layering (CVE-2025-8451) hides markup from every
      attribute-level review.
fix_apis:
  - textContent
  - Node.append() / Element.append() with a string or Text node
  - jQuery .text()
  - document.createElement() + setAttribute()
  - wp.escapeHtml()
  - _.escape()
  - wp.sanitize.stripTags()
  - "{{ }}"
  - wp_json_encode()
  - wp_add_inline_script()
  - esc_url() / sanitize_url()
  - URL / URLSearchParams with an origin comparison
  - event.origin allow-list check
examples:
  - cve: CVE-2026-18328
    year: 2026
    severity: 7.2
    auth: unauthenticated
    summary: A query parameter read with URLSearchParams was returned as a payment error message and rendered with jQuery .html() after string concatenation.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-18328
    code_ref: https://plugins.trac.wordpress.org/browser/forminator/tags/1.56.0/assets/js/front/front.stripe.js#L1539
    root_cause: A DOM source (window.location.search) reached an HTML-parsing sink ($.html) with no escaping and no server round-trip, so no server-side control could have stopped it.
  - cve: CVE-2024-1038
    year: 2024
    severity: 6.1
    auth: unauthenticated
    summary: The current page URL was concatenated into a meta refresh element and injected into the parent document head with jQuery .append().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-1038
    code_ref: https://plugins.trac.wordpress.org/browser/beaver-builder-lite-version/tags/2.7.4.2/js/fl-builder.js#L1613
    root_cause: window.parent.location.href was string-concatenated into a quoted HTML attribute and passed to a jQuery HTML-parsing sink; the only guard was a substring check on the hostname.
  - cve: CVE-2026-2433
    year: 2026
    severity: 6.1
    auth: unauthenticated
    summary: A postMessage listener accepted messages from any origin and passed the payload URL to window.open() and to an iframe navigation helper.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-2433
    code_ref: https://plugins.trac.wordpress.org/browser/wp-rss-aggregator/tags/5.0.10/core/js/admin-shell.js#L58
    root_cause: >-
      No event.origin check on the message handler and no scheme allow-list on the
      URL before navigation, so any page could hand the admin screen a
      "javascript:" URL.
  - cve: CVE-2024-2123
    year: 2024
    severity: 6.1
    auth: unauthenticated
    summary: A member-directory wp.template used triple-brace interpolation for the display name inside a title attribute and for the card body.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-2123
    code_ref: https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.3/templates/members-grid.php#L44
    root_cause: '{{{ }}} is the unescaped interpolation in wp.template; the escaped form {{ }} differs by one character and was used elsewhere in the same file.'
  - cve: CVE-2025-8451
    year: 2025
    severity: 6.4
    auth: contributor+
    summary: Gallery item markup was base64-encoded into a data attribute, then decoded client-side and handed to jQuery .append().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-8451
    code_ref: https://plugins.trac.wordpress.org/browser/essential-addons-for-elementor-lite/tags/6.2.2/assets/front-end/js/view/filterable-gallery.js
    root_cause: esc_attr() protected the attribute but the base64 layer carried raw markup through it, and JSON.parse(atob(...)) restored it before an HTML-parsing sink.
  - cve: CVE-2025-13535
    year: 2026
    severity: 6.4
    auth: contributor+
    summary: A countdown widget read a JSON data attribute and interpolated two of its members into a template literal passed to jQuery .after(), assigning a third to location.href.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-13535
    code_ref: https://plugins.trac.wordpress.org/browser/king-addons/tags/51.1.38/includes/widgets/Countdown/script.js#L119
    root_cause: Server-side filtering (wp_kses plus a hand-rolled regex blacklist) was applied to one member and none to the others, and none of it survives a client-side re-parse as HTML.
  - cve: CVE-2024-4619
    year: 2024
    severity: 5.4
    auth: contributor+
    summary: An editor-preview template concatenated a widget setting into a class attribute of an img tag while escaping the adjacent src value.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-4619
    code_ref: https://plugins.trac.wordpress.org/browser/elementor/tags/3.21.5/includes/widgets/image-box.php#L696
    root_cause: _.escape() was applied to one interpolated value and omitted on the next one in the same concatenation, inside a JS template shipped in a PHP file.
  - cve: CVE-2025-5096
    year: 2025
    severity: 5.4
    auth: contributor+
    summary: Table caption, title and footer settings were emitted as data attributes and rendered by the bundled DataTables library with jQuery .html().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-5096
    code_ref: https://plugins.trac.wordpress.org/browser/tablepress/tags/3.1.2/js/jquery.datatables.min.js
    root_cause: The HTML-parsing sink lived inside a bundled third-party library, so no review of the plugin's own JavaScript would have found it.
  - cve: CVE-2024-13901
    year: 2025
    severity: 4.8
    auth: admin+
    summary: A live-preview builder read the stored counter content out of an editor field and rendered it with jQuery .html().
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-13901
    code_ref: https://plugins.trac.wordpress.org/browser/counter-box/tags/2.0.6/admin/assets/js/5.builder.js#L35
    root_cause: A stored setting was passed to an HTML-parsing sink so that placeholder tokens could be replaced with markup; the replacement design made escaping look impossible.
---

## What it is

DOM-based XSS is XSS where the whole flow - source, transformation and sink -
happens in the browser. The server never sees the payload in the response body it
generated; the JavaScript takes a value out of the page or the URL and writes it
back into the DOM through an API that parses HTML.

Two consequences follow immediately and shape everything below:

1. **No server-side control can fix it.** `esc_html()` cannot help with a value
   the server never rendered. In the `location.hash` variant the payload is never
   even transmitted to the server, so it appears in no access log and no WAF rule
   can see it.
2. **The escaping that is present is usually correct - for the wrong layer.** The
   dominant WordPress shape is a value that was correctly `esc_attr()`'d into a
   `data-*` attribute, then read back with `.data()` and handed to `.html()`.
   The attribute encoding did its job. It provided exactly zero protection for the
   second, client-side parse.

In `kb/taxonomy.json` this class carries only 6 Wordfence records (0.11%), which
is why its `prevalence_rank` is 21. **That number is an artefact, not a
measurement.** Wordfence buckets most of these as "Stored XSS" or "Reflected XSS"
regardless of where the sink lives; a keyword sweep of the NVD corpus for
"DOM-Based" / "DOM-based" phrasing returns 98 WordPress records over the same
window, and 25 of those carry a `trac` reference. Treat the rank as a floor. In
practice, every page-builder addon pack in the ecosystem has shipped at least one
of these.

## Why it happens in WordPress

### Data attributes are the ecosystem's IPC channel

WordPress has no first-class way to hand per-instance settings from a PHP render
callback to the JavaScript that animates it. The universal workaround is a
`data-*` attribute, usually JSON-encoded, sometimes base64-on-top-of-JSON. Every
page builder does this: Elementor, Divi, Beaver Builder, Essential Addons, King
Addons, Kadence, FooBox, TablePress.

That channel is exactly where a Contributor's widget settings live. The PHP side
looks impeccable - `esc_attr( wp_json_encode( $settings ) )` - and it is correct
for the attribute. The JS side then does `$el.data('settings')`, gets a decoded
object back, and interpolates a member into an HTML string. The escaping was
consumed by the HTML parser on the way in and is simply not present any more.

This is why so many CVE descriptions in this family literally say **"via HTML
data attributes"**.

### `wp.template` makes the unsafe form one character shorter than the safe one

WordPress ships Underscore templating configured (in `wp-includes/js/wp-util.js`)
with these delimiters:

| Delimiter | Meaning |
| --- | --- |
| `{{{ value }}}` | **interpolate - raw, unescaped** |
| `{{ value }}` | **escape** |
| `<# code #>` | evaluate |

So the dangerous form is `{{{ }}}` and the safe form is `{{ }}`. They are visually
near-identical, they appear side by side in the same template, and the raw form is
often *required* for the adjacent member (a pre-rendered avatar `<img>`, say)
while being wrong for the one next to it (a display name). CVE-2024-2123 is
exactly this: `{{{user.cover_photo}}}` legitimately raw on one line,
`title="{{{user.display_name}}}"` wrongly raw on the next.

### jQuery's HTML-parsing methods are the default idiom

`.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`, `.replaceWith()`
and `$( someString )` all parse their argument as HTML when it is a string
containing `<`. In a codebase where jQuery is loaded on every admin screen by
core, "insert this markup" is the path of least resistance, and `.text()` requires
restructuring the code to build nodes.

Two related traps:

- **`$( str )` is a selector *or* an HTML parser depending on the string.**
  `$( userInput ).hide()` looks like a selector call and is an HTML parse when
  `userInput` starts with `<`.
- **`innerHTML` does not run a bare `<script>` tag, which is widely
  misremembered as "innerHTML is safe".** `<img src=x onerror=alert(1)>` and
  `<svg onload=alert(1)>` both fire, and both are what an attacker uses.

### `wp_localize_script()` silently entity-decodes your escaping

This is the most surprising WordPress-specific fact in the class. Core's
`WP_Scripts::localize()` does this before encoding:

```php
} elseif ( is_array( $l10n ) ) {
    foreach ( $l10n as $key => $value ) {
        if ( ! is_scalar( $value ) ) {
            continue;
        }
        $l10n[ $key ] = html_entity_decode( (string) $value, ENT_QUOTES, 'UTF-8' );
    }
}
$script = "var $object_name = " . wp_json_encode( $l10n, JSON_HEX_TAG | JSON_UNESCAPED_SLASHES ) . ';';
```

Three things to take from it:

- Any `esc_html()` / `esc_attr()` you applied before calling
  `wp_localize_script()` is **undone**. Pre-escaping is not just useless here, it
  is actively misleading to a reviewer.
- `JSON_HEX_TAG` rewrites `<` and `>` as the JSON escapes `\u003C` and
  `\u003E`, which is what stops a value from terminating the `<script>`
  block. The *script block* is therefore safe. But `\u003C` is only how JSON
  spells `<`: the **value** the JavaScript engine hands your code is the raw
  decoded string, markup and all, and any DOM sink that receives it is exposed.
- Non-scalar members (nested arrays, objects) hit the `continue` and skip the
  decode entirely - so a nested structure behaves differently from a flat one.

`wp_add_inline_script()` has the opposite problem: it does **no** encoding at all.
Whatever string you pass is emitted verbatim into the script block, so an
interpolated `</script>` closes it. `wp_json_encode()` on the payload is the
control, and `wp_add_inline_script( $h, 'var x = ' . wp_json_encode( $v ) . ';', 'before' )`
is the idiom.

### The sink is often in code the plugin author did not write

TablePress ships DataTables; Essential Addons ships Isotope and Magnific Popup;
half the ecosystem ships Slick, Swiper, lightGallery or typed.js. Those libraries
render captions, titles and labels with `.html()` because that is their documented
contract. CVE-2025-5096 and CVE-2025-13535 are both "the plugin handed a
contributor-settable string to a library that HTML-parses it". Reviewing only the
plugin's own `.js` files will not find these.

## Vulnerable pattern

```php
<?php
// SERVER SIDE ------------------------------------------------------------

// 1. Attribute encoding is correct here and irrelevant to what happens next.
printf(
    '<div class="my-countdown" data-actions=\'%s\'></div>',
    esc_attr( wp_json_encode( array(
        'message'      => $settings['display_message_text'],   // contributor text
        'hide-element' => $settings['hide_element_selector'],
        'redirect'     => $settings['redirect_url'],
    ) ) )
);

// 2. Base64 hides the payload from every attribute-level review.
echo '<div class="gallery" data-gallery-items="'
   . esc_attr( base64_encode( wp_json_encode( $item_markup_strings ) ) )
   . '"></div>';

// 3. Pre-escaping here is UNDONE by WP_Scripts::localize().
wp_localize_script( 'my-js', 'MyCfg', array(
    'label' => esc_html( get_post_meta( $id, 'label', true ) ),
) );

// 4. wp_add_inline_script() does no encoding whatsoever.
wp_add_inline_script( 'my-js', "window.cfg = { msg: '" . $message . "' };" );

// 5. A wp.template shipped inside a PHP file. {{{ }}} is the RAW form.
?>
<script type="text/html" id="tmpl-member-card">
  <a href="{{{user.profile_url}}}" title="{{{user.display_name}}}">
    {{{user.avatar}}}
  </a>
  <div class="name">{{{user.display_name_html}}}</div>
</script>

<?php
// 6. A JS template emitted from a PHP content_template(), escaping one value
//    and not the next one in the same concatenation.
?>
<script type="text/template">
  var imageHtml = '<img src="' + _.escape( image_url )
                + '" class="anim-' + settings.hover_animation + '" />';
</script>
```

```javascript
// CLIENT SIDE ------------------------------------------------------------

// 7. DOM source straight into a jQuery HTML-parsing sink.
var params  = new URLSearchParams( window.location.search );
var message = params.get( 'error_description' ) || '';
$form.find( '.response' ).html( '<p>' + message + '</p>' );

// 8. The current URL concatenated into a quoted attribute, then parsed as HTML.
var href = window.parent.location.href;
if ( href.includes( 'playground.wordpress.net' ) ) {              // substring check, not an origin check
    var meta = '<meta http-equiv="refresh" content="0; URL=\'' + href + '\'" />';
    $( 'head', window.parent.document ).append( meta );
}

// 9. Data attribute -> template literal -> HTML-parsing sink.
var dataActions = $wrap.data( 'actions' );
$wrap.after( `<div class="msg">${ dataActions['message'] }</div>` );
$( dataActions['hide-element'] ).hide();     // $(str) parses as HTML when str starts with "<"
window.location.href = dataActions['redirect'];   // javascript: is script execution

// 10. base64 -> JSON -> markup strings -> .append()
var items = JSON.parse( atob( $gallery.data( 'gallery-items' ) ) );
for ( var i = 0; i < n; i++ ) { $gallery.append( items[ i ] ); }

// 11. Stored setting rendered through .html() so tokens can become markup.
var content = $( '#builder-content' ).val();
content = content.replace( '{counter}', '<span class="counter">' + start + '</span>' );
$( '#preview' ).html( content );

// 12. postMessage handler with no origin check, payload reaching a URL sink.
window.addEventListener( 'message', function ( event ) {
    var msg = event.data || {};
    if ( msg.type === 'openUrl' ) {
        window.open( msg.payload.url, msg.payload.target );
    }
} );

// 13. Native sinks.
el.innerHTML = '<span>' + userName + '</span>';
wrapper.insertAdjacentHTML( 'beforeend', '<button>' + label + '</button>' );
```

## Secure pattern

```php
<?php
// SERVER SIDE ------------------------------------------------------------

// 1. Escape for the attribute AND constrain each member for its eventual DOM
//    use. A selector is not free text; a URL needs a scheme allow-list.
$selector = sanitize_text_field( $settings['hide_element_selector'] );
$redirect = wp_http_validate_url( $settings['redirect_url'] ) ? sanitize_url( $settings['redirect_url'] ) : '';
printf(
    '<div class="my-countdown" data-actions="%s"></div>',
    esc_attr( wp_json_encode( array(
        'message'      => wp_kses_post( $settings['display_message_text'] ),
        'hide-element' => preg_match( '/^[A-Za-z0-9_.#-]+$/', $selector ) ? $selector : '',
        'redirect'     => $redirect,
    ) ) )
);

// 2. Do not ship markup through a data attribute at all. Ship DATA, and let the
//    client build nodes from it.
echo '<div class="gallery" data-gallery-items="'
   . esc_attr( wp_json_encode( $item_data ) )   // {id, title, url} - no HTML
   . '"></div>';

// 3. Do NOT pre-escape for wp_localize_script(): it entity-decodes scalars.
//    Sanitize instead, and escape in the JS at the point of DOM insertion.
wp_localize_script( 'my-js', 'MyCfg', array(
    'label' => sanitize_text_field( get_post_meta( $id, 'label', true ) ),
) );

// 4. wp_add_inline_script(): let wp_json_encode() supply the quoting.
wp_add_inline_script(
    'my-js',
    'window.cfg = ' . wp_json_encode( array( 'msg' => $message ) ) . ';',
    'before'
);

// 5. Use the ESCAPED delimiter. Reserve {{{ }}} for values you generated.
?>
<script type="text/html" id="tmpl-member-card">
  <a href="{{ user.profile_url }}" title="{{ user.display_name }}">
    {{{user.avatar}}}   <!-- deliberate: plugin-generated <img>, documented as such -->
  </a>
  <div class="name">{{ user.display_name }}</div>
</script>

<?php
// 6. Escape every interpolated value, not just the first one.
?>
<script type="text/template">
  var imageHtml = '<img src="' + _.escape( image_url )
                + '" class="anim-' + _.escape( settings.hover_animation ) + '" />';
</script>
```

```javascript
// CLIENT SIDE ------------------------------------------------------------

// 7. Text is text. .text() / textContent never parse HTML.
var params  = new URLSearchParams( window.location.search );
var message = params.get( 'error_description' ) || '';
$form.find( '.response' ).empty().append( $( '<p>' ).text( message ) );

// 8. Compare origins, do not substring-match hostnames; and never concatenate a
//    URL into markup.
var target = new URL( window.parent.location.href );
if ( target.origin === window.location.origin ) {
    window.parent.location.assign( target.toString() );
}

// 9. Build nodes; validate a URL's scheme before navigating.
var dataActions = $wrap.data( 'actions' ) || {};
$wrap.after( $( '<div>' ).addClass( 'msg' ).text( dataActions.message || '' ) );
if ( /^[A-Za-z0-9_.#-]+$/.test( dataActions['hide-element'] || '' ) ) {
    $( dataActions['hide-element'] ).hide();
}
if ( /^https?:\/\//i.test( dataActions.redirect || '' ) ) {
    window.location.assign( dataActions.redirect );
}

// 10. Ship data, build DOM.
var items = JSON.parse( $gallery.attr( 'data-gallery-items' ) || '[]' );
items.forEach( function ( item ) {
    var $a = $( '<a>' ).attr( 'href', item.url ).text( item.title );
    $gallery.append( $( '<div>' ).addClass( 'item' ).append( $a ) );
} );

// 11. Split the template so untrusted text is never part of the markup string.
var $preview = $( '#preview' ).empty();
content.split( '{counter}' ).forEach( function ( chunk, i ) {
    if ( i > 0 ) { $preview.append( $( '<span>' ).addClass( 'counter' ).text( start ) ); }
    $preview.append( document.createTextNode( chunk ) );
} );

// 12. Check the origin FIRST, and the source frame where you can.
window.addEventListener( 'message', function ( event ) {
    if ( event.origin !== window.location.origin ) { return; }
    if ( event.source !== myFrame.contentWindow ) { return; }
    var msg = event.data || {};
    if ( msg.type === 'openUrl' && /^https?:\/\//i.test( msg.payload.url ) ) {
        window.open( msg.payload.url, '_blank', 'noopener' );
    }
} );

// 13. Native equivalents.
el.textContent = userName;
var btn = document.createElement( 'button' );
btn.textContent = label;
wrapper.append( btn );

// 14. When markup genuinely must be assembled, escape each hole.
var html = '<span class="' + wp.escapeHtml( cls ) + '">' + wp.escapeHtml( txt ) + '</span>';
```

### Sink / source reference

| Sink | Parses HTML? | Safe alternative |
| --- | --- | --- |
| `.html( s )`, `.append( s )`, `.prepend( s )`, `.after( s )`, `.before( s )`, `.replaceWith( s )` | yes, when `s` is a string | `.text( s )`, or `.append( $('<tag>').text(s) )` |
| `$( s )` where `s` starts with `<` | yes | validate as a selector first, or `$( document ).find( s )` |
| `.innerHTML =`, `.outerHTML =`, `.insertAdjacentHTML()` | yes | `.textContent =`, `insertAdjacentText()` |
| `document.write()` / `writeln()` | yes | build nodes |
| `{{{ x }}}` in `wp.template` | yes | `{{ x }}` |
| `location.href =`, `.assign()`, `.replace()`, `window.open()`, `a.href =` | no, but `javascript:` executes | scheme allow-list `/^https?:\/\//i` |
| `eval()`, `new Function()`, `setTimeout('string')` | executes directly | never pass a string |
| `el.setAttribute( 'on*', v )`, `el.onclick =` | executes | `addEventListener` with a function |
| `.setAttribute( 'src'/'href', v )` | no, but `javascript:`/`data:` execute | validate the scheme |

| Source | Notes |
| --- | --- |
| `location.search`, `URLSearchParams` | sent to the server; visible in logs |
| `location.hash` | **never sent to the server** - invisible to logs and WAFs |
| `location.href`, `location.pathname` | includes both of the above |
| `document.referrer` | attacker-controlled by whoever linked to the page |
| `.data( k )` / `.attr( 'data-…' )` | the dominant *stored* channel in WordPress |
| `event.data` in a `message` handler | any origin, unless you check |
| `window.name`, `localStorage`, `sessionStorage` | survive navigation; cross-page in the same tab |
| an AJAX / REST response body | trust it exactly as much as you trust its writer |

## Real-world case studies

Every snippet was read from the WordPress plugin repository at the stated tag.
(`plugins.trac.wordpress.org` serves a JavaScript browser challenge to non-browser
clients; the same bytes are served by `plugins.svn.wordpress.org` at
`<slug>/tags/<version>/<path>`. The trac URL is recorded as `code_ref` because it
is the canonical human-readable location.)

### Query parameter to `.html()` (CVE-2026-18328)

`https://plugins.trac.wordpress.org/browser/forminator/tags/1.56.0/assets/js/front/front.stripe.js#L1539`

```javascript
getCheckoutReturnErrorMessage: function() {                                  // line 189
    if ( ! this.isCheckoutSession() || ! window.location.search ) { return ''; }
    var params       = new window.URLSearchParams( window.location.search );  // line 195
    var errorMessage = params.get('error_description') || params.get('error_message') || '';  // line 196
    if ( errorMessage ) { return errorMessage; }                              // line 201
    ...
this._checkoutReturnError = this.getCheckoutReturnErrorMessage();             // line 468
...
    self.show_error( self._checkoutReturnError );                             // line 543
...
show_error: function( message ) {                                             // line 1537
    var $target_message = this._form.find('.forminator-response-message');
    $target_message.html( '<p>' + message + '</p>' );                         // line 1539
},
```

The complete chain in one file: `window.location.search` → `URLSearchParams.get()`
→ a stored property → a shared error renderer → `.html()` with concatenation. Four
hops and 1350 lines between the source and the sink, which is why grepping only
for sinks or only for sources finds nothing actionable and the *join* of the two
is what matters.

Note the delivery: this is a public payment form, so the attacker position is
unauthenticated and the victim is any visitor who follows a crafted return URL.
The 7.2 score reflects that. Note also that `show_error()` has fourteen callers -
fixing line 543 would have left thirteen other paths into the same sink. The fix
belongs at line 1539.

### `location.href` into a `<meta>` tag (CVE-2024-1038)

`https://plugins.trac.wordpress.org/browser/beaver-builder-lite-version/tags/2.7.4.2/js/fl-builder.js#L1613`

```javascript
_exit: function() {
    var href = window.parent.location.href;                                   // line 1580
    ...
    if ( FLBuilder._exitUrl ) { href = FLBuilder._exitUrl; }                  // line 1604
    else {
        href = href.replace( '&fl_builder_ui', '' );                          // line 1607
        ...
    }
    if ( href.includes( 'playground.wordpress.net' ) ) {                      // line 1613
        const meta = '<meta http-equiv="refresh" content="0; URL=\'' + href + '\'" />';  // line 1614
        $( 'head', window.parent.document ).append( meta );                   // line 1615
    } else {
        window.parent.location.href = href;                                   // line 1617
    }
},
```

Line 1614 concatenates the page's own URL into a **single-quoted attribute inside
a double-quoted HTML string**, and line 1615 hands it to jQuery `.append()`, which
parses it. A `'` in the URL closes the `content` attribute; everything after it is
new markup injected into the parent document's `<head>`.

Two details worth carrying forward:

- **`.includes( 'playground.wordpress.net' )` is not an origin check.** It is a
  substring test that `https://victim.example/?x=playground.wordpress.net`
  satisfies. Any host check that is not a parsed-URL origin comparison is
  decoration.
- The `href.replace(...)` calls at 1607-1610 give the value a *processed* look
  without sanitising anything. String munging is not validation, and it is a
  recurring reason authors believe a value is clean.

### postMessage with no origin check (CVE-2026-2433)

`https://plugins.trac.wordpress.org/browser/wp-rss-aggregator/tags/5.0.10/core/js/admin-shell.js#L58`

```javascript
onReceive( type, handler ) {                                                  // line 57
    window.addEventListener( "message", ( event ) => {                        // line 58
        const msg = event.data ?? {}
        if ( typeof msg === "object" && ( msg.type ?? "" ) === type ) {       // line 60
            handler( msg.payload )                                            // line 61
        }
    })
}
...
this.frame.onReceive( FrameMessage.openUrl, ( payload ) => {                  // line 146
    if ( typeof payload !== "object" || typeof payload.url !== "string" ) { return; }   // line 147
    if ( payload.target ) {
        window.open( payload.url, payload.target )                            // line 153
    } else {
        this.frame.navigate( payload.url, "openUrl" )                         // line 155
    }
})
```

Line 58 registers the listener. `event.origin` is never read anywhere in the
file. The only validation is line 147's `typeof payload.url === "string"`, which a
`javascript:` URL satisfies perfectly. Line 153 then executes it.

This is the shape rule XSSD-005 exists to inventory. Note that the guard the
author *did* write - a type check - is the kind that looks like validation in
review and is orthogonal to the actual threat. When triaging a `message` handler,
ask the three questions in that order: origin, source, sink. A type check answers
none of them.

### One character between safe and unsafe (CVE-2024-2123)

`https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.3/templates/members-grid.php#L44`

```php
<a href="{{{user.profile_url}}}" title="<# if ( user.display_name ) { #>{{{user.display_name}}}<# } #>">
    {{{user.cover_photo}}}                                                    <!-- line 45 -->
</a>                                                                          <!-- line 44 -->
...
<a href="{{{user.profile_url}}}" title="{{{user.display_name}}}">             <!-- line 65 -->
    {{{user.display_name_html}}}                                              <!-- line 66 -->
</a>
```

`{{{ }}}` is the **unescaped** interpolation in `wp.template`. Line 45's
`{{{user.cover_photo}}}` is legitimately raw - the member carries a
plugin-generated `<img>` element. Lines 44 and 65 use the same delimiter for
`user.display_name`, which is free text any registered user sets on their own
profile, dropped straight into a `title` attribute.

The template is a `.php` file, so a JavaScript-only sweep misses it entirely, and
a PHP-only sweep sees no `echo` and no sink. Rule XSSD-007 exists because the
`{{{` token is the only thing on the line that identifies a raw write. Run it
over `.php`, `.html` and `.js` alike.

The correct fix on lines 44 and 65 is `{{ user.display_name }}`. The correct fix
on line 66 is to stop generating `display_name_html` server-side and let the
template escape a plain string.

### Base64 carries markup through `esc_attr()` (CVE-2025-8451)

`https://plugins.trac.wordpress.org/browser/essential-addons-for-elementor-lite/tags/6.2.2/assets/front-end/js/view/filterable-gallery.js`

```javascript
var $gallery = $( ".eael-filter-gallery-container", $scope ),
    fg_items = JSON.parse( atob( $gallery.data( "gallery-items" ) ) ),
    ...
if ( "yes" === $is_randomize ) {
    fg_items = shuffleGalleryItems( fg_items );
    $gallery.empty();
    for ( var i = 0; i < $init_show_setting; i++ ) {
        $gallery.append( fg_items[ i ] );          // each element is an HTML string
    }
}
...
$gallery.append( $items );                          // and again, twice more
```

(The shipped file is a single webpack `eval()` bundle, so line anchors are not
meaningful; the statements above are quoted verbatim from the decoded module.)

The server built each gallery item as an HTML *string*, JSON-encoded the array,
base64-encoded the JSON, and `esc_attr()`'d the base64 into `data-gallery-items`.
Every one of those steps is individually correct. The composition is the bug:
`atob()` + `JSON.parse()` reverse all of it, and the resulting strings go to
`.append()`, which parses them as HTML.

The general rule this teaches: **encoding is not escaping.** Base64, JSON and
URL-encoding are transport formats; each one is reversed by the consumer, and
none of them constrains what the decoded bytes mean in their final context. A
review that stops at "the attribute is escaped" stops one layer too early.

The structural fix is to stop shipping markup through the attribute at all - send
`{id, title, url}` and build nodes client-side.

### Data attribute to template literal (CVE-2025-13535)

`https://plugins.trac.wordpress.org/browser/king-addons/tags/51.1.38/includes/widgets/Countdown/script.js#L119`

```javascript
function expiredActions() {
    const dataActions = countDownWrap.data( "actions" );                       // line 96
    ...
    if ( dataActions.hasOwnProperty( "hide-element" ) ) {
        $( dataActions["hide-element"] ).hide();                               // line 107
    }
    if ( dataActions.hasOwnProperty( "message" ) ) {
        ...
        countDownWrap.after(
            `<div class="king-addons-countdown-message">${dataActions["message"]}</div>`   // line 119
        );
    }
    if ( dataActions.hasOwnProperty( "redirect" ) ) {
        window.location.href = dataActions["redirect"];                        // line 126
    }
}
```

Three sinks fed from one JSON data attribute: a template literal into `.after()`
(HTML parse), a bare string into `$()` (HTML parse when it starts with `<`), and a
raw assignment to `location.href` (`javascript:` executes).

The producer side, in `Countdown.php` at the same tag, is instructive about what
*does not* work. Line 1000 wraps the whole JSON in `esc_attr()`; line 1077 runs
the message through `wp_kses()`; line 1076 then runs a hand-rolled
`sanitize_no_js()` that strips `<script>`, `<iframe>` and `on\w+=` with seven
regexes; line 1082 `esc_url()`s the redirect. Lines 1073 and 1085 -
`hide_element_selector` and `load_template` - get nothing at all.

Two lessons:

1. **A regex blacklist is not a sanitizer.** `sanitize_no_js()` enumerates seven
   bad shapes. HTML has more. Allow-listing (`wp_kses` with a reviewed array) is
   the only approach that closes rather than narrows.
2. **`wp_kses()` output is safe as a text node, not as a value that will be
   re-parsed as HTML in a second context.** The client-side re-parse is a
   different trust boundary and needs its own control - here, `.text()` instead of
   a template literal.

### The library is the sink (CVE-2025-5096)

`https://plugins.trac.wordpress.org/browser/tablepress/tags/3.1.2/js/jquery.datatables.min.js`

```javascript
// bundled DataTables, minified:
var n = a.children("caption"),
    n = ( c.caption && ( n = 0 === n.length ? H("<caption/>").appendTo(a) : n ).html( c.caption ), n.length && ... )
...
n.length || ( n = H("<caption/>").html(a), e.captionNode = n[0], o ) || ( t.prepend(n), ... ), n.html(a),
```

The plugin emits table settings - `data-caption`, `data-s-title`,
`data-s-content-padding`, `data-footer` - as data attributes, correctly escaped.
DataTables reads the caption out of its config and renders it with `.html()`,
because rendering a caption as HTML is DataTables' documented behaviour.

Nothing in the plugin's own JavaScript is wrong. The vulnerability lives at the
boundary: a contributor-settable string was handed to a component whose contract
is "I will parse this as HTML", and nobody checked that contract.

For an auditing agent this is the single most important reason **not** to exclude
`*.min.js` and `vendor/` from a DOM-XSS sweep the way you would for a PHP sweep.
Instead: inventory every value the plugin passes into a third-party widget's
config, and check that widget's documentation for which options are HTML.

### Escaped one, missed the next (CVE-2024-4619)

`https://plugins.trac.wordpress.org/browser/elementor/tags/3.21.5/includes/widgets/image-box.php#L696`

```php
var image_url = elementor.imagesManager.getImageUrl( image );                  // line 694

var imageHtml = '<img src="' + _.escape( image_url ) + '" class="elementor-animation-' + settings.hover_animation + '" />';   // line 696

if ( settings.link.url ) {
    imageHtml = '<a href="' + _.escape( settings.link.url ) + '" tabindex="-1">' + imageHtml + '</a>';   // line 699
}
```

This is JavaScript living inside a PHP file - Elementor's `content_template()`
method, which supplies the editor's live preview. Line 696 escapes `image_url`
with `_.escape()` and, in the very same concatenation, interpolates
`settings.hover_animation` bare into a `class` attribute. Line 699 escapes again.
Two out of three.

`hover_animation` is a widget setting, so it comes from `_elementor_data` post
meta and any Contributor editing a draft can set it. The payload needs no `<`:
`x" onmouseover=alert(1) y="` breaks the `class` attribute.

The file-type lesson is the same as CVE-2024-2123 from the other direction: a
`.js`-only sweep never opens `image-box.php`, and a PHP-only sweep sees a string
assignment with no `echo`. Rules XSSD-001 and XSSD-002 must be run over `.php` as
well as `.js`.

### Stored setting through a live preview (CVE-2024-13901)

`https://plugins.trac.wordpress.org/browser/counter-box/tags/2.0.6/admin/assets/js/5.builder.js#L35`

```javascript
let content = $( '#wpie-fulleditor-1' ).val();                                // line 10
previewContent( content );
editor.on( 'change keyup click', function () { previewContent( editor.getContent() ); } );   // line 13
...
function previewContent( content ) {                                          // line 23
    content = content.replace( '{year}',  '<span class="counter-element -year">01</span>' );
    content = content.replace( '{day}',   '<span class="counter-element -day">10</span>' );
    ...
    content = content.replace( '{counter}', '<span class="counter-element -counter">' + start + '</span>' );
    $( element ).html( content );                                             // line 35
}
```

The counter "content" is a stored plugin setting. The preview replaces
`{year}`, `{day}`, `{counter}` placeholders with `<span>` markup and then calls
`.html()`, because after the replacement the string genuinely *is* markup.

That is the trap worth naming: **once a design requires the string to be HTML,
escaping it becomes impossible without redesigning it.** The fix is structural -
split on the placeholder, build a `<span>` node for each token, and append the
surrounding chunks as text nodes (see item 11 in the secure pattern). Reviewers
who look for "where is the missing `escapeHtml()`?" find no place to put one and
conclude the code is fine.

Severity is lower here (4.8, admin+) because the setting is behind a
`manage_options` screen. It is still a real finding: in multisite an
Administrator does not hold `unfiltered_html`, and the preview also renders for
anyone the site grants that screen to.

## Detection guidance

### Measurement basis

Hit rates were measured with Python's `re` and cross-checked with ripgrep (Rust
regex) against a negative corpus of seven large, actively maintained, heavily
audited plugins - WooCommerce, Yoast SEO, UpdraftPlus, Contact Form 7, WP Super
Cache, Elementor and WPForms Lite: **1,073,398 lines of non-minified JavaScript**
(excluding `node_modules/`, `vendor/`, `dist/` and `*.min.js`) and **1,470,620
lines of PHP**. Every rule also runs against a paired fixture of vulnerable and
safe lines derived from the case studies above.

| Rule | Language | Hits | Per KLOC |
| --- | --- | ---: | ---: |
| XSSD-009 `.data()` / `.attr('data-…')` read | JS | 811 | 0.76 |
| XSSD-002 jQuery HTML sink + bare variable | JS | 657 | 0.61 |
| XSSD-007 `{{{ }}}` triple brace | PHP | 385 | 0.26 |
| XSSD-004 DOM sources | JS | 355 | 0.33 |
| XSSD-003 innerHTML / insertAdjacentHTML / document.write | JS | 145 | 0.14 |
| XSSD-006 navigation sink from a variable | JS | 111 | 0.10 |
| XSSD-001 jQuery HTML sink + concatenation | JS | 49 | 0.05 |
| XSSD-005 `message` listener | JS | 32 | 0.03 |
| XSSD-008 `wp_add_inline_script` / `wp_localize_script` with PHP vars | PHP | 24 | 0.02 |
| *(supplementary)* `eval`/`setTimeout`/`Function` with a concatenated string | JS | 2 | 0.00 |

The supplementary grep is, with `Q` standing for the three-character class
"single quote, double quote, backtick":

```
\b(eval|setTimeout|setInterval|Function)\s*\(\s*[Q][^Q]*[Q]\s*\+
```

It returned two hits across 1.07M lines. It costs nothing to run and both hits
are worth reading. It is not promoted to a numbered rule only because passing a
concatenated string to `eval`/`setTimeout` is rare enough in modern plugin code
that it belongs in the manual sweep rather than the standing rule set.

### The controlling idea: this class is a JOIN, not a grep

Every other class in this knowledge base can be found by matching a single line.
DOM XSS cannot. The source and the sink are routinely hundreds of lines apart, in
different functions, sometimes in different files and different languages
(CVE-2026-18328 spans 1350 lines; CVE-2025-5096 spans two repositories).

The workable procedure is therefore:

1. **Inventory sinks** with XSSD-001, XSSD-002, XSSD-003, XSSD-006 and XSSD-007.
2. **Inventory sources** with XSSD-004, XSSD-005, XSSD-008 and XSSD-009.
3. **Join on file.** A file appearing in both lists is where a human or an agent
   reads code. On the negative corpus this join collapses roughly 2400 raw hits to
   a few dozen files.
4. **Trace each pair.** Follow the value from source to sink through assignments
   and function boundaries. This is the step no regex performs.

Do **not** run this sweep with `--type js` alone. Three of the nine case studies
have their sink inside a `.php` file (`members-grid.php`, `image-box.php`,
`Countdown.php`'s producer side) and one is inside a minified vendor bundle.

### Triage questions, in order

For a **sink** hit:

1. Is the argument a string, or a jQuery object / DOM node? Only strings parse.
2. Is the string a literal? Then it is safe regardless of what else is nearby.
3. Where did each interpolated value come from - literal, plugin-generated,
   translated constant, or attacker-reachable?

For a **`message` listener** hit:

1. Is `event.origin` compared against an allow-list?
2. Is `event.source` compared against a frame this page created?
3. Does the payload reach a sink? Missing (1) plus present (3) is a finding.

For a **data-attribute** hit:

1. Which PHP writes that attribute? Grep the attribute name across `.php`.
2. Is the value contributor-reachable - a shortcode/block attribute, a
   page-builder setting, post meta, a profile field?
3. Is there an encoding layer (JSON, base64) that hides markup from the
   attribute-level review?

### What these regexes MISS - read code manually when you see these

- **Minified and bundled JavaScript.** The rules are written against readable
  source. `*.min.js`, webpack `eval()` bundles and Rollup output will match
  erratically or not at all. CVE-2025-5096's sink is inside a minified vendor
  file and CVE-2025-8451's is inside a webpack `eval()` string.
- **Frameworks that own the DOM.** React `dangerouslySetInnerHTML`, Vue `v-html`,
  Svelte `{@html}`, Alpine `x-html`, Handlebars/Mustache triple-stache, Angular
  `[innerHTML]`. Every one is the same hazard under a different name; add the
  ones your target uses to the sink rule.
- **The block editor.** `RichText.Content`, `dangerouslySetInnerHTML` inside a
  `save()` function, and any block that stores rendered HTML in `post_content`
  rather than storing attributes.
- **jQuery version-specific behaviour.** jQuery below 3.5.0 carries its own XSS
  issues (CVE-2020-11022 / CVE-2020-11023) where `.html()`-style methods execute
  content that later versions neutralise. Check the bundled version; a plugin
  shipping its own jQuery is common.
- **Sinks reached through a wrapper.** `this.render( html )`, `App.setContent( s )`,
  a project `template()` helper. Grep for local helpers that call a sink and add
  them to the rule set before trusting a clean result.
- **`document.currentScript.dataset`, `window.name`, `localStorage`,
  `sessionStorage`, `IndexedDB`, service-worker caches.** All are sources; none
  are matched by XSSD-004.
- **Server-rendered JS.** A PHP variable interpolated directly into a `<script>`
  block is `WP-XSS-S` by mechanism (the server emitted it) even though the sink
  is JavaScript. See the CVE-2023-5707 case study in that file.
- **Whether the value is Contributor-reachable.** As everywhere in the XSS
  family, this is the difference between a 6.4 CVE and a non-issue, and it
  requires reading the write path and its capability check.
- **CSP.** A site with a strict `script-src` may neutralise a real finding, and
  its absence does not create one. Report the flaw; note the CSP separately.

## Audit checklist

- [ ] Sweep `.js`, `.php`, `.html` and any template extension the project uses.
      A `--type js` filter alone misses a third of the real cases.
- [ ] Run XSSD-001 first (0.05/KLOC). Every hit is an HTML string being
      assembled at runtime; read each one.
- [ ] Run XSSD-003 and discard `= ''` and `= '<literal>'`; read the rest.
- [ ] Run XSSD-007 over PHP and templates. For each `{{{ }}}`, name the member
      and decide whether it is plugin-generated or user-controlled.
- [ ] Run XSSD-005 and read every listener body against the three questions:
      origin, source, sink.
- [ ] Run XSSD-004 and XSSD-009 to build the source inventory, then **join on
      file** with the sink inventory. Read only the intersection first.
- [ ] For every `data-*` attribute consumed by JavaScript, grep its name in PHP
      and identify who can write the value and with what capability.
- [ ] Grep `atob\s*\(|JSON\.parse\s*\(` and check whether the decoded result
      reaches a sink. Encoding layers defeat attribute-level review.
- [ ] Grep `wp_localize_script` and confirm no value was pre-escaped with
      `esc_html`/`esc_attr` - core entity-decodes scalars and it will be undone.
- [ ] Grep `wp_add_inline_script` and confirm the payload is
      `wp_json_encode()`-generated, not string-concatenated. This function does
      no encoding of its own.
- [ ] Grep `\$\(\s*[A-Za-z_$]` for `$( variable )` calls and check whether the
      variable can start with `<`; jQuery parses those as HTML.
- [ ] Inventory every third-party widget the plugin configures (DataTables,
      Slick, Swiper, Magnific Popup, lightGallery, typed.js, Isotope) and check
      which of its options are documented as accepting HTML.
- [ ] Check the bundled jQuery version; below 3.5.0 the sink methods have their
      own known issues.
- [ ] Grep `eval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"]` and read every
      hit.
- [ ] For every navigation sink (`location.href`, `window.open`, `a.href =`,
      `.setAttribute('href'`), confirm a scheme allow-list, not an escaper.
- [ ] For each confirmed finding, state whether the fix is client-side. A
      server-side `esc_*` call is never the answer to a DOM-XSS finding, and
      proposing one is a sign the flow was not traced.
