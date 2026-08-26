---
class_id: WP-XSS-S
title: Stored XSS via saved content re-emitted without context-correct escaping
cwe: [CWE-79, CWE-80]
owasp: A03:2021-Injection
severity_typical: medium
auth_required_typical: contributor+
prevalence_rank: 1
detection:
  - id: XSSS-001
    description: >-
      An HTML attribute value is opened with a quote, the PHP string literal is
      closed, and a bare variable is concatenated in - the canonical attribute
      break-out shape (`class="' . $x . '"`).
    regex: '=\s*\\?["''][^"'']*["'']\s*\.\s*\$'
    confidence: medium
    false_positive_notes: >-
      968 hits per 1.47M LOC (0.66/KLOC) on the negative corpus, versus 4757 for
      a naive "echo with a variable" sweep - a 80% noise reduction that keeps every
      fixture true positive. It fires on string *building* regardless of whether the
      result is ever emitted, and it cannot see an escaper applied on an earlier
      line. The residue is dominated by two benign shapes: (a) the value is a plugin
      constant, an integer, or a hard-coded URL, and (b) the value was escaped at its
      assignment. Note the rule is deliberately blind to the wrapper - it only asks
      "was the token after the concatenation dot a `$`?" - because `. esc_attr( $x )`
      has an identifier there and never matches. That is what keeps it cheap and
      lookahead-free.
  - id: XSSS-002
    description: >-
      Same break-out shape, but the attribute is one that takes a URL, so the fix
      is esc_url() and not esc_attr().
    regex: '\b(href|src|action|formaction|poster|data-url)\s*=\s*\\?["''][^"'']*["'']\s*\.\s*\$'
    confidence: high
    false_positive_notes: >-
      26 hits per 1.47M LOC (0.02/KLOC). Nearly every hit is a real missing
      esc_url(). The benign residue is a hard-coded vendor URL held in a variable,
      or a URL that already went through esc_url()/sanitize_url() at assignment.
      Treat a hit as a finding until you have walked back to the assignment.
      Distinguish this from XSSS-001 because `esc_attr()` is NOT a valid fix here -
      it passes `javascript:` through untouched.
  - id: XSSS-003
    description: >-
      A PHP variable is interpolated inside a double-quoted string that is building
      an HTML attribute (`"<div class=\"{$atts['cls']}\">"`). No function call
      exists, so every wrapper-anchored rule is blind to it.
    regex: '=\s*\\?["''][^"''<>]*\{\$[A-Za-z_]'
    confidence: medium
    false_positive_notes: >-
      584 hits per 1.47M LOC (0.40/KLOC). Interpolation is the main way an
      attribute sink hides from concatenation-based rules, which is why this rule
      exists despite the noise. Benign cases are numeric ids, loop counters,
      generated CSS class prefixes, and values already hardened at assignment.
      Heredoc and nowdoc bodies use the same `{$var}` syntax and are matched by this
      rule only when the attribute assignment and the interpolation land on one
      line - grep `<<<` separately and read those bodies by hand.
  - id: XSSS-004
    description: >-
      A persistent-storage read is echoed with no wrapper at all - the shortest
      possible stored-XSS statement.
    regex: '\b(echo|print)\s+(get_post_meta|get_option|get_user_meta|get_term_meta|get_comment_meta|get_post_custom|get_metadata|get_site_option|get_transient|get_theme_mod)\s*\('
    confidence: high
    false_positive_notes: >-
      1 hit per 1.47M LOC of mature audited code, and that one hit is
      `echo get_option( 'blog_charset' )` - a core option with a constrained value
      set. In other words this rule is silent on well-maintained code, so a hit in
      an unaudited plugin is almost certainly real. Confirm the output context
      before naming the fix: a meta value landing in `href` needs esc_url(), not
      esc_html().
  - id: XSSS-005
    description: >-
      A shortcode / block / widget attribute array element is concatenated or
      interpolated directly, with no escaping wrapper. This is the single most
      common contributor-reachable stored-XSS shape in the ecosystem.
    regex: '\$(atts|attributes|settings|instance)\s*\[\s*["''][A-Za-z0-9_-]+["'']\s*\]\s*(\.|\})'
    confidence: medium
    false_positive_notes: >-
      14 hits per 1.47M LOC (0.01/KLOC). Very quiet because the correct forms
      (`esc_attr( $atts['x'] )`, `$atts['x'],` as a function argument) put a `)` or
      a `,` after the closing bracket rather than a `.` or a `}`. Residual noise is
      string building that never reaches markup - building a cache key, a CSS file
      path, an option name. The variable names are a heuristic: rename-happy
      codebases use `$a`, `$args`, `$params`, `$props`; widen the alternation to
      match the local convention before trusting a zero-hit result.
  - id: XSSS-006
    description: >-
      A value is run through an entity DECODER. Whatever escaping the storage layer
      or KSES left in place is undone at this point, and everything downstream is
      raw again.
    regex: '\b(html_entity_decode|htmlspecialchars_decode|wp_specialchars_decode)\s*\(\s*\$'
    confidence: medium
    false_positive_notes: >-
      95 hits per 1.47M LOC (0.06/KLOC). Cheap enough to read every hit. Legitimate
      uses exist - decoding before a strlen()/mb_strlen() width calculation, before
      a strict string comparison, or before writing to a plain-text email body or a
      PDF. The rule earns its place because when the decoded value then reaches
      markup, it is a guaranteed XSS with no escaping anywhere in the chain (this
      is CVE-2023-7070 exactly). Triage question: does the decoded value reach an
      echo/return that produces HTML?
  - id: XSSS-007
    description: >-
      An escaping function is wrapped around the printf/sprintf FORMAT STRING while
      an argument is passed bare. The format string is usually a translated
      constant, so the escaping protects nothing and the untrusted argument is
      interpolated raw.
    regex: '\b(printf|vprintf|sprintf|wp_sprintf)\s*\(\s*esc_(html|attr|js|url|textarea)(__|_x)?\s*\(.*,\s*\$'
    confidence: medium
    false_positive_notes: >-
      60 hits per 1.47M LOC (0.04/KLOC). A hit is benign when the bare argument is
      an integer, is bound to a `%d`/`%u` specifier, or was escaped at assignment.
      Read the format string: only `%s` positions matter. This mistake is
      particularly hard to spot in review because the line visibly contains an
      `esc_*` call, which satisfies a "did they escape it?" skim - see CVE-2023-1404.
  - id: XSSS-008
    description: >-
      A superglobal is written straight into persistent storage with no sanitizer.
      This is the input half of the class: it does not itself prove an XSS, but it
      guarantees that every reader of that key is unprotected.
    regex: '\b((update|add)_(post|user|term|comment)_meta|update_option|set_transient)\s*\([^;]*,\s*\$_(POST|GET|REQUEST|COOKIE)\s*\['
    confidence: high
    false_positive_notes: >-
      0 hits per 1.47M LOC. Mature code always interposes a sanitizer or a cast,
      so any hit is an unreviewed write path. Remember that clearing this rule is
      not sufficient: sanitizing on input does not license echoing on output, and
      sanitize_text_field() in particular leaves `"` and `'` intact.
  - id: XSSS-009
    description: >-
      A variable is used as the REPLACEMENT argument of preg_replace/str_replace.
      The replacement is spliced into the subject with no escaping, so if the
      subject is markup this is an output sink that no echo-anchored rule can see.
    regex: '\b(preg_replace|str_replace|str_ireplace)\s*\([^;]*,\s*\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*\$'
    confidence: low
    false_positive_notes: >-
      82 hits per 1.47M LOC (0.06/KLOC), most of them benign because the subject is
      a file path, a SQL fragment, a slug, or a plain-text string rather than
      markup. The rule exists because CVE-2024-0255 is invisible to every other rule
      in this file: the sink is `preg_replace( '/#[0-9a-f]{3,6}/mi', $color, $icon )`
      where `$icon` is SVG markup. Triage by asking what the SUBJECT is, not what the
      replacement is. Note that with preg_replace a `$` or `\\` in the replacement is
      also a backreference, so untrusted replacements have a second failure mode.
fix_apis:
  - esc_html()
  - esc_attr()
  - esc_url()
  - esc_js()
  - esc_textarea()
  - esc_xml()
  - wp_kses()
  - wp_kses_post()
  - wp_kses_data()
  - wp_json_encode()
  - sanitize_text_field()
  - sanitize_textarea_field()
  - sanitize_key()
  - sanitize_html_class()
  - sanitize_hex_color()
  - absint()
  - in_array( $v, $allowed, true )
  - current_user_can()
examples:
  - cve: CVE-2023-7070
    year: 2024
    severity: 5.4
    auth: contributor+
    summary: A shortcode attribute was passed through html_entity_decode() and then concatenated straight into an anchor element.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-7070
    code_ref: https://plugins.trac.wordpress.org/browser/email-encoder-bundle/tags/2.1.9/core/includes/classes/class-email-encoder-bundle-run.php#L518
    root_cause: An entity DECODER was applied to untrusted input, undoing the encoding that made it safe, and no escaper was applied at the output site.
  - cve: CVE-2024-6264
    year: 2024
    severity: 5.4
    auth: contributor+
    summary: A post meta KEY was echoed unescaped into two HTML attributes and a heading on an admin screen, three lines after the same value was correctly escaped in a table cell.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-6264
    code_ref: https://plugins.trac.wordpress.org/browser/post-meta-data-manager/tags/1.2.3/includes/admin/html/pmdm_wp_display_post_metadata_html.php#L42
    root_cause: Missing esc_attr() on an array KEY (not a value) printed inside data-* and id attributes; escaping was applied per line rather than per output site.
  - cve: CVE-2023-1404
    year: 2023
    severity: 5.4
    auth: contributor+
    summary: The author display name was interpolated into a title attribute through sprintf, with the escaping applied to the translated format string instead of to the value.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-1404
    code_ref: https://plugins.trac.wordpress.org/browser/show-posts/tags/1.6/includes/atw-showposts-sc.php#L368
    root_cause: esc_attr() wrapped the format string, which is a constant, while the untrusted %s argument was passed bare.
  - cve: CVE-2023-3387
    year: 2023
    severity: 5.4
    auth: contributor+
    summary: One sprintf built an img tag whose alt attribute was escaped and whose class attribute, fed from a shortcode attribute, was not.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-3387
    code_ref: https://plugins.trac.wordpress.org/browser/lana-text-to-image/tags/1.0.0/lana-text-to-image.php#L97
    root_cause: Missing esc_attr() on one of two attributes in the same statement; the class attribute was assembled with implode() and never escaped.
  - cve: CVE-2024-0255
    year: 2024
    severity: 5.4
    auth: contributor+
    summary: A shortcode colour attribute was used as the replacement argument of a preg_replace whose subject was SVG markup.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-0255
    code_ref: https://plugins.trac.wordpress.org/browser/wp-recipe-maker/tags/9.1.0/includes/public/class-wprm-icon.php#L52
    root_cause: The output sink was a regex replacement rather than an echo, so no escaper was applied and no echo-anchored review would have found it; sanitize_hex_color() was the correct control.
  - cve: CVE-2024-0792
    year: 2024
    severity: 5.4
    auth: contributor+
    summary: Items from a contributor-chosen RSS feed were rendered into a link list with esc_attr() on the permalink that lands in href.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-0792
    code_ref: https://plugins.trac.wordpress.org/browser/shortcodes-ultimate/tags/7.0.1/includes/shortcodes/feed.php#L78
    root_cause: Escaping was present but wrong for the context - esc_attr() does not strip javascript:, so esc_url() was required.
  - cve: CVE-2023-5669
    year: 2023
    severity: 5.4
    auth: contributor+
    summary: A metabox save handler wrote two raw $_POST fields into post meta while correctly sanitizing a third in the same array literal.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5669
    code_ref: https://plugins.trac.wordpress.org/browser/featured-image-caption/trunk/classes/MetaBox.php?rev=2300545#L91
    root_cause: No sanitizer on the caption and source-text fields at the write, and no escaper at the shortcode that later renders them.
  - cve: CVE-2024-1985
    year: 2024
    severity: 6.1
    auth: unauthenticated
    summary: A member profile view called extract() on the stored member record and echoed the resulting variables into value attributes, with registration open to anonymous visitors.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-1985
    code_ref: https://plugins.trac.wordpress.org/browser/simple-membership/tags/4.4.2/views/edit-v2.php#L103
    root_cause: Missing esc_attr() on database-sourced values, compounded by extract() erasing every syntactic clue that the variables were untrusted.
  - cve: CVE-2023-5707
    year: 2023
    severity: 5.4
    auth: contributor+
    summary: Twelve post meta values were read for a slider; five were hardened by a boolean cast and the rest were interpolated raw into a JavaScript object literal and a CSS block.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2023-5707
    code_ref: https://plugins.trac.wordpress.org/browser/seo-slider/trunk/includes/shortcode.php?rev=2367856#L68
    root_cause: Stored values reached script and style contexts where HTML escaping is not the control; wp_json_encode() and a numeric/hex allow-list were required.
---

## What it is

Stored XSS is when untrusted content is written to persistent storage in one
request and rendered into a page in some later request without being encoded for
the place it lands in. The store can be a post, post meta, an option, user meta,
a term, a comment, a transient, or a custom table. Unlike reflected XSS the
payload does not need a delivered link: it fires for every visitor to the
affected page, including administrators who never clicked anything.

It is by a wide margin the largest vulnerability class in the WordPress
ecosystem. In the Wordfence-derived prevalence sample behind `kb/taxonomy.json`
it is 1786 of 5620 records - **31.8% of everything** - and the single sub-bucket
"Authenticated (Contributor+) Stored XSS" is 997 records on its own, about 18% of
all WordPress vulnerabilities of any class. An independent count over five
consecutive 120-day NVD publication windows (2023-01-01 → 2024-08-26) put stored
XSS at 1828 records against 281 for reflected - a ratio of roughly **6.5 : 1**.

The typical CVSS vector is `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` at 6.4, or
`PR:N/UI:R` at 6.1 when the write path is unauthenticated. `S:C` (scope change)
is the load-bearing metric: the script runs in the site origin with whatever
session the *viewer* has, so a Contributor-planted payload executes with
administrator privileges the moment an administrator opens the post.

## Why it happens in WordPress

### The contributor is the attacker, and core already drew that boundary

WordPress core deliberately runs post content from any user lacking the
`unfiltered_html` capability through KSES (`content_save_pre` →
`wp_filter_post_kses`). Per the roles documentation, Contributors and Authors
never have `unfiltered_html`, and **in multisite even Administrators and Editors
do not** - only Super Admins do. So core's own security model says: a Contributor
must not be able to get script onto a page.

That makes "a Contributor can inject script" a real vulnerability rather than a
role working as intended, and it is why 997 of the 1786 records in this class sit
at exactly that privilege level. A Contributor can write drafts and nothing else.
They cannot publish and cannot upload. All they need is for an editor or admin to
open their draft - which is the entire point of the Contributor role.

### The five storage paths that bypass KSES

KSES operates on *tags* in `post_content`. Every one of these carries attacker
bytes past it untouched:

| Path | Why KSES misses it |
| --- | --- |
| **Shortcode attributes** | `[box cls='" onmouseover=alert(1) x="']` contains no `<` at all. KSES has nothing to strip; the string arrives at the callback byte-for-byte. |
| **Block attributes** | Stored as JSON inside the block's HTML *comment* delimiter (`<!-- wp:my/block {"cls":"..."} -->`). Comments are not markup KSES inspects. |
| **Page-builder settings** | Elementor, Divi, Beaver Builder and friends serialise widget settings into post meta (`_elementor_data`), not into `post_content`. |
| **Post meta / custom fields** | `update_post_meta()` applies no filter of its own. `register_meta()`'s `sanitize_callback` is opt-in and usually absent. |
| **Plugin options and custom tables** | `update_option()` runs `sanitize_option()` only for options core knows about. A plugin's own option name is not one of them. |

The consequence is that **nearly every stored XSS in this class is an
attribute-context break-out, not a `<script>` injection** - because the payload
that survives the trip has no angle brackets in it. That is also why `esc_attr()`
is the fix in the large majority of cases and why "we call `wp_kses_post()`
somewhere" is not a defence.

### Sanitizing on input is not escaping on output

The handbook rule is "sanitize on input, escape on output, escape as late as
possible", and the second clause is the one plugins skip. Two reasons it is not
optional:

1. **The destination is unknown at input time.** The same stored string is safe
   in `<p>`, dangerous in `href`, and differently dangerous inside `<script>`.
   Only the output site knows which, so only the output site can choose the
   encoder.
2. **`sanitize_text_field()` does not neutralise quotes.** It strips tags,
   handles a lone `<`, removes invalid UTF-8 and percent-encoded octets, and
   trims. It never touches `"` or `'`. A payload of
   `" autofocus onfocus=alert(1) x="` contains no `<`, passes through untouched,
   and still breaks out of a quoted attribute.

There is a third, WordPress-specific reason: **a stored value has many readers.**
One forgotten `echo` anywhere in the plugin - an admin list table, a REST
response rendered client-side, an export screen, an email preview - reopens the
hole. Input sanitising bounds the blast radius; it does not close the class.

### The anti-escapers

Three constructs actively remove protection that was already in place, and every
one of them shows up in real CVEs:

- **`html_entity_decode()` / `htmlspecialchars_decode()` / `wp_specialchars_decode()`.**
  Applied after storage, they convert `&lt;script&gt;` back into `<script>`.
  CVE-2023-7070 is this and nothing else.
- **`extract()`.** Turns a database row into local variables. `echo $phone;` now
  looks like an ordinary local read, and no reviewer scanning that line can tell
  it came from an untrusted store. CVE-2024-1985.
- **`wp_localize_script()`.** Core's `WP_Scripts::localize()` runs
  `html_entity_decode( (string) $value, ENT_QUOTES, 'UTF-8' )` over **every scalar
  value** before JSON-encoding it. Any `esc_html()`/`esc_attr()` you applied
  first is silently undone. (The `JSON_HEX_TAG` flag still protects the
  `<script>` block itself; what arrives in JavaScript is the raw decoded string,
  which is a problem for the JS that consumes it - see `WP-XSS-DOM`.)

### Escaping is per-output-site, not per-file and not per-value

The most repeated finding across the case studies below: the same file, often the
same statement, escapes one thing correctly and the adjacent thing not at all.
CVE-2024-6264 escapes a meta key in a table cell and prints it raw into a
`data-id` attribute three lines later. CVE-2023-3387 escapes `alt` and not
`class` in one `sprintf()`. CVE-2023-1404 escapes the format string and not the
argument. Never discount a scanner hit because neighbouring lines look clean.

## Vulnerable pattern

```php
<?php
// 1. Shortcode attribute straight into an attribute value. The payload needs no
//    "<" at all, so KSES never saw it on the way in.
add_shortcode( 'mybox', function ( $atts ) {
    $a = shortcode_atts( array( 'cls' => '', 'title' => '' ), $atts );
    return '<div class="' . $a['cls'] . '" title="' . $a['title'] . '">'
         . $a['title'] . '</div>';
} );

// 2. Block render_callback. $attributes came from JSON inside a block comment.
function render_my_block( $attributes ) {
    $tag = $attributes['titleTag'];                       // no allow-list at all
    return '<' . $tag . ' class="' . $attributes['titleClass'] . '">'
         . esc_html( $attributes['text'] ) . '</' . $tag . '>';   // text IS escaped
}

// 3. Raw superglobal into post meta on save, no sanitizer.
add_action( 'save_post', function ( $post_id ) {
    update_post_meta( $post_id, '_caption', array(
        'caption_text' => $_POST['caption_text'],          // raw
        'source_text'  => $_POST['source_text'],           // raw
        'source_url'   => esc_url( $_POST['source_url'] ), // one of three hardened
    ) );
} );

// 4. Storage read echoed with no wrapper.
echo get_post_meta( get_the_ID(), 'subtitle', true );
echo get_option( 'my_plugin_banner_html' );

// 5. Meta KEY (not value) into attributes on an admin screen.
foreach ( $post_meta as $meta_key => $value ) : ?>
    <td><?php echo esc_html( $meta_key ); ?></td>
    <a data-id="<?php echo $meta_key; ?>" id="edit-<?php echo $meta_key; ?>">Edit</a>
<?php endforeach;

// 6. Escaping the format string instead of the argument.
printf( esc_attr( __( 'View all posts by %s', 'my-plugin' ) ), get_the_author() );

// 7. Entity decoding undoes whatever protection the value had.
$display = html_entity_decode( $atts['display'] );
echo '<a href="mailto:' . $email . '">' . $display . '</a>';

// 8. extract() erases the provenance of every variable.
$user_data = (array) $auth->userData;
extract( $user_data, EXTR_SKIP ); ?>
<input type="text" id="phone" value="<?php echo $phone; ?>" />

<?php
// 9. Escaping present, wrong for the context: esc_attr() passes javascript:.
printf( '<li><a href="%s">%s</a></li>',
    esc_attr( $item->get_permalink() ),
    wp_kses_post( $item->get_title() )
);

// 10. The sink is a regex replacement, so no echo-anchored review sees it.
$icon = file_get_contents( $svg_path );
$icon = preg_replace( '/#[0-9a-f]{3,6}/mi', $color, $icon );   // $color from a shortcode

// 11. Stored values into script and style contexts.
$transition = get_post_meta( $id, 'seo_slider_transition', true );
$text       = get_post_meta( $id, 'seo_slider_text', true );
$js  = "jQuery('.s-$id').slick({ speed: $transition });";
$css = ".s-$id p { color: $text; }";
wp_add_inline_script( 'my-slider', $js );
wp_add_inline_style( 'my-slider', $css );
```

## Secure pattern

```php
<?php
// 1. Escape per attribute, at the point of emission, with the encoder that
//    matches the destination.
add_shortcode( 'mybox', function ( $atts ) {
    $a = shortcode_atts( array( 'cls' => '', 'title' => '' ), $atts );
    return sprintf(
        '<div class="%1$s" title="%2$s">%3$s</div>',
        esc_attr( $a['cls'] ),
        esc_attr( $a['title'] ),
        esc_html( $a['title'] )
    );
} );

// 2. A tag name is not escapable - validate it against an allow-list.
//    Validation beats sanitization, and for structural tokens it is the only option.
function render_my_block( $attributes ) {
    $allowed = array( 'h2', 'h3', 'h4', 'p', 'div' );
    $tag = in_array( $attributes['titleTag'] ?? '', $allowed, true )
        ? $attributes['titleTag']
        : 'h2';
    return sprintf(
        '<%1$s class="%2$s">%3$s</%1$s>',
        $tag,
        esc_attr( $attributes['titleClass'] ?? '' ),
        esc_html( $attributes['text'] ?? '' )
    );
}

// 3. Sanitize every field on the way in - and still escape on the way out.
add_action( 'save_post', function ( $post_id ) {
    if ( ! current_user_can( 'edit_post', $post_id ) ) { return; }
    check_admin_referer( 'my_caption_save', 'my_caption_nonce' );
    update_post_meta( $post_id, '_caption', array(
        'caption_text' => sanitize_text_field( wp_unslash( $_POST['caption_text'] ) ),
        'source_text'  => sanitize_text_field( wp_unslash( $_POST['source_text'] ) ),
        'source_url'   => sanitize_url( wp_unslash( $_POST['source_url'] ) ),
    ) );
} );

// Better still, declare the shape once so every writer is covered:
register_post_meta( 'post', 'subtitle', array(
    'type'              => 'string',
    'single'            => true,
    'show_in_rest'      => true,
    'sanitize_callback' => 'sanitize_text_field',
    'auth_callback'     => function ( $allowed, $meta_key, $post_id ) {
        return current_user_can( 'edit_post', $post_id );
    },
) );

// 4. Escape at every read.
echo esc_html( get_post_meta( get_the_ID(), 'subtitle', true ) );
echo wp_kses_post( get_option( 'my_plugin_banner_html' ) );   // if it must carry HTML

// 5. Keys need escaping too, and the attribute context needs esc_attr().
foreach ( $post_meta as $meta_key => $value ) : ?>
    <td><?php echo esc_html( $meta_key ); ?></td>
    <a data-id="<?php echo esc_attr( $meta_key ); ?>"
       id="edit-<?php echo esc_attr( sanitize_html_class( $meta_key ) ); ?>">Edit</a>
<?php endforeach;

// 6. Escape the ARGUMENT. The format string is a constant; use the i18n variant.
printf(
    /* translators: %s: author display name */
    esc_attr__( 'View all posts by %s', 'my-plugin' ),
    esc_attr( get_the_author() )
);

// 7. Never decode entities on a value bound for markup. If HTML is genuinely
//    wanted, allow-list it instead.
echo '<a href="' . esc_url( 'mailto:' . sanitize_email( $email ) ) . '">'
   . wp_kses_post( $atts['display'] ) . '</a>';

// 8. Keep the array. Named reads make provenance visible to every reviewer.
$user_data = (array) $auth->userData; ?>
<input type="text" id="phone" value="<?php echo esc_attr( $user_data['phone'] ); ?>" />

<?php
// 9. href gets esc_url(), link text gets esc_html(). One value, two encoders.
printf( '<li><a href="%s">%s</a></li>',
    esc_url( $item->get_permalink() ),
    esc_html( $item->get_title() )
);

// 10. A colour is a constrained shape - validate it, do not try to escape it.
//     sanitize_hex_color() returns NULL (not '') when invalid, so test explicitly.
$color = sanitize_hex_color( $atts['color'] );
if ( null !== $color ) {
    $icon = preg_replace( '/#[0-9a-f]{3,6}/mi', $color, $icon );
}

// 11. Script and style contexts: emit JSON and let it supply its own quoting;
//     constrain style values numerically.
$opts = array(
    'speed' => absint( get_post_meta( $id, 'seo_slider_transition', true ) ),
    'id'    => absint( $id ),
);
wp_add_inline_script(
    'my-slider',
    'window.mySlider = ' . wp_json_encode( $opts ) . ';',
    'before'
);
$text = sanitize_hex_color( get_post_meta( $id, 'seo_slider_text', true ) );
if ( null !== $text ) {
    wp_add_inline_style( 'my-slider', sprintf( '.s-%d p { color: %s; }', absint( $id ), $text ) );
}
```

### Escaper selection table

| Where the value lands | Use | Do not use |
| --- | --- | --- |
| Text between tags (`<p>HERE</p>`) | `esc_html()` | - |
| Any attribute value (`class`, `value`, `data-*`, `title`, `alt`, `id`) | `esc_attr()` | `esc_html()` - not the documented control, and useless on an *unquoted* attribute |
| `href`, `src`, `action`, `formaction`, `poster` | `esc_url()` | `esc_attr()` alone - it does not strip `javascript:` |
| A URL being stored, or passed to an HTTP client / redirect | `sanitize_url()` (alias `esc_url_raw()`) | never as an output escaper |
| Inside a quoted JavaScript string literal | `esc_js()` | `esc_html()`, `esc_attr()` |
| A whole JavaScript value | `wp_json_encode()`, emitted without surrounding quotes | string concatenation, `esc_js()` |
| Inside `<textarea>` | `esc_textarea()` | `esc_html()` (mangles entities on round-trip) |
| Inside `<style>` or a `style="..."` value | numeric cast / `sanitize_hex_color()` / strict allow-list | any `esc_*` alone - CSS `url()` and `expression()` need validation |
| An HTML **tag name** or attribute name | `in_array( $v, $allowed, true )` | nothing else - there is no escaper for structure |
| A CSS class token | `sanitize_html_class()`, then `esc_attr()` | `esc_attr()` alone if the value must be a single token |
| XML / RSS node | `esc_xml()` | - |
| HTML that must survive (rich text) | `wp_kses_post()` / `wp_kses( $h, $allowed )` | `esc_html()` (destroys the markup) |
| A numeric id | `absint()` / `(int)` | anything else - a cast is stronger than an escaper |

Two rules that catch most of the residual mistakes:

- **`wp_kses_post()` output is safe as a text node only.** Dropping it into an
  attribute without `esc_attr()` is still a break-out.
- **Never escape twice, and never escape at assignment.** If a value arrives
  already escaped, fix the producer. The handbook's sanctioned exception is a
  variable deliberately suffixed `_escaped`, `_safe` or `_clean`.

## Real-world case studies

Every snippet below was read from the WordPress plugin repository at the stated
tag or revision. (`plugins.trac.wordpress.org` serves a JavaScript browser
challenge to non-browser clients; the same bytes are served by
`plugins.svn.wordpress.org` at `<slug>/tags/<version>/<path>`, or at
`<slug>/trunk/<path>?p=<rev>` for a historical trunk revision. The trac URL is
recorded as `code_ref` because it is the canonical human-readable location.)

### The anti-escaper (CVE-2023-7070)

`https://plugins.trac.wordpress.org/browser/email-encoder-bundle/tags/2.1.9/core/includes/classes/class-email-encoder-bundle-run.php#L518`

```php
$display  = html_entity_decode( $atts['display'] );                                  // line 518
$noscript = html_entity_decode( $atts['noscript'] );                                 // line 524
$class_name .= ' class="' . esc_attr( $custom_class ) . '"';                         // line 528  SAFE
$mailto = '<a href="mailto:' . $email . '"'. $class_name . '>' . $display . '</a>';  // line 529  VULNERABLE
```

Line 528 escapes a plugin setting correctly. Line 529, immediately below,
concatenates `$display` - which line 518 just entity-*decoded* - into the element
body, and `$email` into an `href` with no `esc_url()`. The decode is the whole
bug: whatever the editor or KSES left encoded is turned back into live markup one
statement before it reaches the page.

Read this as the general lesson: an `html_entity_decode()` on a value bound for
markup is not a missing escape, it is a *removed* escape, and it defeats every
control upstream of it. XSSS-006 exists for exactly this shape and costs
0.06 hits per KLOC to run.

### The key, not the value (CVE-2024-6264)

`https://plugins.trac.wordpress.org/browser/post-meta-data-manager/tags/1.2.3/includes/admin/html/pmdm_wp_display_post_metadata_html.php#L42`

```php
foreach ( $post_meta as $meta_key => $value ) {
    ...
    <td><?php echo esc_html( $meta_key ); ?></td>                                   // line 39  SAFE
    <td><?php echo esc_html( var_export( $value, true ) ); ?></td>                   // line 40  SAFE
    <a href="javascript:;" data-id="<?php echo $meta_key; ?>"
       id="edit-<?php echo $meta_key; ?>" class="edit-meta">Edit</a>                 // line 42  VULNERABLE
    ...
    <h1><strong>Currently you are editing</strong>: <?php echo $meta_key; ?></h1>    // line 47  VULNERABLE
```

Three things make this the most instructive case in the file.

First, **the sink is an array key.** A reviewer looking for "unescaped meta
values" reads lines 39-40, sees `esc_html()` on both, and moves on. The
attacker-controlled string is the key of the `foreach`, and it is printed raw
eight characters later.

Second, **lines 39 and 42 are the same value.** Escaping is per output site.
"This file escapes things" is not evidence about line 42.

Third, the file elsewhere (lines 66, 68) reaches for
`htmlspecialchars( $v, ENT_QUOTES )` rather than `esc_attr()`. That happens to be
adequate here, but it is a signal worth noting during triage: a codebase using
raw PHP escapers instead of the WordPress ones is a codebase where nobody checked
the context-to-encoder mapping.

### Escaping the wrong argument (CVE-2023-1404)

`https://plugins.trac.wordpress.org/browser/show-posts/tags/1.6/includes/atw-showposts-sc.php#L368`

```php
printf( __( '... <a class="url fn n" href="%5$s" title="%6$s" rel="author">%7$s</a> ...', 'show-posts' ),
    esc_url( get_permalink() ),                                        // line 363  SAFE
    ...
    sprintf( esc_attr( __( 'View all posts by %s', 'show-posts' ) ), get_the_author() ),   // line 368  VULNERABLE
    esc_html( get_the_author() )                                       // line 369  SAFE
);
```

Line 368 and line 369 use the same untrusted value, `get_the_author()` - the
profile display name, which any registered user can set on their own account. Line
369 escapes it. Line 368 wraps `esc_attr()` around the *format string*, which is a
translated constant, and passes the display name in bare. The result lands in a
`title` attribute.

This is the hardest shape in the class to catch by eye, because the line
visibly contains `esc_attr(`. Rule XSSS-007 anchors on the structure - an escaper
opening the argument list of `printf`/`sprintf` with a bare `$` after the comma -
and costs 0.04 hits per KLOC.

### One statement, two attributes, one escaper (CVE-2023-3387)

`https://plugins.trac.wordpress.org/browser/lana-text-to-image/tags/1.0.0/lana-text-to-image.php#L97`

```php
$classes = array_merge( $classes, $a['class'] );                       // line 90
...
$image = sprintf( '<img src="data:image/png;base64,%s" class="%s" alt="%s">',
    base64_encode( $image_data ),
    implode( ' ', $classes ),                                          // line 97  VULNERABLE
    esc_attr( $a['alt'] )                                              // line 97  SAFE
);
```

`$a` is the `shortcode_atts()` result, so `$a['class']` and `$a['alt']` have
identical provenance and identical trust. In one call, one is escaped and one is
not. The unescaped one passes through `preg_split()` and `implode()` first, which
is likely why it read as "processed" to the author - neither function escapes
anything.

### The sink that is not an echo (CVE-2024-0255)

`https://plugins.trac.wordpress.org/browser/wp-recipe-maker/tags/9.1.0/includes/public/class-wprm-icon.php#L52`

```php
$icon = file_get_contents( $source['dir'] . '/' . $keyword_or_url . '.svg' );   // line 41
...
$icon = '<img src="' . esc_attr( $keyword_or_url ) . '" alt="" data-pin-nopin="true"/>';  // line 48  SAFE
...
if ( $color ) {
    $icon = preg_replace( '/#[0-9a-f]{3,6}/mi', $color, $icon );                // line 52  VULNERABLE
}
return $icon;                                                                   // line 55
```

The author clearly knew about escaping - line 48 uses `esc_attr()`. The bug is at
line 52, where a shortcode attribute is the *replacement* argument of a
`preg_replace()` whose subject is SVG markup. Every hex colour in the SVG is
swapped for the attacker's string, and the result is returned as markup.

Three lessons:

1. **Output sinks are not only `echo`.** `preg_replace`, `str_replace`,
   `sprintf`, `wp_add_inline_script`, `wp_send_json`, and template engines all
   emit. A grep anchored on `echo` finds none of them.
2. **Escaping is the wrong tool here anyway.** A colour has a known shape;
   `sanitize_hex_color()` (which returns `null`, not `''`, on failure) is the
   correct control, and validation beats sanitization beats escaping whenever the
   value has a shape.
3. With `preg_replace` specifically, `$` and `\` in the replacement are
   *backreferences*, so an untrusted replacement has a second failure mode beyond
   XSS.

### Escaping present, context wrong (CVE-2024-0792)

`https://plugins.trac.wordpress.org/browser/shortcodes-ultimate/tags/7.0.1/includes/shortcodes/feed.php#L78`

```php
$feed  = fetch_feed( $atts['url'] );                                   // line 62
$items = $feed->get_items( 0, (int) $atts['limit'] );                  // line 68
foreach ( $items as $item ) {
    $output .= sprintf(
        '<li><a href="%s" target="_%s" title="%s">%s</a></li>',
        esc_attr( $item->get_permalink() ),                            // line 78  VULNERABLE
        sanitize_key( $atts['target'] ),                               // line 79  SAFE
        esc_attr( $item->get_description() ),                          // line 80  SAFE
        wp_kses_post( $item->get_title() )                             // line 81  SAFE
    );
}
```

Four arguments, four different controls, three of them right. Line 78 puts
`esc_attr()` on a value that lands in `href`. `esc_attr()` HTML-encodes; it does
not touch the URL scheme, so `javascript:alert(1)` survives it intact. The fix is
`esc_url()`, which runs `wp_allowed_protocols()` and strips `javascript:`,
`data:` and `vbscript:`.

Note also the delivery: a Contributor writes `[su_feed url="https://attacker/"]`
into a draft, and the *server* fetches that feed and renders the attacker's
`<link>` elements. The untrusted store here is a remote document, reached because
an attacker-supplied URL was accepted.

**This shape will never appear in any "missing escape" scan.** Only a
context-aware read finds it. Rule EXTRA in the detection guidance below
(`esc_attr\s*\(\s*[^);]*(url|Url|URL|link|Link|permalink|href|src)`) is a cheap
name-based heuristic that catches a useful fraction at 0.07 hits per KLOC.

### The write side (CVE-2023-5669)

`https://plugins.trac.wordpress.org/browser/featured-image-caption/trunk/classes/MetaBox.php?rev=2300545#L91`

```php
if ( ! current_user_can( 'edit_post', $post_id ) ) { return $post_id; }   // line 83  (auth IS checked)
...
$caption = array(
    'caption_text' => $_POST[ CCFIC_KEY . '_caption_text' ],             // line 91  raw
    'source_text'  => $_POST[ CCFIC_KEY . '_source_text' ],              // line 92  raw
    'source_url'   => esc_url( $_POST[ CCFIC_KEY . '_source_url' ] ),    // line 93  hardened
    'new_window'   => ( ! empty( $_POST[ CCFIC_KEY . '_new_window' ] ) ? true : false ),  // line 94  cast
);
update_post_meta( $post_id, '_' . CCFIC_KEY, $caption );                 // line 98
```

The nonce and capability checks are both present and correct - this is not an
authorization bug. Two of four fields are hardened and two are stored verbatim,
and the shortcode that renders them later escapes nothing either.

Worth noting that `esc_url()` on line 93 is itself the wrong function for a write
(`sanitize_url()` is the storage-side variant; `esc_url()` converts `&` to `&amp;`
in the database). Even the correct-looking line is a context error.

Rule XSSS-008 targets exactly this line shape and returned **0 hits across 1.47M
LOC** of mature plugin code - it is silent on reviewed code, so any hit is a write
path nobody looked at.

### `extract()` hides the provenance (CVE-2024-1985)

`https://plugins.trac.wordpress.org/browser/simple-membership/tags/4.4.2/views/edit-v2.php#L103`

```php
$auth      = SwpmAuth::get_instance();
$user_data = (array) $auth->userData;                    // line 3   database row
extract( $user_data, EXTR_SKIP );                        // line 5   row -> local variables
...
<input type="text" id="phone" value="<?php echo $phone; ?>" name="phone" />              // line 103
<input type="text" id="address_street" value="<?php echo $address_street; ?>" ... />      // line 112
<input type="text" id="address_city" value="<?php echo $address_city; ?>" ... />          // line 121
<input type="text" id="address_state" value="<?php echo $address_state; ?>" ... />        // line 130
```

Line 5 is the interesting one. After `extract()`, `$phone` is syntactically
indistinguishable from a local variable the file computed itself. Every downstream
`echo $phone;` reads as benign. The provenance - an untrusted member record whose
fields anyone can set through open registration - is visible only at line 3, a
hundred lines away.

Because registration is open to anonymous visitors, the write is
unauthenticated and the read happens on a page an administrator visits. That is
the `PR:N / UI:R` variant of this class, and it scores higher than the
Contributor case for that reason.

For an auditing agent the rule is: **`extract()` in a template file invalidates
variable-name-based reasoning for the rest of the file.** Grep `extract\s*\(` and
treat every bare `echo $var` below it as untrusted until proven otherwise.

### Stored values in script and style contexts (CVE-2023-5707)

`https://plugins.trac.wordpress.org/browser/seo-slider/trunk/includes/shortcode.php?rev=2367856#L68`

```php
$dots       = ( get_post_meta( $id, $prefix . 'dots', true ) ? 'true' : 'false' );   // line 50  SAFE (cast)
$arrows     = ( get_post_meta( $id, $prefix . 'arrows', true ) ? 'true' : 'false' ); // line 51  SAFE (cast)
$duration   = get_post_meta( $id, $prefix . 'duration', true );                      // line 55  raw
$transition = get_post_meta( $id, $prefix . 'transition', true );                    // line 56  raw
$overlay    = get_post_meta( $id, $prefix . 'overlay', true );                       // line 59  raw
$text       = get_post_meta( $id, $prefix . 'text', true );                          // line 60  raw

$js = "
jQuery( document ).ready( function($) {
    $( '.slick-slider-$id' ).slick( {
        dots: $dots,
        speed: $transition,                                                          // line 68  VULNERABLE
        autoplaySpeed: $duration,                                                    // line 71  VULNERABLE
    } );
} );
";
$css = "
.slick-slider-$id li { color: $text; }                                               // line 94  VULNERABLE
.slick-slider-$id .slick-overlay { background-color: $overlay; }                     // line 97  VULNERABLE
";
wp_add_inline_script( seo_slider_get_slug(), $js );                                   // line 109
wp_add_inline_style( seo_slider_get_slug(), seo_slider_minify_css( $css ) );          // line 115
```

Twelve meta reads. Five are wrapped in a ternary that collapses them to the
literal strings `'true'` or `'false'` - accidentally perfect hardening. The other
seven go through raw, into a **JavaScript object literal** (lines 66-72) and a
**CSS block** (lines 82-103).

The teaching point is that `esc_html()` and `esc_attr()` would both be wrong
fixes for line 68. Neither escapes a backslash, neither stops `</script>` from
terminating the block, and an attacker does not need any HTML syntax at all -
`0, x: alert(1), y:` is valid JavaScript inside that object literal. The correct
constructions are `absint()` for the numeric options, `wp_json_encode()` for the
whole options object, and `sanitize_hex_color()` for the colours.

Line 123 of the same file - `class="slick-slider-<?php echo esc_attr( $id ); ?>"` -
shows the author escaping correctly in the HTML context a few lines later. Same
file, same author, right answer in one context and no answer in the other.

Note also that `wp_add_inline_script()` is an output sink even though it contains
no `echo`. See `WP-XSS-DOM` for the client-side half of this story.

### Corroborating records read in earlier passes

These were verified against NVD and read from the repository during the project's
first research pass (`research/notes_xss.md`), and are recorded here as evidence
that the sub-patterns recur independently rather than as fresh case studies:

- **CVE-2023-5706** (6.4, Contributor+) - a block `render_callback` used
  `$attributes['ancestorTitleTagName']` as an unvalidated **tag name** and
  `$attributes['ancestorTitleClassName']` as an unescaped class, while correctly
  `esc_html()`-ing the text node three lines later.
  <https://nvd.nist.gov/vuln/detail/CVE-2023-5706>
- **CVE-2024-1276** (6.4, Contributor+) - a page-builder widget setting from
  `_elementor_data` post meta concatenated into `<i class="...">`, seven lines
  above a correctly escaped `src`/`alt` pair.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-1276>
- **CVE-2024-12527** (6.4, Contributor+) - the minimal case:
  `'<div data-pp-guid="' . $atts['guid'] . '"></div>'`.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-12527>
- **CVE-2023-4960** (5.4, Contributor+) - seven adjacent assignments inside a
  `<script>` block, six wrapped in `esc_attr()` and one not; the six "safe" lines
  are themselves a context error, since `esc_attr()` is not the JavaScript
  escaper. <https://nvd.nist.gov/vuln/detail/CVE-2023-4960>
- **CVE-2024-1852** (6.1, unauthenticated) - the `X-Forwarded-For` request header
  logged to storage and rendered on a user-profile admin screen. Headers are
  untrusted input; this is the same class with an unusual source.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-1852>

## Detection guidance

### Measurement basis

All hit rates below were measured with Python's `re` and cross-checked with
ripgrep (Rust regex) against **1,470,620 lines of PHP** from seven large,
actively maintained, heavily audited plugins - WooCommerce, Yoast SEO,
UpdraftPlus, Contact Form 7, WP Super Cache, Elementor and WPForms Lite - with
`vendor/` and `node_modules/` excluded. This is a **negative corpus**: nearly
every hit is a false positive by construction, so the number is a noise floor,
not a detection rate. Each rule was also run against a paired fixture of
vulnerable and safe lines derived from the case studies above; all nine rules
match every intended vulnerable line and none of the safe lines.

| Rule | Shape | Hits / 1.47M LOC | Per KLOC |
| --- | --- | ---: | ---: |
| naive `echo` anywhere on a line with a `$` | baseline | 4757 | 3.23 |
| XSSS-001 | attribute closed, bare `$var` concatenated | 968 | 0.66 |
| XSSS-003 | `{$var}` interpolated inside an attribute | 584 | 0.40 |
| XSSS-005 | `$atts['x'] .` / `{$atts['x']}` | 14 | 0.01 |
| XSSS-006 | entity decoder on a variable | 95 | 0.06 |
| XSSS-009 | variable as a `preg_replace` replacement | 82 | 0.06 |
| XSSS-007 | escaper wrapping the printf format string | 60 | 0.04 |
| XSSS-002 | `href`/`src`/`action` + bare `$var` | 26 | 0.02 |
| XSSS-004 | `echo get_post_meta()` / `get_option()` … | **1** | 0.00 |
| XSSS-008 | superglobal straight into meta/option | **0** | 0.00 |

Two supplementary greps worth running by hand, measured on the same corpus:

| Grep | What it finds | Hits | Per KLOC |
| --- | --- | ---: | ---: |
| `esc_attr\s*\(\s*[^);]*(url\|Url\|URL\|link\|Link\|permalink\|href\|src)` | `esc_attr()` on something named like a URL - the CVE-2024-0792 shape | 104 | 0.07 |
| `=\s*\\?["'][^"']*["']\s*\.\s*wp_kses(_post\|_data)?\s*\(` | KSES output placed into an attribute | 14 | 0.01 |

### The controlling idea

`echo esc_attr( $x );` and `echo $x;` differ at exactly one character position -
the token immediately after the output keyword. The same trick generalises to
concatenation: `. esc_attr( $x )` has an identifier after the dot, `. $x` has a
`$`. Every rule here anchors on *that* position rather than on "is there a
variable somewhere on this line", which is what takes the baseline from 4757 hits
to 968 (XSSS-001) or to single digits (XSSS-002, -004, -008).

The important consequence is that **the escaper allow-list never appears inside
the regex.** It only appears in the second stage, when an agent looks at the
wrapper that *was* found and asks whether it was correct for the destination -
which is a much smaller question, and one no regex can answer.

### Triage procedure for XSSS-001 / XSSS-003 / XSSS-005 hits

1. **Walk back to the assignment.** A literal, an `(int)`/`absint()` cast, or an
   `esc_*`/`wp_kses*` call there - drop it. The handbook-sanctioned `_escaped`,
   `_safe`, `_clean` suffixes are a legitimate marker of the pre-escaped case.
2. **Trace to a source.** If the chain reaches `get_post_meta`, `get_option`,
   `get_user_meta`, `get_term_meta`, `get_comment_meta`, `$wpdb->get_*`, a
   `$atts`/`$attributes`/`$settings` array, `get_the_author*`, `get_comment_*`,
   or a REST/AJAX payload, keep it. If it reaches `$_GET`/`$_POST` and is echoed
   in the *same* request, that is `WP-XSS-R`, not this class.
3. **Identify the output context** - text node, attribute, URL attribute,
   `<script>`, `<style>`, `<textarea>` - and pick the encoder from the table
   above. This is not derivable from the regex hit.
4. **Establish the attacker position.** Can a Contributor set this value? A
   shortcode attribute, a block attribute, a page-builder setting, post meta on
   their own draft, and their own profile display name all say yes. A
   `manage_options`-gated settings field says Administrator, which is still a
   finding in multisite (no `unfiltered_html`) and still worth reporting on
   single site, but at a lower severity.
5. **Check for a suppression comment.** `// phpcs:ignore WordPress.Security.EscapeOutput`
   means the author considered it. Not proof of safety, but weight the hit down;
   its absence in a codebase that annotates elsewhere is a reason to weight it up.

### What these regexes MISS - read code manually when you see these

- **Escaping through a project wrapper** - `$this->e( $x )`, `Plugin::out( $x )`,
  `render( $tpl, $vars )`, a Twig/Blade/Timber template. Reads as escaped when it
  is not, or vice versa. Grep for a local helper that wraps `esc_*` before
  reviewing any hits.
- **Escaping applied several lines earlier.** Regex cannot do dataflow. This is
  the main source of XSSS-001's 968 hits.
- **Heredoc and nowdoc bodies.** `{$var}` inside `<<<HTML … HTML;` is a real sink
  and XSSS-003 only catches it when the attribute and the interpolation share a
  line. Grep `<<<` separately and read every body.
- **`.js`, `.twig`, `.html` templates and `wp.template` markup.** A PHP-only
  sweep misses everything in `WP-XSS-DOM`. Several CVEs in this family have their
  trac anchors inside a `.js` file.
- **`wp_localize_script()` / `wp_add_inline_script()` / `wp_send_json()`.** All
  three are output sinks with no `echo`. `wp_localize_script()` additionally
  **entity-decodes every scalar value**, so pre-escaping is silently undone.
- **`wp_kses_post()` output placed into an attribute.** Syntactically escaped,
  semantically the wrong context.
- **A custom `wp_kses( $x, $allowed )` allow-list** that adds `script`, `iframe`,
  `object`, `style`, or a wildcard attribute list. Read the array - it *is* the
  security boundary.
- **`extract()`.** Erases the provenance of every variable in scope.
- **Whether the value is Contributor-reachable.** That is the difference between
  a 6.4 CVE and a non-issue, and it is not a regex question. It requires reading
  the write path and the capability check on it.
- **Second-order storage** - a value written to a transient or option in one
  request and rendered in the next. The write and the read are usually in
  different files; only a taint-aware pass or manual review joins them.

## Audit checklist

- [ ] Run XSSS-002, XSSS-004 and XSSS-008 first. They are near-silent on
      maintained code (0.02, 0.00 and 0.00 per KLOC); treat every hit as a
      finding until disproved.
- [ ] Run XSSS-001, XSSS-003 and XSSS-005 and triage with the five-step
      walk-back. Budget roughly 1.1 hits per KLOC across the three.
- [ ] Grep for a project-local output helper wrapping `esc_*` and add it to the
      triage allow-list *before* reading any XSSS-001 results.
- [ ] Enumerate every write path into storage: grep
      `update_post_meta|add_post_meta|update_user_meta|update_term_meta|update_comment_meta|update_option|set_transient|\$wpdb->(insert|update|replace)`.
      For each, confirm a capability check, a nonce check, and a sanitizer.
- [ ] Enumerate every `add_shortcode\s*\(` and read each callback. Confirm
      `shortcode_atts()` is used, then confirm every attribute is escaped for its
      destination at the point of emission.
- [ ] Enumerate every `register_block_type` `render_callback` and every
      page-builder widget `render()`. `$attributes` and `get_settings_for_display()`
      results are Contributor-controlled.
- [ ] Grep `register_meta|register_post_meta` and check for a `sanitize_callback`
      and an `auth_callback`. Their absence means every writer is unguarded.
- [ ] Grep `html_entity_decode|htmlspecialchars_decode|wp_specialchars_decode`
      and confirm no decoded value reaches markup.
- [ ] Grep `extract\s*\(` and treat every bare `echo $var` after it as untrusted.
- [ ] Grep `<<<` for heredocs and read every interpolated variable in the body.
- [ ] Grep `wp_localize_script|wp_add_inline_script|wp_send_json` and trace each
      payload into the JavaScript that consumes it - then switch to `WP-XSS-DOM`.
- [ ] Grep `preg_replace|str_replace|str_ireplace` and check whether the SUBJECT
      is markup; if so, the replacement argument is an output sink.
- [ ] Re-check existing `esc_*` calls for **wrong-context** escaping: `esc_attr()`
      on `href`/`src`, `esc_attr()`/`esc_html()` inside `<script>`, `esc_html()`
      inside `<textarea>`, any `esc_*` inside `<style>`.
- [ ] Grep `wp_kses\s*\(` and read every custom `$allowed` array.
- [ ] For every tag name, attribute name, class token or callback name derived
      from stored data, confirm an `in_array( …, true )` allow-list. No escaper
      makes structure safe.
- [ ] For each confirmed finding, name the attacker's role (Contributor / Author /
      Administrator / unauthenticated) by reading the write path's capability
      check - severity and the multisite `unfiltered_html` question both depend
      on it.
- [ ] Confirm every proposed fix escapes at the point of emission, not at
      assignment: "escape when you echo, not before."
