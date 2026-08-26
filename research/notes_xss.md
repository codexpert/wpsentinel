# Research notes — XSS and Open Redirect classes

Scope: `WP-XSS-R`, `WP-XSS-S`, `WP-REDIRECT`.
Disclosure window: 2023-01-01 → 2026-08-26.
Compiled: 2026-08-26.

---

## 1. Sources actually used

| Source | How it was queried | Notes |
| --- | --- | --- |
| NVD REST API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` with `keywordSearch` + `pubStartDate`/`pubEndDate` in 120-day windows | Primary. Gives CVE ID, CVSS v3.1 vector, publish date, and — critically — the **reference URLs**, which for Wordfence-CNA entries include exact `plugins.trac.wordpress.org/browser/...#Lnnn` links. |
| `plugins.svn.wordpress.org` | Plain HTTP `GET` of `<slug>/tags/<version>/<path>` | Serves the *same* repository that trac browses, but without trac's bot challenge. Historical revisions of `trunk` are reachable at `/!svn/bc/<rev>/<slug>/trunk/<path>`, which is how pre-patch `trunk` code was recovered. |
| Patchstack database | `curl` of `patchstack.com/database/wordpress/plugin/<slug>/vulnerability/<slug>` | Server-rendered; CVE ID, CVSS, required privilege, patched version all present in HTML. |
| WordPress developer docs | `developer.wordpress.org/apis/security/escaping/`, `/sanitizing/`, `/reference/functions/wp_safe_redirect/` | Normative wording for the escaping API and the safe-redirect contract. |
| WordPress documentation | `wordpress.org/documentation/article/roles-and-capabilities/` | Authoritative statement on `unfiltered_html` across single-site vs multisite. |

### Sources that did NOT work
- `wordfence.com/threat-intel/...` HTML pages return `202` with an empty body to non-browser clients; the v2 intelligence feeds (`/api/intelligence/v2/vulnerabilities/{production,scanner}`) now return **410 Gone**, and v3 returns **401**. Wordfence data was therefore obtained indirectly, via the NVD records for which Wordfence is the CNA.
- `plugins.trac.wordpress.org` itself returns a JS browser-challenge (`403`) to `curl`. Trac URLs are still recorded as `code_ref` for provenance because they are the canonical human-readable location; the bytes were read from the SVN mirror.

---

## 2. Measured prevalence

Same methodology for all three classes: NVD `keywordSearch` of `WordPress <class phrase>`, summed over consecutive 120-day publication windows. Counts are `totalResults`, i.e. distinct CVE records.

| Window (publication date) | "Stored Cross-Site Scripting" | "Reflected Cross-Site Scripting" | "Open Redirect" |
| --- | ---: | ---: | ---: |
| 2023-01-01 → 2023-04-29 | 309 | 43 | 3 |
| 2023-04-29 → 2023-08-26 | 159 | 68 | 6 |
| 2023-08-26 → 2023-12-24 | 196 | 37 | 0 |
| 2024-01-01 → 2024-04-29 | 501 | 62 | 3 |
| 2024-04-29 → 2024-08-26 | 663 | 71 | 0 |
| **Total** | **1828** | **281** | **12** |

Ratio ≈ **6.5 : 1 : 0.04**.

Caveats worth carrying into the KB:
- Keyword search is CNA-phrasing-dependent. Wordfence and Patchstack both use the literal words "Stored Cross-Site Scripting"/"Reflected Cross-Site Scripting"; WPScan-CNA records often say only "does not escape ... which could lead to Reflected Cross-Site Scripting", which still matches. Open-redirect phrasing is more varied ("does not validate the redirection URL", "leading to an Open Redirect issue"), so 12 is a **floor**, not a true count. Even allowing generously for that, open redirect is one to two orders of magnitude rarer than stored XSS.
- Filtering NVD by `cweId=CWE-79` / `CWE-601` is unusable for this window: NVD's CWE enrichment backlog means windows after roughly mid-2024 return `totalResults: 0` for CWE filters while keyword search returns hundreds. Any future harvest must use keyword search, not `cweId`.
- The stored-XSS number is dominated by one sub-pattern: a shortcode / block / page-builder-widget attribute that a **Contributor** can set, rendered into markup without escaping. That sub-pattern alone accounts for the majority of the `PR:L` (low-privilege) CVSS vectors in the sample.

---

## 3. Escaping API — the context table that the whole XSS teaching rests on

From `developer.wordpress.org/apis/security/escaping/`, verbatim role statements:

- `esc_html()` — "Use anytime an HTML element encloses a section of data being displayed."
- `esc_attr()` — "Use on everything else that's printed into an HTML element's attribute."
- `esc_url()` — "Use on all URLs, including those in the src and href attributes of an HTML element."
- `esc_url_raw()` — "Use when storing a URL in the database" (NOT an output escaper, and NOT a redirect validator).
- `esc_js()` — "Use for inline Javascript."
- `esc_textarea()` — "Use this to encode text for use inside a textarea element."
- `esc_xml()` — "Use to escape XML block."
- `wp_kses()` — "Use to safely escape for all non-trusted HTML (post text, comment text, etc.). This preserves HTML."
- `wp_kses_post()` — "Alternative version of wp_kses() that automatically allows all HTML that is permitted in post content."
- `wp_kses_data()` — allows only the HTML permitted in post comments.

Timing rule, verbatim: "It is best to do the output escaping as late as possible, ideally as data is being outputted" and "You always want to escape when you echo, not before." The documented exception is to postfix a deliberately pre-escaped variable with `_escaped`, `_safe` or `_clean` — which doubles as a useful triage signal when reviewing scanner hits.

The sanitizing page says validation is preferred to sanitization, but contains **no** statement that sanitizing input substitutes for escaping output. That silence is itself the trap; see CVE-2024-12466 below.

### `sanitize_text_field()` is not an escaper
`_sanitize_text_fields()` handles `<` (via `wp_pre_kses_less_than()` + `wp_strip_all_tags()`), strips invalid UTF-8, strips percent-encoded octets, and trims. It does **not** touch `"` or `'`. A value that has been through `sanitize_text_field()` and is then printed inside a quoted HTML attribute can still break out with `" autofocus onfocus=... x="`. This is the exact mechanism of CVE-2024-12466.

---

## 4. `unfiltered_html` — the severity model for stored XSS

From `wordpress.org/documentation/article/roles-and-capabilities/`, verbatim: "In WordPress Multisite, only Super Admins have the `unfiltered_html` capability."

Role matrix as documented:

| Role | `unfiltered_html` (single site) | `unfiltered_html` (multisite) |
| --- | --- | --- |
| Super Admin | n/a | yes |
| Administrator | yes | **no** |
| Editor | yes | **no** |
| Author | no | no |
| Contributor | no | no |
| Subscriber | no | no |

Documented Contributor capability set is only `read`, `edit_posts`, `delete_posts` — i.e. write drafts, cannot publish, cannot upload. Author adds `publish_posts`, `upload_files`, `edit_published_posts`, `delete_published_posts`.

Consequence, and the reason Contributor+ stored XSS is treated as a genuine vulnerability rather than "working as intended": WordPress core deliberately runs post content from users **without** `unfiltered_html` through KSES (`content_save_pre` → `wp_filter_post_kses`). Core's own security boundary says a Contributor must not be able to get script into a page. Any plugin storage path that sidesteps that filter — post meta, plugin options, block attributes serialised in the block comment delimiter, page-builder settings, shortcode attribute strings — re-opens a hole core explicitly closed.

Why shortcode attributes slip past KSES: KSES operates on *tags*. A payload with no `<` in it, e.g. `[some_shortcode cls='" onmouseover=alert(1) x="']`, is invisible to KSES and arrives at the shortcode callback byte-for-byte. That is why nearly every shortcode-attribute stored XSS is an **attribute-context** break-out, not a `<script>` injection.

`wp_kses_post()` itself is not bypassable in the naive ways people assume — it strips `on*` handlers (they are not in `$allowedposttags` for any tag) and runs `wp_kses_bad_protocol()` over `href`/`src`, which kills `javascript:`. The realistic failure modes are:
1. Passing KSES output into an **attribute** without `esc_attr()`. KSES output is safe as a text node, not as an attribute value.
2. A hand-rolled `wp_kses( $x, $custom_allowed )` where `$custom_allowed` adds `script`, `iframe`, `object`, `style`, or a wildcard attribute list.
3. Calling `wp_kses()` with a widened `$allowed_protocols` array.
4. Applying `html_entity_decode()` *after* the sanitiser, which undoes the entity encoding that made the value safe. This is CVE-2023-7070 exactly.

---

## 5. `wp_redirect()` vs `wp_safe_redirect()`

From `developer.wordpress.org/reference/functions/wp_safe_redirect/`: `wp_safe_redirect()` "Performs a safe (local) redirect, using wp_redirect()" and "Checks whether the $location is using an allowed host, if it has an absolute path." If the host is not allowed, "the redirect defaults to wp-admin on the siteurl instead. This prevents malicious redirects which redirect to another host."

Mechanics that matter for detection:
- `wp_safe_redirect()` is a thin wrapper: `$location = wp_validate_redirect( $location, apply_filters( 'wp_safe_redirect_fallback', admin_url(), $status ) ); return wp_redirect( $location, $status, $x_redirect_by );`
- `wp_validate_redirect( $location, $fallback )` is the actual control. It normalises the URL, then compares the host against `wp_parse_url( home_url() )['host']` plus whatever the `allowed_redirect_hosts` filter adds. Not a match → `$fallback`.
- Therefore `wp_redirect( wp_validate_redirect( $x, home_url('/') ) )` is *equivalent* in safety to `wp_safe_redirect( $x )` and must not be flagged.
- `esc_url_raw()`, `sanitize_url()`, `sanitize_text_field()`, `urldecode()`, `wp_unslash()` around a redirect target provide **zero** host validation. `esc_url_raw( 'https://evil.example/' )` returns the string unchanged. Seeing one of these wrapped around `wp_redirect()` is a strong signal the author believed they had validated and had not.
- `allowed_redirect_hosts` is the sanctioned extension point. A filter callback that appends a request-derived value to the array defeats the entire mechanism, and is worth a dedicated check.
- Raw `header( 'Location: ' . $x )` bypasses the whole stack — no `wp_redirect` filter, no validation, no `x_redirect_by` header. Any occurrence in plugin code is worth reading.

---

## 6. Case-by-case code verification log

Every entry below was read from `plugins.svn.wordpress.org` at the stated tag/revision. Line numbers were confirmed against the trac line anchors cited by NVD.

### WP-XSS-R

**CVE-2025-2165** — `sh-email-alert` `tags/1.0/manage.php`, line 156 (matches trac `#L156`):
```php
<input type="hidden" name="mid" value="<?php echo $_GET['mid']; ?>">
```
Superglobal straight into a double-quoted attribute value. Needed: `esc_attr()`. Same file, line 138, also concatenates `$_GET['mid']` into an SQL string — an independent issue, out of scope here.

**CVE-2025-2481** — `mediaview` `tags/1.1.2/inc/forms/addMedia.inc.php`, lines 48 and 50 (trac `#L48`):
```php
<input type="hidden" name="key" value="<?php echo $_GET['id']; ?>"/>
...
<a href="?page=mediaview&view=viewshortcode&id=<?php echo $_GET['id']; ?>" class="mv-cancel">
```
Two distinct contexts from one parameter: attribute value → `esc_attr()`, and a URL query segment → `esc_url()` on the assembled URL (or `esc_attr( add_query_arg(...) )`). Good illustration that "escape the input once" is the wrong mental model.

**CVE-2025-2269** — `photo-gallery` `tags/1.8.34/admin/views/Editimage.php`, lines 28, 39, 40, 45 (trac `#L39`):
```php
$image_id = WDWLibrary::get('image_id', '0');
...
var file_type = window.parent.document.getElementById("input_filetype_<?php echo $image_id; ?>").value;
```
Inside a `<script>` block, within a JS double-quoted string. `esc_html()`/`esc_attr()` would be the *wrong* fix here (they leave `\` and do not neutralise `</script>`); the right fixes are `(int)`/`absint()` for a numeric id, `esc_js()` for a JS single/double-quoted string literal, or `wp_json_encode()` emitted without surrounding quotes.

**CVE-2024-12466** — `proofreading` `tags/1.2.1.1/admin/partials/proofreading-admin-display.php`, lines 50 and 103 (trac `#L103`):
```php
$nonce = sanitize_text_field(wp_unslash($_POST['nonce']));   // line 50
...
<input type="hidden" name="nonce" value="<?php echo $nonce ?>" />   // line 103
```
The canonical sanitize-is-not-escape case. `sanitize_text_field()` leaves `"` intact, so the attribute is escapable. Needed: `esc_attr( $nonce )` at line 103.

**CVE-2024-9208** — `enable-accessibility` `tags/1.4.1/includes/accessibility-attachments-alt.php`, lines 62, 64, 70 (trac `#L62`):
```php
<?php $query_string = remove_query_arg( array( 'oc-filter', 'paged' ) ); ?>   // 62
<a href="<?php echo esc_attr( add_query_arg( 'oc-filter', "all", $query_string ) ); ?>"    // 64  SAFE
<a href="<?php echo add_query_arg( 'oc-filter', "to-fix", $query_string ); ?>"             // 70  VULNERABLE
```
The single most instructive snippet found in this whole research pass. `remove_query_arg()` / `add_query_arg()` called without an explicit `$uri` argument default to `$_SERVER['REQUEST_URI']`, so the "internal" URL is attacker-controlled. Two sibling `<a>` tags, eight lines apart, one escaped and one not — proof that a detector must decide per-output-site, and that "this file already uses `esc_attr`" is not evidence of safety. Lines 146/152/155 in the same file repeat the unescaped form inside a pagination loop.

**CVE-2024-11375** — `wc1c-main` `tags/0.23.0/views/promo/activation.php`, lines 3 and 25 (trac `#L25`):
```php
$activation_url = get_home_url('', add_query_arg(['section' => 'settings', 'do_settings' => 'activation']));   // 3
...
<a href="<?php printf('%s', $activation_url); ?>"><?php printf('%s', $activation_url); ?></a>                  // 25
```
Same `add_query_arg`-defaults-to-`REQUEST_URI` root cause, but emitted via `printf('%s', ...)`. Any detector keyed only on `echo` misses this entirely. Note the same value needs *two different* escapers on one line: `esc_url()` in the `href`, `esc_html()` in the link text.

**CVE-2023-0937 / CVE-2024-12595 / CVE-2024-10815** — three separate WPScan-CNA records with identical wording: the plugin "does not escape the `$_SERVER['REQUEST_URI']` parameter before outputting it back in an attribute". No trac reference published for any of them, so no code was read; recorded as corroboration that the `REQUEST_URI`-into-attribute pattern recurs independently rather than as detailed case studies. NVD adds the qualifier "in old web browsers", because modern browsers percent-encode the path portion of `REQUEST_URI` — but the query string and, on some server configurations, the raw path still reach PHP undecoded, and `PHP_SELF` is not encoded at all.

### WP-XSS-S

**CVE-2023-7070** — `email-encoder-bundle` `tags/2.1.9/core/includes/classes/class-email-encoder-bundle-run.php`, lines 518, 524, 529 (trac `#L518`, `#L529`):
```php
$display = html_entity_decode( $atts['display'] );                                        // 518
$noscript = html_entity_decode( $atts['noscript'] );                                      // 524
$mailto = '<a href="mailto:' . $email . '"'. $class_name . '>' . $display . '</a>';       // 529
```
`html_entity_decode()` on a shortcode attribute actively reverses whatever entity encoding KSES or the editor left in place, then the result is concatenated into an `<a>` element. Line 555 in the same file shows the author *did* know about escaping — it uses `antispambot()` on both values — so the bug is an inconsistent branch, not ignorance. `$email` also lands in an `href` with no `esc_url()`.

**CVE-2023-4960** — `wc-multivendor-marketplace` `tags/3.6.1/views/store-lists/wcfmmp-view-store-lists.php`, line 207 (trac `#L207`), with the attribute read at `core/class-wcfmmp-shortcode.php` line 241:
```php
$per_row     = '<?php echo esc_attr($per_row); ?>';
$per_page    = '<?php echo esc_attr($limit); ?>';
$includes    = '<?php echo implode(",", $includes ); ?>';        // 207  VULNERABLE
$excludes    = '<?php echo esc_attr($excludes); ?>';
```
Inside a `<script>` block. Seven adjacent assignments, six escaped with `esc_attr()`, one not. Also a context error in the *safe* lines: `esc_attr()` is the wrong escaper for a JS string literal (`esc_js()` or `wp_json_encode()` is correct) — it happens to block the obvious payloads here but is not the documented control for that context.

**CVE-2023-5706** — `vk-blocks` `tags/1.63.0.1/inc/vk-blocks/build/blocks/ancestor-page-list/index.php`, lines 50, 54, 57 (all three trac anchors):
```php
$tag_name = $attributes['ancestorTitleTagName'];                 // 50
...
$class .= ' ' . $attributes['ancestorTitleClassName'];           // 54
...
$title .= '<' . $tag_name . ' class="' . $class . '">';          // 57
...
$title .= esc_html( $title_text );                               // 61  (text node IS escaped)
```
Block `render_callback` reading `$attributes`. Two failures at once: an unvalidated **tag name** (no allow-list) and an unescaped **class attribute**. Line 61 escapes the text node correctly, which is why a "does this file escape anything?" heuristic fails. Block attributes are stored inside the block's HTML comment delimiter in `post_content` as JSON; they are not post *markup*, so `wp_filter_post_kses` never inspects them — a Contributor draft carries them verbatim.

**CVE-2024-1276** — `essential-addons-for-elementor-lite` `tags/5.9.8/includes/Elements/Content_Ticker.php`, lines 812–822 (trac `#L815`):
```php
$arrow = '<i class="' . $settings['arrow'] . '"></i>';                                        // 815  VULNERABLE
...
$html .= '<img src="' . esc_url($arrow['url']) . '" alt="' . esc_attr(get_post_meta(...)) . '" />';  // 822  SAFE
```
Page-builder widget setting from `get_settings_for_display()`, i.e. from the `_elementor_data` post meta blob. Seven lines apart: one raw class attribute, one correctly escaped `src`/`alt` pair.

**CVE-2024-12527** — `perfect-portal-widgets` `tags/3.0.3/perfect-portal-widgets.php`, line 330 (trac `#L330`):
```php
$html = '<div data-pp-guid="' . $atts['guid'] . '"></div>';
```
Shortcode attribute into a `data-*` attribute. Minimal, textbook. Needed: `esc_attr()`.

**CVE-2026-3002** — retrieved from the Patchstack database page (server-rendered HTML). CVSS 6.5, required privilege **Contributor**, patched in 4.0.3, published 2026-08-25, stored XSS across multiple blocks. Recorded to show the pattern is still the top reported class in 2026, not a historical artifact. No code reference published.

### WP-REDIRECT

**CVE-2024-8761** — `share-this-image` `tags/2.03/includes/class-sti-shortlink.php`, lines 64, 74–81, 221 (trac `#L64`, `#L74`):
```php
add_action( 'wp_ajax_nopriv_sti_shortLinks', array( $this, 'ajax_add_link' ) );   // 64
...
public function ajax_add_link() {                                                 // 74
    $hash = sanitize_key( $_POST['hash'] );
    $link = $_POST['link'];                                                       // 81  no validation at all
    $this->insert_into_links_table( $hash, $link );
...
public function redirects() {                                                     // 194
    ...
    if ( $link ) { wp_redirect( $link, 301 ); }                                    // 221
```
A **stored** open redirect. `wp_ajax_nopriv_` makes the writer unauthenticated; `$hash` gets `sanitize_key()` but the URL itself gets nothing; the sink at line 221 is `wp_redirect()`, not `wp_safe_redirect()`. Two independent controls missing: no capability/nonce on the write, no host validation on the read. Also note the sink is reached via `template_redirect` on the public front end, so the redirect is a permanent 301 that browsers will cache.

**CVE-2024-12561** — `wecantrack` `trunk/WecantrackApp.php` at r3320551 (pre-patch; trac cites `#L66`). Recovered via `https://plugins.svn.wordpress.org/!svn/bc/3320551/wecantrack/trunk/WecantrackApp.php`:
```php
if (strlen($_GET['data']) > 50 && substr($_GET['afflink'], 0, 4) === 'http') {   // 66
    $this->parameter_redirect($_GET['afflink']);                                 // 67
}
...
private static function setRedirectHeader($link, $code = 301) {                  // 197
    header('Location: '.$link, true, $code);                                     // 198
}
```
The "validation" is `substr($link, 0, 4) === 'http'` — which `https://evil.example` satisfies. The sink is a raw `header('Location: ...')`, bypassing `wp_redirect()` entirely, so none of WordPress's redirect filters or validation ever run. Diffing r3320551 against r3320552 shows the fix was removal of the whole `afflink`/`link` parameter-redirect feature, not the addition of validation.

**CVE-2025-6238** — `ai-engine` `tags/2.8.4/labs/oauth.php`, lines 67, 92, 107, 118–119 (trac cites the file):
```php
$redirect_uri = $request->get_param( 'redirect_uri' );          // 67
...
if ( empty( $client_id ) || empty( $redirect_uri ) || empty( $code_challenge ) ) { ... }   // 78  presence check only
...
$redirect_url = add_query_arg( $redirect_params, $redirect_uri );   // 118
wp_redirect( $redirect_url );                                       // 119
```
OAuth `redirect_uri` taken from the request and never compared against a registered client URI. Because the authorisation `code` is appended as a query arg at line 118, this is not merely a phishing redirect: the code (and therefore an access token) is delivered to the attacker's host. Line 167 later compares `$code_data['redirect_uri'] !== $redirect_uri` at the token endpoint — but that compares the attacker's value to the attacker's own stored value, so it adds nothing. CVSS 8.0 rather than the usual 6.1 for this reason. Fix in 3321384 was to stop loading the OAuth class.

**CVE-2025-1488, CVE-2024-13888, CVE-2025-3433, CVE-2023-0552** — NVD records verified (IDs, CVSS vectors, descriptions, publication dates). `CVE-2025-1488` is the `redirect_to` login-flow parameter; `CVE-2023-0552` is login *and logout* redirection. No trac line anchors published for these, so no code was read; they are recorded as pattern corroboration.

---

## 7. Detection engineering — what was measured

### Corpus
256,198 lines of PHP across five large, actively maintained, heavily audited plugins (WooCommerce, Yoast SEO, UpdraftPlus, Contact Form 7, WP Super Cache) — i.e. a **negative** corpus where nearly every hit is a false positive by construction. Plus a hand-built fixture (`/private/tmp/wpsentinel-fixtures-xss/`) with paired vulnerable/safe lines for each pattern.

### Results

| Rule | Regex intent | Hits / 256k LOC | Reading |
| --- | --- | ---: | --- |
| naive `\becho\b.*\$` | "echo with a variable" | **3489** | Unusable. 13.6 hits per KLOC. |
| `echo`/`print` + superglobal directly | XSSR-001 | **0** | Zero hits in mature code. Any hit is near-certainly real. |
| `<?=` + superglobal | XSSR-002 | 0 | Same. |
| `echo`/`print` + bare `$var` + terminator | XSSR-003 | 203 | 0.79/KLOC. 94% quieter than naive. Reviewable. |
| `echo`/`print` + `add_query_arg`/`remove_query_arg` | XSSR-004 | **0** | vs **48** hits for `esc_url( add_query_arg( ... ) )` in the same corpus — the correct form is what mature code actually contains. |
| superglobal in a concatenation | XSSR-005 | 10 | Tight. |
| `printf`/`vprintf` with `$`-leading argument | XSSR-007 | 22 | Noisy on `%d`; low confidence. |
| attribute + inline `<?php echo $` | XSSR-009 | 49 | Reviewable, and precisely the CVE-2025-2165/2481 shape. |
| `'...' . $arr['k']` into markup | XSSS-001 | 323 | Medium. Needs the "is this inside a quoted attribute?" second pass. |
| `echo get_post_meta`/`get_option`/... | XSSS-003 | 1 | Extremely quiet. |
| `html_entity_decode($...)` | XSSS-004 | 38 | Every hit deserves a look; cheap. |
| `'...' . $var . '...'` | XSSS-006 | **1251** | Too noisy to act on alone. Secondary filter only. |
| `wp_redirect( $_GET[...] )` | REDIR-001 | **0** | Zero. |
| `wp_redirect( $var` | REDIR-002 | 6 | All six are triageable by hand in minutes. |
| raw `header('Location:` | REDIR-003 | 8 | All eight worth reading. |
| `wp_redirect( esc_url_raw( ...` etc. | REDIR-006 | 9 | High-value: author thought they validated. |

### The controlling insight

**Anchor on the token that immediately follows the output keyword, not on whether a variable appears anywhere on the line.**

`echo esc_html( $x );` and `echo $x;` differ in exactly one place: the character after `echo␣`. If it is `$`, nothing wrapped the value. If it is an identifier, *something* wrapped it, and the question becomes "was it the right escaper for this context?" — a much smaller, much higher-signal question than "is there a variable here?".

This single change takes `echo`-based XSS detection from 3489 hits to 203 on the same corpus (−94%) while still firing on every fixture true positive, and it is expressible without lookahead, which Rust's regex engine (and therefore ripgrep) does not support.

The corollary is that the escape-function allow-list never has to be enumerated inside the regex — which is what would have required a negative lookahead. It only has to be enumerated in the *second* stage, when a human or agent looks at the wrapper that was found and asks whether `esc_attr` was right for a `<script>` string literal (it was not — see CVE-2023-4960).

### Secondary triage signals discovered in the corpus
- `// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect` appears 7 times. Mature projects annotate deliberate `wp_redirect()` use. Presence of the annotation ⇒ the author considered it; absence ⇒ look harder. Same idea applies to `WordPress.Security.EscapeOutput` ignores.
- The docs-sanctioned `_escaped` / `_safe` / `_clean` variable-name suffix is a legitimate "already escaped" marker; treat `echo $foo_escaped;` as lower priority than `echo $foo;`.
- `return add_query_arg( ... );` is not an output sink and dominated an early version of XSSR-004. Dropping `return` from that rule took it from 47 hits to 0. Sink-vs-transport matters: only flag at the point of emission.
- Numeric format specifiers (`%d`, `%u`) in `printf` make the corresponding argument safe. That accounts for most of XSSR-007's noise.

### What the regexes cannot see
- Escaping done through a wrapper (`$this->e( $x )`, `MyPlugin::out( $x )`) reads as unescaped.
- Escaping applied several lines earlier and stored in a variable — the main source of XSSR-003's 203 hits.
- Template engines (Twig/Blade/Timber) and `.js`/`.twig` files. CVE-2025-0215's trac anchors point into a `.js` file, so a PHP-only sweep would have missed it entirely.
- Heredoc/nowdoc bodies with `{$var}` interpolation.
- `wp_kses_post()` output placed into an attribute — syntactically "escaped", semantically wrong context.
- Whether a shortcode/block/widget attribute is actually reachable by a Contributor. That is the difference between a 6.4 CVE and a non-issue, and it is not a regex question.
- Redirect targets that flow through a database round-trip (CVE-2024-8761). The write and the read are in different functions; only a taint-aware pass or manual review joins them.

---

## 8. Reusable commands

```bash
# NVD harvest (no API key: ~1 req / 6-10s, expect 429s; retry with backoff)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=WordPress%20Stored%20Cross-Site%20Scripting&pubStartDate=2025-01-01T00:00:00.000&pubEndDate=2025-04-29T00:00:00.000&resultsPerPage=500"

# read a plugin file at a released tag (trac blocks curl; SVN does not)
curl -s -H 'User-Agent: Mozilla/5.0' \
  "https://plugins.svn.wordpress.org/<slug>/tags/<version>/<path>.php"

# read trunk as it existed at an arbitrary revision (for pre-patch code)
curl -s -H 'User-Agent: Mozilla/5.0' \
  "https://plugins.svn.wordpress.org/!svn/bc/<rev>/<slug>/trunk/<path>.php"

# list released tags
curl -s "https://plugins.svn.wordpress.org/<slug>/tags/"
```
