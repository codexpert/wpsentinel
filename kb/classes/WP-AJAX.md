---
class_id: WP-AJAX
title: Unprotected admin-ajax Handlers Registered on wp_ajax_nopriv_
cwe: [CWE-862, CWE-306, CWE-284]
owasp: A01:2021-Broken Access Control
severity_typical: high
auth_required_typical: unauthenticated
prevalence_rank: 16
detection:
  - id: AJAX-001
    description: Handler registered on wp_ajax_nopriv_ — reachable by anyone on the internet
    regex: '[''"]wp_ajax_nopriv_'
    confidence: high
    false_positive_notes: >-
      Matches the quoted hook string wherever it appears, which is deliberate: it fires on
      the plain add_action( 'wp_ajax_nopriv_x', ... ) form, on concatenation
      ( 'wp_ajax_nopriv_' . $action ), on interpolation ( "wp_ajax_nopriv_$actionName" ), and
      on wrapper APIs such as $this->loader->add_action(...) and a plugin's own
      loader->my_add_action(...) that a rule anchored on ^\s*add_action would miss entirely.
      A hit is not automatically a vulnerability — some endpoints are legitimately public
      (a search suggest, a public form submit, a payment webhook) — but each one is an
      unauthenticated entry point that must be justified. The volume is low enough to
      enumerate every hit by hand in any plugin.
  - id: AJAX-002
    description: AJAX hook name assembled from a bare prefix — the action name is not greppable
    regex: 'add_action\s*\(\s*[''"]wp_ajax_?[''"]\s*\.'
    confidence: medium
    false_positive_notes: >-
      Catches add_action( 'wp_ajax_' . $action, ... ) and add_action( 'wp_ajax' . $x, ... ),
      where the registered action name exists only at runtime. Benign as a construct, but it
      means the endpoint inventory cannot be completed by grepping action names — you must
      read what feeds the variable, which is usually a route table, a $_REQUEST value, or a
      loop over a class's public methods. The _nopriv_ variant of this shape is already
      covered by AJAX-001; this rule exists to stop the inventory silently coming up short.
  - id: AJAX-003
    description: Every AJAX registration — the full endpoint inventory, including Subscriber-reachable ones
    regex: '[''"]wp_ajax_[a-zA-Z0-9_{$]'
    confidence: low
    false_positive_notes: >-
      Deliberately a superset of AJAX-001: it also matches the wp_ajax_ (logged-in) twin. That
      is the point. wp_ajax_{action} authenticates but does not authorize — it admits every
      Subscriber, which on a site with open registration, WooCommerce customers, LMS students
      or forum members is effectively the internet plus one signup form. Use this rule to
      build the inventory, then diff it against current_user_can() occurrences. Does not match
      the bare string 'wp_ajax' or admin_url('admin-ajax.php'), so it stays usable.
  - id: AJAX-004
    description: admin-post handler registered for logged-out callers
    regex: '[''"]admin_post_nopriv'
    confidence: high
    false_positive_notes: >-
      Same trust model as wp_ajax_nopriv_ and worth a separate rule because admin-post.php is
      designed for form submissions that perform a state change and redirect, so its handlers
      are far more likely to write than to read. Note it also matches the bare
      'admin_post_nopriv' hook (no action suffix), which fires when $_REQUEST['action'] is
      EMPTY — an easy endpoint to miss when enumerating by action name.
  - id: AJAX-005
    description: A nonce published into a page, i.e. readable by whoever can load that page
    regex: '[''"]nonce[''"]\s*=>\s*wp_create_nonce\s*\('
    confidence: medium
    false_positive_notes: >-
      Publishing a nonce to the page is how AJAX is supposed to work, so most hits are normal.
      The rule matters because a nonce is routinely the ONLY control on a nopriv handler, and
      then the real question is who can read it. Follow each hit to its wp_localize_script() /
      wp_add_inline_script() call and to the enqueue hook: wp_enqueue_scripts means every
      anonymous visitor, and an unconditional admin_enqueue_scripts means every logged-in user
      including Subscribers. Either way the nonce is not an access control.
  - id: AJAX-006
    description: Variable dispatch inside a handler — the sink is not statically reachable from the hook
    regex: '(->\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\(|::\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\(|\bcall_user_func(_array)?\s*\(\s*\$)'
    confidence: low
    false_positive_notes: >-
      Reclassified low by scripts/test_rules.py: this fires on correct code in
      tests/fixtures/safe.php, and kb/SCHEMA.md reserves high/medium for rules that stay
      silent there. No coverage is lost - the high-confidence rules in this class still
      cover the unambiguous shapes; this one is the worklist that needs triage.
      Common in framework code and often benign. It becomes critical when the dispatching
      function is a nopriv handler: one registration then exposes every method of the target
      class, and no sink-side rule can connect the hook to the sink because the edge does not
      exist until runtime. Whenever a hit sits inside an AJAX-001 handler, enumerate the full
      set of methods that can be selected and rate the worst one.
  - id: AJAX-007
    description: Ajax-context predicate used as an authorization guard
    regex: '\bif\s*\(\s*[!\s]*wp_doing_ajax\s*\(\s*\)|\bif\s*\(\s*defined\s*\(\s*[''"]DOING_AJAX[''"]'
    confidence: medium
    false_positive_notes: >-
      wp_doing_ajax() and DOING_AJAX answer "did this request come through admin-ajax.php".
      They are true for a completely anonymous request and carry no authorization value at
      all. Legitimate uses exist — suppressing output buffering, choosing a response format,
      skipping a redirect — so read the guarded block. If it writes anything, it is a finding.
      The same reasoning applies to is_admin(), which is covered by WP-AUTHZ AUTHZ-004.
fix_apis:
  - current_user_can()
  - check_ajax_referer()
  - wp_send_json_error()
  - wp_send_json_success()
  - is_user_logged_in()
  - wp_verify_nonce()
  - hash_equals()
examples:
  - cve: CVE-2026-12153
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A single nopriv registration exposed a generic dispatcher that resolved a request-supplied module name to a class and then invoked a request-supplied method name on it, one of which installed and activated an arbitrary plugin.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-12153
    code_ref: https://plugins.trac.wordpress.org/browser/learn-manager/tags/1.1.8/includes/ajax.php#L10
    root_cause: A nopriv hook wired to a variable-method dispatcher, so one registration published every method of every model class to anonymous callers.
  - cve: CVE-2025-2266
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: Two handlers in the same 49-line file were each registered on both the logged-in and the logged-out AJAX hook; the second performed an option write with no capability check, giving anonymous callers an arbitrary-option primitive.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-2266
    code_ref: https://plugins.trac.wordpress.org/browser/checkout-mestres-wp/tags/8.7.5/backend/core/base/ajax.php#L29
    root_cause: Reflexive double registration of an administrative action on wp_ajax_ and wp_ajax_nopriv_, where only one of the two handlers carried a capability check.
  - cve: CVE-2025-5304
    year: 2025
    severity: 9.8
    auth: unauthenticated
    summary: Five administrative user-management actions were each registered on the logged-out hook as well as the logged-in one, and the handlers verified only a nonce before granting administrator capabilities.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2025-5304
    code_ref: https://plugins.trac.wordpress.org/browser/project-notebooks/tags/1.1.3/includes/structure/admin/pto_admin_settings.php#L32
    root_cause: An admin-screen feature registered on wp_ajax_nopriv_, with a nonce mistaken for the access control.
  - cve: CVE-2026-4283
    year: 2026
    severity: 9.1
    auth: unauthenticated
    summary: A base class registered every subclass action on the logged-out hook by default, and one such action honoured a request flag that skipped the intended email-confirmation step and immediately anonymised the named account.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4283
    code_ref: https://plugins.trac.wordpress.org/browser/shapepress-dsgvo/tags/3.1.38/includes/class-sp-dsgvo-ajax-action.php#L64
    root_cause: Public exposure was the framework default rather than an explicit per-action decision, and the only control was a nonce printed on every page carrying the plugin's public shortcode.
  - cve: CVE-2026-18316
    year: 2026
    severity: 9.1
    auth: subscriber+
    summary: Fourteen administrative actions, including theme install, plugin install and ZIP import, were registered on the logged-out AJAX hook through a loader wrapper, guarded only by a nonce emitted into every admin page.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-18316
    code_ref: https://plugins.trac.wordpress.org/browser/solace-extra/tags/1.6.0/includes/class-solace-extra.php#L336
    root_cause: Bulk nopriv registration of installer actions via an indirection wrapper, with a globally readable nonce standing in for a capability check.
  - cve: CVE-2026-4003
    year: 2026
    severity: 9.8
    auth: unauthenticated
    summary: A dedicated "ajax nopriv" class handled public form saves; its unauthenticated-caller check only fired when the submitted user ID was empty, so supplying an ID reached update_user_meta() for any account.
    source_url: https://nvd.nist.gov/vuln/detail/CVE-2026-4003
    code_ref: https://plugins.trac.wordpress.org/browser/userspn/tags/1.0.31/includes/class-userspn-ajax-nopriv.php#L190
    root_cause: A nopriv endpoint whose authorization was one disjunct of a condition that also validated input, so attacker input decided whether the check applied.
---

## What it is

`add_action( 'wp_ajax_nopriv_{action}', $callback )` publishes `$callback` at
`/wp-admin/admin-ajax.php?action={action}` **for every anonymous request on the internet**.
No cookie, no nonce, no account, no rate limit. `admin_post_nopriv_{action}` does the same at
`/wp-admin/admin-post.php`. Registering an administrative operation there is the bug, and the
signature is at the **registration site**, not the sink.

That is why this is a class of its own rather than a subset of **WP-AUTHZ**. WP-AUTHZ asks
"does this handler check a capability before it acts". WP-AJAX asks the prior question:
"who can call it at all". The two are found by different greps, they live in different files,
and a handler can fail both independently. Keep the split in your head while auditing:

| Class | Question | Where the evidence lives |
|---|---|---|
| **WP-AJAX** (this) | Who can reach this function? | `add_action( 'wp_ajax_nopriv_…' )` |
| **WP-AUTHZ** | What does the function fail to check? | the function body |
| **WP-REST** | Does `permission_callback` authorise? | `register_rest_route( … )` |

The Wordfence taxonomy has no bucket for this pattern — these findings are counted inside
"Authorization Bypass" — so its prevalence rank of 16 is an artefact of the source
taxonomy, not a measure of rarity. In practice `wp_ajax_nopriv_` is one of the most common
starting points for a real unauthenticated finding, and it is the fastest one to enumerate:
a single grep gives you the complete list of a plugin's anonymous entry points.

## Why it happens in WordPress

- **The dispatcher provides no authorization.** `admin-ajax.php`, in full:
  `$action = $_REQUEST['action']; if ( is_user_logged_in() ) { do_action( "wp_ajax_{$action}" ); } else { do_action( "wp_ajax_nopriv_{$action}" ); }`.
  `is_user_logged_in()` only selects *which* of the two hooks fires. There is no capability
  check, no nonce check, no referer check anywhere in the file.
- **`WP_ADMIN` is `true` on `admin-ajax.php`.** It is defined before `wp-load.php` is even
  required, so `is_admin()` returns `true` for an anonymous AJAX request. Developers guard
  handlers with `is_admin()` believing it means "an administrator is here"
  (entry-points.md §1).
- **Double registration is a reflex.** The pattern
  `add_action( 'wp_ajax_x', 'h' ); add_action( 'wp_ajax_nopriv_x', 'h' );` is copied from
  tutorials, from the plugin's own working public endpoints, and from Stack Overflow answers
  that diagnose "my AJAX returns 0" — which is exactly what core returns when the `_nopriv_`
  hook is missing. The "fix" for a logged-out tester is to add the `_nopriv_` line, and the
  administrative endpoint next to it inherits the habit.
- **`GET` works.** The action name is read from `$_REQUEST`, so a handler the developer only
  ever calls by `POST` is invocable by `GET` — which makes it reachable from an `<img>` tag,
  a prefetch, or a crawler.
- **The action name may not exist in source.** `add_action( "wp_ajax_nopriv_$actionName", … )`
  and `add_action( 'wp_ajax_nopriv_' . $action, … )` are common in framework code, so an
  inventory built by grepping literal action names comes up short.
- **Registration is often indirected.** The WordPress Plugin Boilerplate's
  `$this->loader->add_action(...)`, and plugins' own `Helpers::ajaxAction()` or
  `Loader::my_add_action()` wrappers, mean the literal `add_action(` token is nowhere near
  the hook name. Rules must key on the quoted hook string, not on the function call.
- **A nonce is not authorization, and a public nonce is not even CSRF protection.** Every
  case study below has a nonce. Nonces on `nopriv` endpoints must be printed somewhere the
  anonymous caller can read them, or the endpoint would not work — which is the whole
  problem.

## Vulnerable pattern

```php
// The reflex. Two lines, one of which should not exist.
add_action( 'wp_ajax_example_export_users',        'example_export_users' );
add_action( 'wp_ajax_nopriv_example_export_users', 'example_export_users' );

function example_export_users() {
    // check_ajax_referer succeeds, because the nonce is printed on the front end
    // (it has to be — the endpoint is public).
    check_ajax_referer( 'example-nonce', 'nonce' );

    $rows = get_users( array( 'fields' => array( 'ID', 'user_login', 'user_email' ) ) );
    wp_send_json_success( $rows );          // no current_user_can() anywhere
}
```

```php
// Registration through a wrapper: the literal add_action() is in another file.
$this->loader->add_action( 'wp_ajax_action-import-zip',        $admin, 'import_zip' );
$this->loader->add_action( 'wp_ajax_nopriv_action-import-zip', $admin, 'import_zip' );
```

```php
// Framework default: subclasses become public unless they opt out.
public static function listen( $public = TRUE ) {
    $actionName = self::getActionName();
    add_action( "wp_ajax_$actionName", array( self::getClassName(), 'boot' ) );
    if ( $public ) {
        add_action( "wp_ajax_nopriv_$actionName", array( self::getClassName(), 'boot' ) );
    }
}
```

```php
// The worst shape: one nopriv registration exposing a variable-method dispatcher.
add_action( 'wp_ajax_nopriv_example_router', array( $this, 'route' ) );

function route() {
    $module = $_REQUEST['module'];
    $task   = $_REQUEST['task'];
    echo Example_Includer::get_model( $module )->$task();   // any method, any class
    die();
}
```

The last one is why a sink-side scan cannot replace a registration-side scan: there is no
static edge from the hook to `installPluginFromAjax()`. It only exists at runtime, chosen by
the attacker.

## Secure pattern

```php
/**
 * Rule 1: register the _nopriv_ hook ONLY for endpoints that are genuinely public
 *         AND read-only AND non-sensitive. Everything else gets one line, not two.
 */
add_action( 'wp_ajax_example_export_users', 'example_export_users' );   // no _nopriv_ twin

function example_export_users() {
    // Rule 2: authorize FIRST, and terminate on failure.
    if ( ! current_user_can( 'list_users' ) ) {
        wp_send_json_error( array( 'message' => 'forbidden' ), 403 );   // calls wp_die()
    }

    // Rule 3: then verify intent. The third argument makes the die explicit.
    check_ajax_referer( 'example-export', 'nonce', true );

    // Rule 4: then validate input.
    $role = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
    if ( $role && ! get_role( $role ) ) {
        wp_send_json_error( array( 'message' => 'unknown role' ), 400 );
    }

    wp_send_json_success( get_users( array(
        'role'   => $role,
        'fields' => array( 'ID', 'user_login' ),
    ) ) );
}
```

For an endpoint that really must be anonymous — a contact form, a search suggest, a
third-party webhook — the correct controls are different in kind, not merely absent:

```php
add_action( 'wp_ajax_nopriv_example_webhook', 'example_webhook' );
add_action( 'wp_ajax_example_webhook',        'example_webhook' );

function example_webhook() {
    // A remote service has no WordPress cookie, so a nonce is meaningless here.
    // Authenticate the PAYLOAD instead.
    $body = file_get_contents( 'php://input' );
    $sent = isset( $_SERVER['HTTP_X_EXAMPLE_SIGNATURE'] ) ? $_SERVER['HTTP_X_EXAMPLE_SIGNATURE'] : '';
    $mine = hash_hmac( 'sha256', $body, EXAMPLE_WEBHOOK_SECRET );

    // hash_equals(), never == or === on the raw strings: timing side channel.
    if ( ! $sent || ! hash_equals( $mine, $sent ) ) {
        wp_send_json_error( array( 'message' => 'bad signature' ), 401 );
    }

    // Replay protection: a signature alone lets an attacker resend a captured request.
    $event_id = isset( $_SERVER['HTTP_X_EXAMPLE_EVENT_ID'] ) ? sanitize_key( $_SERVER['HTTP_X_EXAMPLE_EVENT_ID'] ) : '';
    if ( ! $event_id || get_transient( 'example_seen_' . $event_id ) ) {
        wp_send_json_error( array( 'message' => 'replay' ), 409 );
    }
    set_transient( 'example_seen_' . $event_id, 1, DAY_IN_SECONDS );

    // The handler still does the smallest possible thing. A webhook is not an RPC endpoint.
    example_record_payment( json_decode( $body, true ) );
    wp_send_json_success();
}
```

And for a genuinely public *read*:

```php
add_action( 'wp_ajax_nopriv_example_suggest', 'example_suggest' );
add_action( 'wp_ajax_example_suggest',        'example_suggest' );

function example_suggest() {
    $q = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '';
    if ( strlen( $q ) < 3 ) { wp_send_json_success( array() ); }

    // Public means public: return only what an anonymous visitor could already see,
    // and never let the request influence which fields, post statuses or tables are read.
    $posts = get_posts( array(
        's'           => $q,
        'post_status' => 'publish',
        'numberposts' => 10,
        'fields'      => 'ids',
    ) );
    wp_send_json_success( array_map( 'get_the_title', $posts ) );
}
```

The decision procedure for every `_nopriv_` registration, in order:

1. **Does an anonymous user need this at all?** If not, delete the line. This closes more of
   this class than any other single action.
2. **If yes: is it read-only?** A public write endpoint needs payload authentication (HMAC),
   or rate limiting plus an idempotent, minimal effect.
3. **If it writes: what is the worst thing the request can select?** Table names, option
   names, user IDs, meta keys, file paths and method names must all be allowlisted, not
   sanitised.
4. **Share the handler with the logged-in hook only if the handler itself checks the
   capability.** Registering one callback on both hooks is fine for
   `example_suggest()` above and fatal for anything administrative.

## Real-world case studies

### One registration, every method (CVE-2026-12153, 9.8, unauthenticated)

The entire AJAX layer is twenty-five lines:

```php
class JSLEARNMANAGERajax {

    function __construct() {
        add_action("wp_ajax_jslearnmanager_ajax", array($this, "ajaxhandler")); // when user is login
        add_action("wp_ajax_nopriv_jslearnmanager_ajax", array($this, "ajaxhandler")); // when user is not login
        add_action("wp_ajax_jslearnmanager_loginwith_ajax", array($this, "ajaxhandlerloginwith"));
        add_action("wp_ajax_nopriv_jslearnmanager_loginwith_ajax", array($this, "ajaxhandlerloginwith"));
    }

    function ajaxhandler() {
        $module = JSLEARNMANAGERrequest::getVar('jslmsmod');
        $task = JSLEARNMANAGERrequest::getVar('task');
        $result = JSLEARNMANAGERincluder::getJSModel($module)->$task();
        echo wp_kses($result, JSLEARNMANAGER_ALLOWED_TAGS);
        die();
    }
}
```
`https://plugins.trac.wordpress.org/browser/learn-manager/tags/1.1.8/includes/ajax.php#L10`

Nine hundred lines away, in a different file, one of the methods that `$task` can name:

```php
function installPluginFromAjax(){
    $pluginslug = JSLEARNMANAGERrequest::getVar('pluginslug');
    ...
    require_once( ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php' );
    $api = plugins_api( 'plugin_information', array( 'slug' => $pluginslug, ... ) );
```
`https://plugins.trac.wordpress.org/browser/learn-manager/tags/1.1.8/modules/jslearnmanager/model.php#L879`

**Root cause at that line:** `->$task()` is dispatch by attacker-supplied string. The comment
`// when user is not login` shows the exposure was deliberate; what was not deliberate is
that "the AJAX endpoint" is in fact *every public method of every model class*, one of which
installs plugins from the repository. There is no nonce, no capability check, and no method
allowlist.

**Why this case decides the class boundary.** No sink-side rule can find this. There is no
call graph edge from the hook to `installPluginFromAjax()` — the edge is a string in
`$_REQUEST`. The only durable signature is the four `add_action` lines, i.e. AJAX-001 plus
AJAX-006 on the dispatcher. When those two rules co-occur in one function, enumerate the
reachable method set and rate the worst member.

### The reflex, twice, in a 49-line file (CVE-2025-2266, 9.8, unauthenticated)

```php
add_action( 'wp_ajax_cwmpChangeFuncionalidade', 'cwmpChangeFuncionalidade' );
add_action( 'wp_ajax_nopriv_cwmpChangeFuncionalidade', 'cwmpChangeFuncionalidade' );
function cwmpChangeFuncionalidade(){
	if(current_user_can('manage_options')){          // <- guarded
...
add_action( 'wp_ajax_cwmpUpdateOptions', 'cwmpUpdateOptions' );
add_action( 'wp_ajax_nopriv_cwmpUpdateOptions', 'cwmpUpdateOptions' );
function cwmpUpdateOptions() {
    if (isset($_POST['data'])) {                     // <- not guarded
        parse_str($_POST['data'], $parsed_data);
        ...
            update_option(sanitize_text_field($campo), $safe_value);
```
`https://plugins.trac.wordpress.org/browser/checkout-mestres-wp/tags/8.7.5/backend/core/base/ajax.php#L29`

**Root cause at that line:** neither handler has any business being on `wp_ajax_nopriv_` —
both write plugin options. The `_nopriv_` registration is the class-level defect; the missing
`current_user_can()` in the second handler is the WP-AUTHZ defect on top of it. `parse_str()`
over `$_POST['data']` means the option *name* is attacker-chosen, so this is an
arbitrary-option write: `default_role=administrator`, `users_can_register=1`, register, log
in as an administrator.

**The audit lesson is the asymmetry.** AJAX-001 flags both functions and cannot rank them.
The first is (barely) safe, the second is a site takeover. A `wp_ajax_nopriv_` inventory is a
*worklist*, and the triage step — reading each handler for a terminating capability check —
is not optional and cannot be skipped by sampling.

### Bulk registration of administrative actions (CVE-2025-5304, 9.8, unauthenticated)

```php
/* remove user */
add_action('wp_ajax_nopriv_wpnb_pto_users_deletd', array($this, 'wpnb_pto_users_deletd'));
add_action('wp_ajax_wpnb_pto_users_deletd', array($this, 'wpnb_pto_users_deletd'));

/* add new users */
add_action('wp_ajax_nopriv_wpnb_pto_new_users_add', array($this, 'wpnb_pto_new_users_add'));
add_action('wp_ajax_wpnb_pto_new_users_add', array($this, 'wpnb_pto_new_users_add'));
...
/* email_system_save */
add_action('wp_ajax_nopriv_wpnb_pto_new_email_system_save', array($this, 'wpnb_pto_new_email_system_save'));
```
`https://plugins.trac.wordpress.org/browser/project-notebooks/tags/1.1.3/includes/structure/admin/pto_admin_settings.php#L32`

**Root cause at that line:** every action in a file literally named `pto_admin_settings.php`
is exposed to logged-out callers. The handler for `wpnb_pto_new_users_add` verifies a nonce
and then copies the entire administrator capability set onto a request-supplied user ID (see
WP-AUTHZ for that half of the finding).

**Pattern to look for:** `_nopriv_` registrations inside a file, class or directory whose
name says *admin*, *settings*, *manage*, *import*, *tools* or *setup*. The directory layout
is a statement of intent, and a `nopriv` hook inside it is almost always an accident that
survived because a logged-out tester once got `0` back.

### Public by default in the framework (CVE-2026-4283, 9.1, unauthenticated)

```php
public static function listen($public = TRUE){
    $actionName = self::getActionName();
    $className = self::getClassName();
	add_action("wp_ajax_$actionName", array($className, 'boot'));

	if($public){
		add_action("wp_ajax_nopriv_$actionName", array($className, 'boot'));
	}
}
```
`https://plugins.trac.wordpress.org/browser/shapepress-dsgvo/tags/3.1.38/includes/class-sp-dsgvo-ajax-action.php#L64`

One of the subclasses:

```php
public function run(){
    if(!empty($_POST['website'])) die(); // anti spam honeypot
    $this->checkCSRF();
    ...
    $unsubscriber = SPDSGVOUnsubscriber::insert(array(
        ...
        'process_now'=> $this->get('process_now'),
    ));
    ...
    if($this->has('process_now')){
        $unsubscriber->doSuperUnsubscribe();
    }
```
`https://plugins.trac.wordpress.org/browser/shapepress-dsgvo/tags/3.1.38/public/shortcodes/super-unsubscribe/unsubscribe-form-action.php#L39`

**Root cause at that line:** `$public = TRUE` is the default, so a subclass is exposed to the
internet unless its author remembered to pass `FALSE` — the safe choice requires an action,
the unsafe one requires nothing. The action itself is intended to send a confirmation email
and wait; supplying `process_now` skips straight to `doSuperUnsubscribe()`, which randomises
the password, overwrites the username and email, strips all roles and wipes user meta for the
named account. Irreversible, anonymous, one request. The `checkCSRF()` nonce is printed on
every page carrying the plugin's public `[unsubscribe_form]` shortcode.

**Two detection lessons.** First, the hook name is `"wp_ajax_nopriv_$actionName"` — built by
interpolation. A rule that greps for literal action names finds nothing here; AJAX-001 keys
on the quoted prefix and still fires. Second, when a *base class* or *loader* registers
hooks, one line is N endpoints: find the callers before you count entry points.

### Registration through a wrapper (CVE-2026-18316, 9.1, subscriber+)

```php
// Install Active Theme
$this->loader->add_action( 'wp_ajax_action-install-activate-theme', $plugin_admin, 'install_and_activate_theme' );
$this->loader->add_action( 'wp_ajax_nopriv_action-install-activate-theme', $plugin_admin, 'install_and_activate_theme' );

// Install Active Plugin
$this->loader->add_action( 'wp_ajax_action-install-activate-plugin', $plugin_admin, 'install_and_activate_plugins' );
$this->loader->add_action( 'wp_ajax_nopriv_action-install-activate-plugin', $plugin_admin, 'install_and_activate_plugins' );

// Import Zip Elementor
$this->loader->add_action( 'wp_ajax_action-import-zip', $plugin_admin, 'import_zip' );
$this->loader->add_action( 'wp_ajax_nopriv_action-import-zip', $plugin_admin, 'import_zip' );
```
`https://plugins.trac.wordpress.org/browser/solace-extra/tags/1.6.0/includes/class-solace-extra.php#L336`

**Root cause:** fourteen `_nopriv_` registrations in one method, covering theme install,
plugin install and ZIP import. The only control in `import_zip()` is a check of the
`ajax-nonce` nonce, which `wp_localize_script()` emits on every admin page through an
unrestricted `admin_enqueue_scripts` hook — so any Subscriber can read it from the page
source and replay it.

**Detection consequence:** the token `add_action(` is preceded by `$this->loader->`. AJAX-001
matches on the quoted hook string, which is why it must not be anchored to the start of a
statement or to a bare `add_action`. A different plugin in this corpus registers through
`$this->loader->userspn_add_action( 'wp_ajax_nopriv_userspn_ajax_nopriv', … )` — a
plugin-specific wrapper name that no `add_action`-anchored rule could ever anticipate.

### A dedicated nopriv class, and a check that input can skip (CVE-2026-4003, 9.8, unauthenticated)

```php
$this->loader->userspn_add_action('wp_ajax_userspn_ajax_nopriv', $plugin_ajax_nopriv, 'userspn_ajax_nopriv_server');
$this->loader->userspn_add_action('wp_ajax_nopriv_userspn_ajax_nopriv', $plugin_ajax_nopriv, 'userspn_ajax_nopriv_server');
```

```php
$user_id = !empty($_POST['userspn_form_user_id']) ? USERSPN_Forms::userspn_sanitizer(wp_unslash($_POST['userspn_form_user_id'])) : 0;
...
if (($userspn_form_type == 'user' && empty($user_id) && !in_array($userspn_form_subtype, ['user_alt_new']))
    || ...
    || ($userspn_form_type == 'option' && !is_user_logged_in())) {
    ... echo wp_json_encode(['error_key' => 'userspn_form_save_error_unlogged', ]);exit;
}else{
    // falls through to update_user_meta($user_id, $userspn_key, $userspn_value)
```
`https://plugins.trac.wordpress.org/browser/userspn/tags/1.0.31/includes/class-userspn-ajax-nopriv.php#L190`

**Root cause at that line:** the class is *named* `USERSPN_Ajax_Nopriv` and its file is
`class-userspn-ajax-nopriv.php`, so the exposure was intentional and visible. What was not
visible is that the rejection branch requires `empty($user_id)`: send a user ID and the
branch is skipped, the `else` runs, and arbitrary user meta is written for that account. The
`userspn-nonce` is published to every visitor via `wp_localize_script()` on
`wp_enqueue_scripts`.

**Generalisable tell:** when a `nopriv` handler contains `is_user_logged_in()` inside a
compound condition alongside `empty()` / `isset()` tests on request data, the authorization
is conditional on attacker input. Authorization belongs in its own statement, first, with its
own terminating branch.

## Detection guidance

**What the regexes catch reliably**

- `AJAX-001` is close to a complete enumerator of a plugin's anonymous AJAX surface. It
  survives concatenation, interpolation, loader wrappers and plugin-specific wrapper names
  because it keys on the quoted hook prefix rather than on `add_action`. In the corpus files
  checked while writing this class it fired on every single confirmed case.
- `AJAX-004` does the same for `admin-post.php`, including the suffix-less
  `admin_post_nopriv` hook that fires on an empty `action` parameter.
- `AJAX-003` gives the complete inventory including the Subscriber-reachable `wp_ajax_` twin.
  Diff its count against `current_user_can` occurrences; a deficit names the handlers to read.
- `AJAX-006` finds the dispatcher shape. Its value is entirely in co-occurrence with
  `AJAX-001` inside the same function.

**What the regexes CANNOT catch — read the code**

1. **Whether a public endpoint is *supposed* to be public.** A search suggest, a contact
   form, a Stripe webhook and a "load more posts" endpoint are all legitimately `nopriv`.
   Only the handler's behaviour distinguishes them from an exported user list. This is a
   judgement call on every hit, not a rule.
2. **Whether the handler checks a capability.** That is WP-AUTHZ. Run both classes on the
   same file and correlate by function name; a `nopriv` registration whose handler is also
   flagged by AUTHZ-007/008/009 is the highest-priority finding in a plugin.
3. **The reachable method set behind a variable dispatcher.** CVE-2026-12153. You must read
   the target class (or classes, if the class name is also request-supplied) and enumerate
   every public method, then rate the worst one. Grep cannot follow that edge.
4. **How many endpoints one registration creates.** A base class, a loader, or a loop over a
   route table turns one matched line into N endpoints. Always find the *callers* of a
   registration helper before you believe an endpoint count.
5. **Who can read the nonce.** `AJAX-005` finds the creation site; you must follow it to
   `wp_localize_script()` / `wp_add_inline_script()` and then to the enqueue hook.
   `wp_enqueue_scripts` = every anonymous visitor. Unconditional `admin_enqueue_scripts` =
   every logged-in user. Neither is an access control.
6. **Handlers reachable by `GET`.** Core reads `action` from `$_REQUEST`. A handler that only
   reads `$_POST` can still be *invoked* by `GET`, which matters for CSRF-by-`<img>` and for
   anything with a side effect in the first few lines before the `$_POST` check.
7. **CORS widening.** `admin-ajax.php` calls `send_origin_headers()`, which honours the
   `allowed_http_origins` filter. A plugin that widens that filter makes every AJAX response
   cross-origin readable. Grep `allowed_http_origins` separately.
8. **`admin_init` piggybacking.** `admin_init` fires on `admin-ajax.php` and
   `admin-post.php` before the login branch, so a plugin with *no* `nopriv` registration at
   all can still be reachable anonymously through any *other* plugin's registered action.
   See WP-AUTHZ and entry-points.md §4.
9. **Whether the `_nopriv_` twin is conditional.** `if ( get_option( 'example_public' ) ) { add_action( 'wp_ajax_nopriv_…' ); }`
   makes exposure depend on a setting. Record the condition; a finding gated on a non-default
   option is de-escalated, one gated on a default-on option is not.

## Audit checklist

- [ ] `rg -n "['\"]wp_ajax_nopriv_" --type php` — this is the plugin's complete anonymous AJAX
      surface. Enumerate **every** hit; do not sample.
- [ ] `rg -n "['\"]admin_post_nopriv" --type php` — same, for `admin-post.php`, including the
      suffix-less `admin_post_nopriv` hook.
- [ ] For each hit, record: action name, callback, file:line, and what the callback writes.
- [ ] For each callback, answer in order: (a) does an anonymous user need this? (b) is it
      read-only? (c) if it writes, is every request-selectable identifier (table, option key,
      meta key, user ID, method name, path) allowlisted?
- [ ] Locate `current_user_can()` inside each callback and confirm the failure branch
      terminates. Absent → cross-file finding with **WP-AUTHZ**.
- [ ] `rg -n "add_action\s*\(\s*['\"]wp_ajax_?['\"]\s*\." --type php` — find hook names built
      at runtime, then read what feeds the variable so the inventory is complete.
- [ ] Find every registration *wrapper* (`->loader->add_action`, `Helpers::ajaxAction`,
      `->my_add_action`) and follow it to its callers; one wrapper line can be N endpoints.
- [ ] `rg -n "['\"]wp_ajax_[a-zA-Z0-9_{$]" --type php` and compare the count with
      `rg -c current_user_can`. A deficit is your read list.
- [ ] For every nonce-only handler, trace `wp_create_nonce()` → `wp_localize_script()` →
      enqueue hook and record who can read the nonce.
- [ ] For every handler containing `->$var(`, `::$var(` or `call_user_func( $…`, enumerate the
      full set of selectable targets and rate the worst.
- [ ] Grep `wp_doing_ajax|DOING_AJAX|is_admin\s*\(` used as guards; none of them authorises.
- [ ] Grep `allowed_http_origins` for CORS widening on `admin-ajax.php`.
- [ ] For webhook-style endpoints, confirm HMAC verification with `hash_equals()` (not `==` /
      `===` on the raw strings), plus replay protection. No verification at all is
      authentication bypass, not merely missing authorization.
- [ ] Cross-reference **WP-REST**: many plugins expose the same operation twice, once as an
      AJAX action and once as a REST route. Fixing one leaves the other open.
