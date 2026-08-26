<?php
/**
 * Plugin Name: Deliberately Vulnerable Test Plugin
 *
 * NOT REAL CODE. Every function below reproduces the shape of a published
 * WordPress CVE class documented in kb/classes/. Used to prove the scanner
 * detects real bug shapes, not just that it stays quiet on correct code.
 * Each function names the class it exercises.
 */

// WP-AJAX: handler exposed to the entire internet.
add_action( 'wp_ajax_nopriv_vt_save', 'vt_save_handler' );
add_action( 'wp_ajax_vt_save', 'vt_save_handler' );

// WP-AUTHZ + WP-CSRF: no capability check, nonce result thrown away.
function vt_save_handler() {
    wp_verify_nonce( $_POST['_wpnonce'], 'vt_save' );
    update_option( 'vt_setting', $_POST['value'] );
    echo 'saved: ' . $_POST['value'];              // WP-XSS-R: unescaped reflection
}

// WP-SQLI: request data interpolated straight into a query.
function vt_lookup() {
    global $wpdb;
    $id = $_GET['id'];
    return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE ID = " . $id );
}

// WP-UPLOAD: client-declared MIME trusted, raw move_uploaded_file.
function vt_upload() {
    if ( $_FILES['f']['type'] === 'image/jpeg' ) {
        move_uploaded_file( $_FILES['f']['tmp_name'], ABSPATH . 'wp-content/uploads/' . $_FILES['f']['name'] );
    }
}

// WP-LFI: user-controlled include.
function vt_render() {
    include ABSPATH . 'templates/' . $_GET['tpl'] . '.php';
}

// WP-POI: unserialize on request data.
function vt_state() {
    return unserialize( $_COOKIE['vt_state'] );
}

// WP-RCE: request data reaches a dispatcher and a shell.
function vt_run() {
    call_user_func( $_GET['fn'] );
    system( 'convert ' . $_POST['file'] );
}

// WP-DELETE / WP-TRAVERSAL: unfiltered path into unlink.
function vt_delete() {
    unlink( ABSPATH . 'wp-content/uploads/' . $_POST['file'] );
}

// WP-SSRF: user URL fetched with the unvalidated helper.
function vt_fetch() {
    return wp_remote_get( $_GET['url'] );
}

// WP-REDIRECT: open redirect.
function vt_go() {
    wp_redirect( $_GET['next'] );
    exit;
}

// WP-REST: route open to the world.
function vt_routes() {
    register_rest_route( 'vt/v1', '/all', array(
        'methods'             => 'GET',
        'callback'            => 'vt_all',
        'permission_callback' => '__return_true',
    ) );
}

// WP-PRIVESC: role taken from the request.
function vt_promote() {
    $u = new WP_User( (int) $_POST['user_id'] );
    $u->set_role( $_POST['role'] );
}

// WP-SECRETS: hardcoded key and weak randomness.
function vt_token() {
    $api_key = 'sk_live_51H8xQ2eZvKYlo2CxAmPl3K9dUmMyRealLookingKey';
    return md5( time() ) . $api_key;
}

// WP-XXE: external entities enabled explicitly.
function vt_xml( $xml ) {
    $d = new DOMDocument();
    $d->loadXML( $xml, LIBXML_NOENT | LIBXML_DTDLOAD );
    return $d;
}

// WP-CSVINJ: raw database rows exported with no formula neutralisation.
function vt_export_log() {
    global $wpdb;
    $data = $wpdb->get_results( "SELECT query, hits FROM {$wpdb->prefix}search_log", ARRAY_A );
    header( 'Content-Disposition: attachment; filename=search-log.csv' );
    $df = fopen( 'php://output', 'w' );
    foreach ( $data as $row ) {
        fputcsv( $df, $row );
    }
    fclose( $df );
}
