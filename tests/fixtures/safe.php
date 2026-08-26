<?php
// Correctly written WordPress code. NOTHING here should be flagged.
// Any rule that fires on this file is producing a false positive.

function wps_safe_save() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Denied', 'td' ) );
    }
    if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'wps_save' ) ) {
        wp_die( esc_html__( 'Bad nonce', 'td' ) );
    }
    $value = sanitize_text_field( wp_unslash( $_POST['value'] ) );
    update_option( 'wps_setting', $value );
}

function wps_safe_query( $id ) {
    global $wpdb;
    return $wpdb->get_results($wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id ));
}

function wps_safe_query2( $table, $id ) {
    global $wpdb;
    return $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE ID = %d", $table, $id ) );
}

function wps_safe_output( $text ) {
    echo esc_html( $text );
    printf( '<a href="%s">%s</a>', esc_url( $link ), esc_html( $label ) );
}

function wps_safe_rest() {
    register_rest_route( 'wps/v1', '/items', array(
        'methods'             => 'POST',
        'callback'            => 'wps_items',
        'permission_callback' => function () { return current_user_can( 'edit_posts' ); },
    ) );
}

function wps_safe_upload() {
    $overrides = array( 'test_form' => false, 'mimes' => array( 'jpg|jpeg' => 'image/jpeg' ) );
    return wp_handle_upload( $_FILES['file'], $overrides );
}

function wps_safe_redirect( $to ) {
    wp_safe_redirect( $to );
    exit;
}

function wps_safe_token() {
    return wp_generate_password( 32, false );
}

// ---- correct patterns for the classes that landed after the first fixture pass ----

function wps_safe_http( $user_url ) {
    // wp_safe_remote_get() applies the internal-host / private-range blocks.
    $url = esc_url_raw( $user_url );
    if ( ! wp_http_validate_url( $url ) ) {
        return new WP_Error( 'bad_url', 'Rejected' );
    }
    return wp_safe_remote_get( $url, array( 'timeout' => 5, 'redirection' => 0 ) );
}

function wps_safe_shell( $name ) {
    $cmd = 'convert ' . escapeshellarg( $name ) . ' out.png';
    return $cmd; // not executed here
}

function wps_safe_callback( $which ) {
    $allowed = array( 'alpha' => 'wps_alpha', 'beta' => 'wps_beta' );
    if ( ! isset( $allowed[ $which ] ) ) {
        return null;
    }
    return call_user_func( $allowed[ $which ] );
}

function wps_safe_include( $view ) {
    $allowed = array( 'list', 'detail' );
    if ( ! in_array( $view, $allowed, true ) ) {
        return;
    }
    include plugin_dir_path( __FILE__ ) . 'views/' . $view . '.php';
}

function wps_safe_decode( $raw ) {
    // json_decode, never unserialize, on untrusted input
    return json_decode( $raw, true );
}

function wps_safe_delete( $name ) {
    $base = wp_upload_dir()['basedir'] . '/wps/';
    $path = realpath( $base . basename( $name ) );
    if ( $path && strpos( $path, realpath( $base ) ) === 0 && is_file( $path ) ) {
        wp_delete_file( $path );
    }
}

function wps_safe_xml( $xml ) {
    // PHP 8 disables external entities by default; be explicit anyway.
    $doc = new DOMDocument();
    $doc->loadXML( $xml, LIBXML_NONET );
    return $doc;
}

// ---- the documented "correct fix" shapes, added to test rules that claim to match them ----

function wps_safe_in_clause( array $ids ) {
    global $wpdb;
    // The canonical correct way to build an IN() clause.
    $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
    $sql = $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID IN( $placeholders )", $ids );
    return $wpdb->get_results( $sql );
}

function wps_safe_unserialize( $blob ) {
    // PHP 7+ safe form: no object instantiation possible.
    return unserialize( $blob, array( 'allowed_classes' => false ) );
}

function wps_safe_prefix_query() {
    global $wpdb;
    // Concatenating a trusted prefix property is not injection.
    return $wpdb->query( "DROP TABLE IF EXISTS " . $wpdb->prefix . "wps_tmp" );
}

// ---- correct CSV export (WP-CSVINJ) ----

function wps_csv_field( $value ) {
    $value = (string) $value;
    if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@' ), true ) ) {
        $value = "'" . $value;
    }
    return str_replace( array( "\t", "\r" ), '', $value );
}

function wps_safe_export( array $rows ) {
    if ( ! current_user_can( 'export' ) ) {
        wp_die( esc_html__( 'Denied', 'td' ) );
    }
    check_admin_referer( 'wps_export' );
    $df = fopen( 'php://output', 'w' );
    foreach ( $rows as $row ) {
        fputcsv( $df, array_map( 'wps_csv_field', $row ) );
    }
    fclose( $df );
}
