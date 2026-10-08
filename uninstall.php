<?php
// WP Login 2FA — clean up on uninstall.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

$meta_keys = array(
    'wp2fa_enabled',
    'wp2fa_secret',
    'wp2fa_pending',
    'wp2fa_backup_codes',
);

$placeholders = implode( ',', array_fill( 0, count( $meta_keys ), '%s' ) );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- intentional bulk meta cleanup
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN ({$placeholders})", $meta_keys ) ); // phpcs:ignore
