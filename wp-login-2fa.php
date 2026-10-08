<?php
/**
 * Plugin Name: WP Login 2FA
 * Description: Lightweight, dependency-free TOTP two-factor authentication for wp-login.php (works with Google Authenticator, Authy, 1Password). No external services, no bloat.
 * Version: 1.0.0
 * Author: Azan Umer
 * License: MIT
 * Text Domain: wp-login-2fa
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WP2FA_STEP', 30 );          // TOTP time step in seconds (RFC 6238)
define( 'WP2FA_DIGITS', 6 );
define( 'WP2FA_SKEW', 1 );           // accept ±1 step for clock drift

/* ------------------------------------------------------------------
 * 1. TOTP primitives (RFC 6238 / RFC 4648 Base32)
 * ------------------------------------------------------------------ */

function wp2fa_base32_decode( $input ) {
    $input   = strtoupper( rtrim( $input, '=' ) );
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits    = '';
    $output  = '';

    $len = strlen( $input );
    for ( $i = 0; $i < $len; $i++ ) {
        $pos = strpos( $alphabet, $input[ $i ] );
        if ( $pos === false ) {
            return false; // invalid character
        }
        $bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
    }

    $bitlen = strlen( $bits );
    for ( $i = 0; $i + 8 <= $bitlen; $i += 8 ) {
        $output .= chr( bindec( substr( $bits, $i, 8 ) ) );
    }

    return $output;
}

function wp2fa_generate_secret( $length = 20 ) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret   = '';
    $max      = strlen( $alphabet ) - 1;
    for ( $i = 0; $i < $length; $i++ ) {
        $secret .= $alphabet[ random_int( 0, $max ) ];
    }
    return $secret;
}

function wp2fa_totp( $secret, $time_slice ) {
    $key = wp2fa_base32_decode( $secret );
    if ( $key === false ) {
        return false;
    }

    // 64-bit big-endian counter (high 32 bits zero, per RFC 6238)
    $counter = pack( 'N*', 0 ) . pack( 'N*', $time_slice );
    $hm      = hash_hmac( 'sha1', $counter, $key, true );

    $offset = ord( substr( $hm, -1 ) ) & 0x0F;
    $code   = (
        ( ( ord( $hm[ $offset ] ) & 0x7F ) << 24 ) |
        ( ( ord( $hm[ $offset + 1 ] ) & 0xFF ) << 16 ) |
        ( ( ord( $hm[ $offset + 2 ] ) & 0xFF ) << 8 ) |
        ( ord( $hm[ $offset + 3 ] ) & 0xFF )
    );

    return str_pad( (string) ( $code % ( 10 ** WP2FA_DIGITS ) ), WP2FA_DIGITS, '0', STR_PAD_LEFT );
}

function wp2fa_verify_code( $secret, $code ) {
    $code = preg_replace( '/\s+/', '', (string) $code );
    if ( ! preg_match( '/^\d{6}$/', $code ) ) {
        return false;
    }

    $slice = (int) floor( time() / WP2FA_STEP );
    for ( $d = - WP2FA_SKEW; $d <= WP2FA_SKEW; $d++ ) {
        $expected = wp2fa_totp( $secret, $slice + $d );
        if ( $expected !== false && hash_equals( $expected, $code ) ) {
            return true;
        }
    }
    return false;
}

function wp2fa_otpauth_uri( $secret, $account, $issuer ) {
    return 'otpauth://totp/' . rawurlencode( $issuer ) . ':' . rawurlencode( $account )
         . '?secret=' . rawurlencode( $secret )
         . '&issuer=' . rawurlencode( $issuer )
         . '&digits=' . WP2FA_DIGITS . '&period=' . WP2FA_STEP;
}

/* ------------------------------------------------------------------
 * 2. Backup codes (hashed, single use)
 * ------------------------------------------------------------------ */

function wp2fa_generate_backup_codes( $user_id ) {
    $codes  = array();
    $hashed = array();
    for ( $i = 0; $i < 8; $i++ ) {
        $code = strtoupper( substr( bin2hex( random_bytes( 6 ) ), 0, 10 ) );
        $codes[]  = $code;
        $hashed[] = hash( 'sha256', $code );
    }
    update_user_meta( $user_id, 'wp2fa_backup_codes', $hashed );
    return $codes; // plain codes shown ONCE in the admin UI
}

function wp2fa_consume_backup_code( $user_id, $code ) {
    $code   = preg_replace( '/\s+/', '', strtoupper( (string) $code ) );
    $hash   = hash( 'sha256', $code );
    $stored = get_user_meta( $user_id, 'wp2fa_backup_codes', true );
    if ( ! is_array( $stored ) ) {
        return false;
    }

    foreach ( $stored as $i => $h ) {
        if ( hash_equals( $h, $hash ) ) {
            unset( $stored[ $i ] );
            update_user_meta( $user_id, 'wp2fa_backup_codes', array_values( $stored ) );
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------
 * 3. Login form: extra field + enforcement
 * ------------------------------------------------------------------ */

function wp2fa_is_enabled( $user_id ) {
    return (bool) get_user_meta( $user_id, 'wp2fa_enabled', true );
}

add_action( 'login_form', function () {
    ?>
    <p class="wp2fa-code">
        <label for="wp2fa_code"><?php esc_html_e( 'Two-factor code', 'wp-login-2fa' ); ?><br />
        <input type="text" name="wp2fa_code" id="wp2fa_code" class="input"
               value="" size="20" autocomplete="one-time-code"
               inputmode="numeric" /></label>
        <span class="description"><?php esc_html_e( 'Only required if 2FA is enabled on your account.', 'wp-login-2fa' ); ?></span>
    </p>
    <?php
} );

add_filter( 'authenticate', function ( $user, $username, $password ) {
    if ( ! $user instanceof WP_User ) {
        return $user; // username/password already failed — bail early
    }
    if ( ! wp2fa_is_enabled( $user->ID ) ) {
        return $user; // 2FA not enabled for this account
    }

    $code = isset( $_POST['wp2fa_code'] ) ? trim( wp_unslash( $_POST['wp2fa_code'] ) ) : '';

    if ( $code !== '' ) {
        $secret = get_user_meta( $user->ID, 'wp2fa_secret', true );
        if ( $secret && wp2fa_verify_code( $secret, $code ) ) {
            return $user;
        }
        if ( wp2fa_consume_backup_code( $user->ID, $code ) ) {
            return $user;
        }
    }

    return new WP_Error(
        'wp2fa_invalid_code',
        __( '<strong>Error:</strong> the two-factor authentication code is missing or invalid.', 'wp-login-2fa' )
    );
}, 40, 3 );

/* ------------------------------------------------------------------
 * 4. Profile page: enable / disable / regenerate
 * ------------------------------------------------------------------ */

add_action( 'show_user_profile', 'wp2fa_profile_fields' );
add_action( 'edit_user_profile', 'wp2fa_profile_fields' );

// Profile/user-edit pages never call settings_errors() themselves —
// render our enable/disable feedback (including one-time backup codes).
add_action( 'admin_notices', function () {
    if ( ! function_exists( 'get_current_screen' ) ) {
        return;
    }
    $screen = get_current_screen();
    if ( $screen && in_array( $screen->base, array( 'profile', 'user-edit' ), true ) ) {
        settings_errors( 'wp2fa' );
    }
} );

function wp2fa_profile_fields( $user ) {
    if ( ! current_user_can( 'edit_user', $user->ID ) ) {
        return;
    }
    $enabled = wp2fa_is_enabled( $user->ID );
    $pending = get_user_meta( $user->ID, 'wp2fa_pending', true );
    $issuer  = get_bloginfo( 'name' );
    ?>
    <h2><?php esc_html_e( 'Two-Factor Authentication', 'wp-login-2fa' ); ?></h2>
    <table class="form-table" role="presentation">
        <tr>
            <th scope="row"><?php esc_html_e( 'Status', 'wp-login-2fa' ); ?></th>
            <td>
                <?php if ( $enabled ) : ?>
                    <span style="color:green;font-weight:bold;">● <?php esc_html_e( 'Enabled', 'wp-login-2fa' ); ?></span>
                    <p class="description">
                        <label><input type="checkbox" name="wp2fa_disable" value="1" />
                        <?php esc_html_e( 'Disable 2FA (also clears backup codes)', 'wp-login-2fa' ); ?></label>
                    </p>
                <?php elseif ( $pending ) : ?>
                    <p><?php esc_html_e( 'Scan the secret below with your authenticator app, then enter a 6-digit code to confirm.', 'wp-login-2fa' ); ?></p>
                    <p><strong><?php esc_html_e( 'Manual secret:', 'wp-login-2fa' ); ?></strong>
                        <code style="user-select:all;"><?php echo esc_html( $pending ); ?></code></p>
                    <p class="description" style="word-break:break-all;">
                        <?php esc_html_e( 'or import this URI:', 'wp-login-2fa' ); ?><br />
                        <code style="user-select:all;"><?php echo esc_html( wp2fa_otpauth_uri( $pending, $user->user_login, $issuer ) ); ?></code>
                    </p>
                    <p><label><?php esc_html_e( 'Confirmation code:', 'wp-login-2fa' ); ?>
                        <input type="text" name="wp2fa_confirm" value="" size="10" inputmode="numeric" /></label></p>
                <?php else : ?>
                    <p><label><input type="checkbox" name="wp2fa_start_setup" value="1" />
                        <?php esc_html_e( 'Set up two-factor authentication', 'wp-login-2fa' ); ?></label></p>
                <?php endif; ?>
            </td>
        </tr>
    </table>
    <?php
}

add_action( 'personal_options_update', 'wp2fa_save_profile_fields' );
add_action( 'edit_user_profile_update', 'wp2fa_save_profile_fields' );

function wp2fa_save_profile_fields( $user_id ) {
    if ( ! current_user_can( 'edit_user', $user_id ) ) {
        return;
    }

    // Disable path.
    if ( ! empty( $_POST['wp2fa_disable'] ) ) {
        delete_user_meta( $user_id, 'wp2fa_enabled' );
        delete_user_meta( $user_id, 'wp2fa_secret' );
        delete_user_meta( $user_id, 'wp2fa_pending' );
        delete_user_meta( $user_id, 'wp2fa_backup_codes' );
        return;
    }

    // Step 1: start setup — generate a pending secret.
    if ( ! empty( $_POST['wp2fa_start_setup'] ) && ! wp2fa_is_enabled( $user_id ) ) {
        if ( ! get_user_meta( $user_id, 'wp2fa_pending', true ) ) {
            update_user_meta( $user_id, 'wp2fa_pending', wp2fa_generate_secret() );
        }
        return;
    }

    // Step 2: confirm pending secret with a real code.
    $pending = get_user_meta( $user_id, 'wp2fa_pending', true );
    if ( $pending && isset( $_POST['wp2fa_confirm'] ) && trim( wp_unslash( $_POST['wp2fa_confirm'] ) ) !== '' ) {
        if ( wp2fa_verify_code( $pending, trim( wp_unslash( $_POST['wp2fa_confirm'] ) ) ) ) {
            update_user_meta( $user_id, 'wp2fa_secret', $pending );
            update_user_meta( $user_id, 'wp2fa_enabled', 1 );
            delete_user_meta( $user_id, 'wp2fa_pending' );
            $codes = wp2fa_generate_backup_codes( $user_id );
            add_settings_error(
                'wp2fa',
                'wp2fa_backup_codes',
                sprintf(
                    /* translators: %s: comma-separated backup codes */
                    __( '2FA enabled. Save these backup codes somewhere safe (each works once): %s', 'wp-login-2fa' ),
                    implode( ', ', $codes )
                ),
                'success'
            );
        } else {
            add_settings_error( 'wp2fa', 'wp2fa_bad_code', __( 'That code was not valid — setup not completed.', 'wp-login-2fa' ), 'error' );
        }
    }
}
