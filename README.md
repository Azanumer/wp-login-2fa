# WP Login 2FA

Lightweight, dependency-free TOTP two-factor authentication for `wp-login.php`.
Works with Google Authenticator, Authy, 1Password, Bitwarden — any RFC 6238 app.
No external services, no bloat, one plugin file.

## Features

- Per-user enable/disable from the WordPress profile page
- QR-less setup: manual Base32 secret + `otpauth://` URI (copy into your authenticator app)
- ±30s clock-drift tolerance, constant-time code comparison (`hash_equals`)
- 8 hashed, single-use backup codes generated on setup
- Codes never logged; disabling 2FA wipes secrets and backup codes

## Install

1. Copy `wp-login-2fa.php` (and `uninstall.php`) into `wp-content/plugins/wp-login-2fa/`
2. Activate in **Plugins**
3. Go to **Users → Profile**, tick *Set up two-factor authentication*, update the profile
4. Enter the secret (or the `otpauth://` URI) into your authenticator app, then submit one 6-digit code to confirm

After enabling, the login page shows a *Two-factor code* field. It is only
required for accounts with 2FA enabled.

## Requirements

- WordPress 5.0+
- PHP 7.4+ (uses `random_int()`, `**`, arrow-free closures)

## Security notes

- Secrets are stored in user meta; enable this plugin only with HTTPS admin access
- Backup codes are stored as SHA-256 hashes and deleted on use
- `uninstall.php` removes all plugin meta from the database

MIT licensed.
