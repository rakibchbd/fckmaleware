<?php
/**
 * Optional server hardening rules written into .htaccess files.
 *
 * Only Apache/LiteSpeed honour these; nginx needs the equivalent rule in the
 * server config (see README).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Hardening {

	private const MARKER = 'FckMaleware';

	/** Add or remove the "no PHP in uploads" rule. */
	public static function apply_uploads_rule( bool $enabled ): bool {
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		$uploads = wp_upload_dir( null, false );
		$file    = trailingslashit( $uploads['basedir'] ) . '.htaccess';

		if ( ! $enabled && ! file_exists( $file ) ) {
			return true;
		}

		$lines = $enabled ? array(
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht)$">',
			'	<IfModule mod_authz_core.c>',
			'		Require all denied',
			'	</IfModule>',
			'	<IfModule !mod_authz_core.c>',
			'		Order allow,deny',
			'		Deny from all',
			'	</IfModule>',
			'</FilesMatch>',
		) : array();

		return insert_with_markers( $file, self::MARKER, $lines );
	}
}
