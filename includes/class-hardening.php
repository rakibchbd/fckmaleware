<?php
/**
 * WordPress hardening: reversible rules and report-only checks.
 *
 * Every entry documents what it does, the risk it addresses, its known
 * compatibility impact and how to roll it back. Rules are off by default
 * (except where noted) and each can be turned off again from the same screen.
 *
 * This is configuration hardening, not a web application firewall: there is
 * no request-filtering layer in front of WordPress.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Hardening {

	public const OPTION = 'fckmw_hardening';
	private const MARKER       = 'FckMaleware';
	private const STATUS_CACHE = 'fckmw_hardening_status';

	/** @return array<string, array{title: string, description: string, risk: string, compatibility: string, rollback: string, toggle: bool}> */
	public static function catalog(): array {
		$meta    = array(
			'uploads_php'        => array( 'php', 'high' ),
			'disallow_file_edit' => array( 'core', 'medium' ),
			'disable_xmlrpc'     => array( 'api', 'medium' ),
			'rest_users'         => array( 'api', 'low' ),
			'author_enum'        => array( 'auth', 'low' ),
			'security_headers'   => array( 'headers', 'low' ),
			'debug_exposure'     => array( 'config', 'medium' ),
			'directory_listing'  => array( 'exposure', 'medium' ),
			'exposed_backups'    => array( 'exposure', 'high' ),
			'permissions'        => array( 'filesystem', 'high' ),
			'updates'            => array( 'core', 'high' ),
			'abandoned_plugins'  => array( 'core', 'medium' ),
			'accounts'           => array( 'auth', 'medium' ),
			'transport'          => array( 'config', 'high' ),
			'cloaked_redirects'  => array( 'exposure', 'high' ),
		);
		$catalog = self::rules();
		foreach ( $catalog as $id => $rule ) {
			$catalog[ $id ]['category'] = $meta[ $id ][0] ?? 'core';
			$catalog[ $id ]['level']    = $meta[ $id ][1] ?? 'medium';
		}
		return $catalog;
	}

	/** Categories in display order. */
	public static function categories(): array {
		return array(
			'core'       => __( 'WordPress core and components', 'fckmaleware' ),
			'auth'       => __( 'Authentication and accounts', 'fckmaleware' ),
			'filesystem' => __( 'File permissions and filesystem', 'fckmaleware' ),
			'headers'    => __( 'HTTP security headers', 'fckmaleware' ),
			'api'        => __( 'XML-RPC and REST API', 'fckmaleware' ),
			'php'        => __( 'PHP execution restrictions', 'fckmaleware' ),
			'exposure'   => __( 'Directory and file exposure', 'fckmaleware' ),
			'config'     => __( 'Configuration and transport', 'fckmaleware' ),
		);
	}

	/** @return array<string, array> */
	private static function rules(): array {
		return array(
			'uploads_php'       => array(
				'title'         => __( 'Block PHP execution in uploads', 'fckmaleware' ),
				'description'   => __( 'Adds an .htaccess rule to wp-content/uploads that refuses to run .php, .phtml, .phar and similar files.', 'fckmaleware' ),
				'risk'          => __( 'Most WordPress backdoors are dropped into uploads through vulnerable plugins and then requested directly.', 'fckmaleware' ),
				'compatibility' => __( 'Apache and LiteSpeed only (nginx ignores .htaccess; add the nginx rule from the docs). A few plugins wrongly run PHP from uploads and would stop working.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off: the marked block is removed from uploads/.htaccess.', 'fckmaleware' ),
				'toggle'        => true,
			),
			'disallow_file_edit' => array(
				'title'         => __( 'Disable the built-in file editor', 'fckmaleware' ),
				'description'   => __( 'Defines DISALLOW_FILE_EDIT so Appearance → Theme File Editor and Plugins → Plugin File Editor are unavailable. Uses of the editor are always logged.', 'fckmaleware' ),
				'risk'          => __( 'A stolen administrator session can turn into code execution in one click through the editor.', 'fckmaleware' ),
				'compatibility' => __( 'Developers who edit code from the dashboard lose that ability. No effect on updates or installs.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off (unless DISALLOW_FILE_EDIT is also set in wp-config.php).', 'fckmaleware' ),
				'toggle'        => true,
			),
			'disable_xmlrpc'    => array(
				'title'         => __( 'Disable XML-RPC', 'fckmaleware' ),
				'description'   => __( 'Turns off the XML-RPC API and pingbacks.', 'fckmaleware' ),
				'risk'          => __( 'XML-RPC allows many password guesses per request (system.multicall) and pingback abuse.', 'fckmaleware' ),
				'compatibility' => __( 'Breaks Jetpack, the official mobile apps on some setups and remote publishing tools that use XML-RPC.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off.', 'fckmaleware' ),
				'toggle'        => true,
			),
			'rest_users'        => array(
				'title'         => __( 'Hide the user list from anonymous REST requests', 'fckmaleware' ),
				'description'   => __( 'Requires a logged-in user for /wp/v2/users.', 'fckmaleware' ),
				'risk'          => __( 'The public endpoint reveals login names, the first half of every password-guessing attack.', 'fckmaleware' ),
				'compatibility' => __( 'Themes or apps that show author lists through the REST API without logging in will get an error.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off.', 'fckmaleware' ),
				'toggle'        => true,
			),
			'author_enum'       => array(
				'title'         => __( 'Block ?author= enumeration', 'fckmaleware' ),
				'description'   => __( 'Returns 404 for /?author=N requests from visitors who are not logged in, instead of redirecting to the author archive.', 'fckmaleware' ),
				'risk'          => __( 'Iterating ?author=1,2,3 reveals login names through the redirect.', 'fckmaleware' ),
				'compatibility' => __( 'Pretty author archive URLs (/author/name/) keep working.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off.', 'fckmaleware' ),
				'toggle'        => true,
			),
			'security_headers'  => array(
				'title'         => __( 'Send security headers', 'fckmaleware' ),
				'description'   => __( 'Adds X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN and Referrer-Policy: strict-origin-when-cross-origin to WordPress responses that do not already set them.', 'fckmaleware' ),
				'risk'          => __( 'Reduces MIME-sniffing attacks, clickjacking and referrer leaks.', 'fckmaleware' ),
				'compatibility' => __( 'Sites that are deliberately embedded in frames on other domains must keep this off.', 'fckmaleware' ),
				'rollback'      => __( 'Turn the rule off.', 'fckmaleware' ),
				'toggle'        => true,
			),
			'debug_exposure'    => array(
				'title'         => __( 'Debug output and logs', 'fckmaleware' ),
				'description'   => __( 'Checks WP_DEBUG_DISPLAY and whether wp-content/debug.log can be downloaded.', 'fckmaleware' ),
				'risk'          => __( 'Errors and logs reveal paths, queries and sometimes credentials.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Fix in wp-config.php: define( \'WP_DEBUG_DISPLAY\', false ); and keep logs outside the web root.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'directory_listing' => array(
				'title'         => __( 'Directory listing', 'fckmaleware' ),
				'description'   => __( 'Requests the uploads directory URL and checks whether the server lists its contents.', 'fckmaleware' ),
				'risk'          => __( 'Listings expose every uploaded file, including private documents and backups.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Fix with "Options -Indexes" (Apache) or "autoindex off" (nginx).', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'exposed_backups'   => array(
				'title'         => __( 'Exposed backups and repositories', 'fckmaleware' ),
				'description'   => __( 'Looks for database dumps, archives, editor backups of wp-config.php and .git folders in web-reachable locations.', 'fckmaleware' ),
				'risk'          => __( 'A downloadable backup or .git folder hands over the database credentials and the whole site.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Move backups outside the web root or delete them.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'permissions'       => array(
				'title'         => __( 'File permissions', 'fckmaleware' ),
				'description'   => __( 'Checks wp-config.php and key directories for world-writable or world-readable permissions.', 'fckmaleware' ),
				'risk'          => __( 'Other accounts on a shared server can read credentials or plant files.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Typical safe values: 0640 or 0600 for wp-config.php, 0755 for directories, 0644 for files.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'updates'           => array(
				'title'         => __( 'Pending updates', 'fckmaleware' ),
				'description'   => __( 'Counts available core, plugin and theme updates.', 'fckmaleware' ),
				'risk'          => __( 'Most WordPress compromises use publicly known vulnerabilities that already have a fix.', 'fckmaleware' ),
				'compatibility' => __( 'Report only.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'abandoned_plugins' => array(
				'title'         => __( 'Closed or abandoned plugins', 'fckmaleware' ),
				'description'   => __( 'Asks wordpress.org about each installed plugin: closed plugins (often for security reasons) and plugins without updates for two years are reported.', 'fckmaleware' ),
				'risk'          => __( 'Unmaintained plugins do not receive security fixes.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Only plugins hosted on wordpress.org can be checked; this is not a vulnerability database lookup.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'accounts'          => array(
				'title'         => __( 'Account hygiene', 'fckmaleware' ),
				'description'   => __( 'Checks for an account named "admin" and for open registration with a privileged default role.', 'fckmaleware' ),
				'risk'          => __( '"admin" is the first login name every brute-force attack tries.', 'fckmaleware' ),
				'compatibility' => __( 'Report only.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'transport'         => array(
				'title'         => __( 'HTTPS and PHP version', 'fckmaleware' ),
				'description'   => __( 'Checks that the site address uses HTTPS and that PHP still receives security support.', 'fckmaleware' ),
				'risk'          => __( 'Plain HTTP exposes login cookies; unsupported PHP versions get no security fixes.', 'fckmaleware' ),
				'compatibility' => __( 'Report only.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
			'cloaked_redirects' => array(
				'title'         => __( 'Cloaked redirects', 'fckmaleware' ),
				'description'   => __( 'Loads the home page the way a visitor from Google on a phone would and checks whether it redirects to another domain.', 'fckmaleware' ),
				'risk'          => __( 'Redirect malware only targets search and mobile visitors, so administrators never see it.', 'fckmaleware' ),
				'compatibility' => __( 'Report only. Needs the server to be able to request its own home page; the result is "unknown" when it cannot.', 'fckmaleware' ),
				'rollback'      => __( 'Nothing to roll back.', 'fckmaleware' ),
				'toggle'        => false,
			),
		);
	}

	public static function enabled(): array {
		$state = Store::get( self::OPTION, array() );
		$state = is_array( $state ) ? $state : array();
		// 0.x stored the uploads rule as a setting.
		if ( ! isset( $state['uploads_php'] ) && Settings::get( 'block_uploads_php' ) ) {
			$state['uploads_php'] = true;
		}
		return $state;
	}

	public static function is_enabled( string $id ): bool {
		return ! empty( self::enabled()[ $id ] );
	}

	/** Install runtime hooks for the enabled rules. */
	public function register(): void {
		$enabled = self::enabled();
		if ( ! empty( $enabled['disallow_file_edit'] ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
		if ( ! empty( $enabled['disable_xmlrpc'] ) ) {
			// xmlrpc_enabled only stops authenticated methods; removing every method
			// also stops pingbacks, system.multicall and the unauthenticated demo methods.
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array', PHP_INT_MAX );
			add_filter(
				'wp_headers',
				static function ( $headers ) {
					unset( $headers['X-Pingback'] );
					return $headers;
				}
			);
		}
		if ( ! empty( $enabled['rest_users'] ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'restrict_rest_users' ), 10, 3 );
		}
		if ( ! empty( $enabled['author_enum'] ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_enum' ), 0 );
		}
		if ( ! empty( $enabled['security_headers'] ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
		}
		// Uses of the file editor are always logged ("unauthorized file editing" detection).
		add_action( 'wp_ajax_edit-theme-plugin-file', array( $this, 'log_file_edit' ), 0 );
	}

	/**
	 * @param mixed            $result
	 * @param \WP_REST_Server  $server
	 * @param \WP_REST_Request $request
	 * @return mixed
	 */
	public function restrict_rest_users( $result, $server, $request ) {
		if ( null === $result && 0 === strpos( (string) $request->get_route(), '/wp/v2/users' ) && ! is_user_logged_in() ) {
			return new \WP_Error( 'rest_user_cannot_view', __( 'Sorry, you are not allowed to list users.', 'fckmaleware' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	public function block_author_enum(): void {
		if ( ! is_user_logged_in() && isset( $_GET['author'] ) && ! is_admin() ) { // phpcs:ignore WordPress.Security.NonceVerification
			global $wp_query;
			$wp_query->set_404();
			status_header( 404 );
			nocache_headers();
		}
	}

	public function send_security_headers(): void {
		if ( headers_sent() ) {
			return;
		}
		$existing = array_map( 'strtolower', array_map( static function ( $h ) {
			return trim( explode( ':', $h, 2 )[0] );
		}, headers_list() ) );
		$headers = array(
			'X-Content-Type-Options' => 'nosniff',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
		);
		foreach ( $headers as $name => $value ) {
			if ( ! in_array( strtolower( $name ), $existing, true ) ) {
				header( "{$name}: {$value}" );
			}
		}
	}

	public function log_file_edit(): void {
		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- logging only; WordPress verifies the request.
		$what = isset( $_POST['plugin'] ) ? 'plugin ' . sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : 'theme ' . ( isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '' ); // phpcs:ignore WordPress.Security.NonceVerification
		ActivityLog::log(
			'file.edited',
			sprintf( /* translators: 1: file, 2: plugin/theme */ __( 'File edited in the dashboard editor: %1$s (%2$s)', 'fckmaleware' ), $file, $what ),
			array( 'file' => $file, 'target' => $what, 'user' => get_current_user_id(), 'ip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' ),
			'warning'
		);
	}

	// --- Toggling ---------------------------------------------------------------

	/** @return true|\WP_Error */
	public function set( string $id, bool $on ) {
		$catalog = self::catalog();
		if ( ! isset( $catalog[ $id ] ) || ! $catalog[ $id ]['toggle'] ) {
			return new \WP_Error( 'fckmw_rule', __( 'Unknown or report-only rule.', 'fckmaleware' ) );
		}
		if ( 'uploads_php' === $id ) {
			Store::delete( 'fckmw_uploads_rule_test' );
		}
		if ( 'uploads_php' === $id && ! self::apply_uploads_rule( $on ) ) {
			return new \WP_Error( 'fckmw_htaccess', __( 'The uploads .htaccess file could not be written.', 'fckmaleware' ) );
		}
		$state        = self::enabled();
		$state[ $id ] = $on;
		Store::set( self::OPTION, $state );
		if ( 'uploads_php' === $id ) {
			Settings::update( array( 'block_uploads_php' => $on ? '1' : '' ), array( 'block_uploads_php' ) );
		}
		delete_site_transient( self::STATUS_CACHE );
		ActivityLog::log( 'hardening.' . ( $on ? 'enabled' : 'disabled' ), sprintf( /* translators: 1: enabled/disabled, 2: rule */ __( 'Hardening rule %1$s: %2$s', 'fckmaleware' ), $on ? __( 'enabled', 'fckmaleware' ) : __( 'disabled', 'fckmaleware' ), $catalog[ $id ]['title'] ), array( 'rule' => $id ), 'notice' );
		return true;
	}

	/** Add or remove the "no PHP in uploads" rule. */
	public static function apply_uploads_rule( bool $enabled ): bool {
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		$uploads = wp_upload_dir( null, false );
		$file    = trailingslashit( $uploads['basedir'] ) . '.htaccess';

		if ( ! $enabled && ! file_exists( $file ) ) {
			return true;
		}
		self::backup_file( $file, 'uploads-htaccess' );
		$lines = $enabled ? array(
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht|phps)$">',
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

	/**
	 * Keep a copy of a configuration file before changing it (newest five per
	 * name) in the private data folder.
	 */
	public static function backup_file( string $file, string $name ): void {
		if ( ! is_file( $file ) || ! Paths::ensure_data_dir() ) {
			return;
		}
		$dir = Paths::data_dir() . '/backups';
		// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		$target = $dir . '/' . $name . '-' . gmdate( 'Ymd-His' ) . '.bak';
		if ( @copy( $file, $target ) ) {
			@chmod( $target, 0600 );
		}
		$old = (array) glob( $dir . '/' . $name . '-*.bak' );
		sort( $old );
		foreach ( array_slice( $old, 0, max( 0, count( $old ) - 5 ) ) as $stale ) {
			@unlink( (string) $stale );
		}
		// phpcs:enable
	}

	/**
	 * Check over HTTP whether PHP in uploads actually runs: a harmless probe
	 * that only prints a marker is written to uploads, requested and deleted.
	 * nginx and some LiteSpeed setups ignore .htaccess, so the rule being
	 * written does not prove it is enforced.
	 *
	 * @return array{state: string, detail: string}
	 */
	public function test_uploads_rule(): array {
		$uploads = wp_upload_dir( null, false );
		$name    = 'fckmw-probe-' . strtolower( wp_generate_password( 12, false, false ) ) . '.php';
		$path    = trailingslashit( $uploads['basedir'] ) . $name;
		$marker  = 'fckmw-probe-' . wp_generate_password( 8, false, false );
		// phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === @file_put_contents( $path, "<?php echo '" . $marker . "-' . 'ran';\n" ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$result = self::result( 'unknown', __( 'Could not write the test file to uploads.', 'fckmaleware' ) );
		} else {
			$response = wp_remote_get( trailingslashit( $uploads['baseurl'] ) . $name, array( 'timeout' => 10, 'redirection' => 0, 'sslverify' => false ) );
			wp_delete_file( $path );
			if ( is_wp_error( $response ) ) {
				$result = self::result( 'unknown', sprintf( /* translators: %s: error */ __( 'The site could not request its own uploads folder (%s), so enforcement could not be tested.', 'fckmaleware' ), $response->get_error_message() ) );
			} elseif ( false !== strpos( (string) wp_remote_retrieve_body( $response ), $marker . '-ran' ) ) {
				$result = self::result( 'fail', __( 'Test failed: a PHP file in uploads was executed. The server does not enforce the rule (nginx ignores .htaccess); add the server rule shown below.', 'fckmaleware' ) );
			} else {
				/* translators: %d: HTTP status */
				$result = self::result( 'pass', sprintf( __( 'Test passed: a PHP file in uploads was not executed (HTTP %d).', 'fckmaleware' ), (int) wp_remote_retrieve_response_code( $response ) ) );
			}
		}
		Store::set( 'fckmw_uploads_rule_test', $result + array( 'time' => time() ) );
		ActivityLog::log( 'hardening.tested', sprintf( /* translators: %s: result */ __( 'Uploads PHP execution test: %s', 'fckmaleware' ), $result['detail'] ), array( 'state' => $result['state'] ), 'fail' === $result['state'] ? 'warning' : 'info' );
		delete_site_transient( self::STATUS_CACHE );
		return $result;
	}

	// --- Status -----------------------------------------------------------------

	/**
	 * @return array<string, array{state: string, detail: string}> state: pass, warn, fail, info, unknown
	 */
	public function status( bool $refresh = false ): array {
		$cached = $refresh ? false : get_site_transient( self::STATUS_CACHE );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$out = array();
		foreach ( array_keys( self::catalog() ) as $id ) {
			try {
				$out[ $id ] = $this->{'status_' . $id}();
			} catch ( \Throwable $e ) {
				$out[ $id ] = array( 'state' => 'unknown', 'detail' => $e->getMessage() );
			}
		}
		set_site_transient( self::STATUS_CACHE, $out, 10 * MINUTE_IN_SECONDS );

		// Kept beyond the cache lifetime as input for the health score.
		$summary = array( 'pass' => 0, 'warn' => 0, 'fail' => 0, 'time' => time() );
		foreach ( $out as $item ) {
			if ( isset( $summary[ $item['state'] ] ) ) {
				$summary[ $item['state'] ]++;
			}
		}
		Store::set( 'fckmw_hardening_summary', $summary );
		return $out;
	}

	private static function result( string $state, string $detail ): array {
		return array( 'state' => $state, 'detail' => $detail );
	}

	private function status_uploads_php(): array {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$on     = self::is_enabled( 'uploads_php' );
		if ( false !== strpos( $server, 'nginx' ) ) {
			return self::result( 'info', __( 'This server runs nginx, which ignores .htaccess. Add: location ~* ^/wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar)$ { deny all; }', 'fckmaleware' ) );
		}
		$test = Store::get( 'fckmw_uploads_rule_test', array() );
		if ( is_array( $test ) && isset( $test['state'] ) && 'unknown' !== $test['state'] ) {
			return self::result( $test['state'], $test['detail'] );
		}
		return $on ? self::result( 'pass', __( 'PHP execution in uploads is blocked by .htaccess. Use "Test" to confirm the server enforces it.', 'fckmaleware' ) ) : self::result( 'warn', __( 'PHP files placed in uploads can be executed.', 'fckmaleware' ) );
	}

	private function status_disallow_file_edit(): array {
		return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT
			? self::result( 'pass', __( 'The dashboard file editor is disabled.', 'fckmaleware' ) )
			: self::result( 'warn', __( 'Administrators can edit plugin and theme code from the dashboard.', 'fckmaleware' ) );
	}

	private function status_disable_xmlrpc(): array {
		if ( self::is_enabled( 'disable_xmlrpc' ) ) {
			return self::result( 'pass', __( 'XML-RPC is disabled.', 'fckmaleware' ) );
		}
		if ( function_exists( 'is_plugin_active' ) && is_plugin_active( 'jetpack/jetpack.php' ) ) {
			return self::result( 'info', __( 'XML-RPC is enabled; Jetpack is active and needs it.', 'fckmaleware' ) );
		}
		return self::result( 'warn', __( 'XML-RPC is enabled.', 'fckmaleware' ) );
	}

	private function status_rest_users(): array {
		return self::is_enabled( 'rest_users' ) ? self::result( 'pass', __( 'Anonymous visitors cannot list users through the REST API.', 'fckmaleware' ) ) : self::result( 'warn', __( 'Login names can be listed at /wp-json/wp/v2/users.', 'fckmaleware' ) );
	}

	private function status_author_enum(): array {
		return self::is_enabled( 'author_enum' ) ? self::result( 'pass', __( '?author= enumeration is blocked.', 'fckmaleware' ) ) : self::result( 'info', __( 'Login names can be discovered through ?author=N redirects.', 'fckmaleware' ) );
	}

	private function status_security_headers(): array {
		return self::is_enabled( 'security_headers' ) ? self::result( 'pass', __( 'Security headers are added to responses that lack them.', 'fckmaleware' ) ) : self::result( 'info', __( 'FCK Malware does not add security headers (your server may already send them).', 'fckmaleware' ) );
	}

	private function status_debug_exposure(): array {
		$problems = array();
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
			$problems[] = __( 'WP_DEBUG is on and errors are displayed to visitors.', 'fckmaleware' );
		}
		if ( file_exists( WP_CONTENT_DIR . '/debug.log' ) ) {
			$code = self::http_status( content_url( 'debug.log' ) );
			if ( 200 === $code ) {
				$problems[] = __( 'wp-content/debug.log can be downloaded by anyone.', 'fckmaleware' );
			}
		}
		return $problems ? self::result( 'fail', implode( ' ', $problems ) ) : self::result( 'pass', __( 'No debug output or public debug log found.', 'fckmaleware' ) );
	}

	private function status_directory_listing(): array {
		$response = wp_remote_get( trailingslashit( wp_upload_dir( null, false )['baseurl'] ), array( 'timeout' => 8, 'redirection' => 0, 'sslverify' => (bool) apply_filters( 'https_local_ssl_verify', false ) ) );
		if ( is_wp_error( $response ) ) {
			return self::result( 'unknown', __( 'The server could not request its own uploads URL.', 'fckmaleware' ) );
		}
		$body = (string) wp_remote_retrieve_body( $response );
		if ( 200 === (int) wp_remote_retrieve_response_code( $response ) && preg_match( '/<title>\s*Index of|<h1>\s*Index of/i', $body ) ) {
			return self::result( 'fail', __( 'The uploads directory is listed publicly.', 'fckmaleware' ) );
		}
		return self::result( 'pass', __( 'The uploads directory is not listed.', 'fckmaleware' ) );
	}

	private function status_exposed_backups(): array {
		$found = array();
		$dirs  = array( ABSPATH, WP_CONTENT_DIR . '/', trailingslashit( wp_upload_dir( null, false )['basedir'] ) );
		foreach ( $dirs as $dir ) {
			foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( preg_match( '/\.(?:sql|sql\.gz|sql\.zip|bak|old|orig|save|swp|tar|tar\.gz|tgz|zip|7z|rar)$|^wp-config\.php.+$|^\.wp-config\.php\.swp$/i', (string) $name ) && is_file( $dir . $name ) ) {
					$found[] = Paths::relative( wp_normalize_path( $dir . $name ) ) ?? $name;
				}
			}
		}
		if ( is_dir( ABSPATH . '.git' ) ) {
			$found[] = '.git/';
		}
		return $found ? self::result( 'fail', sprintf( /* translators: %s: files */ __( 'Potentially downloadable: %s', 'fckmaleware' ), implode( ', ', array_slice( $found, 0, 15 ) ) ) ) : self::result( 'pass', __( 'No backups or repositories found in web-reachable locations.', 'fckmaleware' ) );
	}

	private function status_permissions(): array {
		$problems = array();
		$config   = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $config ) ) {
			$mode = fileperms( $config ) & 0777;
			if ( $mode & 0002 ) {
				$problems[] = sprintf( 'wp-config.php is world-writable (%o)', $mode );
			} elseif ( $mode & 0004 ) {
				$problems[] = sprintf( 'wp-config.php is world-readable (%o)', $mode );
			}
		}
		foreach ( array( ABSPATH, WP_CONTENT_DIR, WP_PLUGIN_DIR, wp_upload_dir( null, false )['basedir'] ) as $dir ) {
			if ( is_dir( $dir ) && ( fileperms( $dir ) & 0002 ) ) {
				$problems[] = sprintf( '%s is world-writable (%o)', Paths::relative( wp_normalize_path( $dir ) ) ?: '/', fileperms( $dir ) & 0777 );
			}
		}
		return $problems ? self::result( 'warn', implode( '; ', $problems ) ) : self::result( 'pass', __( 'No world-writable directories; wp-config.php is not world-readable.', 'fckmaleware' ) );
	}

	private function status_updates(): array {
		$core    = get_site_transient( 'update_core' );
		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		$counts  = array(
			'core'    => 0,
			'plugins' => is_object( $plugins ) && ! empty( $plugins->response ) ? count( $plugins->response ) : 0,
			'themes'  => is_object( $themes ) && ! empty( $themes->response ) ? count( $themes->response ) : 0,
		);
		if ( is_object( $core ) && ! empty( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( 'upgrade' === ( $update->response ?? '' ) ) {
					$counts['core'] = 1;
				}
			}
		}
		$total = array_sum( $counts );
		return $total
			? self::result( 'warn', sprintf( /* translators: 1: core, 2: plugins, 3: themes */ __( 'Updates available: core %1$d, plugins %2$d, themes %3$d.', 'fckmaleware' ), $counts['core'], $counts['plugins'], $counts['themes'] ) )
			: self::result( 'pass', __( 'Everything is up to date (as of WordPress\'s last update check).', 'fckmaleware' ) );
	}

	private function status_abandoned_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$cache = get_site_transient( 'fckmw_plugin_maintenance' );
		$cache = is_array( $cache ) ? $cache : array();
		$found = array();
		$budget = microtime( true ) + 8;
		foreach ( array_keys( get_plugins() ) as $file ) {
			$slug = false === strpos( $file, '/' ) ? basename( $file, '.php' ) : dirname( $file );
			if ( ! isset( $cache[ $slug ] ) ) {
				if ( microtime( true ) > $budget ) {
					continue; // Remaining plugins are checked on the next refresh.
				}
				$cache[ $slug ] = self::plugin_maintenance( $slug );
			}
			if ( 'closed' === $cache[ $slug ]['state'] ) {
				$found[] = sprintf( /* translators: %s: plugin */ __( '%s (closed on wordpress.org)', 'fckmaleware' ), $slug );
			} elseif ( 'stale' === $cache[ $slug ]['state'] ) {
				$found[] = sprintf( /* translators: 1: plugin, 2: date */ __( '%1$s (last updated %2$s)', 'fckmaleware' ), $slug, $cache[ $slug ]['updated'] );
			}
		}
		set_site_transient( 'fckmw_plugin_maintenance', $cache, DAY_IN_SECONDS );
		return $found ? self::result( 'warn', implode( '; ', $found ) ) : self::result( 'pass', __( 'No closed or abandoned wordpress.org plugins found.', 'fckmaleware' ) );
	}

	private static function plugin_maintenance( string $slug ): array {
		$response = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][sections]=0', array( 'timeout' => 6 ) );
		if ( is_wp_error( $response ) ) {
			return array( 'state' => 'unknown' );
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( isset( $data['error'] ) ) {
			// "closed" plugins report an error with a closed flag; others are simply not hosted there.
			return array( 'state' => ! empty( $data['closed'] ) || false !== stripos( (string) $data['error'], 'closed' ) ? 'closed' : 'not-hosted' );
		}
		$updated = isset( $data['last_updated'] ) ? strtotime( (string) $data['last_updated'] ) : false;
		if ( false !== $updated && $updated < time() - 2 * YEAR_IN_SECONDS ) {
			return array( 'state' => 'stale', 'updated' => gmdate( 'Y-m-d', $updated ) );
		}
		return array( 'state' => 'ok' );
	}

	private function status_accounts(): array {
		$problems = array();
		if ( get_user_by( 'login', 'admin' ) ) {
			$problems[] = __( 'An account with the login "admin" exists.', 'fckmaleware' );
		}
		if ( get_option( 'users_can_register' ) && ! in_array( get_option( 'default_role' ), array( 'subscriber', 'customer' ), true ) ) {
			$problems[] = sprintf( /* translators: %s: role */ __( 'Anyone can register and gets the "%s" role.', 'fckmaleware' ), get_option( 'default_role' ) );
		}
		return $problems ? self::result( 'warn', implode( ' ', $problems ) ) : self::result( 'pass', __( 'No "admin" login; registration does not grant a privileged role.', 'fckmaleware' ) );
	}

	private function status_transport(): array {
		$problems = array();
		if ( 0 !== strpos( (string) get_option( 'siteurl' ), 'https://' ) ) {
			$problems[] = __( 'The site address does not use HTTPS.', 'fckmaleware' );
		}
		// PHP versions without security support as of the plugin's release.
		if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
			$problems[] = sprintf( /* translators: %s: version */ __( 'PHP %s no longer receives security fixes.', 'fckmaleware' ), PHP_VERSION );
		}
		return $problems ? self::result( 'warn', implode( ' ', $problems ) ) : self::result( 'pass', __( 'HTTPS is used and PHP is supported.', 'fckmaleware' ) );
	}

	private function status_cloaked_redirects(): array {
		$home     = home_url( '/' );
		$host     = wp_parse_url( $home, PHP_URL_HOST );
		$profiles = array(
			'search' => array( 'Referer' => 'https://www.google.com/search?q=' . rawurlencode( (string) $host ), 'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' ),
			'mobile' => array( 'Referer' => 'https://www.google.com/', 'User-Agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1' ),
		);
		foreach ( $profiles as $name => $headers ) {
			$response = wp_remote_get( $home, array( 'timeout' => 8, 'redirection' => 0, 'headers' => $headers, 'sslverify' => (bool) apply_filters( 'https_local_ssl_verify', false ), 'cookies' => array() ) );
			if ( is_wp_error( $response ) ) {
				return self::result( 'unknown', __( 'The server could not request its own home page.', 'fckmaleware' ) );
			}
			$code     = (int) wp_remote_retrieve_response_code( $response );
			$location = (string) wp_remote_retrieve_header( $response, 'location' );
			$target   = (string) wp_parse_url( $location, PHP_URL_HOST );
			if ( $code >= 300 && $code < 400 && '' !== $target && strtolower( $target ) !== strtolower( (string) $host ) && strtolower( $target ) !== 'www.' . strtolower( (string) $host ) ) {
				return self::result( 'fail', sprintf( /* translators: 1: visitor profile, 2: URL */ __( 'Visitors (%1$s) are redirected to %2$s.', 'fckmaleware' ), $name, esc_url_raw( $location ) ) );
			}
			$body = (string) wp_remote_retrieve_body( $response );
			if ( preg_match( '#(?:window|document|top)\.location(?:\.href)?\s*=\s*["\']https?://([^/"\']+)#i', $body, $m ) && strtolower( $m[1] ) !== strtolower( (string) $host ) ) {
				return self::result( 'fail', sprintf( /* translators: 1: visitor profile, 2: host */ __( 'The page served to %1$s visitors contains a script redirect to %2$s.', 'fckmaleware' ), $name, $m[1] ) );
			}
		}
		return self::result( 'pass', __( 'No off-site redirect for search or mobile visitors.', 'fckmaleware' ) );
	}

	private static function http_status( string $url ): int {
		$response = wp_remote_head( $url, array( 'timeout' => 6, 'redirection' => 0, 'sslverify' => (bool) apply_filters( 'https_local_ssl_verify', false ) ) );
		return is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
	}

	/** Share of rules/checks in a passing state (input for the health score). */
	public function score(): array {
		$status = $this->status();
		$pass   = 0;
		$total  = 0;
		foreach ( $status as $item ) {
			if ( in_array( $item['state'], array( 'unknown', 'info' ), true ) ) {
				continue;
			}
			$total++;
			if ( 'pass' === $item['state'] ) {
				$pass++;
			}
		}
		return array( 'pass' => $pass, 'total' => $total );
	}
}
