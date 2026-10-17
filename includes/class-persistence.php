<?php
/**
 * Layer D: behaviour and persistence checks.
 *
 * Looks for the footholds malware leaves outside individual files:
 * hidden or unexpected administrators, privilege changes, dangerous
 * registration settings, changed site URLs, PHP auto_prepend_file,
 * malicious cron payloads, and hook callbacks that come from eval()'d code
 * or from directories where no legitimate plugin lives.
 *
 * Callback origins are found with Reflection, which reads metadata only;
 * nothing is executed.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Persistence {

	private const SNAPSHOT_OPTION = 'fckmw_persistence_snapshot';

	/** Hooks whose callbacks control authentication, redirects or page output. */
	private const SENSITIVE_HOOKS = array( 'authenticate', 'wp_authenticate_user', 'check_password', 'determine_current_user', 'login_init', 'wp_login', 'set_logged_in_cookie', 'auth_cookie_valid', 'init', 'wp_loaded', 'template_redirect', 'wp_head', 'wp_footer', 'the_content', 'wp_redirect', 'pre_user_query', 'all_plugins', 'user_has_cap', 'map_meta_cap' );

	/** Capabilities that let a role take over the site. */
	private const TAKEOVER_CAPS = array( 'manage_options', 'install_plugins', 'activate_plugins', 'edit_plugins', 'delete_plugins', 'edit_files', 'update_core', 'unfiltered_upload', 'install_themes', 'edit_themes', 'create_users', 'promote_users' );

	/** Roles shipped by WordPress or well-known plugins that legitimately hold some takeover caps. */
	private const TRUSTED_ROLES = array( 'administrator' );

	/** @var Findings */
	private $findings;

	/** @var Signatures */
	private $signatures;

	/** @var array<int, array> */
	private $detections = array();

	public function __construct( Findings $findings, Signatures $signatures ) {
		$this->findings   = $findings;
		$this->signatures = $signatures;
	}

	/**
	 * Run every check, store findings and resolve the ones no longer present.
	 *
	 * @return array{found: int, new: int, resolved: int}
	 */
	public function run( string $trigger = 'manual' ): array {
		$this->detections = array();
		$snapshot         = Store::get( self::SNAPSHOT_OPTION, array() );
		$snapshot         = is_array( $snapshot ) ? $snapshot : array();
		$first_run        = ! $snapshot;

		$this->check_hidden_admins();
		$this->check_new_admins( $snapshot, $first_run );
		$this->check_user_level_caps();
		$this->check_roles();
		$this->check_registration();
		$this->check_site_urls( $snapshot, $first_run );
		$this->check_auto_prepend();
		$this->check_cron();
		$this->check_hooks();

		Store::set( self::SNAPSHOT_OPTION, $this->snapshot( $snapshot, $first_run ) );

		$scan_id = 'persistence:' . time();
		$found   = 0;
		$new     = 0;
		foreach ( $this->detections as $detection ) {
			$result = $this->findings->upsert( $detection + array( 'scan_id' => $scan_id, 'source' => 'behaviour' ) );
			if ( 'ignored' !== $result['outcome'] ) {
				$found++;
			}
			if ( 'new' === $result['outcome'] ) {
				$new++;
			}
		}
		$resolved = 0;
		foreach ( array( 'user', 'role', 'option', 'config', 'cron', 'hook' ) as $type ) {
			$resolved += $this->findings->resolve_stale( $scan_id, array( 'behaviour' ), $type );
		}

		ActivityLog::log(
			'persistence.check',
			sprintf( /* translators: 1: findings, 2: new */ __( 'Persistence check: %1$d findings, %2$d new.', 'fckmaleware' ), $found, $new ),
			array( 'trigger' => $trigger, 'found' => $found, 'new' => $new, 'resolved' => $resolved ),
			$new ? 'warning' : 'info'
		);
		Store::set( 'fckmw_last_persistence_check', array( 'time' => time(), 'found' => $found, 'new' => $new ) );
		return array( 'found' => $found, 'new' => $new, 'resolved' => $resolved );
	}

	/** Accept the current administrators / site URLs as known-good (used when a finding is ignored). */
	public function accept_current_state(): void {
		Store::set( self::SNAPSHOT_OPTION, $this->snapshot( array(), true ) );
	}

	private function add( string $type, string $ref, string $label, string $id, string $name, string $severity, int $confidence, string $evidence, string $remediation = 'review', string $excerpt = '' ): void {
		$this->detections[] = array(
			'object_type'    => $type,
			'object_ref'     => $type . ':' . $ref,
			'file'           => $label,
			'signature_id'   => $id,
			'signature_name' => $name,
			'family'         => 'Behaviour.' . ucfirst( $type ),
			'severity'       => $severity,
			'confidence'     => $confidence,
			'verdict'        => Signatures::verdict( $confidence ),
			'evidence'       => $evidence,
			'excerpt'        => $excerpt,
			'remediation'    => $remediation,
		);
	}

	// --- Users and roles ------------------------------------------------------

	/** @return int[] IDs of users whose stored capabilities include the administrator role. */
	private static function admin_ids_sql(): array {
		global $wpdb;
		$ids = array();
		$keys = is_multisite() ? array_map(
			static function ( $blog ) use ( $wpdb ) {
				return $wpdb->get_blog_prefix( (int) $blog ) . 'capabilities';
			},
			get_sites( array( 'fields' => 'ids', 'number' => 1000 ) )
		) : array( $wpdb->get_blog_prefix() . 'capabilities' );
		foreach ( $keys as $key ) {
			$found = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s", $key, '%' . $wpdb->esc_like( '"administrator"' ) . '%' ) ); // phpcs:ignore WordPress.DB
			$ids   = array_merge( $ids, array_map( 'intval', (array) $found ) );
		}
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( $user ) {
					$ids[] = (int) $user->ID;
				}
			}
		}
		return array_values( array_unique( $ids ) );
	}

	/**
	 * Administrators present in the database but missing from WP_User_Query:
	 * something (usually a pre_user_query filter) is hiding them.
	 */
	private function check_hidden_admins(): void {
		$sql_ids = self::admin_ids_sql();
		$visible = array_map( 'intval', get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'blog_id' => get_current_blog_id() ) ) );
		if ( is_multisite() ) {
			$visible = array_merge( $visible, array_map( 'intval', get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'blog_id' => 0 ) ) ) );
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( $user ) {
					$visible[] = (int) $user->ID;
				}
			}
		}
		// get_users() for one blog cannot see admins of other blogs; only compare where it can.
		$compare = is_multisite() ? array() : array_diff( $sql_ids, $visible );
		foreach ( $compare as $id ) {
			$user = get_userdata( $id );
			$this->add(
				'user',
				(string) $id,
				sprintf( 'User #%d (%s)', $id, $user ? $user->user_login : '?' ),
				'FMW-BEH-001',
				__( 'Hidden administrator account', 'fckmaleware' ),
				'critical',
				90,
				__( 'This administrator exists in the database but is hidden from the WordPress user list. Malware hides rogue admins with a pre_user_query filter.', 'fckmaleware' )
			);
		}
	}

	private function check_new_admins( array $snapshot, bool $first_run ): void {
		if ( $first_run ) {
			return; // The first run records the current administrators as known.
		}
		$known = array_map( 'intval', (array) ( $snapshot['admins'] ?? array() ) );
		foreach ( array_diff( self::admin_ids_sql(), $known ) as $id ) {
			$user = get_userdata( $id );
			$this->add(
				'user',
				(string) $id,
				sprintf( 'User #%d (%s)', $id, $user ? $user->user_login : '?' ),
				'FMW-BEH-002',
				__( 'New administrator account', 'fckmaleware' ),
				'high',
				55,
				sprintf(
					/* translators: 1: login, 2: email, 3: date */
					__( 'Administrator "%1$s" (%2$s, registered %3$s) appeared since the last check. If you created it, ignore this finding to accept it.', 'fckmaleware' ),
					$user ? $user->user_login : '?',
					$user ? $user->user_email : '?',
					$user ? $user->user_registered : '?'
				)
			);
		}
	}

	/** Users granted takeover capabilities directly (not through a role). */
	private function check_user_level_caps(): void {
		global $wpdb;
		$key  = $wpdb->get_blog_prefix() . 'capabilities';
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s LIMIT 200", $key, '%' . $wpdb->esc_like( 'manage_options' ) . '%' ), ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			if ( false !== strpos( $row['meta_value'], '"administrator"' ) ) {
				continue;
			}
			$user = get_userdata( (int) $row['user_id'] );
			$this->add(
				'user',
				'caps:' . $row['user_id'],
				sprintf( 'User #%d (%s)', $row['user_id'], $user ? $user->user_login : '?' ),
				'FMW-BEH-003',
				__( 'User granted administrator capabilities directly', 'fckmaleware' ),
				'high',
				75,
				__( 'This account is not an administrator but has manage_options assigned directly to the user, a way to hide admin rights from role-based reviews.', 'fckmaleware' )
			);
		}
	}

	private function check_roles(): void {
		$roles = wp_roles()->roles;
		foreach ( $roles as $slug => $role ) {
			if ( in_array( $slug, self::TRUSTED_ROLES, true ) ) {
				continue;
			}
			$caps      = array_keys( array_filter( (array) ( $role['capabilities'] ?? array() ) ) );
			$takeovers = array_values( array_intersect( $caps, self::TAKEOVER_CAPS ) );
			if ( ! $takeovers ) {
				continue;
			}
			$this->add(
				'role',
				(string) $slug,
				sprintf( 'Role "%s"', $slug ),
				'FMW-BEH-004',
				__( 'Non-administrator role can take over the site', 'fckmaleware' ),
				in_array( 'manage_options', $takeovers, true ) || in_array( 'install_plugins', $takeovers, true ) ? 'high' : 'medium',
				60,
				sprintf( /* translators: 1: role, 2: capabilities */ __( 'Role "%1$s" has: %2$s. Membership or shop plugins sometimes add a few of these; anything granting plugin installation or options management to non-admins should be deliberate.', 'fckmaleware' ), $slug, implode( ', ', $takeovers ) )
			);
		}
	}

	private function check_registration(): void {
		$default = (string) get_option( 'default_role' );
		$open    = (bool) get_option( 'users_can_register' );
		if ( 'administrator' === $default ) {
			$this->add( 'option', 'default_role', 'Option "default_role"', 'FMW-BEH-005', __( 'New users become administrators', 'fckmaleware' ), $open ? 'critical' : 'high', 90, __( 'The default role for new accounts is administrator. Attackers set this so a self-registered account gains full control.', 'fckmaleware' ), 'review' );
		} elseif ( $open && in_array( $default, array( 'editor', 'shop_manager' ), true ) ) {
			$this->add( 'option', 'default_role', 'Option "default_role"', 'FMW-BEH-006', __( 'Open registration grants a privileged role', 'fckmaleware' ), 'medium', 55, sprintf( /* translators: %s: role */ __( 'Anyone can register and receives the "%s" role.', 'fckmaleware' ), $default ) );
		}
	}

	private function check_site_urls( array $snapshot, bool $first_run ): void {
		if ( $first_run ) {
			return;
		}
		foreach ( array( 'siteurl', 'home' ) as $option ) {
			$now    = (string) get_option( $option );
			$before = (string) ( $snapshot['urls'][ $option ] ?? $now );
			if ( wp_parse_url( $now, PHP_URL_HOST ) !== wp_parse_url( $before, PHP_URL_HOST ) ) {
				$this->add( 'option', $option, sprintf( 'Option "%s"', $option ), 'FMW-BEH-007', __( 'Site address changed to another domain', 'fckmaleware' ), 'high', 70, sprintf( /* translators: 1: before, 2: after */ __( 'Changed from %1$s to %2$s. Redirect malware rewrites these options; ignore this finding if you moved the site.', 'fckmaleware' ), $before, $now ), 'review', $now );
			}
		}
	}

	private function check_auto_prepend(): void {
		$prepend = (string) ini_get( 'auto_prepend_file' );
		if ( '' === $prepend ) {
			return;
		}
		// Known firewalls install themselves this way.
		if ( preg_match( '#(?:wordfence-waf|malcare|bbwaf|sucuri|ninjafirewall|aios-bootstrap|imunify)#i', $prepend ) ) {
			return;
		}
		$this->add( 'config', 'auto_prepend_file', 'PHP auto_prepend_file', 'FMW-BEH-008', __( 'PHP runs a file before every request', 'fckmaleware' ), 'medium', 60, sprintf( /* translators: %s: path */ __( 'auto_prepend_file is set to %s. Firewalls use this legitimately; malware uses it for persistence. Confirm what installed it.', 'fckmaleware' ), $prepend ), 'review', $prepend );
	}

	// --- Cron -----------------------------------------------------------------

	private function check_cron(): void {
		$crons = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
		foreach ( (array) $crons as $timestamp => $hooks ) {
			foreach ( (array) $hooks as $hook => $events ) {
				foreach ( (array) $events as $event ) {
					$payload = (string) wp_json_encode( array( $hook, $event['args'] ?? array() ), JSON_UNESCAPED_SLASHES );
					$matches = array_merge( $this->signatures->match( $payload, 'db' ), $this->signatures->match( stripslashes( $payload ), 'php' ) );
					if ( ! $matches ) {
						continue;
					}
					$sig = $matches[0]['signature'];
					$this->add( 'cron', md5( $hook . $payload ), sprintf( 'Cron event "%s"', $hook ), 'FMW-BEH-009', __( 'Scheduled task carries malicious code', 'fckmaleware' ), 'high', max( 70, (int) $sig['confidence'] ), sprintf( /* translators: %s: signature name */ __( 'The arguments of this scheduled event match "%s". Malware stores payloads in cron events to re-infect the site.', 'fckmaleware' ), $sig['name'] ), 'review', $matches[0]['excerpt'] );
				}
			}
		}
	}

	// --- Hook callbacks ---------------------------------------------------------

	private function check_hooks(): void {
		global $wp_filter;
		$allowed = self::trusted_roots();
		foreach ( self::SENSITIVE_HOOKS as $hook ) {
			if ( empty( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof \WP_Hook ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$file = self::callback_file( $callback['function'] );
					if ( null === $file ) {
						continue;
					}
					if ( false !== strpos( $file, "eval()'d code" ) || false !== strpos( $file, 'runtime-created function' ) ) {
						$this->add( 'hook', $hook . ':' . md5( $file ), sprintf( 'Hook "%s" (priority %d)', $hook, $priority ), 'FMW-BEH-010', __( 'Hook callback created by eval()', 'fckmaleware' ), 'critical', 90, __( 'A callback on a sensitive hook was defined by eval()\'d code, so it exists in no file on disk: a hallmark of fileless malware.', 'fckmaleware' ), 'review', $file );
						continue;
					}
					$normalized = wp_normalize_path( $file );
					$trusted    = false;
					foreach ( $allowed as $root ) {
						if ( 0 === strpos( $normalized, $root ) ) {
							$trusted = true;
							break;
						}
					}
					if ( ! $trusted ) {
						$rel = Paths::relative( $normalized ) ?? $normalized;
						$this->add( 'hook', $hook . ':' . md5( $normalized ), sprintf( 'Hook "%s" (priority %d)', $hook, $priority ), 'FMW-BEH-011', __( 'Hook callback loaded from an unexpected location', 'fckmaleware' ), 'high', 75, sprintf( /* translators: %s: file */ __( 'A callback on this sensitive hook is defined in %s, outside WordPress core, plugins, must-use plugins, drop-ins and themes.', 'fckmaleware' ), $rel ), 'review', $rel );
					}
				}
			}
		}
	}

	/** @return string[] Normalized directories legitimate callbacks come from. */
	private static function trusted_roots(): array {
		$roots = array(
			trailingslashit( wp_normalize_path( ABSPATH . WPINC ) ),
			trailingslashit( wp_normalize_path( ABSPATH . 'wp-admin' ) ),
			trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ),
			trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) ),
			trailingslashit( wp_normalize_path( get_theme_root() ) ),
			trailingslashit( wp_normalize_path( (string) realpath( FCKMW_DIR ) ) ),
		);
		// Plugins and themes may be symlinked from elsewhere (common in development and managed hosting).
		foreach ( (array) wp_get_active_and_valid_plugins() as $plugin ) {
			$roots[] = trailingslashit( wp_normalize_path( dirname( (string) realpath( $plugin ) ) ) );
		}
		// WP-CLI registers its own callbacks when the check runs from the command line.
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI', false ) ) {
			$cli    = wp_normalize_path( (string) ( new \ReflectionClass( '\\WP_CLI' ) )->getFileName() );
			$vendor = strpos( $cli, '/vendor/' );
			if ( false !== $vendor ) {
				$roots[] = substr( $cli, 0, $vendor + 8 );
			}
		}
		foreach ( array( 'advanced-cache.php', 'object-cache.php', 'db.php', 'sunrise.php', 'db-error.php', 'maintenance.php', 'php-error.php', 'fatal-error-handler.php' ) as $dropin ) {
			$roots[] = wp_normalize_path( WP_CONTENT_DIR . '/' . $dropin );
		}
		/**
		 * Extra directories (or files) whose hook callbacks are trusted.
		 *
		 * @param string[] $roots Normalized absolute paths.
		 */
		return array_values( array_unique( (array) apply_filters( 'fckmw_trusted_callback_roots', $roots ) ) );
	}

	/** File that defines a callback, without calling it. */
	private static function callback_file( $callback ): ?string {
		try {
			if ( is_string( $callback ) && false !== strpos( $callback, '::' ) ) {
				$callback = explode( '::', $callback, 2 );
			}
			if ( is_array( $callback ) && 2 === count( $callback ) ) {
				$reflection = new \ReflectionMethod( is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0], (string) $callback[1] );
			} elseif ( $callback instanceof \Closure || ( is_string( $callback ) && function_exists( $callback ) ) ) {
				$reflection = new \ReflectionFunction( $callback );
			} elseif ( is_object( $callback ) && method_exists( $callback, '__invoke' ) ) {
				$reflection = new \ReflectionMethod( $callback, '__invoke' );
			} else {
				return null;
			}
		} catch ( \ReflectionException $e ) {
			return null;
		}
		if ( $reflection->isInternal() ) {
			return null;
		}
		$file = $reflection->getFileName();
		return false === $file ? null : (string) $file;
	}

	private function snapshot( array $previous, bool $reset ): array {
		$snapshot = $reset ? array() : $previous;
		// Known admins only grow through explicit acceptance (or a fresh snapshot).
		$snapshot['admins'] = $reset ? self::admin_ids_sql() : array_values( array_unique( array_map( 'intval', (array) ( $previous['admins'] ?? array() ) ) ) );
		if ( $reset || ! isset( $snapshot['urls'] ) ) {
			$snapshot['urls'] = array(
				'siteurl' => (string) get_option( 'siteurl' ),
				'home'    => (string) get_option( 'home' ),
			);
		}
		$snapshot['time'] = time();
		return $snapshot;
	}
}
