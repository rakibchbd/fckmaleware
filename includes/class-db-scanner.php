<?php
/**
 * Database threat scanner (posts, options, comments; every site on multisite).
 *
 * Rows are read in bounded primary-key ranges with an SQL LIKE prefilter so
 * only candidate rows reach PHP. Values are matched as raw strings against
 * signatures targeting "db": serialized data is never unserialized (no PHP
 * object injection) and never rewritten. Remediation is a preview plus a link
 * to the right editor; nothing is search-and-replaced.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class DbScanner {

	public const STATE_OPTION = 'fckmw_db_scan_state';

	private const LOCK       = 'db-scan';
	private const RANGE      = 2000;
	private const MAX_VALUE  = 1048576;
	private const NEEDLES    = array( '<script', '<iframe', 'eval(', 'fromCharCode', 'atob(', 'display:none', 'display: none', 'base64_decode', 'document.write', '<?php', 'left:-', 'gzinflate' );

	/** @var Signatures */
	private $signatures;

	/** @var Findings */
	private $findings;

	public function __construct( Signatures $signatures, Findings $findings ) {
		$this->signatures = $signatures;
		$this->findings   = $findings;
	}

	public function state(): array {
		$state = Store::get( self::STATE_OPTION, array() );
		return is_array( $state ) && $state ? $state : array( 'status' => 'idle' );
	}

	/** @return array|\WP_Error */
	public function start( string $trigger = 'manual' ) {
		$state = $this->state();
		if ( 'running' === $state['status'] && time() - (int) $state['updated'] < 900 ) {
			return new \WP_Error( 'fckmw_running', __( 'A database scan is already running.', 'fckmaleware' ) );
		}
		$state = array(
			'id'       => bin2hex( random_bytes( 8 ) ),
			'status'   => 'running',
			'trigger'  => $trigger,
			'tables'   => self::tables(),
			'table'    => 0,
			'cursor'   => 0,
			'rows'     => 0,
			'found'    => 0,
			'new'      => 0,
			'started'  => time(),
			'updated'  => time(),
		);
		Store::set( self::STATE_OPTION, $state );
		ActivityLog::log( 'dbscan.start', __( 'Database scan started.', 'fckmaleware' ), array( 'scan' => $state['id'], 'tables' => count( $state['tables'] ) ) );
		return $state;
	}

	/**
	 * Tables to scan: [blog id, table, primary key, value columns, label column, type].
	 *
	 * @return array<int, array>
	 */
	private static function tables(): array {
		global $wpdb;
		$blogs = is_multisite() ? get_sites( array( 'fields' => 'ids', 'number' => 1000 ) ) : array( get_current_blog_id() );
		$out   = array();
		foreach ( $blogs as $blog ) {
			$prefix = $wpdb->get_blog_prefix( (int) $blog );
			$out[]  = array( (int) $blog, $prefix . 'posts', 'ID', array( 'post_content', 'post_excerpt', 'post_title' ), 'post_title', 'post' );
			$out[]  = array( (int) $blog, $prefix . 'options', 'option_id', array( 'option_value' ), 'option_name', 'option' );
			$out[]  = array( (int) $blog, $prefix . 'comments', 'comment_ID', array( 'comment_content', 'comment_author_url' ), 'comment_author', 'comment' );
		}
		return $out;
	}

	public function step( float $budget = 10.0 ): array {
		$state = $this->state();
		if ( 'running' !== $state['status'] ) {
			return $state;
		}
		$token = Lock::acquire( self::LOCK, (int) ceil( $budget ) + 60 );
		if ( null === $token ) {
			return $state;
		}
		try {
			$deadline = microtime( true ) + $budget;
			while ( $state['table'] < count( $state['tables'] ) && microtime( true ) < $deadline ) {
				$state = $this->scan_range( $state );
			}
			if ( $state['table'] >= count( $state['tables'] ) ) {
				$state = $this->finish( $state );
			}
			$state['updated'] = time();
			Store::set( self::STATE_OPTION, $state );
			return $state;
		} finally {
			Lock::release( self::LOCK, $token );
		}
	}

	/** @return array|\WP_Error */
	public function run( string $trigger = 'cli' ) {
		$state = $this->start( $trigger );
		if ( is_wp_error( $state ) ) {
			return $state;
		}
		while ( 'running' === $state['status'] ) {
			$state = $this->step( 10.0 );
		}
		return $state;
	}

	private function scan_range( array $state ): array {
		global $wpdb;
		list( $blog, $table, $pk, $columns, $label, $type ) = $state['tables'][ $state['table'] ];

		// phpcs:disable WordPress.DB
		$max = (int) $wpdb->get_var( "SELECT MAX({$pk}) FROM {$table}" );
		if ( $state['cursor'] >= $max ) {
			$state['table']++;
			$state['cursor'] = 0;
			return $state;
		}
		$like  = array();
		$args  = array( $state['cursor'], $state['cursor'] + self::RANGE );
		foreach ( $columns as $column ) {
			foreach ( self::NEEDLES as $needle ) {
				$like[] = "{$column} LIKE %s";
				$args[] = '%' . $wpdb->esc_like( $needle ) . '%';
			}
		}
		$where_extra = '';
		if ( 'option' === $type ) {
			// Cron payloads are analysed by the persistence check with full context; our own options hold scan metadata.
			$where_extra = " AND option_name <> 'cron' AND option_name NOT LIKE 'fckmw\\_%'";
		}
		$select = implode( ', ', array_unique( array_merge( array( $pk, $label ), $columns, 'post' === $type ? array( 'post_type', 'post_status' ) : array() ) ) );
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT {$select} FROM {$table} WHERE {$pk} > %d AND {$pk} <= %d{$where_extra} AND (" . implode( ' OR ', $like ) . ')', $args ), ARRAY_A );
		// phpcs:enable

		foreach ( (array) $rows as $row ) {
			$state['rows']++;
			foreach ( $columns as $column ) {
				$value = (string) $row[ $column ];
				if ( '' === $value || strlen( $value ) > self::MAX_VALUE ) {
					continue;
				}
				foreach ( $this->signatures->match( $value, 'db' ) as $match ) {
					$sig    = $match['signature'];
					$result = $this->findings->upsert(
						array(
							'scan_id'        => $state['id'],
							'source'         => 'database',
							'object_type'    => $type,
							'object_ref'     => "{$blog}:{$type}:{$row[ $pk ]}:{$column}",
							'file'           => self::describe( $blog, $type, $row, $pk, $label, $column ),
							'file_hash'      => hash( 'sha256', $value ),
							'signature_id'   => $sig['id'],
							'signature_name' => $sig['name'],
							'family'         => $sig['family'],
							'severity'       => $sig['severity'],
							'confidence'     => $sig['confidence'],
							'verdict'        => Signatures::verdict( (int) $sig['confidence'] ),
							'excerpt'        => $match['excerpt'],
							'evidence'       => $sig['description'],
							'remediation'    => 'review',
						)
					);
					if ( 'ignored' !== $result['outcome'] ) {
						$state['found']++;
					}
					if ( 'new' === $result['outcome'] ) {
						$state['new']++;
					}
				}
			}
		}
		$state['cursor'] += self::RANGE;
		return $state;
	}

	private static function describe( int $blog, string $type, array $row, string $pk, string $label, string $column ): string {
		$site = is_multisite() ? sprintf( '[site %d] ', $blog ) : '';
		switch ( $type ) {
			case 'post':
				return sprintf( '%sPost #%d "%s" (%s, %s) › %s', $site, $row[ $pk ], wp_strip_all_tags( (string) $row[ $label ] ), $row['post_type'], $row['post_status'], $column );
			case 'option':
				return sprintf( '%sOption "%s"', $site, $row[ $label ] );
			default:
				return sprintf( '%sComment #%d by "%s" › %s', $site, $row[ $pk ], wp_strip_all_tags( (string) $row[ $label ] ), $column );
		}
	}

	private function finish( array $state ): array {
		$resolved = 0;
		foreach ( array( 'post', 'option', 'comment' ) as $type ) {
			$resolved += $this->findings->resolve_stale( $state['id'], array( 'database' ), $type );
		}
		$state['status']   = 'complete';
		$state['finished'] = time();
		$state['resolved'] = $resolved;
		unset( $state['tables'] );
		Store::set( 'fckmw_last_db_scan', $state );
		ActivityLog::log(
			'dbscan.complete',
			sprintf( /* translators: 1: rows, 2: detections, 3: new */ __( 'Database scan complete: %1$d candidate rows inspected, %2$d detections, %3$d new.', 'fckmaleware' ), $state['rows'], $state['found'], $state['new'] ),
			array_intersect_key( $state, array_flip( array( 'id', 'rows', 'found', 'new', 'resolved' ) ) ),
			$state['new'] ? 'warning' : 'info'
		);
		do_action( 'fckmw_db_scan_complete', $state );
		return $state;
	}

	/**
	 * Admin link for reviewing a database finding.
	 */
	public static function edit_link( array $finding ): string {
		$parts = explode( ':', (string) $finding['object_ref'] );
		if ( count( $parts ) < 3 ) {
			return '';
		}
		list( $blog, $type, $id ) = $parts;
		switch ( $type ) {
			case 'post':
				return get_admin_url( (int) $blog, 'post.php?post=' . (int) $id . '&action=edit' );
			case 'comment':
				return get_admin_url( (int) $blog, 'comment.php?action=editcomment&c=' . (int) $id );
			case 'option':
				return 0 === strpos( (string) $finding['file'], 'Option "widget_' ) ? get_admin_url( (int) $blog, 'widgets.php' ) : '';
		}
		return '';
	}
}
