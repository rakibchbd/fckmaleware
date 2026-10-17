<?php
/**
 * Notification engine: email, dashboard notices and signed webhooks.
 *
 * Alert items (new or reinfected findings, critical security events) are
 * queued, grouped and delivered in digests:
 *   - grouping: items wait up to two minutes; while a scan runs they wait
 *     for its end (at most 30 minutes) so one scan produces one message;
 *   - deduplication: each item has a fingerprint, and a fingerprint is not
 *     re-sent within the cooldown period;
 *   - retries: failed webhook deliveries are retried with backoff;
 *   - delivery log: every send and failure is recorded in the activity log.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Notifier {

	public const QUEUE_OPTION  = 'fckmw_notify_queue';
	public const SENT_OPTION   = 'fckmw_notify_sent';
	public const RETRY_OPTION  = 'fckmw_notify_retry';
	public const SECRET_OPTION = 'fckmw_webhook_secret';
	public const SEEN_OPTION   = 'fckmw_notice_seen';
	public const CRON          = 'fckmw_notify_flush';

	private const GROUP_DELAY   = 120;
	private const MAX_HOLD      = 1800;
	private const MAX_ITEMS     = 50;
	private const MAX_RETRIES   = 3;

	/** Security events that alert on their own (activity-log type => category). */
	private const EVENT_ALERTS = array(
		'user.admin_created'       => 'admin',
		'user.promoted'            => 'admin',
		'user.super_admin'         => 'admin',
		'upload.blocked'           => 'threat',
		'quarantine.auto'          => 'quarantine',
		'threat.reinfection'       => 'reinfection',
		'signatures.corrupt'       => 'update_failure',
		'signatures.update_failed' => 'update_failure',
		'option.changed'           => 'config',
		'plugin.deactivated'       => 'config',
	);

	public function register(): void {
		add_action( 'fckmw_finding_recorded', array( $this, 'on_finding' ), 10, 2 );
		add_action( 'fckmw_event', array( $this, 'on_event' ) );
		add_action( 'fckmw_scan_complete', array( $this, 'on_scan_complete' ), 20 );
		add_action( self::CRON, array( $this, 'flush' ) );
		if ( Settings::get( 'dashboard_notices' ) ) {
			add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'dashboard_notice' ) );
		}
	}

	// --- Collecting -------------------------------------------------------------

	/**
	 * @param array $finding Normalized detection.
	 * @param array $result  Findings::upsert() result.
	 */
	public function on_finding( array $finding, array $result ): void {
		if ( ! in_array( $result['outcome'], array( 'new', 'reinfection' ), true ) ) {
			return;
		}
		if ( Signatures::severity_rank( (string) $finding['severity'] ) < Signatures::severity_rank( (string) Settings::get( 'notify_min_severity' ) ) ) {
			return;
		}
		$reinfection = 'reinfection' === $result['outcome'];
		$this->queue(
			array(
				'category'    => $reinfection ? 'reinfection' : self::category_for( $finding ),
				// Reinfections have their own fingerprint so they alert even within the cooldown of the first alert.
				'fingerprint' => ( $reinfection ? 'reinfection:' : 'finding:' ) . $finding['object_type'] . ':' . $finding['object_ref'] . ':' . $finding['signature_id'],
				'severity'    => $finding['severity'],
				'title'       => $finding['signature_name'],
				'object'      => $finding['file'],
				'detail'      => sprintf( '%s · %s · %d%%', $finding['source'], $finding['verdict'], $finding['confidence'] ),
				'finding'     => $result['id'],
			)
		);
	}

	private static function category_for( array $finding ): string {
		switch ( $finding['source'] ) {
			case 'integrity':
				return 'integrity';
			case 'behaviour':
				return in_array( $finding['object_type'], array( 'user', 'role' ), true ) ? 'admin' : 'persistence';
			case 'database':
				return 'database';
		}
		return 'threat';
	}

	public function on_event( array $event ): void {
		$type = (string) $event['type'];
		if ( 0 === strpos( $type, 'notify.' ) || ! isset( self::EVENT_ALERTS[ $type ] ) ) {
			return;
		}
		// Only the noteworthy variants of noisy event types.
		if ( 'option.changed' === $type && 'critical' !== $event['severity'] ) {
			return;
		}
		if ( 'plugin.deactivated' === $type && 'warning' !== $event['severity'] ) {
			return;
		}
		if ( 'signatures.update_failed' === $type && 'warning' !== $event['severity'] ) {
			return; // Only after repeated failures.
		}
		$this->queue(
			array(
				'category'    => self::EVENT_ALERTS[ $type ],
				'fingerprint' => 'event:' . $type . ':' . md5( (string) $event['message'] ),
				'severity'    => 'critical' === $event['severity'] ? 'critical' : 'high',
				'title'       => (string) $event['message'],
				'object'      => '',
				'detail'      => $type,
			)
		);
	}

	public function on_scan_complete( array $state ): void {
		if ( Settings::get( 'notify_scan_complete' ) && 'manual' !== $state['trigger'] ) {
			$this->queue(
				array(
					'category'    => 'scan',
					'fingerprint' => 'scan:' . $state['id'],
					'severity'    => 'low',
					'title'       => sprintf( /* translators: 1: mode, 2: files, 3: new */ __( '%1$s scan finished: %2$d files checked, %3$d new detections', 'fckmaleware' ), ucfirst( (string) $state['mode'] ), $state['total'], $state['new'] ),
					'object'      => '',
					'detail'      => '',
				),
				true
			);
		}
		// Deliver whatever the scan collected now, as one digest.
		if ( Store::get( self::QUEUE_OPTION, array() ) ) {
			wp_clear_scheduled_hook( self::CRON );
			wp_schedule_single_event( time(), self::CRON );
		}
	}

	private function queue( array $item, bool $force = false ): void {
		$sent        = (array) Store::get( self::SENT_OPTION, array() );
		$cooldown    = (int) Settings::get( 'notify_cooldown_hours' ) * HOUR_IN_SECONDS;
		$fingerprint = $item['fingerprint'];
		if ( ! $force && isset( $sent[ $fingerprint ] ) && time() - (int) $sent[ $fingerprint ] < $cooldown ) {
			return;
		}
		$queue = (array) Store::get( self::QUEUE_OPTION, array() );
		if ( isset( $queue[ $fingerprint ] ) ) {
			return;
		}
		$item['time']          = time();
		$queue[ $fingerprint ] = $item;
		Store::set( self::QUEUE_OPTION, array_slice( $queue, -500, null, true ) );
		if ( ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( time() + self::GROUP_DELAY, self::CRON );
		}
	}

	// --- Delivering -------------------------------------------------------------

	public function flush(): void {
		$token = Lock::acquire( 'notify', 120 );
		if ( null === $token ) {
			return;
		}
		try {
			$queue = (array) Store::get( self::QUEUE_OPTION, array() );
			if ( $queue ) {
				$oldest = min( array_column( $queue, 'time' ) );
				if ( Plugin::instance()->scanner()->is_running() && time() - $oldest < self::MAX_HOLD ) {
					wp_schedule_single_event( time() + self::GROUP_DELAY, self::CRON ); // Wait for the scan to finish.
					return;
				}
				Store::set( self::QUEUE_OPTION, array() );
				$this->deliver( array_values( $queue ) );
			}
			$this->retry_webhooks();
		} finally {
			Lock::release( 'notify', $token );
		}
	}

	private function deliver( array $items ): void {
		usort(
			$items,
			static function ( $a, $b ) {
				return Signatures::severity_rank( $b['severity'] ) <=> Signatures::severity_rank( $a['severity'] );
			}
		);

		$sent = (array) Store::get( self::SENT_OPTION, array() );
		foreach ( $items as $item ) {
			$sent[ $item['fingerprint'] ] = time();
		}
		// Forget fingerprints older than a week to keep the option small.
		$sent = array_filter(
			$sent,
			static function ( $time ) {
				return time() - (int) $time < WEEK_IN_SECONDS;
			}
		);
		Store::set( self::SENT_OPTION, $sent );

		if ( Settings::get( 'email_alerts' ) ) {
			$this->send_email( $items );
		}
		if ( '' !== (string) Settings::get( 'webhook_url' ) ) {
			$payload = $this->webhook_payload( $items );
			if ( ! $this->send_webhook( $payload ) ) {
				$retry   = (array) Store::get( self::RETRY_OPTION, array() );
				$retry[] = array( 'payload' => $payload, 'attempts' => 1, 'next' => time() + 5 * MINUTE_IN_SECONDS );
				Store::set( self::RETRY_OPTION, array_slice( $retry, -20 ) );
				wp_schedule_single_event( time() + 5 * MINUTE_IN_SECONDS, self::CRON );
			}
		}
	}

	private function send_email( array $items ): void {
		$to    = (string) Settings::get( 'alert_email' );
		$to    = '' !== $to ? $to : (string) get_site_option( 'admin_email', get_option( 'admin_email' ) );
		$site  = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
		$count = count( $items );

		$lines = array(
			/* translators: %s: site URL */
			sprintf( __( 'FCK Malware raised the following alerts on %s:', 'fckmaleware' ), network_home_url() ),
			'',
		);
		$labels = self::category_labels();
		foreach ( array_slice( $items, 0, self::MAX_ITEMS ) as $item ) {
			$lines[] = sprintf( '[%s] %s: %s', strtoupper( $item['severity'] ), $labels[ $item['category'] ] ?? $item['category'], $item['title'] );
			if ( '' !== $item['object'] ) {
				$lines[] = '    ' . $item['object'];
			}
			if ( '' !== $item['detail'] ) {
				$lines[] = '    ' . $item['detail'];
			}
		}
		if ( $count > self::MAX_ITEMS ) {
			/* translators: %d: number of further alerts */
			$lines[] = sprintf( __( '…and %d more.', 'fckmaleware' ), $count - self::MAX_ITEMS );
		}
		$lines[] = '';
		$lines[] = __( 'Review them in your dashboard:', 'fckmaleware' ) . ' ' . self::dashboard_url();
		$lines[] = '';
		$lines[] = __( 'You receive this because email alerts are enabled in FCK Malware → Settings.', 'fckmaleware' );

		$subject = sprintf(
			/* translators: 1: site name, 2: number of alerts */
			_n( '[%1$s] FCK Malware: %2$d security alert', '[%1$s] FCK Malware: %2$d security alerts', $count, 'fckmaleware' ),
			$site,
			$count
		);
		$ok = wp_mail( $to, $subject, implode( "\n", $lines ) );
		ActivityLog::log( $ok ? 'notify.sent' : 'notify.failed', sprintf( /* translators: 1: channel, 2: count */ __( '%1$s alert with %2$d items %3$s', 'fckmaleware' ), 'Email', $count, $ok ? __( 'sent', 'fckmaleware' ) : __( 'could not be sent', 'fckmaleware' ) ), array( 'channel' => 'email', 'to' => $to, 'items' => $count ), $ok ? 'info' : 'warning' );
	}

	private function webhook_payload( array $items ): array {
		return array(
			'source'    => 'fckmaleware',
			'version'   => FCKMW_VERSION,
			'site'      => network_home_url(),
			'sent_at'   => gmdate( 'c' ),
			'dashboard' => self::dashboard_url(),
			'alerts'    => array_map(
				static function ( $item ) {
					return array_intersect_key( $item, array_flip( array( 'category', 'severity', 'title', 'object', 'detail', 'time' ) ) );
				},
				array_slice( $items, 0, self::MAX_ITEMS )
			),
			'total'     => count( $items ),
		);
	}

	/**
	 * True when every address the URL's host resolves to is public
	 * (no private, loopback, link-local/metadata or reserved ranges).
	 */
	public static function is_public_url( string $url ): bool {
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( '' === $host ) {
			return false;
		}
		$host = trim( $host, '[]' );
		$ips  = filter_var( $host, FILTER_VALIDATE_IP ) ? array( $host ) : (array) @gethostbynamel( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $ips ) {
			return false;
		}
		foreach ( $ips as $ip ) {
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				return false;
			}
			// Special-purpose IPv4 ranges PHP's filter treats as public (CGNAT, IETF, benchmarking).
			$long = ip2long( $ip );
			if ( false !== $long ) {
				foreach ( array( array( '100.64.0.0', 10 ), array( '192.0.0.0', 24 ), array( '198.18.0.0', 15 ) ) as $range ) {
					if ( ( $long >> ( 32 - $range[1] ) ) === ( ip2long( $range[0] ) >> ( 32 - $range[1] ) ) ) {
						return false;
					}
				}
			}
		}
		return true;
	}

	/** POST a JSON payload, signed with HMAC-SHA256 in the X-FCKMW-Signature header. */
	private function send_webhook( array $payload ): bool {
		$url  = (string) Settings::get( 'webhook_url' );
		$body = (string) wp_json_encode( $payload );
		if ( ! self::is_public_url( $url ) ) {
			ActivityLog::log( 'notify.failed', __( 'Webhook delivery refused: the URL does not resolve to a public address.', 'fckmaleware' ), array( 'channel' => 'webhook' ), 'warning' );
			return false;
		}
		// wp_safe_remote_post refuses private/loopback addresses (no SSRF into the hosting network).
		$response = wp_safe_remote_post(
			$url,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				'headers'     => array(
					'Content-Type'      => 'application/json',
					'User-Agent'        => 'FCK-Malware/' . FCKMW_VERSION,
					'X-FCKMW-Signature' => 'sha256=' . hash_hmac( 'sha256', $body, self::webhook_secret() ),
				),
				'body'        => $body,
			)
		);
		$code = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		$ok   = $code >= 200 && $code < 300;
		ActivityLog::log(
			$ok ? 'notify.sent' : 'notify.failed',
			$ok ? __( 'Webhook alert delivered.', 'fckmaleware' ) : sprintf( /* translators: %s: error */ __( 'Webhook delivery failed: %s', 'fckmaleware' ), is_wp_error( $response ) ? $response->get_error_message() : 'HTTP ' . $code ),
			array( 'channel' => 'webhook', 'host' => wp_parse_url( $url, PHP_URL_HOST ), 'items' => count( $payload['alerts'] ) ),
			$ok ? 'info' : 'warning'
		);
		return $ok;
	}

	private function retry_webhooks(): void {
		$retry = (array) Store::get( self::RETRY_OPTION, array() );
		if ( ! $retry ) {
			return;
		}
		$keep = array();
		foreach ( $retry as $entry ) {
			if ( $entry['next'] > time() ) {
				$keep[] = $entry;
				continue;
			}
			if ( $this->send_webhook( $entry['payload'] ) ) {
				continue;
			}
			$entry['attempts']++;
			if ( $entry['attempts'] < self::MAX_RETRIES ) {
				$entry['next'] = time() + $entry['attempts'] * 15 * MINUTE_IN_SECONDS;
				$keep[]        = $entry;
			}
		}
		Store::set( self::RETRY_OPTION, $keep );
		if ( $keep && ! wp_next_scheduled( self::CRON ) ) {
			wp_schedule_single_event( min( array_column( $keep, 'next' ) ), self::CRON );
		}
	}

	public static function webhook_secret(): string {
		$secret = (string) Store::get( self::SECRET_OPTION, '' );
		if ( '' === $secret ) {
			$secret = bin2hex( random_bytes( 24 ) );
			Store::set( self::SECRET_OPTION, $secret );
		}
		return $secret;
	}

	/** Send a test message on every enabled channel. */
	public function send_test(): void {
		$this->deliver(
			array(
				array(
					'category'    => 'test',
					'fingerprint' => 'test:' . time(),
					'severity'    => 'low',
					'title'       => __( 'Test notification: delivery works.', 'fckmaleware' ),
					'object'      => '',
					'detail'      => '',
					'time'        => time(),
				),
			)
		);
	}

	// --- Dashboard notice -------------------------------------------------------

	public function dashboard_notice(): void {
		if ( ! current_user_can( Plugin::capability() ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( (string) $screen->id, 'fckmaleware' ) ) {
			Store::set( self::SEEN_OPTION, time() ); // Visiting FCK Malware acknowledges the notice.
			return;
		}
		$counts = Plugin::instance()->findings()->open_counts();
		$urgent = $counts['critical'] + $counts['high'];
		$since  = (int) Store::get( self::SEEN_OPTION, 0 );
		$recent = ActivityLog::query( array( 'severity' => 'critical', 'since' => $since + 1 ), 1, 1 )['total'];
		if ( ! $urgent && ! $recent ) {
			return;
		}
		$message = $urgent
			/* translators: %d: count */
			? sprintf( _n( 'FCK Malware: %d high-severity threat needs review.', 'FCK Malware: %d high-severity threats need review.', $urgent, 'fckmaleware' ), $urgent )
			/* translators: %d: count */
			: sprintf( _n( 'FCK Malware: %d critical security event since your last visit.', 'FCK Malware: %d critical security events since your last visit.', $recent, 'fckmaleware' ), $recent );
		printf(
			'<div class="notice notice-error"><p><strong>%s</strong> <a href="%s">%s</a></p></div>',
			esc_html( $message ),
			esc_url( self::dashboard_url() ),
			esc_html__( 'Open FCK Malware', 'fckmaleware' )
		);
	}

	public static function dashboard_url(): string {
		return is_multisite() ? network_admin_url( 'admin.php?page=fckmaleware' ) : admin_url( 'admin.php?page=fckmaleware' );
	}

	public static function category_labels(): array {
		return array(
			'threat'         => __( 'Malware', 'fckmaleware' ),
			'integrity'      => __( 'Integrity violation', 'fckmaleware' ),
			'reinfection'    => __( 'Reinfection', 'fckmaleware' ),
			'persistence'    => __( 'Persistence', 'fckmaleware' ),
			'database'       => __( 'Database injection', 'fckmaleware' ),
			'quarantine'     => __( 'Quarantine', 'fckmaleware' ),
			'admin'          => __( 'Administrator change', 'fckmaleware' ),
			'config'         => __( 'Configuration change', 'fckmaleware' ),
			'update_failure' => __( 'Signature update', 'fckmaleware' ),
			'scan'           => __( 'Scan', 'fckmaleware' ),
			'test'           => __( 'Test', 'fckmaleware' ),
		);
	}
}
