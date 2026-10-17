<?php
/**
 * Admin screens, AJAX scan driver and form handlers.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Admin {

	private const SLUG       = 'fckmaleware';
	private const CAPABILITY = 'manage_options';

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );

		add_action( 'wp_ajax_fckmw_scan_start', array( $this, 'ajax_scan_start' ) );
		add_action( 'wp_ajax_fckmw_scan_step', array( $this, 'ajax_scan_step' ) );
		add_action( 'wp_ajax_fckmw_scan_cancel', array( $this, 'ajax_scan_cancel' ) );

		add_action( 'admin_post_fckmw_finding', array( $this, 'handle_finding' ) );
		add_action( 'admin_post_fckmw_quarantine', array( $this, 'handle_quarantine' ) );
		add_action( 'admin_post_fckmw_settings', array( $this, 'handle_settings' ) );
		add_action( 'admin_post_fckmw_imunify', array( $this, 'handle_imunify' ) );
	}

	public function menu(): void {
		$counts = $this->plugin->findings()->open_counts();
		$badge  = $counts['total'] ? sprintf( ' <span class="awaiting-mod">%d</span>', $counts['total'] ) : '';
		add_menu_page(
			__( 'FckMaleware', 'fckmaleware' ),
			__( 'FckMaleware', 'fckmaleware' ) . $badge,
			self::CAPABILITY,
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield',
			80
		);
	}

	public function assets( string $hook ): void {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'fckmw-admin', FCKMW_URL . 'assets/admin.css', array(), FCKMW_VERSION );
		wp_enqueue_script( 'fckmw-admin', FCKMW_URL . 'assets/admin.js', array( 'jquery' ), FCKMW_VERSION, true );
		wp_localize_script(
			'fckmw-admin',
			'fckmw',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'fckmw_scan' ),
				'state'   => $this->plugin->scanner()->state(),
				'i18n'    => array(
					'starting'  => __( 'Preparing file list…', 'fckmaleware' ),
					'scanning'  => __( 'Scanned %1$d of %2$d files, %3$d findings', 'fckmaleware' ),
					'done'      => __( 'Scan finished. Reloading…', 'fckmaleware' ),
					'error'     => __( 'Scan error:', 'fckmaleware' ),
					'confirmQ'  => __( 'Move this file to quarantine? The site may break if the file is still needed.', 'fckmaleware' ),
					'confirmDel' => __( 'Permanently delete this quarantined file?', 'fckmaleware' ),
				),
			)
		);
	}

	// --- AJAX scan driver ---------------------------------------------------

	private function ajax_guard(): void {
		check_ajax_referer( 'fckmw_scan' );
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'fckmaleware' ) ), 403 );
		}
	}

	public function ajax_scan_start(): void {
		$this->ajax_guard();
		$state = $this->plugin->scanner()->start( 'manual' );
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( $state );
	}

	public function ajax_scan_step(): void {
		$this->ajax_guard();
		wp_send_json_success( $this->plugin->scanner()->step( 8.0 ) );
	}

	public function ajax_scan_cancel(): void {
		$this->ajax_guard();
		wp_send_json_success( $this->plugin->scanner()->cancel() );
	}

	// --- Form handlers ------------------------------------------------------

	private function form_guard( string $action ): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'Permission denied.', 'fckmaleware' ), 403 );
		}
		check_admin_referer( $action );
	}

	public function handle_finding(): void {
		$this->form_guard( 'fckmw_finding' );
		$id      = absint( $_POST['finding'] ?? 0 );
		$command = sanitize_key( wp_unslash( $_POST['command'] ?? '' ) );
		$result  = new \WP_Error( 'fckmw_bad_command', __( 'Unknown action.', 'fckmaleware' ) );

		switch ( $command ) {
			case 'quarantine':
				$result = $this->plugin->quarantine_finding( $id );
				$ok     = __( 'File moved to quarantine.', 'fckmaleware' );
				break;
			case 'ignore':
				$result = $this->plugin->findings()->set_status( $id, 'ignored' );
				$ok     = __( 'Finding ignored. It will stay ignored while the file content is unchanged.', 'fckmaleware' );
				break;
			case 'resolve':
				$result = $this->plugin->findings()->set_status( $id, 'resolved' );
				$ok     = __( 'Finding marked as resolved. It will reappear on the next scan if the problem is still there.', 'fckmaleware' );
				break;
			case 'reopen':
				$result = $this->plugin->findings()->set_status( $id, 'open' );
				$ok     = __( 'Finding reopened.', 'fckmaleware' );
				break;
		}

		$this->redirect_with( $result, $ok ?? '', 'dashboard' );
	}

	public function handle_quarantine(): void {
		$this->form_guard( 'fckmw_quarantine' );
		$key     = preg_replace( '/[^a-f0-9]/', '', (string) wp_unslash( $_POST['key'] ?? '' ) );
		$command = sanitize_key( wp_unslash( $_POST['command'] ?? '' ) );

		if ( 'restore' === $command ) {
			$result = $this->plugin->quarantine()->restore( $key );
			if ( true === $result ) {
				$this->plugin->release_quarantine_findings( $key, 'open' );
			}
			$this->redirect_with( $result, __( 'File restored to its original location.', 'fckmaleware' ), 'quarantine' );
		}

		$this->plugin->quarantine()->purge( $key );
		$this->plugin->release_quarantine_findings( $key, 'resolved' );
		$this->redirect_with( true, __( 'Quarantined file deleted.', 'fckmaleware' ), 'quarantine' );
	}

	public function handle_settings(): void {
		$this->form_guard( 'fckmw_settings' );
		$before = Settings::all();
		$after  = Settings::update( wp_unslash( (array) ( $_POST['fckmw'] ?? array() ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- sanitized in Settings::sanitize().

		if ( $before['schedule'] !== $after['schedule'] ) {
			Plugin::reschedule();
		}
		$result = true;
		if ( $before['block_uploads_php'] !== $after['block_uploads_php'] && ! Hardening::apply_uploads_rule( $after['block_uploads_php'] ) ) {
			$result = new \WP_Error( 'fckmw_htaccess', __( 'Settings saved, but the uploads .htaccess file could not be written.', 'fckmaleware' ) );
		}
		$this->redirect_with( $result, __( 'Settings saved.', 'fckmaleware' ), 'settings' );
	}

	public function handle_imunify(): void {
		$this->form_guard( 'fckmw_imunify' );
		$command = sanitize_key( wp_unslash( $_POST['command'] ?? '' ) );

		if ( 'scan' === $command ) {
			$result = $this->plugin->imunify()->start_scan( Paths::root() );
			$this->redirect_with( $result, __( 'Imunify360 on-demand scan started for this site. Sync results once it finishes.', 'fckmaleware' ), 'imunify' );
		}

		$result = $this->plugin->sync_imunify();
		$this->redirect_with(
			$result,
			/* translators: %d: number of findings */
			is_wp_error( $result ) ? '' : sprintf( __( 'Synced %d Imunify360 detections.', 'fckmaleware' ), $result ),
			'imunify'
		);
	}

	/** @param mixed $result true/int on success, WP_Error or false on failure. */
	private function redirect_with( $result, string $success, string $tab ): void {
		if ( is_wp_error( $result ) ) {
			$notice = array( 'error', $result->get_error_message() );
		} elseif ( false === $result ) {
			$notice = array( 'error', __( 'The action failed.', 'fckmaleware' ) );
		} else {
			$notice = array( 'success', $success );
		}
		set_transient( 'fckmw_notice_' . get_current_user_id(), $notice, MINUTE_IN_SECONDS );
		wp_safe_redirect( $this->url( $tab ) );
		exit;
	}

	private function url( string $tab = 'dashboard', array $args = array() ): string {
		return add_query_arg( array_merge( array( 'page' => self::SLUG, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
	}

	// --- Rendering ----------------------------------------------------------

	public function render(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		$tabs = array(
			'dashboard'  => __( 'Findings', 'fckmaleware' ),
			'quarantine' => __( 'Quarantine', 'fckmaleware' ),
			'imunify'    => __( 'Imunify360', 'fckmaleware' ),
			'signatures' => __( 'Signatures', 'fckmaleware' ),
			'settings'   => __( 'Settings', 'fckmaleware' ),
		);
		$tab = sanitize_key( wp_unslash( $_GET['tab'] ?? 'dashboard' ) ); // phpcs:ignore WordPress.Security.NonceVerification
		$tab = isset( $tabs[ $tab ] ) ? $tab : 'dashboard';

		echo '<div class="wrap fckmw">';
		echo '<h1>' . esc_html__( 'FckMaleware', 'fckmaleware' ) . '</h1>';

		$notice = get_transient( 'fckmw_notice_' . get_current_user_id() );
		if ( is_array( $notice ) ) {
			delete_transient( 'fckmw_notice_' . get_current_user_id() );
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
		}

		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $key => $label ) {
			printf(
				'<a href="%s" class="nav-tab%s">%s</a>',
				esc_url( $this->url( $key ) ),
				$key === $tab ? ' nav-tab-active' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		$this->{'render_' . $tab}();
		echo '</div>';
	}

	private function render_dashboard(): void {
		$findings = $this->plugin->findings();
		$counts   = $findings->open_counts();
		$last     = get_option( 'fckmw_last_scan' );

		echo '<div class="fckmw-cards">';
		foreach ( array_keys( Signatures::SEVERITIES ) as $severity ) {
			printf(
				'<div class="fckmw-card fckmw-sev-%1$s"><span class="fckmw-num">%2$d</span><span>%3$s</span></div>',
				esc_attr( $severity ),
				(int) $counts[ $severity ],
				esc_html( ucfirst( $severity ) )
			);
		}
		echo '</div>';

		echo '<div class="fckmw-scan">';
		echo '<p>';
		if ( is_array( $last ) ) {
			printf(
				/* translators: 1: time ago, 2: files scanned */
				esc_html__( 'Last full scan: %1$s ago, %2$d files checked.', 'fckmaleware' ),
				esc_html( human_time_diff( (int) $last['finished'] ) ),
				(int) $last['total']
			);
		} else {
			esc_html_e( 'No scan has been run yet.', 'fckmaleware' );
		}
		echo '</p>';
		echo '<button type="button" class="button button-primary" id="fckmw-scan-start">' . esc_html__( 'Scan now', 'fckmaleware' ) . '</button> ';
		echo '<button type="button" class="button" id="fckmw-scan-cancel" hidden>' . esc_html__( 'Cancel', 'fckmaleware' ) . '</button>';
		echo '<div class="fckmw-progress" hidden><div class="fckmw-bar"></div></div><p class="fckmw-status" aria-live="polite"></p>';
		echo '</div>';

		$status   = sanitize_key( wp_unslash( $_GET['status'] ?? 'open' ) ); // phpcs:ignore WordPress.Security.NonceVerification
		$status   = in_array( $status, Findings::STATUSES, true ) ? $status : 'open';
		$page     = max( 1, absint( $_GET['paged'] ?? 1 ) ); // phpcs:ignore WordPress.Security.NonceVerification
		$per_page = 50;
		$result   = $findings->query( $status, $page, $per_page );

		echo '<ul class="subsubsub">';
		$links = array();
		foreach ( Findings::STATUSES as $s ) {
			$links[] = sprintf(
				'<li><a href="%s"%s>%s</a></li>',
				esc_url( $this->url( 'dashboard', array( 'status' => $s ) ) ),
				$s === $status ? ' class="current"' : '',
				esc_html( ucfirst( $s ) )
			);
		}
		echo implode( ' | ', $links ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts.
		echo '</ul>';

		echo '<table class="widefat striped fckmw-findings"><thead><tr>';
		foreach ( array( __( 'Severity', 'fckmaleware' ), __( 'File', 'fckmaleware' ), __( 'Detection', 'fckmaleware' ), __( 'Source', 'fckmaleware' ), __( 'Actions', 'fckmaleware' ) ) as $heading ) {
			echo '<th>' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		if ( ! $result['rows'] ) {
			echo '<tr><td colspan="5">' . esc_html__( 'Nothing here.', 'fckmaleware' ) . '</td></tr>';
		}
		foreach ( $result['rows'] as $row ) {
			echo '<tr>';
			printf( '<td><span class="fckmw-badge fckmw-sev-%1$s">%2$s</span></td>', esc_attr( $row['severity'] ), esc_html( ucfirst( $row['severity'] ) ) );
			printf(
				'<td><code>%s</code>%s</td>',
				esc_html( $row['file'] ),
				$row['line'] ? ' <span class="description">' . esc_html( sprintf( /* translators: %d: line */ __( 'line %d', 'fckmaleware' ), $row['line'] ) ) . '</span>' : ''
			);
			echo '<td><strong>' . esc_html( $row['signature_name'] ) . '</strong> <span class="description">' . esc_html( $row['signature_id'] ) . '</span>';
			if ( '' !== (string) $row['excerpt'] ) {
				echo '<pre class="fckmw-excerpt">' . esc_html( $row['excerpt'] ) . '</pre>';
			}
			echo '</td>';
			echo '<td>' . esc_html( $row['source'] ) . '</td>';
			echo '<td class="fckmw-actions">';
			if ( 'open' === $row['status'] ) {
				if ( $this->plugin->can_quarantine( $row['file'] ) ) {
					$this->finding_button( (int) $row['id'], 'quarantine', __( 'Quarantine', 'fckmaleware' ), 'button-primary fckmw-confirm' );
				}
				$this->finding_button( (int) $row['id'], 'ignore', __( 'Ignore', 'fckmaleware' ) );
				$this->finding_button( (int) $row['id'], 'resolve', __( 'Resolved', 'fckmaleware' ) );
			} elseif ( in_array( $row['status'], array( 'ignored', 'resolved' ), true ) ) {
				$this->finding_button( (int) $row['id'], 'reopen', __( 'Reopen', 'fckmaleware' ) );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';

		$pages = (int) ceil( $result['total'] / $per_page );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo paginate_links( // phpcs:ignore WordPress.Security.EscapeOutput
				array(
					'base'    => add_query_arg( 'paged', '%#%' ),
					'current' => $page,
					'total'   => $pages,
				)
			);
			echo '</div></div>';
		}
	}

	private function finding_button( int $id, string $command, string $label, string $class = '' ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'fckmw_finding' );
		echo '<input type="hidden" name="action" value="fckmw_finding">';
		echo '<input type="hidden" name="finding" value="' . esc_attr( (string) $id ) . '">';
		echo '<input type="hidden" name="command" value="' . esc_attr( $command ) . '">';
		echo '<button type="submit" class="button button-small ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button>';
		echo '</form>';
	}

	private function render_quarantine(): void {
		$items = $this->plugin->quarantine()->all();
		echo '<p>' . esc_html__( 'Quarantined files are compressed and stored in a web-inaccessible folder. Restore a file if it turns out to be a false positive.', 'fckmaleware' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Original file', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Size', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Quarantined', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Actions', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		if ( ! $items ) {
			echo '<tr><td colspan="4">' . esc_html__( 'Quarantine is empty.', 'fckmaleware' ) . '</td></tr>';
		}
		foreach ( $items as $key => $item ) {
			echo '<tr><td><code>' . esc_html( $item['file'] ) . '</code></td>';
			echo '<td>' . esc_html( size_format( (int) $item['size'] ) ) . '</td>';
			echo '<td>' . esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $item['time'] ) ) . '</td><td class="fckmw-actions">';
			foreach ( array( 'restore' => array( __( 'Restore', 'fckmaleware' ), '' ), 'delete' => array( __( 'Delete', 'fckmaleware' ), 'fckmw-confirm-delete' ) ) as $command => $meta ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
				wp_nonce_field( 'fckmw_quarantine' );
				echo '<input type="hidden" name="action" value="fckmw_quarantine">';
				echo '<input type="hidden" name="key" value="' . esc_attr( $key ) . '">';
				echo '<input type="hidden" name="command" value="' . esc_attr( $command ) . '">';
				echo '<button type="submit" class="button button-small ' . esc_attr( $meta[1] ) . '">' . esc_html( $meta[0] ) . '</button></form>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
	}

	private function render_imunify(): void {
		$imunify = $this->plugin->imunify();
		$enabled = (bool) Settings::get( 'imunify_enabled' );

		echo '<table class="form-table"><tbody>';
		echo '<tr><th>' . esc_html__( 'Integration', 'fckmaleware' ) . '</th><td>' . ( $enabled ? esc_html__( 'Enabled', 'fckmaleware' ) : esc_html__( 'Disabled (enable it in Settings)', 'fckmaleware' ) ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Agent binary', 'fckmaleware' ) . '</th><td>' . ( $imunify->binary() ? '<code>' . esc_html( $imunify->binary() ) . '</code>' : esc_html__( 'Not found on this server', 'fckmaleware' ) ) . '</td></tr>';

		if ( $enabled && $imunify->is_available() ) {
			$version = $imunify->version();
			echo '<tr><th>' . esc_html__( 'Agent status', 'fckmaleware' ) . '</th><td>';
			echo is_wp_error( $version )
				? '<span class="fckmw-error">' . esc_html( $version->get_error_message() ) . '</span>'
				: esc_html( sprintf( /* translators: %s: version */ __( 'Reachable, version %s', 'fckmaleware' ), $version ) );
			echo '</td></tr>';
		}
		$last_sync = (int) get_option( 'fckmw_imunify_last_sync', 0 );
		echo '<tr><th>' . esc_html__( 'Last sync', 'fckmaleware' ) . '</th><td>' . ( $last_sync ? esc_html( sprintf( /* translators: %s: time */ __( '%s ago', 'fckmaleware' ), human_time_diff( $last_sync ) ) ) : esc_html__( 'Never', 'fckmaleware' ) ) . '</td></tr>';
		echo '</tbody></table>';

		if ( $enabled ) {
			foreach ( array( 'sync' => __( 'Sync detections now', 'fckmaleware' ), 'scan' => __( 'Start Imunify360 scan of this site', 'fckmaleware' ) ) as $command => $label ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="fckmw-inline">';
				wp_nonce_field( 'fckmw_imunify' );
				echo '<input type="hidden" name="action" value="fckmw_imunify"><input type="hidden" name="command" value="' . esc_attr( $command ) . '">';
				submit_button( $label, 'sync' === $command ? 'primary' : 'secondary', 'submit', false );
				echo '</form> ';
			}
		}
		echo '<p class="description">' . esc_html__( 'The integration calls the local imunify360-agent (or imunify-antivirus) CLI. If the PHP user is not allowed to run it, enable "Run through sudo" and add the sudoers rule from the README.', 'fckmaleware' ) . '</p>';
	}

	private function render_signatures(): void {
		$signatures = $this->plugin->signatures();
		printf(
			'<p>%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: version, 2: count */
					__( 'Signature database version %1$s, %2$d signatures loaded.', 'fckmaleware' ),
					$signatures->version(),
					count( $signatures->all() )
				)
			)
		);
		if ( $signatures->invalid() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( sprintf( /* translators: %s: ids */ __( 'Skipped signatures with invalid patterns: %s', 'fckmaleware' ), implode( ', ', $signatures->invalid() ) ) ) . '</p></div>';
		}
		echo '<table class="widefat striped"><thead><tr><th>ID</th><th>' . esc_html__( 'Name', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Severity', 'fckmaleware' ) . '</th><th>' . esc_html__( 'File types', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Description', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		foreach ( $signatures->all() as $sig ) {
			printf(
				'<tr><td><code>%1$s</code></td><td>%2$s</td><td><span class="fckmw-badge fckmw-sev-%3$s">%4$s</span></td><td>%5$s</td><td>%6$s</td></tr>',
				esc_html( $sig['id'] ),
				esc_html( $sig['name'] ),
				esc_attr( $sig['severity'] ),
				esc_html( ucfirst( $sig['severity'] ) ),
				esc_html( implode( ', ', $sig['targets'] ) ),
				esc_html( $sig['description'] )
			);
		}
		echo '</tbody></table>';
	}

	private function render_settings(): void {
		$s = Settings::all();
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'fckmw_settings' );
		echo '<input type="hidden" name="action" value="fckmw_settings">';
		echo '<table class="form-table"><tbody>';

		echo '<tr><th><label for="fckmw-schedule">' . esc_html__( 'Scheduled scan', 'fckmaleware' ) . '</label></th><td><select id="fckmw-schedule" name="fckmw[schedule]">';
		$labels = array(
			'off'        => __( 'Off', 'fckmaleware' ),
			'hourly'     => __( 'Hourly', 'fckmaleware' ),
			'twicedaily' => __( 'Twice daily', 'fckmaleware' ),
			'daily'      => __( 'Daily', 'fckmaleware' ),
			'weekly'     => __( 'Weekly', 'fckmaleware' ),
		);
		foreach ( $labels as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $s['schedule'], $value, false ), esc_html( $label ) );
		}
		echo '</select></td></tr>';

		printf(
			'<tr><th><label for="fckmw-max">%s</label></th><td><input id="fckmw-max" type="number" min="1" max="64" name="fckmw[max_file_size_mb]" value="%d" class="small-text"> MB</td></tr>',
			esc_html__( 'Skip files larger than', 'fckmaleware' ),
			(int) $s['max_file_size_mb']
		);

		$this->checkbox( 'core_integrity', $s, __( 'Core integrity', 'fckmaleware' ), __( 'Compare WordPress core files against official WordPress.org checksums.', 'fckmaleware' ) );
		$this->checkbox( 'scan_images', $s, __( 'Scan images', 'fckmaleware' ), __( 'Also look for PHP hidden inside PNG/JPG/GIF/WebP files (slower on large media libraries). .ico files are always scanned.', 'fckmaleware' ) );
		$this->checkbox( 'block_uploads_php', $s, __( 'Block PHP in uploads', 'fckmaleware' ), __( 'Write an .htaccess rule that stops PHP files in wp-content/uploads from executing (Apache/LiteSpeed only).', 'fckmaleware' ) );
		$this->checkbox( 'email_alerts', $s, __( 'Email alerts', 'fckmaleware' ), __( 'Email a summary when a scheduled scan finds something.', 'fckmaleware' ) );

		printf(
			'<tr><th><label for="fckmw-email">%s</label></th><td><input id="fckmw-email" type="email" name="fckmw[alert_email]" value="%s" class="regular-text" placeholder="%s"></td></tr>',
			esc_html__( 'Alert address', 'fckmaleware' ),
			esc_attr( $s['alert_email'] ),
			esc_attr( get_option( 'admin_email' ) )
		);

		echo '<tr><th colspan="2"><h2>' . esc_html__( 'Imunify360', 'fckmaleware' ) . '</h2></th></tr>';
		$this->checkbox( 'imunify_enabled', $s, __( 'Enable integration', 'fckmaleware' ), __( 'Use the Imunify360 / ImunifyAV agent installed on this server.', 'fckmaleware' ) );

		echo '<tr><th><label for="fckmw-bin">' . esc_html__( 'Agent binary', 'fckmaleware' ) . '</label></th><td><select id="fckmw-bin" name="fckmw[imunify_binary]">';
		printf( '<option value="">%s</option>', esc_html__( 'Auto-detect', 'fckmaleware' ) );
		foreach ( Imunify::KNOWN_BINARIES as $path ) {
			printf( '<option value="%1$s"%2$s>%1$s</option>', esc_attr( $path ), selected( $s['imunify_binary'], $path, false ) );
		}
		echo '</select></td></tr>';

		$this->checkbox( 'imunify_use_sudo', $s, __( 'Run through sudo', 'fckmaleware' ), __( 'Prefix agent calls with "sudo -n". Requires a sudoers rule for the PHP user.', 'fckmaleware' ) );
		$this->checkbox( 'imunify_sync_scan', $s, __( 'Sync after scans', 'fckmaleware' ), __( 'Pull Imunify360 detections into the findings list after every scan.', 'fckmaleware' ) );

		echo '</tbody></table>';
		submit_button();
		echo '</form>';
	}

	private function checkbox( string $key, array $settings, string $label, string $help ): void {
		printf(
			'<tr><th>%1$s</th><td><label><input type="checkbox" name="fckmw[%2$s]" value="1"%3$s> %4$s</label></td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			checked( ! empty( $settings[ $key ] ), true, false ),
			esc_html( $help )
		);
	}
}
