<?php
/**
 * Integrations: Imunify360 on this server, webhooks, plugin updates from
 * GitHub and WP-CLI.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Imunify;
use Fckmaleware\Notifier;
use Fckmaleware\Settings;
use Fckmaleware\Store;
use Fckmaleware\Updater;

final class Integrations extends Page {

	public function render( string $title ): void {
		$settings = Settings::all();

		Ui::header( $title, __( 'Optional connections. FCK Malware works fully without any of them.', 'fckmaleware' ) );

		echo '<div class="fckmw-grid">';
		Ui::card_start( 'Imunify360' );
		$imunify  = $this->plugin->imunify();
		$detected = Imunify::detect_binary();
		if ( ! $imunify->is_available() ) {
			echo '<p>' . Ui::badge( __( 'Not found', 'fckmaleware' ), 'neutral' ) . ' ' . esc_html( function_exists( 'proc_open' ) ? __( 'No Imunify360 agent was found on this server. Imunify360 is a commercial server product from CloudLinux; if your host runs it, its detections can be shown here alongside FCK Malware\'s own.', 'fckmaleware' ) : __( 'PHP\'s proc_open() is disabled on this server, so the Imunify360 agent cannot be queried.', 'fckmaleware' ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		} else {
			$version = $settings['imunify_enabled'] ? $imunify->version() : '';
			echo '<p>' . Ui::badge( $settings['imunify_enabled'] ? __( 'Connected', 'fckmaleware' ) : __( 'Available', 'fckmaleware' ), $settings['imunify_enabled'] && ! is_wp_error( $version ) ? 'good' : 'neutral' ) . ' <code>' . esc_html( $imunify->binary() ) . '</code>'; // phpcs:ignore WordPress.Security.EscapeOutput
			if ( is_wp_error( $version ) ) {
				echo ' ' . Ui::badge( __( 'Error', 'fckmaleware' ), 'warn' ) . ' ' . esc_html( $version->get_error_message() ); // phpcs:ignore WordPress.Security.EscapeOutput
			} elseif ( '' !== $version ) {
				echo ' ' . esc_html( $version );
			}
			echo '</p>';
			/* translators: %s: time */
			echo '<p class="description">' . esc_html( sprintf( __( 'Last sync: %s.', 'fckmaleware' ), Ui::ago( (int) Store::get( 'fckmw_imunify_last_sync', 0 ) ) ) ) . '</p>';
		}
		Ui::settings_form( 'integrations' );
		Ui::toggle( 'imunify_enabled', $settings['imunify_enabled'], __( 'Use Imunify360', 'fckmaleware' ), __( 'Imports Imunify360\'s malicious-file list for this site as findings. FCK Malware only reads results through the agent\'s command-line tool; it does not use or copy Imunify360\'s signatures.', 'fckmaleware' ) );
		$binaries = array( '' => $detected ? sprintf( /* translators: %s: path */ __( 'Detect automatically (%s)', 'fckmaleware' ), $detected ) : __( 'Detect automatically', 'fckmaleware' ) );
		foreach ( Imunify::KNOWN_BINARIES as $path ) {
			$binaries[ $path ] = $path;
		}
		Ui::select( 'imunify_binary', $settings['imunify_binary'], $binaries, __( 'Agent binary', 'fckmaleware' ) );
		Ui::toggle( 'imunify_use_sudo', $settings['imunify_use_sudo'], __( 'Run through sudo', 'fckmaleware' ), __( 'Only if the host granted the web server user a sudo rule for this exact binary.', 'fckmaleware' ) );
		Ui::toggle( 'imunify_sync_scan', $settings['imunify_sync_scan'], __( 'Sync after every FCK Malware scan', 'fckmaleware' ) );
		submit_button( __( 'Save', 'fckmaleware' ), 'secondary' );
		echo '</form>';
		if ( $settings['imunify_enabled'] && $imunify->is_available() ) {
			echo '<div class="fckmw-actions">';
			Ui::action_button( 'imunify', __( 'Sync now', 'fckmaleware' ), array( 'op' => 'sync', 'return' => 'integrations' ), 'button button-primary' );
			Ui::action_button( 'imunify', __( 'Start Imunify360 scan of this site', 'fckmaleware' ), array( 'op' => 'scan', 'return' => 'integrations' ) );
			echo '</div>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Webhook', 'fckmaleware' ) );
		echo '<p>' . esc_html__( 'Sends alerts as JSON to Slack-compatible or custom receivers. Each request carries an X-FCKMW-Signature header: the HMAC-SHA256 of the body with the secret below. Only public addresses are allowed.', 'fckmaleware' ) . '</p>';
		Ui::settings_form( 'integrations' );
		Ui::input( 'webhook_url', (string) $settings['webhook_url'], __( 'Webhook URL', 'fckmaleware' ), 'url', '', array( 'class' => 'regular-text', 'placeholder' => 'https://' ) );
		submit_button( __( 'Save', 'fckmaleware' ), 'secondary' );
		echo '</form>';
		if ( '' !== $settings['webhook_url'] ) {
			echo '<details><summary>' . esc_html__( 'Show signing secret', 'fckmaleware' ) . '</summary><p><code class="fckmw-secret">' . esc_html( Notifier::webhook_secret() ) . '</code></p></details>';
			echo '<div class="fckmw-actions">';
			Ui::action_button( 'notify_test', __( 'Send test', 'fckmaleware' ), array( 'return' => 'integrations' ) );
			Ui::action_button( 'webhook_secret', __( 'Create new secret', 'fckmaleware' ), array( 'return' => 'integrations' ), 'button', __( 'The current secret stops working immediately. Continue?', 'fckmaleware' ) );
			echo '</div>';
		}
		$log = ActivityLog::query( array( 'type' => 'notify.' ), 1, 5 )['rows'];
		if ( $log ) {
			echo '<h4>' . esc_html__( 'Recent deliveries', 'fckmaleware' ) . '</h4><ul class="fckmw-list">';
			foreach ( $log as $row ) {
				echo '<li>' . esc_html( Ui::ago( (int) $row['created_at'] ) . ': ' . $row['message'] ) . '</li>';
			}
			echo '</ul>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Plugin updates', 'fckmaleware' ) );
		/* translators: %s: repository */
		echo '<p>' . esc_html( sprintf( __( 'New versions are published as GitHub releases of %s and appear in Dashboard → Updates like any other plugin.', 'fckmaleware' ), Updater::REPOSITORY ) ) . '</p>';
		$cached  = get_site_transient( 'fckmw_github_release' );
		$release = is_array( $cached ) ? $cached['release'] : null;
		/* translators: %s: version */
		echo '<p>' . esc_html( sprintf( __( 'Installed: %s.', 'fckmaleware' ), FCKMW_VERSION ) ) . ' ';
		if ( $release ) {
			/* translators: %s: version */
			echo esc_html( sprintf( __( 'Latest release: %s.', 'fckmaleware' ), $release['version'] ) ) . ' <a href="' . esc_url( $release['url'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Release notes', 'fckmaleware' ) . '</a>';
		} elseif ( is_array( $cached ) ) {
			echo esc_html__( 'The last check found no published release.', 'fckmaleware' );
		} else {
			echo esc_html__( 'Not checked recently.', 'fckmaleware' );
		}
		echo '</p><p><a class="button" href="' . esc_url( is_multisite() ? network_admin_url( 'update-core.php?force-check=1' ) : admin_url( 'update-core.php?force-check=1' ) ) . '">' . esc_html__( 'Check for updates', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( 'WP-CLI' );
		echo '<p>' . esc_html__( 'Everything on these screens is also available from the command line:', 'fckmaleware' ) . '</p><pre class="fckmw-code">';
		echo esc_html(
			implode(
				"\n",
				array(
					'wp fckmaleware scan --mode=standard',
					'wp fckmaleware findings --format=table',
					'wp fckmaleware quarantine <id>',
					'wp fckmaleware restore <key>',
					'wp fckmaleware db-scan',
					'wp fckmaleware persistence',
					'wp fckmaleware signature-updates status',
					'wp fckmaleware hardening status',
					'wp fckmaleware imunify sync',
				)
			)
		);
		echo '</pre>';
		Ui::card_end();
		echo '</div>';
		Ui::footer();
	}
}
