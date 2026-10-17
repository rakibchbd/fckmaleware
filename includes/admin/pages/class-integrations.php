<?php
/**
 * Server Security integrations: Imunify360, ImunifyAV and cPGuard, each with
 * detection, connection test, capabilities, actions, instructions and
 * troubleshooting, plus the orchestration policy when several products run.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Imunify;
use Fckmaleware\ServerIntegrations;
use Fckmaleware\Settings;

final class Integrations extends Page {

	public function render( string $title ): void {
		$settings  = Settings::all();
		$center    = $this->plugin->integrations();
		$providers = $center->providers();
		$env       = ServerIntegrations::environment();

		Ui::header( $title, __( 'Optional connections to security products installed on the server. FCK Malware\'s own scanner works fully without any of them. Only documented local interfaces are used; nothing is reported as connected until a test succeeds.', 'fckmaleware' ) );

		if ( ! $env['proc_open'] || $env['open_basedir'] ) {
			Ui::callout(
				trim( ( $env['proc_open'] ? '' : __( 'proc_open() is disabled, so command-line agents cannot be called from WordPress.', 'fckmaleware' ) . ' ' ) . ( $env['open_basedir'] ? __( 'open_basedir is active, so server folders may be invisible to PHP and products can show as "not detected" even when installed.', 'fckmaleware' ) : '' ) ),
				'warning',
				__( 'Hosting restrictions', 'fckmaleware' )
			);
		}

		echo '<div class="fckmw-grid fckmw-grid-3">';
		foreach ( $providers as $provider ) {
			$this->panel( $provider, $settings );
		}
		echo '</div>';

		Ui::card_start( __( 'Server scanner settings', 'fckmaleware' ), '', __( 'Applies to Imunify360 and ImunifyAV, which share the same command-line interface.', 'fckmaleware' ), 'imunify-settings' );
		Ui::settings_form( 'integrations' );
		Ui::toggle( 'imunify_enabled', $settings['imunify_enabled'], __( 'Use the server scanner', 'fckmaleware' ), __( 'Imports the malicious-file list for this site as findings. FCK Malware only reads results through the agent; it does not use or copy the product\'s signatures.', 'fckmaleware' ) );
		$binaries = array( '' => __( 'Detect automatically', 'fckmaleware' ) );
		foreach ( Imunify::KNOWN_BINARIES as $path ) {
			$binaries[ $path ] = $path . ' (' . Imunify::product_of( $path ) . ')';
		}
		Ui::select( 'imunify_binary', $settings['imunify_binary'], $binaries, __( 'Agent binary', 'fckmaleware' ), __( 'Only these fixed paths are accepted; no command or path can be typed in.', 'fckmaleware' ) );
		Ui::toggle( 'imunify_use_sudo', $settings['imunify_use_sudo'], __( 'Run through sudo', 'fckmaleware' ), __( 'Only if the host granted the web server user a sudo rule for this exact binary (sudo -n, never a password).', 'fckmaleware' ) );
		Ui::toggle( 'imunify_sync_scan', $settings['imunify_sync_scan'], __( 'Sync after every FCK Malware scan', 'fckmaleware' ) );
		Ui::select(
			'primary_scanner',
			$settings['primary_scanner'],
			array(
				'fckmw'  => __( 'FCK Malware handles remediation (default)', 'fckmaleware' ),
				'server' => __( 'The server scanner handles remediation', 'fckmaleware' ),
			),
			__( 'When both run', 'fckmaleware' ),
			__( 'Both always detect. Findings for the same file are merged per file, and a quarantine moves every finding on that file. With "server", FCK Malware\'s automatic quarantine is paused so two products never move the same file; manual actions stay available.', 'fckmaleware' )
		);
		Ui::submit( __( 'Save', 'fckmaleware' ) );
		echo '</form>';
		Ui::card_end();
		Ui::footer();
	}

	private function panel( array $provider, array $settings ): void {
		echo '<section class="fckmw-card">';
		echo '<div class="fckmw-provider-head"><div><h2 class="fckmw-card-title">' . esc_html( $provider['name'] ) . '</h2><span class="fckmw-provider-vendor">' . esc_html( $provider['vendor'] ) . '</span></div>';
		if ( $provider['enabled'] ) {
			echo Ui::status( __( 'In use', 'fckmaleware' ), 'good' ); // phpcs:ignore WordPress.Security.EscapeOutput
		} elseif ( $provider['detected'] ) {
			echo Ui::status( __( 'Detected', 'fckmaleware' ), 'neutral' ); // phpcs:ignore WordPress.Security.EscapeOutput
		} else {
			echo Ui::status( __( 'Not detected', 'fckmaleware' ), 'off' ); // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</div>';

		$test = $provider['test'];
		$rows = array(
			array( __( 'Installation', 'fckmaleware' ), $provider['detected'] ? '<code>' . esc_html( $provider['binary'] ) . '</code>' : esc_html__( 'Not found on this server', 'fckmaleware' ) ),
			array( __( 'Connection', 'fckmaleware' ), is_array( $test ) ? Ui::status( $test['ok'] ? __( 'Test passed', 'fckmaleware' ) : __( 'Test failed', 'fckmaleware' ), $test['ok'] ? 'good' : 'bad' ) . '<span class="fckmw-sub">' . esc_html( $test['message'] . ' · ' . Ui::ago( (int) $test['time'] ) ) . '</span>' : esc_html__( 'Not tested', 'fckmaleware' ) ),
		);
		if ( 'cpguard' !== $provider['id'] ) {
			$rows[] = array( __( 'Last sync', 'fckmaleware' ), $provider['last_sync'] ? Ui::when( (int) $provider['last_sync'] ) : esc_html__( 'never', 'fckmaleware' ) );
		}
		Ui::kv( $rows );
		if ( '' !== $provider['blocked'] && $provider['detected'] ) {
			Ui::callout( $provider['blocked'], 'warning' );
		}

		echo '<p><strong>' . esc_html__( 'What FCK Malware can do with it', 'fckmaleware' ) . '</strong></p><ul class="fckmw-list">';
		foreach ( $provider['capabilities'] as $capability ) {
			echo '<li>' . esc_html( $capability ) . '</li>';
		}
		echo '</ul>';

		echo '<div class="fckmw-actions">';
		Ui::action_button( 'integration_test', __( 'Test connection', 'fckmaleware' ), array( 'provider' => $provider['id'], 'return' => 'integrations' ) );
		if ( $provider['enabled'] && in_array( 'sync', $provider['actions'], true ) ) {
			Ui::action_button( 'imunify', __( 'Sync now', 'fckmaleware' ), array( 'op' => 'sync', 'return' => 'integrations' ), 'button button-primary' );
			Ui::action_button( 'imunify', __( 'Start server scan', 'fckmaleware' ), array( 'op' => 'scan', 'return' => 'integrations' ), 'button', __( 'Ask the server scanner to scan this site now? Sync the results once it finishes.', 'fckmaleware' ) );
		}
		echo '</div>';

		Ui::disclosure_start( __( 'Setup', 'fckmaleware' ) );
		echo '<ol>';
		foreach ( $provider['instructions'] as $step ) {
			echo '<li>' . esc_html( $step ) . '</li>';
		}
		echo '</ol>';
		Ui::disclosure_end();
		Ui::disclosure_start( __( 'Troubleshooting', 'fckmaleware' ) );
		echo '<ul class="fckmw-list">';
		foreach ( $provider['troubleshooting'] as $tip ) {
			echo '<li>' . esc_html( $tip ) . '</li>';
		}
		echo '</ul>';
		Ui::disclosure_end();
		echo '</section>';
	}
}
