<?php
/**
 * Integration tests for the 1.1 features: navigation, bulk quarantine with
 * partial failures, safe restore, upload protection and blocking, the
 * uploads check, scheduling, settings import/export and secret storage.
 *
 *   wp --path=/path/to/test-site eval-file tests/integration/features.php
 *
 * Run only against a disposable site with FCK Malware active. Test files go
 * to wp-content/fckmw-ft-<random>/ and uploads/fckmw-ft-<random>/ and are
 * removed afterwards. Settings changed by the tests are restored.
 *
 * @package Fckmaleware
 */

use Fckmaleware\Admin;
use Fckmaleware\Admin\Ui;
use Fckmaleware\BulkJob;
use Fckmaleware\Monitor;
use Fckmaleware\Paths;
use Fckmaleware\Plugin;
use Fckmaleware\ScanHistory;
use Fckmaleware\Secrets;
use Fckmaleware\Settings;
use Fckmaleware\Store;

if ( ! defined( 'ABSPATH' ) || ! class_exists( Plugin::class ) ) {
	fwrite( STDERR, "Run with: wp eval-file tests/integration/features.php (FCK Malware must be active)\n" );
	exit( 2 );
}

$fckmw_failures = 0;
$fckmw_checks   = 0;
$check          = static function ( bool $ok, string $label ) use ( &$fckmw_failures, &$fckmw_checks ): void {
	$fckmw_checks++;
	if ( ! $ok ) {
		$fckmw_failures++;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . "\n";
};

wp_set_current_user( (int) ( get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) )[0] ?? 1 ) );
$plugin   = Plugin::instance();
$suffix   = strtolower( wp_generate_password( 8, false ) );
$dir_rel  = 'wp-content/fckmw-ft-' . $suffix;
$dir      = ABSPATH . $dir_rel;
$uploads  = wp_upload_dir( null, false );
$up_dir   = trailingslashit( $uploads['basedir'] ) . 'fckmw-ft-' . $suffix;
$settings = Store::get( Settings::OPTION, array() );
wp_mkdir_p( $dir );
wp_mkdir_p( $up_dir );

// Inert samples: real malicious patterns, never executed.
$shell   = "<?php\nif (isset(\$_POST['cmd'])) { echo shell_exec(\$_POST['cmd']); }\n";
$loader  = "<?php\n\$x = 'ZWNobyAnaGknOw==';\neval(base64_decode(\$x));\n";
$samples = array(
	'a-shell.php'  => $shell,
	'b-loader.php' => $loader,
	'c-shell.php'  => $shell . "// copy\n",
	'd-gone.php'   => $loader . "// will disappear\n",
);
foreach ( $samples as $name => $code ) {
	file_put_contents( "{$dir}/{$name}", $code ); // phpcs:ignore WordPress.WP.AlternativeFunctions
}

try {
	// --- Navigation -------------------------------------------------------------
	$sections = Admin::sections();
	$check( 5 === count( $sections ), 'five top-level sections' );
	$tabs = 0;
	foreach ( $sections as $section ) {
		$tabs += count( $section[1] );
	}
	$check( 16 === $tabs, 'sixteen tabs in total' );
	$check( false !== strpos( Ui::url( 'findings', array( 'status' => 'open' ) ), 'page=fckmaleware-scan&tab=findings&status=open' ), 'legacy key "findings" maps to the Scan & Threats tab' );
	$check( false !== strpos( Ui::url( 'scanner' ), 'page=fckmaleware-scan' ) && false === strpos( Ui::url( 'scanner' ), 'tab=' ), 'first tab of a section has no tab argument' );
	foreach ( array( 'scanner', 'findings', 'quarantine', 'realtime', 'hardening', 'ai', 'signatures', 'intel', 'schedule', 'reports', 'activity', 'integrations', 'settings' ) as $legacy ) {
		if ( null === Admin::locate( $legacy ) ) {
			$check( false, "every pre-1.1 page slug still resolves ({$legacy})" );
		}
	}
	$check( true, 'every pre-1.1 page slug still resolves' );

	// --- Scan and history ---------------------------------------------------------
	$before = count( ScanHistory::all() );
	$result = $plugin->scanner()->run( 'custom', 'cli', array( 'scope' => $dir_rel ) );
	$check( ! is_wp_error( $result ) && 'complete' === $result['status'], 'custom scan completes' );
	$check( count( ScanHistory::all() ) === min( 100, $before + 1 ) && $dir_rel === ScanHistory::all()[0]['scope'], 'scan recorded in the history with its scope' );
	$check( is_wp_error( $plugin->scanner()->start( 'custom', 'cli', array( 'scope' => (string) Paths::relative( Paths::data_dir() ) ) ) ), 'scanning the private data folder is refused' );

	// --- Bulk quarantine with skips and a missing file ---------------------------
	$selection = BulkJob::selection( array( 'op' => 'quarantine', 'mode' => 'filters', 'filters' => array( 'search' => $dir_rel . '/' ) ) );
	$check( ! is_wp_error( $selection ) && 'open' === $selection['filters']['status'], 'filter selection is limited to open findings' );
	$preview = $plugin->bulk()->preview( $selection );
	$check( $preview['total'] >= 4 && $preview['eligible'] >= 1, 'preview counts matching and eligible findings' );
	$check( $preview['eligible'] + $preview['skipped'] === $preview['total'], 'preview: eligible + skipped = total' );

	$hash_before = hash_file( 'sha256', "{$dir}/a-shell.php" );
	wp_delete_file( "{$dir}/d-gone.php" ); // Disappears between preview and run.
	$job = $plugin->bulk()->start( $selection );
	$check( is_array( $job ) && 'running' === $job['status'] && '' !== $job['point'], 'bulk job starts with one restore point' );
	$check( is_wp_error( $plugin->bulk()->start( $selection ) ), 'a second bulk job is refused while one runs' );
	for ( $i = 0; $i < 20 && 'running' === $job['status']; $i++ ) {
		$job = $plugin->bulk()->step( 5.0 );
	}
	$check( 'complete' === $job['status'], 'bulk job completes' );
	$check( $job['processed'] === $job['succeeded'] + $job['failed'] + $job['skipped'], 'processed = succeeded + failed + skipped' );
	$check( ! file_exists( "{$dir}/a-shell.php" ) && ! file_exists( "{$dir}/c-shell.php" ), 'eligible files were removed' );
	$check( $job['skipped'] >= 1, 'missing file and already-handled findings are skipped, not failed' );
	$check( 0 === $job['failed'], 'no failures' );
	$keys = array();
	foreach ( $plugin->quarantine()->all() as $key => $item ) {
		if ( "{$dir_rel}/a-shell.php" === $item['file'] ) {
			$keys[] = $key;
		}
	}
	$check( 1 === count( $keys ) && $hash_before === $plugin->quarantine()->get( $keys[0] )['hash'], 'quarantine keeps the original hash' );
	$events = Fckmaleware\ActivityLog::query( array( 'type' => 'bulk.' ), 1, 5 )['rows'];
	$check( (bool) array_filter( $events, static function ( $e ) { return 'bulk.completed' === $e['type']; } ), 'bulk job is audited' );
	$check( is_wp_error( $plugin->bulk()->retry() ), 'retry refuses when there are no recoverable failures' );

	// --- Restore never overwrites --------------------------------------------------
	file_put_contents( "{$dir}/a-shell.php", "<?php // new legitimate file\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	$restore = $plugin->remediation()->restore( $keys[0] );
	$check( is_wp_error( $restore ) && "<?php // new legitimate file\n" === file_get_contents( "{$dir}/a-shell.php" ), 'restore refuses to overwrite a file that now exists' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	wp_delete_file( "{$dir}/a-shell.php" );
	$restore = $plugin->remediation()->restore( $keys[0] );
	$check( ! is_wp_error( $restore ) && $shell === file_get_contents( "{$dir}/a-shell.php" ), 'restore puts the exact bytes back once the location is free' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	$check( is_wp_error( Paths::write_new( "{$dir}/a-shell.php", 'x' ) ), 'exclusive create refuses an existing file' );

	// --- Bulk policy -----------------------------------------------------------------
	$fake = array( 'object_type' => 'file', 'file' => 'wp-includes/version.php', 'signature_id' => 'FMW-PHP-001', 'source' => 'signature', 'remediation' => 'quarantine', 'verdict' => 'malicious', 'confidence' => 95, 'status' => 'open' );
	$check( null !== $plugin->remediation()->quarantine_eligibility( $fake, false ), 'core files are never eligible' );
	$check( null !== $plugin->remediation()->quarantine_eligibility( array( 'file' => '.htaccess' ) + $fake, false ), 'root .htaccess is never eligible' );
	$check( null !== $plugin->remediation()->quarantine_eligibility( array( 'file' => 'wp-content/x.php', 'verdict' => 'suspicious' ) + $fake, true ), 'suspicious-only findings are skipped by the bulk policy' );
	$check( null === $plugin->remediation()->quarantine_eligibility( array( 'file' => 'wp-content/x.php', 'verdict' => 'suspicious' ) + $fake, false ), 'explicitly ticked suspicious findings may be quarantined' );
	$check( null !== $plugin->remediation()->quarantine_eligibility( array( 'file' => 'wp-content/x.php', 'confidence' => 60 ) + $fake, true ), 'low confidence is skipped by the bulk policy' );
	$check( null !== $plugin->remediation()->quarantine_eligibility( array( 'file' => 'wp-content/x.php', 'remediation' => 'clean' ) + $fake, true ), 'injected-but-legitimate files are skipped by the bulk policy' );
	$active = 'wp-content/plugins/' . dirname( plugin_basename( FCKMW_FILE ) ) . '/x.php';
	$check( null !== $plugin->remediation()->quarantine_eligibility( array( 'file' => $active, 'source' => 'heuristic' ) + $fake, true ), 'heuristic matches in active plugins are skipped by the bulk policy' );

	// --- Upload protection --------------------------------------------------------------
	Settings::update( array( 'realtime_uploads' => '1', 'upload_block_mode' => 'malicious', 'upload_rate_limit' => '3', 'block_dangerous_extensions' => '1', 'block_mime_mismatch' => '1' ), array( 'realtime_uploads', 'block_dangerous_extensions', 'block_mime_mismatch' ) );
	Monitor::clear_blocks();
	$monitor = $plugin->monitor();
	$upload  = static function ( string $name, string $content ) use ( $monitor ): array {
		$tmp = wp_tempnam( 'fckmw-ft' );
		file_put_contents( $tmp, $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$result = $monitor->check_upload( array( 'name' => $name, 'tmp_name' => $tmp, 'size' => strlen( $content ), 'error' => 0 ) );
		wp_delete_file( $tmp );
		return $result;
	};
	$gif = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";
	$check( empty( $upload( 'pixel.gif', $gif )['error'] ), 'a clean image upload is accepted' );
	$r = $upload( 'note.php.jpg', 'hello' );
	$check( ! empty( $r['error'] ) && false === strpos( $r['error'], 'php' ), 'double extension refused with a generic message' );
	$check( ! empty( $upload( 'avatar.png', "\x89PNG\r\n<?php system(\$_GET['c']); ?>" )['error'] ), 'image containing PHP refused' );
	$check( ! empty( $upload( 'tool.txt', $shell )['error'] ), 'malicious content refused by the signature engine' );
	$check( Monitor::is_blocked( 'user:' . get_current_user_id() ), 'repeated malicious uploads block the account temporarily' );
	$check( ! empty( $upload( 'pixel.gif', $gif )['error'] ), 'blocked account cannot upload even clean files' );
	$lifted = Monitor::clear_blocks();
	$check( $lifted >= 1 && empty( $upload( 'pixel.gif', $gif )['error'] ), 'lifting the block restores uploads' );
	Monitor::clear_blocks();
	Settings::update( array( 'upload_block_mode' => 'monitor' ) );
	$check( empty( $upload( 'tool.txt', $shell )['error'] ), 'monitor mode never blocks on detections' );
	$check( empty( $upload( 'notes.txt', "<?php echo 1;\n" )['error'] ), 'a text file with a PHP tag is not treated as an image' );
	Settings::update( array( 'upload_block_mode' => 'malicious' ) );
	$check( ! empty( $upload( 'tool.txt', $shell )['error'] ), 'malicious mode blocks a malicious upload' );
	Monitor::clear_blocks();

	// --- Uploads check (files written outside WordPress) ------------------------------------
	Store::set( 'fckmw_uploads_watch_last', time() - HOUR_IN_SECONDS );
	file_put_contents( "{$up_dir}/dropped.php", $shell ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	$plugin->monitor()->watch_uploads();
	$plugin->monitor()->process_queue( 30.0 );
	$up_rel = (string) Paths::relative( wp_normalize_path( "{$up_dir}/dropped.php" ) );
	$found  = $plugin->findings()->query( array( 'status' => 'open', 'search' => $up_rel ), 1, 10 )['rows'];
	$check( (bool) $found, 'uploads check finds a file dropped into uploads' );
	$check( 'ok' === ( Plugin::task_runs()['uploads']['status'] ?? '' ), 'uploads check records its run' );

	// --- Scheduling ---------------------------------------------------------------------------
	Settings::update( array( 'schedule' => 'daily', 'integrity_schedule' => 'weekly', 'uploads_watch' => 'hourly', 'schedule_hour' => '4' ) );
	Plugin::reschedule();
	Plugin::reschedule();
	$count = static function ( string $hook ): int {
		$n = 0;
		foreach ( (array) _get_cron_array() as $hooks ) {
			$n += count( (array) ( $hooks[ $hook ] ?? array() ) );
		}
		return $n;
	};
	$check( 1 === $count( Plugin::CRON_SCAN ) && 1 === $count( Plugin::CRON_CORE ) && 1 === $count( Plugin::CRON_UPLOADS ), 'rescheduling twice creates no duplicate events' );
	$next = (int) wp_next_scheduled( Plugin::CRON_SCAN );
	$check( '04' === wp_date( 'H', $next ) && $next > time(), 'daily scan is scheduled at the chosen hour in the site time zone' );
	$plugin->scanner()->start( 'quick', 'manual' );
	$plugin->run_integrity_scan();
	$check( 'skipped' === ( Plugin::task_runs()['integrity']['status'] ?? '' ), 'a scheduled task is skipped while another scan runs' );
	$plugin->scanner()->cancel();

	// --- Settings: secrets, export, import ----------------------------------------------------
	Settings::update( array( 'ai_api_key' => 'sk-test-1234567890' ) );
	$raw = Store::get( Settings::OPTION, array() );
	$check( Secrets::is_encrypted( (string) $raw['ai_api_key'] ) && 'sk-test-1234567890' === Settings::get( 'ai_api_key' ), 'API key is encrypted at rest and readable in use' );
	$check( ! array_key_exists( 'ai_api_key', Settings::export() ), 'export never contains the API key' );
	Settings::import( array( 'ai_api_key' => 'evil', 'heuristic_threshold' => '999', 'scan_exclusions' => "wp-content/cache\n../../etc\n/abs", 'unknown' => 1, 'auto_quarantine' => true ) );
	$check( 'sk-test-1234567890' === Settings::get( 'ai_api_key' ), 'import cannot change the API key' );
	$check( 95 === (int) Settings::get( 'heuristic_threshold' ), 'imported values are clamped to their range' );
	$check( array( 'wp-content/cache', 'abs' ) === Settings::exclusions(), 'path exclusions drop traversal' );
	$check( true === Settings::get( 'auto_quarantine' ), 'imported booleans are applied' );
	Settings::reset();
	$check( false === Settings::get( 'auto_quarantine' ) && 'sk-test-1234567890' === Settings::get( 'ai_api_key' ), 'reset restores defaults and keeps the API key' );

	// --- Integrations ---------------------------------------------------------------------------
	$providers = $plugin->integrations()->providers();
	$check( array( 'imunify360', 'imunifyav', 'cpguard' ) === array_keys( $providers ), 'three server products are listed' );
	$check( ! $providers['cpguard']['enabled'] && array( 'test' ) === $providers['cpguard']['actions'], 'cPGuard is status-only' );
	$test = $plugin->integrations()->test( 'imunify360' );
	$check( is_array( $test ) && ( $providers['imunify360']['detected'] || false === $test['ok'] ), 'a missing agent is reported as not connected' );
	$check( is_wp_error( $plugin->integrations()->test( 'imunify360' ) ), 'connection tests are rate-limited' );

	// --- CSV formula injection ------------------------------------------------------------------
	foreach ( array( '=1+1', '+cmd', '-2', '@SUM(A1)', "\t=x", ' =x', '|calc' ) as $value ) {
		if ( 0 !== strpos( Admin\Actions::csv_cell( $value ), "'" ) ) {
			$check( false, "CSV cell neutralized: {$value}" );
		}
	}
	$check( 'wp-content/x.php' === Admin\Actions::csv_cell( 'wp-content/x.php' ), 'CSV formula cells are neutralized, normal cells untouched' );
} finally {
	Store::set( Settings::OPTION, $settings );
	Plugin::reschedule();
	Monitor::clear_blocks();
	foreach ( array( $dir, $up_dir ) as $folder ) {
		foreach ( (array) glob( "{$folder}/*" ) as $file ) {
			wp_delete_file( $file );
		}
		@rmdir( $folder ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
	}
}

echo "\n{$fckmw_checks} checks, {$fckmw_failures} failed.\n";
if ( $fckmw_failures ) {
	exit( 1 );
}
