<?php
/**
 * WordPress integration tests. They run inside a real (disposable!) site
 * through WP-CLI and exercise the services end to end: scan, findings,
 * quarantine/restore, accept, database scan, persistence, settings, health,
 * hardening and the signature updater's refusal paths.
 *
 *   wp --path=/path/to/test-site eval-file tests/integration/run.php
 *
 * The site must have FCK Malware active. Test files are written to
 * wp-content/fckmw-it-<random>/ and removed afterwards; findings and options
 * created by the tests are left in place for inspection.
 *
 * @package Fckmaleware
 */

use Fckmaleware\Plugin;
use Fckmaleware\Settings;
use Fckmaleware\Store;

if ( ! defined( 'ABSPATH' ) || ! class_exists( Plugin::class ) ) {
	fwrite( STDERR, "Run with: wp eval-file tests/integration/run.php (FCK Malware must be active)\n" );
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

$plugin  = Plugin::instance();
$dir_rel = 'wp-content/fckmw-it-' . strtolower( wp_generate_password( 8, false ) );
$dir     = ABSPATH . $dir_rel;
wp_mkdir_p( $dir );

// Inert samples: real malicious patterns, but nothing here is ever executed.
$samples = array(
	'shell.php'  => "<?php\nif (isset(\$_POST['cmd'])) { echo shell_exec(\$_POST['cmd']); }\n",
	'loader.php' => "<?php\n\$x = 'ZWNobyAnaGknOw==';\neval(base64_decode(\$x));\n",
	'clean.php'  => "<?php\nfunction fckmw_it_hello() { return esc_html__( 'Hello', 'default' ); }\n",
);
foreach ( $samples as $name => $code ) {
	file_put_contents( "{$dir}/{$name}", $code ); // phpcs:ignore WordPress.WP.AlternativeFunctions
}

try {
	// --- Scan -----------------------------------------------------------------
	$result = $plugin->scanner()->run( 'custom', 'cli', array( 'scope' => $dir_rel ) );
	$check( ! is_wp_error( $result ) && 'complete' === $result['status'], 'custom scan completes' );
	$check( 3 === (int) $result['total'], 'custom scan lists the 3 sample files' );

	$rows  = $plugin->findings()->query( array( 'status' => 'open', 'search' => $dir_rel ), 1, 50 )['rows'];
	$files = array_unique( array_column( $rows, 'file' ) );
	$check( in_array( "{$dir_rel}/shell.php", $files, true ), 'shell sample detected' );
	$check( in_array( "{$dir_rel}/loader.php", $files, true ), 'eval(base64_decode()) loader detected' );
	$check( ! in_array( "{$dir_rel}/clean.php", $files, true ), 'clean sample not flagged' );

	// Re-scan: the finding is updated, not duplicated.
	$plugin->scanner()->run( 'custom', 'cli', array( 'scope' => $dir_rel ) );
	$again = $plugin->findings()->query( array( 'status' => 'open', 'search' => $dir_rel ), 1, 50 )['rows'];
	$check( count( $again ) === count( $rows ), 'repeat scan does not duplicate findings' );

	// --- Quarantine and restore ----------------------------------------------
	$shell = null;
	foreach ( $rows as $row ) {
		if ( "{$dir_rel}/shell.php" === $row['file'] ) {
			$shell = $row;
			break;
		}
	}
	$key = $plugin->remediation()->quarantine( (int) $shell['id'] );
	$check( is_string( $key ) && ! file_exists( "{$dir}/shell.php" ), 'quarantine removes the original' );
	$check( 'quarantined' === $plugin->findings()->get( (int) $shell['id'] )['status'], 'finding marked quarantined' );
	$check( $samples['shell.php'] === $plugin->quarantine()->content( (string) $key ), 'quarantined copy is byte-identical' );
	$points = $plugin->remediation()->points();
	$check( (bool) $points, 'restore point recorded' );

	$restored = $plugin->remediation()->restore( (string) $key );
	$check( ! is_wp_error( $restored ) && $samples['shell.php'] === file_get_contents( "{$dir}/shell.php" ), 'restore puts the exact bytes back' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

	// Refusals.
	$check( is_wp_error( $plugin->remediation()->restore( 'deadbeef' ) ), 'restore of unknown key is refused' );
	$check( is_wp_error( $plugin->remediation()->quarantine( 999999999 ) ), 'quarantine of unknown finding is refused' );

	// --- Accept (ignore until the file changes) -------------------------------
	$loader = null;
	foreach ( $rows as $row ) {
		if ( "{$dir_rel}/loader.php" === $row['file'] ) {
			$loader = $row;
			break;
		}
	}
	$plugin->remediation()->accept( (int) $loader['id'] );
	$plugin->scanner()->run( 'custom', 'cli', array( 'scope' => $dir_rel ) );
	$check( 'ignored' === $plugin->findings()->get( (int) $loader['id'] )['status'], 'accepted finding stays ignored while unchanged' );
	file_put_contents( "{$dir}/loader.php", $samples['loader.php'] . "// changed\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	$plugin->file_cache()->forget( "{$dir_rel}/loader.php" );
	$plugin->scanner()->run( 'custom', 'cli', array( 'scope' => $dir_rel ) );
	$reopened = $plugin->findings()->query( array( 'status' => 'open', 'search' => "{$dir_rel}/loader.php" ), 1, 10 )['rows'];
	$check( (bool) $reopened, 'changed file is reported again after accept' );

	// --- Scope safety ---------------------------------------------------------
	$check( is_wp_error( $plugin->scanner()->start( 'custom', 'cli', array( 'scope' => '../../' ) ) ), 'custom scope outside WordPress is refused' );

	// --- Database scan --------------------------------------------------------
	$post_id = wp_insert_post(
		array(
			'post_title'   => 'fckmw integration',
			'post_status'  => 'draft',
			'post_content' => '<p>hi</p><script>eval(atob("ZG9jdW1lbnQud3JpdGUoMSk="))</script>',
		)
	);
	kses_remove_filters(); // Drafts by CLI keep the script tag only without KSES.
	wp_update_post(
		array(
			'ID'           => $post_id,
			'post_content' => '<p>hi</p><script>eval(atob("ZG9jdW1lbnQud3JpdGUoMSk="))</script>',
		)
	);
	$db = $plugin->db_scanner()->run( 'cli' );
	$check( ! is_wp_error( $db ) && 'complete' === $db['status'], 'database scan completes' );
	$post_findings = array_filter(
		$plugin->findings()->query( array( 'status' => 'open', 'object_type' => 'post' ), 1, 200 )['rows'],
		static function ( array $row ) use ( $post_id ): bool {
			return (bool) preg_match( '/:post:' . (int) $post_id . ':/', (string) $row['object_ref'] );
		}
	);
	$check( (bool) $post_findings, 'injected script in post content detected' );
	wp_delete_post( $post_id, true );

	// --- Persistence ----------------------------------------------------------
	$p = $plugin->persistence()->run( 'cli' );
	$check( isset( $p['found'], $p['new'] ), 'persistence check runs' );

	// --- Settings -------------------------------------------------------------
	$before = Settings::all();
	$after  = Settings::update( array( 'heuristic_threshold' => '5', 'schedule' => 'bogus', 'webhook_url' => 'javascript:alert(1)' ) );
	$check( 30 === $after['heuristic_threshold'], 'int setting clamped to its minimum' );
	$check( 'daily' === $after['schedule'], 'invalid enum falls back to default' );
	$check( '' === $after['webhook_url'], 'non-http URL rejected' );
	Store::set( Settings::OPTION, $before );

	// --- Health ---------------------------------------------------------------
	$health = \Fckmaleware\Health::compute( $plugin );
	$check( $health['score'] === max( 0, 100 - array_sum( array_column( $health['deductions'], 'points' ) ) ), 'health score equals 100 minus listed deductions' );

	// --- Hardening ------------------------------------------------------------
	$check( is_wp_error( $plugin->hardening()->set( 'permissions', true ) ), 'report-only check cannot be toggled' );
	$check( true === $plugin->hardening()->set( 'author_enum', true ) && \Fckmaleware\Hardening::is_enabled( 'author_enum' ), 'hardening rule turns on' );
	$plugin->hardening()->set( 'author_enum', false );
	$check( ! \Fckmaleware\Hardening::is_enabled( 'author_enum' ), 'hardening rule turns off' );

	// --- Notifier SSRF guard ---------------------------------------------------
	foreach ( array( 'http://127.0.0.1/', 'http://10.0.0.5/', 'http://169.254.169.254/latest/', 'http://[::1]/', 'http://100.64.1.1/' ) as $url ) {
		$check( ! \Fckmaleware\Notifier::is_public_url( $url ), 'webhook to private address refused: ' . $url );
	}

	// --- Signature updater refuses a bad feed ---------------------------------
	$filter = static function () {
		return 'http://127.0.0.1:1/manifest.json';
	};
	add_filter( 'fckmw_signature_feed_url', $filter );
	$active = $plugin->signatures()->version();
	$update = $plugin->signature_updater()->check();
	remove_filter( 'fckmw_signature_feed_url', $filter );
	$check( 'error' === $update['status'], 'unreachable or unsafe feed URL reports an error' );
	$check( $active === $plugin->signature_updater()->load()->version(), 'failed update keeps the active database' );
} finally {
	foreach ( (array) glob( "{$dir}/*" ) as $file ) {
		wp_delete_file( $file );
	}
	@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
}

echo "\n{$fckmw_checks} checks, {$fckmw_failures} failed.\n";
if ( $fckmw_failures ) {
	exit( 1 );
}
