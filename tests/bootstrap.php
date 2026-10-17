<?php
/**
 * Bootstrap for the standalone (no WordPress) test suite.
 *
 * Only the WordPress-free parts of the plugin are loaded; a handful of WP
 * functions they call for translation and errors are stubbed.
 */

define( 'FCKMW_TESTS', true );
define( 'FCKMW_ROOT', dirname( __DIR__ ) );

if ( ! function_exists( '__' ) ) {
	function __( $text ) {
		return $text;
	}
}
if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $code;
		public $message;
		public function __construct( $code = '', $message = '' ) {
			$this->code    = $code;
			$this->message = $message;
		}
		public function get_error_message() {
			return $this->message;
		}
	}
}
if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

require FCKMW_ROOT . '/includes/class-signatures.php';
require FCKMW_ROOT . '/includes/class-feed.php';
require FCKMW_ROOT . '/includes/class-notifier.php';
require FCKMW_ROOT . '/includes/ai/class-redactor.php';
require FCKMW_ROOT . '/includes/class-imunify.php';
require FCKMW_ROOT . '/includes/detection/class-heuristics.php';
require FCKMW_ROOT . '/includes/detection/class-file-context.php';
require FCKMW_ROOT . '/includes/detection/interface-layer.php';
require FCKMW_ROOT . '/includes/detection/class-signature-layer.php';
require FCKMW_ROOT . '/includes/detection/class-heuristic-layer.php';

$GLOBALS['fckmw_failures'] = 0;
$GLOBALS['fckmw_checks']   = 0;

function check( bool $ok, string $label ): void {
	$GLOBALS['fckmw_checks']++;
	if ( ! $ok ) {
		$GLOBALS['fckmw_failures']++;
		echo "FAIL: {$label}\n";
	}
}

/** Type of a fixture stored as name.<ext>.fixture. */
function fixture_type( string $path ): string {
	preg_match( '/\.([a-z]+)\.fixture$/', $path, $m );
	$map = array( 'htaccess' => 'htaccess', 'ini' => 'ini' );
	return $map[ $m[1] ] ?? ( \Fckmaleware\Signatures::file_type( 'x.' . $m[1] ) ?? 'php' );
}
