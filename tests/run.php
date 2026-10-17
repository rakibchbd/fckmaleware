<?php
/**
 * Standalone test runner (no WordPress, no Composer).
 *
 * Usage: php tests/run.php [filter]
 *
 * Runs every tests/unit/test-*.php file. Malicious samples and fixtures are
 * inert data that is read and matched, never executed.
 */

require __DIR__ . '/bootstrap.php';

$filter = $argv[1] ?? '';
foreach ( glob( __DIR__ . '/unit/test-*.php' ) as $file ) {
	if ( '' !== $filter && false === strpos( basename( $file ), $filter ) ) {
		continue;
	}
	$before = $GLOBALS['fckmw_failures'];
	require $file;
	printf( "%-32s %s\n", basename( $file, '.php' ), $GLOBALS['fckmw_failures'] === $before ? 'ok' : 'FAILED' );
}

$failures = $GLOBALS['fckmw_failures'];
$checks   = $GLOBALS['fckmw_checks'];
echo $failures ? "\n{$failures} of {$checks} checks failed.\n" : "\nAll {$checks} checks passed.\n";
exit( $failures ? 1 : 0 );
