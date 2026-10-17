<?php
/**
 * List candidates awaiting review.
 *
 * Usage: php tools/intel/review.php [intel/candidates/<file>.json] [--rejected]
 */

$root    = dirname( __DIR__, 2 );
$files   = isset( $argv[1] ) && '--rejected' !== $argv[1] ? array( $argv[1] ) : ( glob( $root . '/intel/candidates/*.json' ) ?: array() );
$rejects = in_array( '--rejected', $argv, true );

foreach ( $files as $file ) {
	$data = json_decode( (string) file_get_contents( $file ), true );
	$rows = array_filter(
		(array) $data['candidates'],
		static function ( $c ) use ( $rejects ) {
			return $rejects ? 'rejected' === $c['status'] : 'pending' === $c['status'];
		}
	);
	if ( ! $rows ) {
		continue;
	}
	echo '== ' . basename( $file ) . ' (' . count( $rows ) . ( $rejects ? ' rejected' : ' pending' ) . ")\n";
	foreach ( $rows as $c ) {
		$sig = $c['signature'];
		printf( "%-48s %-9s conf %3d  fixtures %d  %s\n", $sig['id'], $sig['severity'], $sig['confidence'], (int) ( $c['tests']['fixture_hits'] ?? 0 ), $sig['name'] );
		if ( $rejects ) {
			echo "    reason: {$c['reason']}\n";
		} elseif ( 'regex' === $sig['technique'] ) {
			echo '    ' . substr( $sig['pattern'], 0, 160 ) . ( strlen( $sig['pattern'] ) > 160 ? '…' : '' ) . "\n";
		}
	}
}
