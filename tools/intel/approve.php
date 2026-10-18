<?php
/**
 * Approve reviewed candidates into the signature sources (the human step).
 *
 * Usage:
 *   php tools/intel/approve.php intel/candidates/<file>.json --ids=ID1,ID2 --reviewer="Name"
 *   php tools/intel/approve.php intel/candidates/<file>.json --all --reviewer="Name"
 *
 * Only "pending" candidates with zero clean-corpus hits are accepted; each is
 * re-validated (schema, compilation, ReDoS probes). Approved signatures go to
 * signatures/src/approved/<candidate file name>. Then:
 *
 *   php tools/build-signatures.php && php tests/run.php
 *   php tools/feed-publish.php --key=<secret key file>
 *
 * Rolling back an approval: delete the signatures from the approved file,
 * rebuild and publish; the feed version moves forward without them.
 */

require __DIR__ . '/lib.php';

use Fckmaleware\Signatures;

// Parsed by hand: getopt() stops at the first non-option argument, which
// made "approve.php <file> --all ..." (the documented order) ignore options.
$file    = '';
$options = array();
foreach ( array_slice( $argv, 1 ) as $arg ) {
	if ( preg_match( '/^--(ids|reviewer)=(.*)$/s', $arg, $m ) ) {
		$options[ $m[1] ] = $m[2];
	} elseif ( '--all' === $arg ) {
		$options['all'] = true;
	} elseif ( '' === $file ) {
		$file = $arg;
	}
}
if ( ! is_readable( $file ) || ( empty( $options['ids'] ) && ! isset( $options['all'] ) ) || empty( $options['reviewer'] ) ) {
	fwrite( STDERR, "Usage: php tools/intel/approve.php <candidate file> (--ids=A,B | --all) --reviewer=<name>\n" );
	exit( 2 );
}
$root      = dirname( __DIR__, 2 );
$data      = json_decode( (string) file_get_contents( $file ), true );
$wanted    = isset( $options['all'] ) ? null : array_map( 'trim', explode( ',', $options['ids'] ) );
$target    = $root . '/signatures/src/approved/' . basename( $file );
$approved  = is_readable( $target ) ? (array) json_decode( (string) file_get_contents( $target ), true )['signatures'] : array();
$existing  = array_column( (array) json_decode( (string) file_get_contents( $root . '/signatures/signatures.json' ), true )['signatures'], 'id' );
$existing  = array_flip( array_merge( $existing, array_column( $approved, 'id' ) ) );
$count     = 0;

foreach ( $data['candidates'] as &$candidate ) {
	$sig = $candidate['signature'];
	if ( null !== $wanted && ! in_array( $sig['id'], $wanted, true ) ) {
		continue;
	}
	if ( 'pending' !== $candidate['status'] ) {
		echo "skip {$sig['id']}: status {$candidate['status']}" . ( $candidate['reason'] ? " ({$candidate['reason']})" : '' ) . "\n";
		continue;
	}
	if ( ! empty( $candidate['tests']['clean_hits'] ) ) {
		echo "skip {$sig['id']}: matched the clean corpus\n";
		continue;
	}
	$error = Signatures::check( Signatures::normalize( $sig ) ) ?? ( 'regex' === $sig['technique'] ? Signatures::check_regex_performance( $sig['pattern'] ) : null );
	if ( null !== $error ) {
		echo "skip {$sig['id']}: {$error}\n";
		continue;
	}
	if ( isset( $existing[ $sig['id'] ] ) ) {
		echo "skip {$sig['id']}: already in the database\n";
		continue;
	}
	$approved[]               = $sig;
	$existing[ $sig['id'] ]   = true;
	$candidate['status']      = 'approved';
	$candidate['approved_by'] = (string) $options['reviewer'];
	$candidate['approved_at'] = gmdate( 'c' );
	$count++;
}
unset( $candidate );

if ( $count ) {
	@mkdir( dirname( $target ), 0755, true );
	file_put_contents( $target, json_encode( array( 'source' => $data['source'], 'signatures' => $approved ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
	file_put_contents( $file, json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
}
echo "{$count} approved into " . substr( $target, strlen( $root ) + 1 ) . "\n";
if ( $count ) {
	echo "Next: php tools/build-signatures.php && php tests/run.php && php tools/feed-publish.php --key=<secret key file>\n";
}
