<?php
/**
 * Regression corpus: every malware fixture must be detected (signature or
 * heuristic, at any verdict) and no clean fixture may be flagged.
 */

use Fckmaleware\Detection\FileContext;
use Fckmaleware\Detection\HeuristicLayer;
use Fckmaleware\Detection\SignatureLayer;
use Fckmaleware\Signatures;

$sigs   = Signatures::from_file( FCKMW_ROOT . '/signatures/signatures.json' );
$layers = array( new SignatureLayer( $sigs ), new HeuristicLayer( 60 ) );

$detect = static function ( string $path ) use ( $layers ): array {
	$file = FileContext::from_string( basename( $path ), (string) file_get_contents( $path ), fixture_type( $path ) );
	$out  = array();
	foreach ( $layers as $layer ) {
		foreach ( $layer->inspect( $file ) as $detection ) {
			$out[] = $detection;
		}
	}
	return $out;
};

$malware = glob( FCKMW_ROOT . '/tests/fixtures/malware/*.fixture' );
$clean   = glob( FCKMW_ROOT . '/tests/fixtures/clean/*.fixture' );
check( count( $malware ) >= 25, 'malware fixture corpus present' );
check( count( $clean ) >= 10, 'clean fixture corpus present' );

$strong = 0;
foreach ( $malware as $path ) {
	$detections = $detect( $path );
	check( (bool) $detections, 'malware fixture detected: ' . basename( $path ) );
	foreach ( $detections as $d ) {
		if ( 'malicious' === $d['verdict'] ) {
			$strong++;
			break;
		}
	}
}
// Most fixtures should reach a "malicious" verdict, not only "suspicious".
check( $strong >= count( $malware ) - 3, "malicious verdict on at least all-but-3 fixtures ({$strong}/" . count( $malware ) . ')' );

foreach ( $clean as $path ) {
	$detections = $detect( $path );
	$ids        = array_column( $detections, 'signature_id' );
	check( ! $detections, 'clean fixture not flagged: ' . basename( $path ) . ' (got: ' . implode( ',', $ids ) . ')' );
}
