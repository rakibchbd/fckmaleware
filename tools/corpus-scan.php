<?php
/**
 * Run the signature and heuristic layers over a directory tree without WordPress.
 *
 * Used to measure false positives on clean code (WordPress core, popular
 * plugins and themes) and detection on the malware fixture corpus. Files are
 * only read; nothing is included or executed.
 *
 * Usage:
 *   php tools/corpus-scan.php [--threshold=60] [--json] [--min-confidence=0] <dir> [<dir> ...]
 *
 * Exit status: 0 always; parse the output (or --json) to assert expectations.
 */

require dirname( __DIR__ ) . '/includes/class-signatures.php';
require dirname( __DIR__ ) . '/includes/detection/class-heuristics.php';

use Fckmaleware\Detection\Heuristics;
use Fckmaleware\Signatures;

$threshold      = 60;
$min_confidence = 0;
$json           = false;
$dirs           = array();
foreach ( array_slice( $argv, 1 ) as $arg ) {
	if ( 0 === strpos( $arg, '--threshold=' ) ) {
		$threshold = (int) substr( $arg, 12 );
	} elseif ( 0 === strpos( $arg, '--min-confidence=' ) ) {
		$min_confidence = (int) substr( $arg, 17 );
	} elseif ( '--json' === $arg ) {
		$json = true;
	} else {
		$dirs[] = $arg;
	}
}
if ( ! $dirs ) {
	fwrite( STDERR, "Usage: php tools/corpus-scan.php [--threshold=60] [--json] <dir> [<dir> ...]\n" );
	exit( 2 );
}

$sigs    = Signatures::from_file( dirname( __DIR__ ) . '/signatures/signatures.json' );
$files   = 0;
$results = array();
$start   = microtime( true );

foreach ( $dirs as $dir ) {
	$iterator = is_file( $dir ) ? array( new SplFileInfo( $dir ) ) : new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
	foreach ( $iterator as $item ) {
		if ( ! $item->isFile() || $item->isLink() || $item->getSize() > 4 * 1048576 ) {
			continue;
		}
		$path = $item->getPathname();
		$type = Signatures::file_type( $path );
		if ( null === $type && preg_match( '/\.([a-z]+)\.fixture$/', $path, $fixture ) ) {
			// Fixtures are stored as name.<ext>.fixture so they are never served or executed.
			$type = array( 'htaccess' => 'htaccess', 'ini' => 'ini' )[ $fixture[1] ] ?? Signatures::file_type( 'x.' . $fixture[1] );
		}
		if ( null === $type ) {
			continue;
		}
		$files++;
		$content = (string) file_get_contents( $path );
		$hits    = array();

		foreach ( $sigs->match( $content, $type ) as $match ) {
			if ( $match['signature']['confidence'] >= $min_confidence ) {
				$hits[] = array(
					'layer'      => 'signature',
					'id'         => $match['signature']['id'],
					'confidence' => $match['signature']['confidence'],
					'line'       => $match['line'],
				);
			}
		}
		if ( 'php' === $type ) {
			$analysis = Heuristics::analyze( $content );
			$class    = Heuristics::classify( $analysis, $threshold );
			if ( $class['report'] ) {
				$hits[] = array(
					'layer'      => 'heuristic',
					'id'         => 'FMW-HEUR-PHP',
					'confidence' => $class['confidence'],
					'line'       => (int) reset( $analysis['indicators'] )['line'],
					'indicators' => array_keys( $analysis['indicators'] ),
				);
			}
		}
		if ( $hits ) {
			$results[ $path ] = $hits;
		}
	}
}

if ( $json ) {
	echo json_encode( array( 'files' => $files, 'flagged' => $results, 'runtime_errors' => $sigs->runtime_errors() ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ), "\n";
	exit( 0 );
}

foreach ( $results as $path => $hits ) {
	foreach ( $hits as $hit ) {
		printf( "%-9s %-14s %3d  %s:%d%s\n", $hit['layer'], $hit['id'], $hit['confidence'], $path, $hit['line'], isset( $hit['indicators'] ) ? '  [' . implode( ',', $hit['indicators'] ) . ']' : '' );
	}
}
printf( "\n%d files scanned, %d flagged, %.1fs\n", $files, count( $results ), microtime( true ) - $start );
if ( $sigs->runtime_errors() ) {
	echo 'PCRE runtime errors: ' . json_encode( $sigs->runtime_errors() ) . "\n";
}
