<?php
/**
 * Turn voluntary feedback into reviewable proposals (the learning loop).
 *
 * Inputs (any combination):
 *   --bundles=<dir>   Anonymous statistics bundles exported by sites (fckmw-feedback-1 JSON).
 *   --issues=<file>   Reports exported from GitHub, e.g.
 *                     gh issue list --label false-positive,confirmed-malware --state all --json body,labels > issues.json
 *   --clean=<dirs>    Clean corpus for testing any hash candidates.
 *
 * Outputs:
 *   intel/learning/report-<date>.md     Signature effectiveness and proposals.
 *   intel/candidates/<date>-learning.json  Hash candidates (confirmed by 2+ reporters).
 *
 * Nothing is applied automatically: proposals are reviewed, edited into
 * signatures/src by a maintainer, tested, approved and signed like any change.
 */

require __DIR__ . '/lib.php';

$options = getopt( '', array( 'bundles:', 'issues:', 'clean:' ) );
$root    = dirname( __DIR__, 2 );
$db      = json_decode( (string) file_get_contents( $root . '/signatures/signatures.json' ), true );
$known   = array();
foreach ( $db['signatures'] as $sig ) {
	$known[ $sig['id'] ] = $sig;
}

// --- Statistics bundles --------------------------------------------------------
$per_sig   = array();
$reporters = array();
foreach ( glob( rtrim( (string) ( $options['bundles'] ?? '' ), '/' ) . '/*.json' ) ?: array() as $file ) {
	$bundle = json_decode( (string) file_get_contents( $file ), true );
	if ( 'fckmw-feedback-1' !== ( $bundle['format'] ?? '' ) || ! preg_match( '/^[a-f0-9]{16}$/', (string) ( $bundle['reporter'] ?? '' ) ) ) {
		fwrite( STDERR, 'ignored ' . basename( $file ) . ": not a feedback bundle\n" );
		continue;
	}
	if ( isset( $reporters[ $bundle['reporter'] ] ) ) {
		continue; // One bundle per reporter counts.
	}
	$reporters[ $bundle['reporter'] ] = true;
	foreach ( (array) $bundle['signature_stats'] as $id => $counts ) {
		$per_sig[ $id ]          = $per_sig[ $id ] ?? array( 'sites' => 0, 'ignored_sites' => 0, 'open' => 0, 'ignored' => 0, 'quarantined' => 0, 'resolved' => 0 );
		$per_sig[ $id ]['sites']++;
		foreach ( array( 'open', 'ignored', 'quarantined', 'resolved' ) as $status ) {
			$per_sig[ $id ][ $status ] += max( 0, (int) ( $counts[ $status ] ?? 0 ) );
		}
		if ( (int) ( $counts['ignored'] ?? 0 ) > 0 ) {
			$per_sig[ $id ]['ignored_sites']++;
		}
	}
}

// --- Issue reports -------------------------------------------------------------
$fp_reports = array();
$confirmed  = array();
$issues     = isset( $options['issues'] ) ? (array) json_decode( (string) file_get_contents( $options['issues'] ), true ) : array();
foreach ( $issues as $issue ) {
	$body = (string) ( $issue['body'] ?? '' );
	if ( ! preg_match( '/\*\*Detection:\*\* `([A-Z0-9._:-]+)`/', $body, $sig ) ) {
		continue;
	}
	preg_match( '/\*\*SHA-256:\*\* `([a-f0-9]{64})`/', $body, $hash );
	preg_match( '/\*\*Reporter id \(random\):\*\* ([a-f0-9]{16})/', $body, $who );
	preg_match( '/\*\*Component:\*\* (.+)/', $body, $component );
	$reporter = $who[1] ?? md5( $body );
	if ( false !== strpos( $body, '**Report:** false positive' ) ) {
		$fp_reports[ $sig[1] ][ $reporter ] = trim( $component[1] ?? '' );
	} elseif ( false !== strpos( $body, '**Report:** confirmed malware' ) && ! empty( $hash[1] ) ) {
		$confirmed[ $hash[1] ][ $reporter ] = $sig[1];
	}
}

// --- Report --------------------------------------------------------------------
$lines   = array( '# Learning report ' . gmdate( 'Y-m-d' ), '', sprintf( '%d statistics bundles, %d issue reports.', count( $reporters ), count( $issues ) ), '' );
$lines[] = '## Signature effectiveness';
$lines[] = '';
$lines[] = '| Signature | Sites | Ignored | Quarantined | Resolved | Ignore rate | Proposal |';
$lines[] = '|---|---|---|---|---|---|---|';
ksort( $per_sig );
foreach ( $per_sig as $id => $s ) {
	$acted    = $s['ignored'] + $s['quarantined'] + $s['resolved'];
	$rate     = $acted ? $s['ignored'] / $acted : 0;
	$proposal = '';
	if ( $s['ignored_sites'] >= 3 && $rate >= 0.5 ) {
		$current  = (int) ( $known[ $id ]['confidence'] ?? 0 );
		$proposal = sprintf( 'review: lower confidence %d → %d or narrow the pattern', $current, max( 30, $current - 20 ) );
	}
	$lines[] = sprintf( '| `%s` | %d | %d | %d | %d | %d%% | %s |', $id, $s['sites'], $s['ignored'], $s['quarantined'], $s['resolved'], round( $rate * 100 ), $proposal );
}
$lines[] = '';
$lines[] = '## False-positive reports';
$lines[] = '';
foreach ( $fp_reports as $id => $by ) {
	$lines[] = sprintf( '- `%s`: %d reporters (%s)', $id, count( $by ), implode( '; ', array_unique( array_values( $by ) ) ) );
}
if ( ! $fp_reports ) {
	$lines[] = 'None.';
}

// --- Hash candidates from independent confirmations -----------------------------
$hash_sigs = array();
foreach ( $confirmed as $hash => $by ) {
	if ( count( $by ) < 2 ) {
		continue; // A single report is not enough to ship a detection to every site.
	}
	$hash_sigs[] = array(
		'id'          => 'FMW-CF-' . strtoupper( substr( $hash, 0, 12 ) ),
		'name'        => 'Malware confirmed by multiple FCK Malware users',
		'family'      => 'Known.CommunityConfirmed',
		'category'    => 'known-sample',
		'technique'   => 'hash',
		'severity'    => 'critical',
		'confidence'  => 90,
		'targets'     => array( 'any' ),
		'sha256'      => array( $hash ),
		'description' => sprintf( 'File hash reported as malware by %d independent sites (detections: %s).', count( $by ), implode( ', ', array_unique( $by ) ) ),
		'remediation' => 'quarantine',
	) + IntelPipeline::meta( 'FCK Malware community reports', 'GPL-3.0-or-later' );
}
$lines[] = '';
$lines[] = '## Hash candidates';
$lines[] = '';
$lines[] = $hash_sigs ? sprintf( '%d hashes confirmed by 2+ reporters were written as candidates.', count( $hash_sigs ) ) : 'None (a hash needs reports from at least two independent sites).';

@mkdir( $root . '/intel/learning', 0755, true );
$report = $root . '/intel/learning/report-' . gmdate( 'Y-m-d' ) . '.md';
file_put_contents( $report, implode( "\n", $lines ) . "\n" );
echo 'Report: ' . substr( $report, strlen( $root ) + 1 ) . "\n";

if ( $hash_sigs ) {
	$clean = array_filter( array_map( 'realpath', explode( ',', (string) ( $options['clean'] ?? '' ) ) ) );
	if ( ! $clean ) {
		fwrite( STDERR, "Hash candidates need --clean=<dirs> for testing; not written.\n" );
		exit( 1 );
	}
	$result = ( new IntelPipeline( $root, $clean ) )->process( 'learning', $hash_sigs );
	printf( "Hash candidates: %d pending, %d rejected -> %s\n", $result['pending'], $result['rejected'], substr( $result['file'], strlen( $root ) + 1 ) );
}
