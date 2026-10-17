<?php
/**
 * Imunify360 agent JSON normalisation.
 */

use Fckmaleware\Imunify;

// Imunify JSON normalisation.
$root = '/home/site/public_html';
$data = array(
	'items' => array(
		array( 'file' => '/home/site/public_html/wp-content/uploads/x.php', 'type' => 'SMW-INJ-04174-bkdr', 'status' => 'found' ),
		array( 'file' => '/home/other/public_html/evil.php', 'type' => 'SMW-1', 'status' => 'found' ),
		array( 'path' => '/home/site/public_html/index.php', 'signature' => 'SMW-2' ),
		'garbage',
	),
);
$norm = Imunify::normalize_malicious( $data, $root );
check( 2 === count( $norm ), 'imunify: only files under the site root are kept' );
check( 'wp-content/uploads/x.php' === $norm[0]['file'] && 'SMW-INJ-04174-bkdr' === $norm[0]['signature'], 'imunify: file made relative, type used as signature' );
check( 'index.php' === $norm[1]['file'] && 'SMW-2' === $norm[1]['signature'], 'imunify: path/signature fallbacks' );
check( 1 === count( Imunify::normalize_malicious( array( 'data' => array( 'items' => array( $data['items'][0] ) ) ), $root ) ), 'imunify: nested data.items envelope' );
check( array() === Imunify::normalize_malicious( array( 'items' => array( array( 'file' => '/home/site/public_html_old/x.php' ) ) ), $root ), 'imunify: sibling directory with same prefix is excluded' );

