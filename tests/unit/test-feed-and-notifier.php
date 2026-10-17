<?php
/**
 * Signed feed verification and webhook address safety.
 */

use Fckmaleware\Feed;
use Fckmaleware\Notifier;

$pair   = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey( $pair );
$keys   = array( 'k1' => base64_encode( sodium_crypto_sign_publickey( $pair ) ) );
$body   = '{"schema":1}';
$sig    = Feed::sign( $body, $secret, 'k1' );

check( 'k1' === Feed::verify( $body, $sig, $keys ), 'valid signature verifies' );
check( null === Feed::verify( $body . ' ', $sig, $keys ), 'modified manifest fails' );
check( null === Feed::verify( $body, str_replace( 'k1:', 'k2:', $sig ), $keys ), 'unknown key id fails' );
check( null === Feed::verify( $body, 'k1:' . base64_encode( str_repeat( "\0", 64 ) ), $keys ), 'forged signature fails' );
check( null === Feed::verify( $body, 'garbage', $keys ), 'malformed signature line fails' );

$now      = time();
$manifest = array(
	'schema'     => 1,
	'expires'    => gmdate( 'c', $now + 3600 ),
	'signatures' => array( 'version' => '2026.10.18.1', 'file' => 'db.json', 'sha256' => str_repeat( 'a', 64 ), 'size' => 100, 'db_schema' => 2, 'min_plugin' => '0.9.0' ),
);
check( array() === Feed::check_manifest( $manifest, '2026.10.17.4', '0.9.0', $now ), 'acceptable manifest passes' );
check( (bool) Feed::check_manifest( array_replace( $manifest, array( 'expires' => gmdate( 'c', $now - 1 ) ) ), '2026.10.17.4', '0.9.0', $now ), 'expired manifest rejected' );
check( (bool) Feed::check_manifest( array_replace_recursive( $manifest, array( 'signatures' => array( 'file' => '../x.json' ) ) ), '2026.10.17.4', '0.9.0', $now ), 'path in file name rejected' );
check( (bool) Feed::check_manifest( array_replace_recursive( $manifest, array( 'signatures' => array( 'min_plugin' => '9.0.0' ) ) ), '2026.10.17.4', '0.9.0', $now ), 'newer plugin requirement rejected' );
check( (bool) Feed::check_manifest( array_replace_recursive( $manifest, array( 'signatures' => array( 'db_schema' => 99 ) ) ), '2026.10.17.4', '0.9.0', $now ), 'future database schema rejected' );
check( Feed::is_newer( '2026.10.17.5', '2026.10.17.4' ) && Feed::is_newer( '2026.10.18', '2026.10.17.9' ) && ! Feed::is_newer( '2026.10.17', '2026.10.17.1' ), 'version ordering' );
check( ! Feed::is_newer( 'latest', '2026.01.01' ), 'non-date version never newer' );

foreach ( array( 'https://10.1.2.3/', 'https://172.16.0.1/', 'https://192.168.0.1/', 'https://127.0.0.1/', 'https://169.254.169.254/', 'https://100.64.0.1/', 'https://[::1]/', 'https://[fd00::1]/', 'https://0.0.0.0/' ) as $url ) {
	check( ! Notifier::is_public_url( $url ), "webhook to {$url} refused" );
}
check( Notifier::is_public_url( 'https://8.8.8.8/hook' ), 'public IP allowed' );
