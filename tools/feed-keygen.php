<?php
/**
 * Generate an Ed25519 key pair for signing the detection-update feed.
 *
 * The secret key is written to a file OUTSIDE the repository with 0600
 * permissions; never commit it. Add the printed public key to
 * SignatureUpdater::PUBLIC_KEYS (keep the previous key there during a
 * rotation so sites that have not updated the plugin still verify).
 *
 * Usage: php tools/feed-keygen.php <key-id> <secret-key-output-path>
 */

if ( 3 !== $argc || ! preg_match( '/^[a-z0-9._-]{1,64}$/i', $argv[1] ) ) {
	fwrite( STDERR, "Usage: php tools/feed-keygen.php <key-id> <secret-key-output-path>\n" );
	exit( 2 );
}
$repo   = realpath( dirname( __DIR__ ) );
$target = $argv[2];
$dir    = realpath( dirname( $target ) );
if ( false === $dir ) {
	fwrite( STDERR, "Output directory does not exist.\n" );
	exit( 2 );
}
if ( 0 === strpos( $dir . '/', $repo . '/' ) ) {
	fwrite( STDERR, "Refusing to write the secret key inside the repository.\n" );
	exit( 2 );
}
if ( file_exists( $target ) ) {
	fwrite( STDERR, "Refusing to overwrite an existing key file.\n" );
	exit( 2 );
}

$pair   = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey( $pair );
$public = sodium_crypto_sign_publickey( $pair );

umask( 0077 );
file_put_contents( $target, json_encode( array( 'key_id' => $argv[1], 'secret_key' => base64_encode( $secret ), 'public_key' => base64_encode( $public ) ), JSON_PRETTY_PRINT ) . "\n" );
chmod( $target, 0600 );

echo "Secret key written to {$target} (keep it offline; anyone holding it can push detection updates to every site).\n";
echo "Public key for SignatureUpdater::PUBLIC_KEYS:\n";
echo "  '{$argv[1]}' => '" . base64_encode( $public ) . "',\n";
