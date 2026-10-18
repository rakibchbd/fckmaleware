<?php
/**
 * 1.1 policy functions: upload rules, blocking policy, classification,
 * exclusion parsing, CSV neutralization and secret encryption.
 */

use Fckmaleware\Admin\Actions;
use Fckmaleware\Findings;
use Fckmaleware\Monitor;
use Fckmaleware\Secrets;
use Fckmaleware\Settings;
use Fckmaleware\Signatures;

// Dangerous upload names.
foreach ( array( 'shell.php', 'SHELL.PHP', 'photo.php.jpg', 'a.phtml', 'x.phar', 'run.cgi', 'x.pl', 'x.py', 'page.asp', 'page.aspx', 'x.jsp', 'install.sh', 'x.php7', 'x.shtml', '.htaccess', '.user.ini', 'web.config' ) as $name ) {
	check( Monitor::is_dangerous_name( $name ), "dangerous upload name: {$name}" );
}
foreach ( array( 'photo.jpg', 'report.pdf', 'archive.zip', 'phpinfo.txt', 'my-php-notes.docx', 'video.mp4', 'style.css' ) as $name ) {
	check( ! Monitor::is_dangerous_name( $name ), "harmless upload name: {$name}" );
}
check( Monitor::is_image_name( 'a.JPG' ) && Monitor::is_image_name( 'b.webp' ), 'image extensions recognised' );
check( ! Monitor::is_image_name( 'a.txt' ) && ! Monitor::is_image_name( 'a.svg' ) && ! Monitor::is_image_name( 'jpg' ), 'non-images are not images' );

// Blocking policy.
$mal  = array( 'verdict' => 'malicious', 'confidence' => 90 );
$low  = array( 'verdict' => 'malicious', 'confidence' => 70 );
$susp = array( 'verdict' => 'suspicious', 'confidence' => 65 );
check( null !== Monitor::blocking_detection( array( $mal ), 'malicious', 80 ), 'malicious at threshold blocks' );
check( null === Monitor::blocking_detection( array( $low ), 'malicious', 80 ), 'malicious below threshold does not block' );
check( null === Monitor::blocking_detection( array( $susp ), 'malicious', 80 ), 'suspicious does not block in malicious mode' );
check( null !== Monitor::blocking_detection( array( $susp ), 'strict', 80 ), 'suspicious blocks in strict mode' );
check( null === Monitor::blocking_detection( array( $mal ), 'monitor', 80 ), 'monitor mode never blocks' );
check( null === Monitor::blocking_detection( array(), 'strict', 50 ), 'no detection, no block' );

// Classification never turns suspicion into "confirmed".
check( 'confirmed' === Findings::classify( array( 'verdict' => 'malicious', 'confidence' => 95, 'source' => 'signature' ) ), 'high-confidence signature is confirmed' );
check( 'confirmed' === Findings::classify( array( 'verdict' => 'malicious', 'confidence' => 90, 'source' => 'imunify' ) ), 'server scanner detection is confirmed' );
check( 'likely' === Findings::classify( array( 'verdict' => 'malicious', 'confidence' => 98, 'source' => 'heuristic' ) ), 'heuristic is never "confirmed"' );
check( 'likely' === Findings::classify( array( 'verdict' => 'malicious', 'confidence' => 80, 'source' => 'signature' ) ), 'lower-confidence signature is likely' );
check( 'suspicious' === Findings::classify( array( 'verdict' => 'suspicious', 'confidence' => 99, 'source' => 'signature' ) ), 'suspicious stays suspicious' );
check( 'change' === Findings::classify( array( 'verdict' => 'suspicious', 'confidence' => 70, 'source' => 'integrity' ) ), 'integrity difference is an unverified change' );

// Exclusion parsing.
check( array( 'wp-content/cache', 'wp-content/backups' ) === Settings::parse_paths( "wp-content/cache\r\n/wp-content/backups/\n\n" ), 'exclusions are normalised' );
check( array() === Settings::parse_paths( "../etc\nwp-content/../../x\nC:/Windows\nfoo\0bar\nwp-content/<script>" ), 'traversal, drive letters, NUL and odd characters are dropped' );

// CSV formula injection.
foreach ( array( '=HYPERLINK("x")', '+1', '-1', '@A1', "\t=1", "\r=1", ' =1', '|cmd' ) as $value ) {
	check( "'" === substr( Actions::csv_cell( $value ), 0, 1 ), 'CSV formula neutralised: ' . json_encode( $value ) );
}
foreach ( array( 'wp-content/a.php', 'Eval of decoded payload', '42' ) as $value ) {
	check( $value === Actions::csv_cell( $value ), "CSV plain value kept: {$value}" );
}

// Secret encryption.
if ( function_exists( 'sodium_crypto_secretbox' ) ) {
	$sealed = Secrets::encrypt( 'sk-ant-secret' );
	check( Secrets::is_encrypted( $sealed ) && false === strpos( $sealed, 'sk-ant-secret' ), 'secret is sealed' );
	check( 'sk-ant-secret' === Secrets::decrypt( $sealed ), 'sealed secret round-trips' );
	check( $sealed !== Secrets::encrypt( 'sk-ant-secret' ), 'each encryption uses a fresh nonce' );
	check( 'plain-legacy' === Secrets::decrypt( 'plain-legacy' ), 'legacy plain values are still read' );
	check( '' === Secrets::decrypt( 'fckmw-enc:v1:' . base64_encode( str_repeat( 'x', 40 ) ) ), 'tampered ciphertext reads as empty' );
	check( '' === Secrets::encrypt( '' ), 'empty secret stays empty' );
}

// Prefilter derivation: only provably necessary literals, otherwise none.
check( array( 'evil_marker' ) === Signatures::derive_prefilter( '~(?:evil_marker)~i' ), 'prefilter for a plain literal' );
check( array( 'alpha-one', 'beta two' ) === Signatures::derive_prefilter( '~(?:alpha\-one|beta two)~' ), 'prefilter for one-of literals' );
check( array( 'longer literal' ) === Signatures::derive_prefilter( '~\A(?=[\s\S]*?abcd)(?=[\s\S]*?longer literal)~' ), 'prefilter keeps the longest literal of an all-of branch' );
check( array( '$x = 1' ) === Signatures::derive_prefilter( '~(?:(?<![A-Za-z0-9_])\$x \= 1(?![A-Za-z0-9_]))~' ), 'word-boundary lookarounds are allowed' );
check( array() === Signatures::derive_prefilter( '~eval\s*\(~i' ), 'no prefilter when a branch uses \s' );
check( array() === Signatures::derive_prefilter( '~(?:abcd|ef[gh]ij)~' ), 'no prefilter when any branch has a character class' );
check( array() === Signatures::derive_prefilter( '~(?:abcd|x)~' ), 'no prefilter when a branch literal is too short' );
check( array() === Signatures::derive_prefilter( '~abcd~x' ), 'no prefilter with the x modifier' );
$db = new Signatures( array( 'version' => '1', 'signatures' => array( array( 'id' => 'T-PF', 'pattern' => '~needle\s*here~i', 'targets' => array( 'php' ), 'prefilter' => array( 'needle' ) ) ) ) );
check( 1 === count( $db->match( 'xx NEEDLE   here', 'php' ) ), 'prefilter is case-insensitive and lets matches through' );
check( 0 === count( $db->match( 'nothing to see', 'php' ) ), 'prefilter skips files without the literal' );
