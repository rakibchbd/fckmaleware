<?php
/**
 * Redaction of secrets before excerpts are sent to an external AI provider.
 */

use Fckmaleware\Ai\Redactor;

$samples = array(
	"define( 'DB_PASSWORD', 'hunter2' );"                          => 'hunter2',
	"define('AUTH_KEY', 'x8#k\\'L2p');"                            => 'x8#k',
	'$db_pass = "Sup3rS3cret!";'                                   => 'Sup3rS3cret',
	"'api_key' => 'abcd1234efgh'"                                  => 'abcd1234efgh',
	'$token = \'tok_live_123456789\';'                             => 'tok_live_123456789',
	'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAA'                    => 'AAAAAAAAAAAAAAAA',
	'AKIAIOSFODNN7EXAMPLE'                                         => 'AKIAIOSFODNN7EXAMPLE',
	'ghp_' . str_repeat( 'a', 36 )                                 => 'ghp_aaaa',
	'https://user:pa55@example.com/x'                              => 'pa55',
	'contact admin@victim-site.com now'                            => 'admin@victim-site.com',
	"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----" => 'MIIabc',
	'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' => 'eyJzdWIi',
);
foreach ( $samples as $input => $secret ) {
	check( false === strpos( Redactor::redact( $input ), $secret ), 'redacted: ' . substr( $input, 0, 40 ) );
}

// Code that matters for the verdict survives redaction.
$code = '<?php $c = $_POST["c"]; eval(base64_decode($c));';
check( Redactor::redact( $code ) === $code, 'malicious logic is not altered by redaction' );

check( '[ROOT]/wp-content/x.php' === Redactor::anonymize( '/home/acme/public_html/wp-content/x.php', array( '/home/acme/public_html' => '[ROOT]' ) ), 'paths anonymized' );
