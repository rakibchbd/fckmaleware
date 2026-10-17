<?php
/**
 * Regenerates signatures/signatures.json from the definitions below.
 *
 * Patterns are written here as PHP strings so regex escaping stays readable;
 * the JSON file is what the plugin loads at runtime.
 *
 * Usage: php tools/build-signatures.php
 */

$signatures = [
	// --- PHP backdoors and obfuscation -------------------------------------
	[
		'id'          => 'FMW-PHP-001',
		'name'        => 'Eval of decoded payload',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(~i',
		'description' => 'Executes code that is decoded at runtime, the most common backdoor loader.',
	],
	[
		'id'          => 'FMW-PHP-002',
		'name'        => 'Nested decoder chain',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*@?\s*(?:base64_decode|str_rot13|gzinflate|strrev)\s*\(~i',
		'description' => 'Multiple stacked decoders, typical of packed malware payloads.',
	],
	[
		'id'          => 'FMW-PHP-003',
		'name'        => 'Code or command execution from request input',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b~i',
		'description' => 'Passes attacker-controlled request data straight to an execution function.',
	],
	[
		'id'          => 'FMW-PHP-004',
		'name'        => 'Function name taken from request input',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(~i',
		'description' => 'Calls a function whose name comes from the request, e.g. $_GET["f"]($_GET["c"]).',
	],
	[
		'id'          => 'FMW-PHP-005',
		'name'        => 'preg_replace with /e modifier',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~preg_replace\s*\(\s*([\'"])([^\w\s\\\\]).{0,200}?\2[a-df-zA-Z]*e[a-zA-Z]*\1\s*,~',
		'description' => 'The /e modifier evaluates the replacement as PHP code.',
	],
	[
		'id'          => 'FMW-PHP-006',
		'name'        => 'create_function with request input',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~\bcreate_function\s*\([^)]{0,100}\$_(?:GET|POST|REQUEST|COOKIE)~i',
		'description' => 'Builds a function from request data.',
	],
	[
		'id'          => 'FMW-PHP-007',
		'name'        => 'Known web shell marker',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~(?:\bFilesMan\b|\bWSO\s+[0-9]+\.[0-9]+|\bc99shell\b|\br57shell\b|\bb374k\b|\bIndoXploit\b|\bAnonymousFox\b|\bAlfa[\s_-]?(?:Shell|Team)\b|<title>\s*Mini\s*Shell)~i',
		'description' => 'Strings found in widely distributed PHP web shells.',
	],
	[
		'id'          => 'FMW-PHP-008',
		'name'        => 'Hex-encoded include path',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~@?\b(?:include|require)(?:_once)?\s*\(?\s*["\'](?:[^"\'\\\\\n]{0,12}\\\\x[0-9a-f]{2}){6,}~i',
		'description' => 'Includes a file whose path is hidden with \\x escapes; a classic WordPress injection.',
	],
	[
		'id'          => 'FMW-PHP-009',
		'name'        => 'Obfuscated $GLOBALS access',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~\$GLOBALS\s*\[\s*["\'](?:\\\\x[0-9a-f]{2}){3,}~i',
		'description' => 'Global variable names hidden with \\x escapes.',
	],
	[
		'id'          => 'FMW-PHP-010',
		'name'        => 'Long chr() concatenation chain',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~(?:\bchr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){12,}~i',
		'description' => 'Builds strings one character at a time to hide function names or URLs.',
	],
	[
		'id'          => 'FMW-PHP-011',
		'name'        => 'Large embedded base64 blob',
		'severity'    => 'medium',
		'targets'     => [ 'php' ],
		'pattern'     => '~["\'][A-Za-z0-9+/]{2000,}={0,2}["\']~',
		'description' => 'A very long base64 string literal; often a packed payload.',
	],
	[
		'id'          => 'FMW-PHP-012',
		'name'        => 'Eval of remotely fetched code',
		'severity'    => 'critical',
		'targets'     => [ 'php' ],
		'pattern'     => '~\b(?:eval|assert)\s*\(\s*@?\s*(?:file_get_contents|wp_remote_retrieve_body|curl_exec|stream_get_contents)\s*\(~i',
		'description' => 'Downloads code and executes it.',
	],
	[
		'id'          => 'FMW-PHP-013',
		'name'        => 'Writes request data to a file',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)~i',
		'description' => 'Typical uploader/dropper behaviour.',
	],
	[
		'id'          => 'FMW-PHP-014',
		'name'        => 'Creates an administrator account',
		'severity'    => 'medium',
		'targets'     => [ 'php' ],
		'pattern'     => '~\bwp_(?:create|insert)_user\s*\([^;]{0,300}[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"]~is',
		'description' => 'Programmatic admin creation; legitimate in installers, common in backdoors.',
	],
	[
		'id'          => 'FMW-PHP-015',
		'name'        => 'Long hex-escaped string',
		'severity'    => 'medium',
		'targets'     => [ 'php' ],
		'pattern'     => '~(?:\\\\x[0-9a-fA-F]{2}){40,}~',
		'description' => 'A long run of \\x escapes, used to hide code.',
	],
	[
		'id'          => 'FMW-PHP-016',
		'name'        => 'Injected PHP comment header',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~/\*\s*<\?php\s*/\*\*/~',
		'description' => 'The "/*<?php /**/" prefix used by mass WordPress infections.',
	],
	[
		'id'          => 'FMW-PHP-017',
		'name'        => 'Reversed dangerous function name',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~[\'"](?:edoced_46esab|etalfnizg|sserpmocnuzg|lave|tressa|metsys|cexe_llehs|urhtssap)[\'"]~i',
		'description' => 'Function names written backwards for use with strrev().',
	],
	[
		'id'          => 'FMW-PHP-018',
		'name'        => 'Upload to request-supplied path',
		'severity'    => 'high',
		'targets'     => [ 'php' ],
		'pattern'     => '~\bmove_uploaded_file\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)~i',
		'description' => 'Lets the requester choose where an uploaded file is written.',
	],

	// --- JavaScript injections ---------------------------------------------
	[
		'id'          => 'FMW-JS-001',
		'name'        => 'Eval of decoded script',
		'severity'    => 'high',
		'targets'     => [ 'js', 'html', 'php' ],
		'pattern'     => '~\beval\s*\(\s*(?:unescape|atob|String\.fromCharCode)\s*\(~i',
		'description' => 'Executes script decoded at runtime.',
	],
	[
		'id'          => 'FMW-JS-002',
		'name'        => 'document.write of unescaped payload',
		'severity'    => 'high',
		'targets'     => [ 'js', 'html', 'php' ],
		'pattern'     => '~document\.write\s*\(\s*unescape\s*\(~i',
		'description' => 'Classic injected redirect / iframe loader.',
	],
	[
		'id'          => 'FMW-JS-003',
		'name'        => 'Long String.fromCharCode sequence',
		'severity'    => 'medium',
		'targets'     => [ 'js', 'html', 'php' ],
		'pattern'     => '~String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){40,}~i',
		'description' => 'Script hidden as character codes.',
	],
	[
		'id'          => 'FMW-JS-004',
		'name'        => 'Known malicious script host or cryptominer',
		'severity'    => 'high',
		'targets'     => [ 'js', 'html', 'php' ],
		'pattern'     => '~(?:coinhive\.com|coin-hive\.com|crypto-loot\.com|cryptoloot\.pro|jsecoin\.com|webminepool\.com|lowerbeforwarden\.ml|dolohen\.com|trasnaltemyrecords\.com|stivenfernando\.com)~i',
		'description' => 'Domains used by browser miners and past WordPress injection campaigns.',
	],

	// --- Server configuration ----------------------------------------------
	[
		'id'          => 'FMW-HTA-001',
		'name'        => 'Search-engine referrer redirect',
		'severity'    => 'high',
		'targets'     => [ 'htaccess' ],
		'pattern'     => '~RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(?:google|bing|yahoo|yandex|baidu)[^\n]*\n(?:\s*RewriteCond[^\n]*\n)*\s*RewriteRule\s+[^\n]*https?://~i',
		'description' => 'Redirects visitors arriving from search engines to an external site (SEO spam).',
	],
	[
		'id'          => 'FMW-HTA-002',
		'name'        => 'PHP handler for non-PHP extension',
		'severity'    => 'high',
		'targets'     => [ 'htaccess' ],
		'pattern'     => '~\b(?:AddHandler|AddType)\s+\S*php\S*\s+[^\n]*\.(?:jpe?g|png|gif|ico|txt|css|js)\b~i',
		'description' => 'Makes images or text files executable as PHP.',
	],
	[
		'id'          => 'FMW-CFG-001',
		'name'        => 'auto_prepend/append_file directive',
		'severity'    => 'medium',
		'targets'     => [ 'htaccess', 'ini' ],
		'pattern'     => '~\bauto_(?:prepend|append)_file\b~i',
		'description' => 'Loads a file before/after every PHP request; used by security tools and by malware.',
	],

	// --- Payloads hidden in images -----------------------------------------
	[
		'id'          => 'FMW-IMG-001',
		'name'        => 'PHP code inside image file',
		'severity'    => 'high',
		'targets'     => [ 'image' ],
		'pattern'     => '~<\?php|<\?=\s*\$|\beval\s*\(|\bbase64_decode\s*\(~i',
		'description' => 'Image or icon files that contain PHP, usually loaded via include.',
	],
];

$out = [
	'version'    => gmdate( 'Y.m.d' ),
	'signatures' => $signatures,
];

foreach ( $signatures as $sig ) {
	if ( false === @preg_match( $sig['pattern'], '' ) ) {
		fwrite( STDERR, "Invalid pattern in {$sig['id']}\n" );
		exit( 1 );
	}
}

$target = dirname( __DIR__ ) . '/signatures/signatures.json';
file_put_contents( $target, json_encode( $out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
echo 'Wrote ' . count( $signatures ) . " signatures to signatures/signatures.json\n";
