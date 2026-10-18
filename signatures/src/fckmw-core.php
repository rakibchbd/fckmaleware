<?php
/**
 * Signatures authored by the FCK Malware project.
 *
 * Compiled into signatures/signatures.json by tools/build-signatures.php,
 * which validates every entry (schema, regex compilation, ReDoS timing) and
 * runs the regression corpus before writing.
 *
 * Field reference: docs/SIGNATURES.md.
 *
 * @package Fckmaleware
 */

$project = array(
	'source'  => 'FCK Malware project',
	'license' => 'GPL-3.0-or-later',
	'created' => '2026-10-17',
	'updated' => '2026-10-17',
);

$sig = static function ( array $s ) use ( $project ): array {
	return $s + $project + array(
		'technique'       => 'regex',
		'revision'        => 1,
		'false_positives' => array(),
	);
};

return array(

	// ---------------------------------------------------------------------
	// PHP backdoors, web shells and obfuscation.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-PHP-001',
			'name'        => 'Eval of decoded payload',
			'family'      => 'Generic.Backdoor.EvalDecode',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php', 'db' ),
			'pattern'     => '~\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)\s*\(~i',
			'description' => 'Executes code that is decoded at runtime, the most common backdoor loader.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-002',
			'name'        => 'Nested decoder chain',
			'family'      => 'Generic.Obfuscation.DecoderChain',
			'category'    => 'obfuscation',
			'severity'    => 'high',
			'confidence'  => 70,
			'targets'     => array( 'php', 'db' ),
			'pattern'     => '~\b(?:gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*@?\s*(?:base64_decode|str_rot13|gzinflate|strrev)\s*\(~i',
			'description' => 'Multiple stacked decoders, typical of packed payloads. Some legitimate libraries decompress embedded data, so this is reported as suspicious unless other evidence agrees.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-003',
			'name'        => 'Code or command execution from request input',
			'family'      => 'Generic.Backdoor.RequestExec',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 95,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b~i',
			'description' => 'Passes attacker-controlled request data straight to an execution function.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-004',
			'name'        => 'Function name taken from request input',
			'family'      => 'Generic.Backdoor.VariableFunction',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			// The call must carry an argument or close at once: prose such as
			// "$_GET['folder_id'] (exact match)" in comments is not a call.
			'pattern'     => '~\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*(?:\$|["\'@)]|\d)~i',
			'revision'    => 2,
			'description' => 'Calls a function whose name comes from the request, e.g. $_GET["f"]($_GET["c"]).',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-005',
			'name'        => 'preg_replace with /e modifier',
			'family'      => 'Generic.Backdoor.PregReplaceEval',
			'category'    => 'php-backdoor',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~preg_replace\s*\(\s*([\'"])([^\w\s\\\\]).{0,200}?\2[a-df-zA-Z]*e[a-zA-Z]*\1\s*,~',
			'description' => 'The /e modifier evaluates the replacement as PHP (removed in PHP 7, still used by old backdoors).',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-006',
			'name'        => 'create_function with request input',
			'family'      => 'Generic.Backdoor.CreateFunction',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bcreate_function\s*\([^)]{0,100}\$_(?:GET|POST|REQUEST|COOKIE)~i',
			'description' => 'Builds a function from request data.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-007',
			'name'        => 'Known web shell marker',
			'family'      => 'WebShell.Generic',
			'category'    => 'webshell',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:\bFilesMan\b|\bWSO\s+[0-9]+\.[0-9]+|\bc99shell\b|\br57shell\b|\bb374k\b|\bIndoXploit\b|\bAnonymousFox\b|\bAlfa[\s_-]?(?:Shell|Team)\b|<title>\s*Mini\s*Shell)~i',
			'description' => 'Strings from widely distributed PHP web shells (WSO/FilesMan, c99, r57, b374k, IndoXploit, AnonymousFox, Alfa).',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-008',
			'name'        => 'Hex-encoded include path',
			'family'      => 'WP.Injection.HexInclude',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php', 'db' ),
			'pattern'     => '~@?\b(?:include|require)(?:_once)?\s*\(?\s*["\'](?:[^"\'\\\\\n]{0,12}\\\\x[0-9a-f]{2}){6,}~i',
			'description' => 'Includes a file whose path is hidden with \x escapes; a classic WordPress injection that loads a payload disguised as an image or icon.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-009',
			'name'        => 'Obfuscated $GLOBALS access',
			'family'      => 'Generic.Obfuscation.Globals',
			'category'    => 'obfuscation',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'php' ),
			'pattern'     => '~\$GLOBALS\s*\[\s*["\'](?:\\\\x[0-9a-f]{2}){3,}~i',
			'description' => 'Global variable names hidden with \x escapes.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-010',
			'name'        => 'Long chr() concatenation chain',
			'family'      => 'Generic.Obfuscation.ChrChain',
			'category'    => 'obfuscation',
			'severity'    => 'high',
			'confidence'  => 70,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:\bchr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){12,}~i',
			'description' => 'Builds strings one character at a time to hide function names or URLs.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-011',
			'name'        => 'Large embedded base64 blob',
			'family'      => 'Generic.Obfuscation.Base64Blob',
			'category'    => 'obfuscation',
			'severity'    => 'medium',
			'confidence'  => 40,
			'targets'     => array( 'php' ),
			'pattern'     => '~["\'][A-Za-z0-9+/]{2000,}={0,2}["\']~',
			'description' => 'A very long base64 string literal. Legitimate code embeds fonts and images this way, so this is only a weak indicator.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-012',
			'name'        => 'Eval of remotely fetched code',
			'family'      => 'Generic.Backdoor.RemoteEval',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 95,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:eval|assert)\s*\(\s*@?\s*(?:file_get_contents|wp_remote_retrieve_body|curl_exec|stream_get_contents)\s*\(~i',
			'description' => 'Downloads code and executes it.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-013',
			'name'        => 'Writes request data to a file',
			'family'      => 'Generic.Dropper.RequestWrite',
			'category'    => 'dropper',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)~i',
			'description' => 'Writes attacker-supplied content to disk: typical uploader/dropper behaviour.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-014',
			'name'        => 'Creates an administrator account',
			'family'      => 'WP.Persistence.AdminCreation',
			'category'    => 'persistence',
			'severity'    => 'medium',
			'confidence'  => 45,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bwp_(?:create|insert)_user\s*\([^;]{0,300}[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"]~is',
			'description' => 'Programmatic administrator creation. Legitimate in installers and migration tools; common in backdoors that recreate a deleted admin.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-015',
			'name'        => 'Long hex-escaped string',
			'family'      => 'Generic.Obfuscation.HexString',
			'category'    => 'obfuscation',
			'severity'    => 'low',
			'confidence'  => 40,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:\\\\x[0-9a-fA-F]{2}){40,}~',
			'description' => 'A long run of \x escapes, used to hide code.',
			'revision'    => 2,
			'remediation' => 'review',
			'false_positives' => array(
				array( 'date' => '2026-10-17', 'note' => 'symfony/polyfill-intl-normalizer character tables. Lowered from medium/55 to low/40.' ),
			),
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-016',
			'name'        => 'Injected PHP comment header',
			'family'      => 'WP.Injection.CommentHeader',
			'category'    => 'php-backdoor',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~/\*\s*<\?php\s*/\*\*/~',
			'description' => 'The "/*<?php /**/" prefix used by mass WordPress infections to prepend code to every PHP file.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-017',
			'name'        => 'Reversed dangerous function name',
			'family'      => 'Generic.Obfuscation.Strrev',
			'category'    => 'obfuscation',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~[\'"](?:edoced_46esab|etalfnizg|sserpmocnuzg|lave|tressa|metsys|cexe_llehs|urhtssap)[\'"]~i',
			'description' => 'Function names written backwards for use with strrev().',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-018',
			'name'        => 'Upload to request-supplied path',
			'family'      => 'Generic.Dropper.Uploader',
			'category'    => 'dropper',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bmove_uploaded_file\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)~i',
			'description' => 'Lets the requester choose where an uploaded file is written.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-019',
			'name'        => 'Web shell password hash variable',
			'family'      => 'WebShell.WSO',
			'category'    => 'webshell',
			'severity'    => 'critical',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~\$auth_pass\s*=\s*["\'][a-f0-9]{32}["\']~i',
			'description' => 'The $auth_pass MD5 password variable used by WSO-derived shells.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-020',
			'name'        => 'Request-supplied password gate',
			'family'      => 'Generic.Backdoor.PasswordGate',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:md5|sha1)\s*\(\s*\$_(?:COOKIE|REQUEST|POST|GET)\s*\[[^\]]{1,40}\]\s*\)\s*[!=]==?\s*["\'][a-f0-9]{32,40}["\']~i',
			'description' => 'Compares the hash of a request value with a hard-coded hash: the access check of a password-protected backdoor.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-021',
			'name'        => 'Hides a user from the Users screen',
			'family'      => 'WP.Persistence.HiddenAdmin',
			'category'    => 'persistence',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~[\'"]pre_user_query[\'"][\s\S]{0,600}user_login\s*!=\s*[\'"]~i',
			'description' => 'Filters the user query to hide a specific login, used to conceal a rogue administrator.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-022',
			'name'        => 'Plugin hides itself from the Plugins screen',
			'family'      => 'WP.Persistence.HiddenPlugin',
			'category'    => 'plugin-tampering',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~[\'"]all_plugins[\'"][\s\S]{0,400}unset\s*\(\s*\$\w+\s*\[\s*plugin_basename\s*\(\s*__FILE__~i',
			'description' => 'Removes its own entry from the plugins list so administrators cannot see or deactivate it.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-023',
			'name'        => 'Search-engine cloaked redirect',
			'family'      => 'SEO.Cloaking.Redirect',
			'category'    => 'redirect',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:HTTP_(?:REFERER|USER_AGENT)[\s\S]{0,200}(?:google|bing|yahoo|yandex|bot)|(?:google|bing|yahoo|yandex|bot)[\s\S]{0,200}HTTP_(?:REFERER|USER_AGENT))[\s\S]{0,300}header\s*\(\s*[\'"]Location:\s*https?://~i',
			'description' => 'Redirects visitors to an external site depending on referrer or user agent (cloaking).',
			'revision'    => 2,
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-024',
			'name'        => 'Bot-only remote content (SEO spam)',
			'family'      => 'SEO.Cloaking.RemoteContent',
			'category'    => 'seo-spam',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:googlebot|bingbot|slurp|yandexbot)[\s\S]{0,250}(?:file_get_contents|curl_exec|wp_remote_get)\s*\(\s*["\']https?://~i',
			'description' => 'Serves remote spam content only to search-engine crawlers.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-025',
			'name'        => 'Downloads remote code to disk',
			'family'      => 'Generic.Dropper.RemoteWrite',
			'category'    => 'dropper',
			'severity'    => 'high',
			'confidence'  => 55,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bfile_put_contents\s*\([^;]{0,200}\b(?:file_get_contents|curl_exec)\s*\(\s*["\']https?://[^"\']+\.(?:txt|jpg|png|gif)["\']~i',
			'description' => 'Writes the contents of a remote text/image URL to a local file, a common way to fetch a payload disguised as data.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-026',
			'name'        => 'Eval of closing PHP tag payload',
			'family'      => 'Generic.Backdoor.EvalTag',
			'category'    => 'php-backdoor',
			'severity'    => 'medium',
			'confidence'  => 50,
			'targets'     => array( 'php' ),
			'pattern'     => '~\beval\s*\(\s*["\']\?>~i',
			'description' => 'eval("?>" . $payload) executes an arbitrary PHP document. Template engines (Twig) and code-snippet plugins do this legitimately, so it is reported as suspicious.',
			'revision'    => 2,
			'remediation' => 'review',
			'false_positives' => array(
				array( 'date' => '2026-10-17', 'note' => 'Twig Environment::loadTemplate cache fallback; Code Snippets shortcode rendering. Lowered from critical/90 to medium/50.' ),
			),
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-027',
			'name'        => 'Minimal upload form with move_uploaded_file',
			'family'      => 'WebShell.Uploader',
			'category'    => 'webshell',
			'severity'    => 'medium',
			'confidence'  => 55,
			'targets'     => array( 'php' ),
			'pattern'     => '~enctype=["\']multipart/form-data["\'][\s\S]{0,600}\bmove_uploaded_file\s*\(\s*\$_FILES~i',
			'description' => 'A self-contained upload form that writes the file with move_uploaded_file(): the typical file-uploader shell. WordPress code normally uses wp_handle_upload().',
			'remediation' => 'review',
		)
	),

	$sig(
		array(
			'id'          => 'FMW-PHP-028',
			'name'        => 'Includes an image or icon file as PHP',
			'family'      => 'WP.Injection.ImageInclude',
			'category'    => 'hidden-php',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"\n]{1,300}\.(?:ico|png|jpe?g|gif|bmp|webp)[\'"]~i',
			'description' => 'Loads an image file through include/require. Legitimate code never executes images; this is how payloads hidden in .ico or .png files are activated.',
			'remediation' => 'clean',
		)
	),

	// ---------------------------------------------------------------------
	// JavaScript and HTML injections (files and database content).
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-JS-001',
			'name'        => 'Eval of decoded script',
			'family'      => 'JS.Injection.EvalDecode',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~\beval\s*\(\s*(?:unescape|atob|String\.fromCharCode)\s*\(~i',
			'description' => 'Executes script decoded at runtime.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-002',
			'name'        => 'document.write of unescaped payload',
			'family'      => 'JS.Injection.DocumentWrite',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~document\.write\s*\(\s*unescape\s*\(~i',
			'description' => 'Classic injected redirect / iframe loader.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-003',
			'name'        => 'Long String.fromCharCode sequence',
			'family'      => 'JS.Obfuscation.CharCodes',
			'category'    => 'obfuscation',
			'severity'    => 'medium',
			'confidence'  => 60,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){40,}~i',
			'description' => 'Script hidden as character codes.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-004',
			'name'        => 'Known malicious script host or cryptominer',
			'family'      => 'JS.Injection.KnownHost',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:coinhive\.com|coin-hive\.com|crypto-loot\.com|cryptoloot\.pro|jsecoin\.com|webminepool\.com|lowerbeforwarden\.ml|dolohen\.com|trasnaltemyrecords\.com)~i',
			'description' => 'Browser cryptominer services and domains reported in 2019 WordPress plugin-injection campaigns.',
			'source'      => 'FCK Malware project; domains from public incident write-ups (browser miners; 2019 WordPress plugin-injection campaigns)',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-005',
			'name'        => 'Script element with base64-decoded source',
			'family'      => 'JS.Injection.AtobLoader',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~createElement\s*\(\s*[\'"]script[\'"]\s*\)[\s\S]{0,200}\.src\s*=\s*atob\s*\(~i',
			'description' => 'Injects a <script> tag whose URL is hidden in base64.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-006',
			'name'        => 'Redirect to base64-decoded URL',
			'family'      => 'JS.Redirect.Atob',
			'category'    => 'redirect',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:window|document|top)\.location(?:\.href)?\s*=\s*atob\s*\(~i',
			'description' => 'Redirects visitors to a URL hidden in base64.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-007',
			'name'        => 'Script loaded from a raw IP address',
			'family'      => 'JS.Injection.IpHost',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 70,
			'targets'     => array( 'html', 'php', 'db' ),
			'pattern'     => '~<script[^>]+src\s*=\s*["\']?https?://\d{1,3}(?:\.\d{1,3}){3}[/:"\']~i',
			'description' => 'A <script> tag that loads code from a bare IP address instead of a domain.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-DB-001',
			'name'        => 'Inline script with decoder in content',
			'family'      => 'DB.Injection.InlineScript',
			'category'    => 'db-injection',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'db' ),
			'pattern'     => '~<script[^>]*>[^<]{0,2000}?(?:\beval\s*\(|String\.fromCharCode|\batob\s*\(|document\.write\s*\(\s*unescape)~i',
			'description' => 'A <script> block using eval/atob/fromCharCode stored in post or option content.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-DB-002',
			'name'        => 'Hidden iframe in content',
			'family'      => 'DB.Injection.HiddenIframe',
			'category'    => 'db-injection',
			'severity'    => 'high',
			'confidence'  => 70,
			'targets'     => array( 'db', 'html' ),
			'pattern'     => '~<iframe\b[^>]*(?:\bwidth\s*=\s*["\']?[01]["\'\s/>]|\bheight\s*=\s*["\']?[01]["\'\s/>]|style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden))~i',
			'description' => 'An invisible iframe (zero size or hidden by CSS) that loads another page without the visitor noticing.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-DB-003',
			'name'        => 'Hidden block of links (SEO spam)',
			'family'      => 'SEO.Spam.HiddenLinks',
			'category'    => 'seo-spam',
			'severity'    => 'medium',
			'confidence'  => 65,
			'targets'     => array( 'db', 'html' ),
			'pattern'     => '~<(?:div|span|p)\b[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px)[^"\']*["\'][^>]*>(?:[^<]{0,200}<a\s[^>]*href[^>]*>[^<]{0,200}</a>){3,}~i',
			'description' => 'Three or more links inside an element hidden with CSS, the usual shape of injected SEO spam.',
			'remediation' => 'review',
		)
	),

	// ---------------------------------------------------------------------
	// Server configuration.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-HTA-001',
			'name'        => 'Search-engine referrer redirect',
			'family'      => 'SEO.Redirect.Htaccess',
			'category'    => 'redirect',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'htaccess' ),
			'pattern'     => '~RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(?:google|bing|yahoo|yandex|baidu)[^\n]*\n(?:\s*RewriteCond[^\n]*\n)*\s*RewriteRule\s+[^\n]*https?://~i',
			'description' => 'Redirects visitors arriving from search engines to an external site (SEO spam).',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-HTA-002',
			'name'        => 'PHP handler for non-PHP extension',
			'family'      => 'Config.Htaccess.PhpHandler',
			'category'    => 'config-abuse',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'htaccess' ),
			'pattern'     => '~\b(?:AddHandler|AddType)\s+\S*php\S*\s+[^\n]*\.(?:jpe?g|png|gif|ico|txt|css|js)\b~i',
			'description' => 'Makes images or text files executable as PHP.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-HTA-003',
			'name'        => 'Error page redirects off-site',
			'family'      => 'SEO.Redirect.ErrorDocument',
			'category'    => 'redirect',
			'severity'    => 'medium',
			'confidence'  => 60,
			'targets'     => array( 'htaccess' ),
			'pattern'     => '~^\s*ErrorDocument\s+(?:403|404|500)\s+https?://~im',
			'description' => 'Sends visitors who hit an error page to an external site.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-CFG-001',
			'name'        => 'auto_prepend/append_file directive',
			'family'      => 'Config.AutoPrepend',
			'category'    => 'config-abuse',
			'severity'    => 'medium',
			'confidence'  => 35,
			'targets'     => array( 'htaccess', 'ini' ),
			'pattern'     => '~\bauto_(?:prepend|append)_file\b~i',
			'description' => 'Loads a file before or after every PHP request. Firewalls (e.g. Wordfence) use this legitimately; malware uses it for persistence.',
			'remediation' => 'review',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-CFG-002',
			'name'        => 'auto_prepend_file pointing at a non-PHP or temp file',
			'family'      => 'Config.AutoPrepend.Suspicious',
			'category'    => 'config-abuse',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'htaccess', 'ini' ),
			'pattern'     => '~\bauto_(?:prepend|append)_file\b\s*=?\s*["\']?(?:/tmp/|/dev/shm/|/var/tmp/|[^\s"\']+\.(?:jpe?g|png|gif|ico|txt|css))~i',
			'description' => 'Prepends a file from a temp directory or with an image/text extension to every request: persistence trick.',
			'remediation' => 'clean',
		)
	),

	// ---------------------------------------------------------------------
	// Payloads hidden in images.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-IMG-001',
			'name'        => 'PHP code inside image file',
			'family'      => 'Hidden.PhpInImage',
			'category'    => 'hidden-php',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'image' ),
			'pattern'     => '~<\?php|<\?=\s*\$|\beval\s*\(|\bbase64_decode\s*\(~i',
			'description' => 'Image or icon files that contain PHP, usually loaded through an include from an infected file.',
			'remediation' => 'quarantine',
		)
	),

	// ---------------------------------------------------------------------
	// Exact byte patterns (no regex engine involved).
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-BYTES-001',
			'name'        => 'GIF header followed by PHP open tag',
			'family'      => 'Hidden.PolyglotGif',
			'category'    => 'hidden-php',
			'severity'    => 'high',
			'confidence'  => 85,
			'technique'   => 'bytes',
			'targets'     => array( 'php', 'image' ),
			'bytes'       => bin2hex( "GIF89a<?php" ),
			'description' => 'A GIF signature immediately followed by PHP: a polyglot crafted to pass image checks.',
			'remediation' => 'quarantine',
		)
	),
);
