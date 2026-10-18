<?php
/**
 * WordPress-specific malware families and techniques, authored by the
 * FCK Malware project (second set, 1.2).
 *
 * Every rule is validated by tools/build-signatures.php (schema, compilation,
 * ReDoS probes) and must match nothing in the clean corpus (WordPress core
 * plus 68 popular plugins and 10 themes, 78,158 files for 1.2). Each rule has
 * an inert fixture in tests/fixtures/malware/.
 *
 * remediation: "quarantine" = the whole file is malicious (eligible for
 * automatic removal when confidence >= 90); "clean" = injected into a
 * legitimate file (listed for cleaning, never removed automatically);
 * "review" = needs a human decision.
 *
 * @package Fckmaleware
 */

$project = array(
	'source'  => 'FCK Malware project',
	'license' => 'GPL-3.0-or-later',
	'created' => '2026-10-18',
	'updated' => '2026-10-18',
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
	// WordPress persistence and account takeover.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-WP-001',
			'name'        => 'WP-VCD infection loader',
			'family'      => 'WordPress.Backdoor.WPVCD',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 95,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:\$div_code_name\s*=\s*["\']wp_vcd|\bwp_vcd\b[\s\S]{0,400}\$code_add|["\'](?:wp-tmp|wp-feed|wp-vcd)\.php["\'][\s\S]{0,400}\b(?:include|require)(?:_once)?\b)~i',
			'description' => 'The WP-VCD campaign spreads through nulled themes and plugins and injects a loader into every theme\'s functions.php.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-002',
			'name'        => 'Hard-coded administrator account creation',
			'family'      => 'WordPress.Backdoor.AdminCreate',
			'category'    => 'persistence',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bwp_create_user\s*\(\s*["\'][^"\'$]{2,60}["\']\s*,\s*["\'][^"\'$]{4,80}["\'][\s\S]{0,400}->\s*set_role\s*\(\s*["\']administrator["\']~i',
			'description' => 'Creates an administrator with a user name and password written into the code, so the attacker can always log back in.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-003',
			'name'        => 'Credential stealer on the login hook',
			'family'      => 'WordPress.Stealer.Login',
			'category'    => 'credential-theft',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~add_action\s*\(\s*["\'](?:wp_authenticate|wp_login|authenticate)["\'][\s\S]{0,900}\b(?:file_put_contents|fwrite|mail|wp_mail|wp_remote_post|curl_exec)\s*\([\s\S]{0,300}\$(?:password|pass|pwd|user_pass)\b~i',
			'description' => 'Captures passwords as users log in and writes or sends them elsewhere.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-004',
			'name'        => 'Exfiltration to a Telegram bot',
			'family'      => 'Generic.Stealer.Telegram',
			'category'    => 'credential-theft',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php', 'js' ),
			'pattern'     => '~api\.telegram\.org/bot[\s\S]{0,800}(?:\$_(?:POST|REQUEST)\s*\[\s*["\'](?:pwd|pass|password|log|cc|card|cvv)|user_pass|card(?:number|_number)|cvv)~i',
			'description' => 'Sends submitted passwords or card data to a Telegram bot, a common exfiltration channel for skimmers and phishing kits.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-005',
			'name'        => 'Executes code stored in an option',
			'family'      => 'WordPress.Backdoor.OptionEval',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:eval|assert)\s*\(\s*@?\s*(?:(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*)*(?:get_option|get_site_option|get_transient|get_site_transient)\s*\(~i',
			'description' => 'Runs PHP code kept in the database, so the payload survives file cleanups.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-006',
			'name'        => 'Logs in as an administrator from a request parameter',
			'family'      => 'WordPress.Backdoor.AuthBypass',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bisset\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\)[\s\S]{0,400}?(?:\bwp_set_(?:auth_cookie|current_user)\s*\(\s*1\s*[,)]|\bget_users\s*\([^;]{0,120}["\']administrator["\'][\s\S]{0,300}?\bwp_set_auth_cookie\s*\()~i',
			'description' => 'Grants a logged-in administrator session to anyone who knows a secret parameter.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-007',
			'name'        => 'Malicious code added to the head or footer of every page',
			'family'      => 'WordPress.Injection.HeadFooter',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~add_action\s*\(\s*["\']wp_(?:head|footer)["\'][\s\S]{0,600}(?:atob\s*\(|String\.fromCharCode\s*\(\s*\d{2,3}\s*,\s*\d{2,3}\s*,\s*\d{2,3}|\\\\x3c\\\\x73\\\\x63\\\\x72|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e)~i',
			'description' => 'Prints an obfuscated script on every page, the usual way redirect and skimmer code reaches visitors.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-WP-008',
			'name'        => 'Disables WordPress updates for everyone',
			'family'      => 'WordPress.Persistence.UpdateBlock',
			'category'    => 'persistence',
			'severity'    => 'medium',
			'confidence'  => 60,
			'targets'     => array( 'php' ),
			'pattern'     => '~add_filter\s*\(\s*["\']pre_site_transient_update_(?:core|plugins|themes)["\']\s*,\s*(?:["\']__return_null["\']|create_function|function\s*\(\s*\)\s*\{\s*return\s+null)[\s\S]{0,400}pre_site_transient_update_(?:core|plugins|themes)~i',
			'description' => 'Hides all available updates, which keeps the vulnerable code that let the attacker in. Some site managers do this deliberately.',
			'remediation' => 'review',
		)
	),

	// ---------------------------------------------------------------------
	// Web shells and backdoors.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-PHP-029',
			'name'        => 'Known web shell page title',
			'family'      => 'WebShell.Title',
			'category'    => 'webshell',
			'severity'    => 'critical',
			'confidence'  => 95,
			'targets'     => array( 'php', 'html' ),
			'pattern'     => '~<title>\s*(?:IndoSec|0byt3m1n1|Marijuana|Gecko\s*(?:Shell)?|Priv8|Bypass\s*Shell|Shell\s*Bypass|WSO\s*\d|b374k|Alfa\s*Shell|Haxor|Sadrazam|Leaf\s*PHPMailer|Tiny\s*File\s*Manager\s*[-|]\s*Shell|L3n4r0x|xLeet|Kudet|Phantom\s*Shell|Mr\.\s*\w+\s*Shell|Uploader\s*by)\b[^<]{0,60}</title>~i',
			'description' => 'The page title of a widely used PHP web shell or mailer.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-030',
			'name'        => 'Hex-encoded dangerous function name',
			'family'      => 'Generic.Obfuscation.HexName',
			'category'    => 'obfuscation',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~["\'](?:\\\\x62\\\\x61\\\\x73\\\\x65\\\\x36\\\\x34\\\\x5f\\\\x64\\\\x65\\\\x63\\\\x6f\\\\x64\\\\x65|\\\\x65\\\\x76\\\\x61\\\\x6c|\\\\x61\\\\x73\\\\x73\\\\x65\\\\x72\\\\x74|\\\\x73\\\\x79\\\\x73\\\\x74\\\\x65\\\\x6d|\\\\x73\\\\x68\\\\x65\\\\x6c\\\\x6c\\\\x5f\\\\x65\\\\x78\\\\x65\\\\x63|\\\\x67\\\\x7a\\\\x69\\\\x6e\\\\x66\\\\x6c\\\\x61\\\\x74\\\\x65|\\\\x63\\\\x72\\\\x65\\\\x61\\\\x74\\\\x65\\\\x5f\\\\x66\\\\x75\\\\x6e\\\\x63\\\\x74\\\\x69\\\\x6f\\\\x6e)["\']~i',
			'description' => 'base64_decode, eval, assert, system, shell_exec, gzinflate or create_function written as \\x escapes to hide from scanners.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-031',
			'name'        => 'Octal-encoded dangerous function name',
			'family'      => 'Generic.Obfuscation.OctalName',
			'category'    => 'obfuscation',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~["\'](?:\\\\142\\\\141\\\\163\\\\145\\\\66\\\\64\\\\137|\\\\145\\\\166\\\\141\\\\154|\\\\141\\\\163\\\\163\\\\145\\\\162\\\\164|\\\\163\\\\171\\\\163\\\\164\\\\145\\\\155|\\\\147\\\\172\\\\151\\\\156\\\\146\\\\154\\\\141\\\\164\\\\145)~i',
			'description' => 'base64_, eval, assert, system or gzinflate written as octal escapes.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-032',
			'name'        => 'ROT13-encoded dangerous function name',
			'family'      => 'Generic.Obfuscation.Rot13Name',
			'category'    => 'obfuscation',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bstr_rot13\s*\(\s*["\'](?:riny|nffreg|onfr64_qrpbqr|tmvasyngr|flfgrz|furyy_rkrp|cnffgueh|perngr_shapgvba)["\']\s*\)~i',
			'description' => 'Builds eval, assert, base64_decode, gzinflate, system, shell_exec, passthru or create_function from a ROT13 string.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-033',
			'name'        => 'Backdoor liveness probe',
			'family'      => 'Generic.Backdoor.Probe',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 95,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:die|exit|echo|print)\s*\(?\s*pi\s*\(\s*\)\s*\*\s*42\b~i',
			'description' => 'Answers a fixed marker (such as pi()*42) so automated tools can find installed backdoors.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-034',
			'name'        => 'extract() of request data followed by a dynamic call',
			'family'      => 'Generic.Backdoor.ExtractCall',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\)\s*;[\s\S]{0,200}?(?<![\w>:$])\$\w{1,20}\s*\(\s*\$\w{1,20}\s*(?:\)|,)~i',
			'description' => 'Turns request parameters into variables and then calls one of them as a function: a compact remote-code-execution backdoor.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-035',
			'name'        => 'Remote file include',
			'family'      => 'Generic.Backdoor.RemoteInclude',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~(?:^|[;{}]|<\?php)\s*@?(?:include|require)(?:_once)?\s*\(?\s*["\'](?:https?://|ftp://|php://input|expect://)~im',
			'description' => 'Includes PHP code from a URL or the request body, which runs whatever the remote side serves.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-036',
			'name'        => 'Shutdown or callback function from request input',
			'family'      => 'Generic.Backdoor.CallbackInput',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:register_shutdown_function|register_tick_function|array_map|call_user_func(?:_array)?|forward_static_call(?:_array)?)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[~i',
			'description' => 'Uses a request parameter as the name of the function to call.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-037',
			'name'        => 'Silenced error output before code execution',
			'family'      => 'Generic.Backdoor.SilentExec',
			'category'    => 'php-backdoor',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'php' ),
			'pattern'     => '~\A\s*<\?php\s*(?:/\*[^*]{0,200}\*/\s*)?@?(?:error_reporting\s*\(\s*0\s*\)|ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?(?:0|off)["\']?\s*\))\s*;[\s\S]{0,300}?\b(?:eval|assert|system|shell_exec|passthru|popen|proc_open)\s*\(\s*@?\s*(?:\$_|base64_decode|gzinflate|str_rot13|\$\w+\s*\()~i',
			'description' => 'A file that starts by hiding errors and then executes request data or decoded code: the opening of most droppers.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-038',
			'name'        => 'Shell variable alias of request data',
			'family'      => 'Generic.Backdoor.ShortVar',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\$(?:_|__|_{3})\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*;[\s\S]{0,200}?\$(?:_|__|_{3})\s*\[\s*["\']?\w{1,10}["\']?\s*\]\s*\(~i',
			'description' => 'Copies the request into $_ and calls an entry of it as a function.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-039',
			'name'        => 'Mass mailer with request-supplied recipients',
			'family'      => 'Spam.Mailer',
			'category'    => 'spam-mailer',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~\$_POST\s*\[\s*["\'](?:emailList|email_list|maillist|mailist|lista|to_list)["\']\s*\][\s\S]{0,1500}\bmail\s*\(~i',
			'description' => 'Sends mail to a list of addresses posted to the file: a spam relay such as Leaf PHPMailer.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-040',
			'name'        => 'Server information page with command execution',
			'family'      => 'WebShell.Generic',
			'category'    => 'webshell',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php' ),
			'pattern'     => '~\bphp_uname\s*\(\s*\)[\s\S]{0,3000}?\b(?:disable_functions|safe_mode)\b[\s\S]{0,3000}?\b(?:shell_exec|passthru|system|proc_open|popen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)~i',
			'description' => 'Prints server details and runs commands posted to it, the layout of most file-manager web shells.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-041',
			'name'        => 'Defacement page',
			'family'      => 'Defacement',
			'category'    => 'defacement',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'php', 'html' ),
			'pattern'     => '~(?:<title>\s*(?:hacked|owned|defaced)\s+by\b|<h1[^>]{0,100}>\s*(?:hacked|owned|defaced)\s+by\b)~i',
			'description' => 'A "hacked by" page left by a defacement.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-PHP-042',
			'name'        => 'Stream wrapper code execution',
			'family'      => 'Generic.Backdoor.Wrapper',
			'category'    => 'php-backdoor',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'php' ),
			'pattern'     => '~\b(?:include|require)(?:_once)?\s*\(?\s*["\']data:(?://)?text/plain;base64,~i',
			'description' => 'Includes PHP code embedded as a data: URL.',
			'remediation' => 'quarantine',
		)
	),

	// ---------------------------------------------------------------------
	// Front-end injections, skimmers and miners.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-JS-008',
			'name'        => 'Blockchain-hosted loader (ClearFake / EtherHiding)',
			'family'      => 'JS.Injection.ClearFake',
			'category'    => 'js-injection',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:bsc-dataseed\d?\.(?:binance\.org|bnbchain\.org)|data-seed-prebsc-\d-s\d\.(?:binance\.org|bnbchain\.org)|bsc-testnet\.(?:public\.blastapi\.io|publicnode\.com))[\s\S]{0,2000}(?:eth_call|0x[0-9a-f]{8}\b)~i',
			'description' => 'Fetches the next stage from a smart contract on BNB Smart Chain, the technique of the ClearFake fake-browser-update campaign.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-009',
			'name'        => 'Fake browser update overlay',
			'family'      => 'JS.Injection.FakeUpdate',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:Update\s+(?:Chrome|Google\s+Chrome|Edge|Firefox|your\s+browser)[\s\S]{0,400}\.(?:zip|exe|msix|apk)["\']|(?:Chrome|Browser)Update(?:Setup)?\.(?:zip|exe|js|msix)\b)~i',
			'description' => 'Shows visitors a fake "update your browser" page that downloads malware (SocGholish, FakeUpdates).',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-010',
			'name'        => 'Card skimmer exfiltration',
			'family'      => 'JS.Skimmer',
			'category'    => 'skimmer',
			'severity'    => 'critical',
			'confidence'  => 85,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:\[name\*?=\s*["\']?(?:billing_)?(?:cc|card)[_-]?(?:number|num|cvv|cvc|exp)|getElementById\s*\(\s*["\'](?:cc|card)[_-]?(?:number|num|cvv|cvc)["\']\s*\))[\s\S]{0,1200}(?:btoa\s*\(|JSON\.stringify)[\s\S]{0,600}(?:new\s+Image\s*\(\s*\)|navigator\.sendBeacon|new\s+WebSocket|\.src\s*=\s*["\']https?://)~i',
			'description' => 'Reads payment card fields, encodes them and sends them to another server (Magecart-style skimmer).',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-011',
			'name'        => 'Browser cryptominer',
			'family'      => 'JS.Miner',
			'category'    => 'cryptominer',
			'severity'    => 'high',
			'confidence'  => 90,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:CoinHive\.(?:Anonymous|User|Token)|CryptoLoot\.Anonymous|new\s+(?:Client|Miner)\s*\.\s*Anonymous\s*\(|cryptonight(?:[-_.]?wasm|\.js)|webminepool|minero\.cc|coinimp\.com|monerominer|deepminer\.js|(?:"|\')stratum\+tcp://)~i',
			'description' => 'Mines cryptocurrency in visitors\' browsers.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-012',
			'name'        => 'Script injected through a dynamic script element from char codes',
			'family'      => 'JS.Injection.Balada',
			'category'    => 'js-injection',
			'severity'    => 'high',
			'confidence'  => 85,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~createElement\s*\(\s*(?:["\']script["\']|String\.fromCharCode\s*\(\s*115\s*,\s*99\s*,\s*114)[\s\S]{0,400}\.src\s*=\s*(?:String\.fromCharCode\s*\(\s*1(?:04|0[45])\s*,\s*116\s*,\s*116|atob\s*\(|unescape\s*\()~i',
			'description' => 'Creates a script tag whose address is hidden with char codes or encoding, the loader pattern of the Balada Injector campaign.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-013',
			'name'        => 'Mobile-only or search-referrer redirect',
			'family'      => 'JS.Redirect.Conditional',
			'category'    => 'redirect',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'js', 'html', 'php', 'db' ),
			'pattern'     => '~(?:document\.referrer[\s\S]{0,120}(?:google|bing|yahoo|yandex|duckduckgo)|/(?:android|iphone|ipad|mobile)/i\.test\s*\(\s*navigator\.userAgent\s*\))[\s\S]{0,300}(?:window|document|top|self)\.location(?:\.href)?\s*=\s*(?:atob\s*\(|["\']https?://(?![^"\']*\b(?:google|apple|facebook|twitter|bing)\.))~i',
			'description' => 'Sends only visitors from search engines or phones to another site, so administrators never see the redirect.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-JS-014',
			'name'        => 'Packed eval loader in a script tag',
			'family'      => 'JS.Obfuscation.PackedEval',
			'category'    => 'obfuscation',
			'severity'    => 'high',
			'confidence'  => 75,
			'targets'     => array( 'html', 'php', 'db' ),
			'pattern'     => '~<script[^>]{0,200}>\s*eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)~i',
			'description' => 'An inline script packed with Dean Edwards\' packer inside page or post content, a common way to hide injected redirects.',
			'remediation' => 'clean',
		)
	),

	// ---------------------------------------------------------------------
	// Server configuration.
	// ---------------------------------------------------------------------
	$sig(
		array(
			'id'          => 'FMW-HTA-004',
			'name'        => 'Blocks everything except attacker files',
			'family'      => 'Htaccess.Lockout',
			'category'    => 'htaccess',
			'severity'    => 'critical',
			'confidence'  => 90,
			'targets'     => array( 'htaccess' ),
			'pattern'     => '~<FilesMatch\s+["\']?\.\(py\|exe\|phtml\|php\|PHP\|Php\|PHp\|pHp\|pHP\|phP\|PhP\|php5\|suspected\)\$["\']?>~i',
			'description' => 'A rule dropped into many folders at once that denies every PHP file except the attacker\'s own, locking out the real site.',
			'remediation' => 'quarantine',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-HTA-005',
			'name'        => 'Rewrites requests to a hidden PHP file',
			'family'      => 'Htaccess.SpamRewrite',
			'category'    => 'htaccess',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'htaccess' ),
			'pattern'     => '~RewriteRule\s+\^\(?\.\*\)?\$?\s+(?:/?wp-(?:includes|content|admin)/[^\s]{0,80}/)?[\w-]{1,30}\.(?:php|ico|png)\?(?:[\w-]{1,20})=\$1~i',
			'description' => 'Sends every request to a single PHP file with the path as a parameter, the router of SEO spam doorway pages.',
			'remediation' => 'clean',
		)
	),
	$sig(
		array(
			'id'          => 'FMW-CFG-003',
			'name'        => 'php.ini or .user.ini enables remote includes',
			'family'      => 'Config.RemoteInclude',
			'category'    => 'config',
			'severity'    => 'high',
			'confidence'  => 80,
			'targets'     => array( 'ini', 'htaccess' ),
			'pattern'     => '~\b(?:php_flag|php_value)?\s*allow_url_include\s*(?:=|\s)\s*["\']?(?:on|1|true)\b~i',
			'description' => 'Turns on allow_url_include so PHP can include code from URLs. No WordPress site needs it.',
			'remediation' => 'clean',
		)
	),
);
