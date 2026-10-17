<?php
/**
 * Heuristic engine: individual indicators and the reporting rule.
 */

use Fckmaleware\Detection\Heuristics;

$indicators = static function ( string $code ): array {
	return array_keys( Heuristics::analyze( $code )['indicators'] );
};
$reported = static function ( string $code, int $threshold = 60 ): bool {
	return Heuristics::classify( Heuristics::analyze( $code ), $threshold )['report'];
};

// Taint flows across statements, through pass-through calls only.
check( in_array( 'code_exec_input', $indicators( "<?php\n\$a = \$_POST['x'];\n\$b = trim(\$a);\neval(\$b);" ), true ), 'taint through pass-through call reaches eval' );
check( ! in_array( 'code_exec_input', $indicators( "<?php\n\$a = \$_POST['x'];\n\$b = my_validate(\$a);\neval(\$b);" ), true ), 'unknown function stops taint' );
check( ! in_array( 'code_exec_input', $indicators( "<?php\n\$a = sanitize_key(\$_POST['x']);\neval(\$a);" ), true ), 'sanitizer stops taint' );
check( ! in_array( 'code_exec_input', $indicators( "<?php\nfunction a() { \$v = \$_GET['x']; }\nfunction b() { eval(\$v); }" ), true ), 'taint does not cross function boundaries' );
check( ! in_array( 'input_function_call', $indicators( "<?php\n\$h = \$registry[ \$_GET['id'] ];\ncall_user_func(\$h);" ), true ), 'registry lookup by input is not input' );

// Callback rule: only when the callback itself is input.
check( in_array( 'input_function_call', $indicators( "<?php call_user_func(\$_REQUEST['f'], 1);" ), true ), 'callback from request input' );
check( ! in_array( 'input_function_call', $indicators( "<?php array_map('sanitize_text_field', \$_POST['items']);" ), true ), 'array_map over input with fixed callback' );
check( ! in_array( 'input_function_call', $indicators( "<?php call_user_func(array(\$this, 'on_' . \$_POST['a']));" ), true ), 'method on $this with input suffix' );
check( ! in_array( 'input_function_call', $indicators( "<?php \$c = \$_POST['class'];\n\$o = new \$c();" ), true ), 'new $class() is not a function call' );
check( ! in_array( 'input_function_call', $indicators( "<?php \$m = \$_POST['m'];\n\$this->\$m();" ), true ), 'dynamic method call is not a function call' );

// Obfuscation indicators.
check( in_array( 'assembled_function_name', $indicators( "<?php \$f = 'base' . '64_de' . 'code';" ), true ), 'name assembled from fragments' );
check( ! in_array( 'assembled_function_name', $indicators( "<?php \$f = 'base64_decode';" ), true ), 'plain name is not assembled' );
check( in_array( 'escaped_dangerous_name', $indicators( '<?php $f = "\x62\x61\x73\x65\x36\x34\x5f\x64\x65\x63\x6f\x64\x65";' ), true ), 'escaped dangerous name' );
check( in_array( 'reversed_name', $indicators( "<?php \$f = 'edoced_46esab';" ), true ), 'reversed name' );
check( in_array( 'preg_e', $indicators( "<?php preg_replace('#x#e', \$r, \$s);" ), true ), 'preg_replace /e' );
check( ! in_array( 'preg_e', $indicators( "<?php preg_replace('#\\s+#', ' ', \$s);" ), true ), 'preg_replace without /e' );
check( in_array( 'include_non_php', $indicators( "<?php include 'images/x.png';" ), true ), 'include of an image' );
check( in_array( 'globals_call', $indicators( "<?php \$GLOBALS['a']('x');" ), true ), '$GLOBALS call' );

// Reporting rule: weak indicators alone never report; one strong input→sink flow does.
check( ! $reported( "<?php exec('ls'); set_time_limit(0); ignore_user_abort(true); echo php_uname(); echo disk_free_space('/'); echo getmyuid();" ), 'only weak indicators: not reported' );
check( $reported( "<?php eval(\$_GET['c']);" ), 'input to eval: reported' );
check( ! $reported( "<?php eval(\$_GET['c']);", 95 ), 'threshold is honoured' );

$class = Heuristics::classify( Heuristics::analyze( "<?php \$a = \$_POST['x'];\n\$b = base64_decode(\$a);\neval(\$b);" ), 60 );
check( $class['report'] && 'malicious' === $class['verdict'] && in_array( $class['severity'], array( 'high', 'critical' ), true ), 'split backdoor classified malicious/high+' );

// Non-PHP input and oversize input are ignored.
check( array() === Heuristics::analyze( 'just text, eval(x)' )['indicators'], 'no PHP open tag: nothing analyzed' );
check( isset( Heuristics::analyze( '<?php ' . str_repeat( ' ', Heuristics::MAX_BYTES ) )['skipped'] ), 'oversize file skipped' );
