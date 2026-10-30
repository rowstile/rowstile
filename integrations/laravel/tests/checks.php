<?php

// Each check's line, from PHPUnit's report of them (JUnit XML, which paratest merges from its workers): "ok    7: ..."
// or "FAIL  7: ..." and why, worded as the check's TestDox says. Exits 1 if one failed, or none ran.
//   php tests/checks.php <junit.xml>

declare(strict_types=1);

use PHPUnit\Framework\Attributes\TestDox;

require __DIR__.'/../vendor/autoload.php';

$xml = simplexml_load_file($argv[1]);
if ($xml === false) {
    fwrite(STDERR, "{$argv[1]}: no report of the checks\n");
    exit(1);
}
$failed = 0;
$ran = 0;
$cases = $xml->xpath('//testcase');
foreach (is_array($cases) ? $cases : [] as $case) {
    $class = (string) $case['class'];
    $method = (string) $case['name'];
    $words = $method;
    if (class_exists($class) && method_exists($class, $method)) {
        foreach ((new ReflectionMethod($class, $method))->getAttributes(TestDox::class) as $attribute) {
            $words = $attribute->newInstance()->text();
        }
    }
    $ran++;
    $problem = $case->failure ?? $case->error ?? null;
    if ($problem === null) {
        echo "ok    {$words}\n";
    } else {
        $failed++;
        echo "FAIL  {$words}\n", preg_replace('/^/m', '      ', trim((string) $problem)), "\n";
    }
}
exit($failed === 0 && $ran > 0 ? 0 : 1);
