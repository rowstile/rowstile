<?php

// What the checks ran of the SDK (sdk/php/src), from the report PHPUnit's coverage writes (--coverage-php, merged
// from every worker by paratest): each file's lines and branches (Xdebug's), and each line or branch no check ran.
// Exits 1 if there is one. test.sh runs it.
//   php tests/coverage.php <coverage.php>

declare(strict_types=1);

use SebastianBergmann\CodeCoverage\CodeCoverage;

require __DIR__.'/../vendor/autoload.php';

$coverage = require $argv[1];
if (!$coverage instanceof CodeCoverage) {
    fwrite(STDERR, "{$argv[1]} is not a coverage report\n");
    exit(2);
}
$data = $coverage->getData();
$root = (string) realpath(__DIR__.'/../../../sdk/php/src');
$missed = [];
$totals = ['lines' => [0, 0], 'branches' => [0, 0]];
$lines = $data->lineCoverage();
ksort($lines);
foreach ($lines as $file => $byLine) {
    $name = 'sdk/php/src'.substr($file, strlen($root));
    $ran = 0;
    foreach ($byLine as $line => $tests) {
        if ($tests === null) {
            continue; // not a line that runs
        }
        $totals['lines'][1]++;
        if ($tests === []) {
            $missed[] = "{$name}:{$line}: a line no check runs";
        } else {
            $ran++;
            $totals['lines'][0]++;
        }
    }
    $branches = [0, 0];
    foreach ($data->functionCoverage()[$file] ?? [] as $function => $info) {
        foreach ($info->branches as $branch) {
            $branches[1]++;
            if ($branch->hit === []) {
                $missed[] = "{$name}:{$branch->line_start}-{$branch->line_end}: a branch of {$function} no check takes";
            } else {
                $branches[0]++;
            }
        }
    }
    $totals['branches'][0] += $branches[0];
    $totals['branches'][1] += $branches[1];
    printf("%-48s lines %3d/%-3d  branches %3d/%d\n", $name, $ran, count(array_filter($byLine, static fn ($t) => $t !== null)), $branches[0], $branches[1]);
}
printf("%-48s lines %3d/%-3d  branches %3d/%d\n", 'the SDK', $totals['lines'][0], $totals['lines'][1], $totals['branches'][0], $totals['branches'][1]);
foreach ($missed as $line) {
    echo "  {$line}\n";
}
exit($missed === [] ? 0 : 1);
