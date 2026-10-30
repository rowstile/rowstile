<?php

// The installed package (tests/package.sh), loaded by Composer's autoloader from where Composer put it: it holds its
// README, its license and its Laravel half, and says its version.
//   php installed.php <the package's folder in vendor/> <its version>

declare(strict_types=1);

require getcwd().'/vendor/autoload.php';

[, $where, $version] = $argv;
$loaded = (string) (new ReflectionClass(Rowstile\Rowstile::class))->getFileName();
if (!str_starts_with($loaded, $where.'/') || is_link($where)) {
    fwrite(STDERR, "rowstile was loaded from {$loaded}, not from a copy in {$where}\n");
    exit(1);
}
$missing = array_filter(['README.md', 'LICENSE', 'composer.json', 'src/Laravel/RowstileServiceProvider.php', 'src/Testing/Assertions.php'], static fn (string $f): bool => !is_file("{$where}/{$f}"));
if ($missing !== []) {
    fwrite(STDERR, 'the package lacks '.implode(', ', $missing)."\n");
    exit(1);
}
if (Rowstile\Version::VERSION !== $version || Composer\InstalledVersions::getPrettyVersion('rowstile/rowstile') !== $version) {
    fwrite(STDERR, Rowstile\Version::VERSION." isn't {$version}\n");
    exit(1);
}
echo $version, "\n";
