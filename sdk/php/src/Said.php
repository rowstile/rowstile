<?php

declare(strict_types=1);

namespace Rowstile;

use PDOException;
use Throwable;

use function explode, implode, in_array, preg_match;

/**
 * What the database said, read from the driver's error (PDOException, or the first of an error's causes that is one:
 * Laravel's QueryException keeps it). pdo_pgsql gives the SQLSTATE and the server's text, its primary message, then
 * its DETAIL, HINT and CONTEXT lines; not the fields that name a table or a constraint, so a refusal's table and
 * command are read from the words the runtime writes ("may not insert this row into app.notes").
 *
 * @internal
 */
final class Said
{
    private function __construct(
        public readonly string $sqlstate,
        public readonly string $message,
        public readonly ?string $detail,
        public readonly ?string $hint,
    ) {
    }

    public static function of(Throwable $error): ?self
    {
        for ($e = $error; $e !== null; $e = $e->getPrevious()) {
            if ($e instanceof PDOException) {
                // (one PDO raises itself, "could not find driver", holds no SQLSTATE: not the database's)
                $sqlstate = Rowstile::text($e->errorInfo[0] ?? null);
                return $sqlstate === '' ? null : self::read($sqlstate, Rowstile::text($e->errorInfo[2] ?? null));
            }
        }
        return null;
    }

    /**
     * The server's text, cut at the lines libpq begins each part with ("DETAIL:  ", "HINT:  "): the lines after one
     * (a DETAIL of several lines) are that part's too.
     */
    private static function read(string $sqlstate, string $text): self
    {
        $parts = [];
        $part = 'MESSAGE';
        foreach (explode("\n", $text) as $line) {
            if (preg_match('/^(ERROR|FATAL|PANIC|DETAIL|HINT|CONTEXT|QUERY|LINE \d+|STATEMENT):  ?(.*)$/', $line, $m) === 1) {
                $part = in_array($m[1], ['ERROR', 'FATAL', 'PANIC'], true) ? 'MESSAGE' : $m[1];
                $line = $m[2];
            }
            $parts[$part][] = $line;
        }
        $joined = static fn (string $name): ?string => isset($parts[$name]) ? implode("\n", $parts[$name]) : null;
        return new self($sqlstate, (string) $joined('MESSAGE'), $joined('DETAIL'), $joined('HINT'));
    }

    /** rowstile's code, from the HINT, where the runtime puts it (rowstile help AZ709). */
    public function code(): ?string
    {
        return preg_match('/rowstile help (AZ\d{3})/', (string) $this->hint, $m) === 1 ? $m[1] : null;
    }
}
