<?php

declare(strict_types=1);

namespace Rowstile;

use PDOException;
use Throwable;

use function array_slice, explode, implode, preg_match;

/**
 * What the database said, read from the driver's error (PDOException, or the first of an error's causes that is one:
 * Laravel's QueryException keeps it). pdo_pgsql gives the SQLSTATE and the server's text, its primary message, then
 * its DETAIL, HINT and CONTEXT lines; not the fields that name a table or a constraint, so a refusal's table and
 * command are read from the words the runtime writes ("may not insert this row into app.notes"), nor the function
 * that raised it, so Postgres's own refusal is told by its English words alone.
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
     * (a DETAIL of several lines) are that part's too. The first line is the severity's, in the server's language
     * ("ERROR:  ", "FEHLER:  "), then the message. A message may quote text that holds a line like a part's (the
     * request's own input): libpq writes its own parts after the message, so of a part named twice the last is read.
     */
    private static function read(string $sqlstate, string $text): self
    {
        $lines = explode("\n", $text);
        $parts = ['MESSAGE' => [preg_match('/^[^\s:]+:  ?(.*)$/', $lines[0], $m) === 1 ? $m[1] : $lines[0]]];
        $part = 'MESSAGE';
        foreach (array_slice($lines, 1) as $line) {
            if (preg_match('/^(DETAIL|HINT|CONTEXT|QUERY|LINE \d+|STATEMENT):  ?(.*)$/', $line, $m) === 1) {
                $part = $m[1];
                $parts[$part] = [$m[2]];
                continue;
            }
            $parts[$part][] = $line;
        }
        $joined = static fn (string $name): ?string => isset($parts[$name]) ? implode("\n", $parts[$name]) : null;
        return new self($sqlstate, (string) $joined('MESSAGE'), $joined('DETAIL'), $joined('HINT'));
    }

    /**
     * rowstile's code, from the HINT, where the runtime puts it, at its end (rowstile help AZ709), and never the
     * message, which may hold the request's own input (Postgres's own words quote a value it couldn't read).
     */
    public function code(): ?string
    {
        return preg_match('/rowstile help (AZ\d{3})\)?$/', (string) $this->hint, $m) === 1 ? $m[1] : null;
    }
}
