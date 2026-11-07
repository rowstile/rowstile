<?php

declare(strict_types=1);

namespace Rowstile;

use PDOException;
use Throwable;

use function array_pop, array_slice, count, end, explode, implode, preg_match, preg_replace, strlen, substr;

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
     * (a DETAIL of several lines) are that part's too. The first line is the severity's, in the server's language
     * ("ERROR:  ", "FEHLER:  "), then the message. libpq writes the parts once each, in one order (the message,
     * LINE, DETAIL, HINT, QUERY, CONTEXT), and a part's text may hold what the app sent, a line that looks like a
     * label among it. So a label out of that order ends the parts it would come after, which were text of the part
     * before them: the server's HINT, written after the message and the DETAIL, is the last. After a QUERY or a CONTEXT
     * (the statement a function ran, its literals the app's) only a later part begins. A LINE is one only with the
     * caret libpq writes under it: a DETAIL that quotes "LINE 2: " keeps it.
     */
    private static function read(string $sqlstate, string $text): self
    {
        $lines = explode("\n", $text);
        $lines[0] = (string) preg_replace('/^[^\s:]+:  ?/', '', $lines[0]); // the severity, in the server's language
        /** @var list<array{int, int, string, int}> $parts where each part begins: its line, its place, its name, its label's length */
        $parts = [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^(?:LINE \d+: |(DETAIL|HINT|QUERY|CONTEXT|STATEMENT):  ?)/', $line, $m) !== 1) {
                continue;
            }
            $name = $m[1] ?? 'LINE';
            if ($name === 'LINE' && preg_match('/^ *\^$/', $lines[$i + 1] ?? '') !== 1) {
                continue; // libpq writes a caret under the statement's line: without it, text of the part it is in
            }
            $place = self::ORDER[$name];
            $last = $parts === [] ? 0 : end($parts)[1];
            if ($place <= $last && $last >= self::ORDER['QUERY']) {
                continue; // in the statement a function ran, or its context
            }
            while ($parts !== [] && end($parts)[1] >= $place) {
                array_pop($parts); // what began there was text of the part before
            }
            $parts[] = [$i, $place, $name, strlen($m[0])];
        }
        $text = static fn (int $from, int $to): string => implode("\n", array_slice($lines, $from, $to - $from));
        $said = ['MESSAGE' => $text(0, $parts[0][0] ?? count($lines))];
        foreach ($parts as $k => [$from, , $name, $label]) {
            $said[$name] = substr($text($from, $parts[$k + 1][0] ?? count($lines)), $label);
        }
        return new self($sqlstate, $said['MESSAGE'], $said['DETAIL'] ?? null, $said['HINT'] ?? null);
    }

    /** Each part's place in the order libpq writes them. */
    private const ORDER = ['MESSAGE' => 0, 'LINE' => 1, 'DETAIL' => 2, 'HINT' => 3, 'QUERY' => 4, 'CONTEXT' => 5, 'STATEMENT' => 6];

    /**
     * rowstile's code, from the HINT, where the runtime puts it: its HINT ends with it ("rowstile help AZ709", or a
     * sentence then "(rowstile help AZ716)"). Never from the message's words.
     */
    public function code(): ?string
    {
        return preg_match('/\browstile help (AZ\d{3})\)?$/', (string) $this->hint, $m) === 1 ? $m[1] : null;
    }
}
