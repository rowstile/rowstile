<?php

declare(strict_types=1);

namespace Rowstile;

use Closure;
use LogicException;
use PDO;
use Throwable;
use WeakMap;

use function array_map, array_values, count, explode, implode, in_array, is_array, is_string, json_decode, ltrim, preg_match, sprintf, str_replace, str_starts_with, strpbrk;

/**
 * rowstile for PHP apps on PDO (pdo_pgsql), a preview: it may change in any release.
 *
 * Every transaction signs in as whoever the code acts for, with authz.act_as(); the database's refusals become
 * Refused (a 403 with the reason), rows the user can't see NotFound (a 404), and the other codes the runtime answers
 * with CallError (each with its page's status). The SDK holds no rowstile logic: it calls the authz.* functions the
 * policy made, and translates their answers.
 *
 *     $count = Rowstile::transactionAs($pdo, Principal::user(42), fn (PDO $pdo) => ...);
 *
 * In a Laravel app the service provider does the rest (Rowstile\Laravel): each request's and each job's transactions
 * sign in, and refusals are answered as problem bodies.
 */
final class Rowstile
{
    private static ?Principal $current = null;

    /** @var ?WeakMap<PDO, Principal> who each PDO's open transaction signed in as */
    private static ?WeakMap $signed = null;

    private const UNSEEN = 'this user may not see the row as written (the select rule). An insert that reads it back '
        .'(RETURNING), an upsert, and an update with a WHERE need to see it.';

    /**
     * authz.explain_rule's answer for a row, as JSON, in the same transaction and as the same user (NULL: the row
     * isn't there for this user); who is signed in, in the words the database's own refusals use ('user 2',
     * 'service 3', 'someone not signed in'); and the table as the policy names it (a table named without its schema
     * is looked up on the search_path).
     */
    private const EXPLAIN = 'SELECT pg_catalog.to_json(authz.explain_rule(t.tbl, ?, ?, NULL)) AS lines, '
        ."coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in') AS who, "
        .'t.tbl AS tbl FROM (SELECT coalesce((SELECT n.nspname || \'.\' || c.relname FROM pg_catalog.pg_class c '
        .'JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE position(\'.\' in CAST(? AS text)) = 0 '
        .'AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident(CAST(? AS text)))), CAST(? AS text)) AS tbl) t';

    /**
     * Who the code running now acts for (a request, a job, actingAs), or null when nothing set it: a transaction
     * begun then isn't signed in, and the database refuses what needs to know who asks (AZ701).
     */
    public static function current(): ?Principal
    {
        return self::$current;
    }

    /**
     * Runs $fn acting for who: every transaction it begins on the Laravel connection, or with transaction(), signs in
     * as them. A user's id (42, "42"), a Principal (Principal::of('service', 3)), or null for nobody.
     *
     * @template T
     * @param Closure(): T $fn
     * @return T
     */
    public static function actingAs(Principal|int|string|null $who, Closure $fn): mixed
    {
        $before = self::$current;
        self::$current = Principal::from($who);
        try {
            return $fn();
        } finally {
            self::$current = $before;
        }
    }

    /**
     * Runs $fn in a transaction on $pdo signed in as whoever the code acts for (nobody if nothing set it), and
     * commits it if $fn returns. See transactionAs.
     *
     * @template T
     * @param Closure(PDO): T $fn
     * @return T
     */
    public static function transaction(PDO $pdo, Closure $fn): mixed
    {
        return self::transactionAs($pdo, self::$current, $fn);
    }

    /**
     * Runs $fn in a transaction on $pdo signed in as who (and acting for them), and commits it if $fn returns. The
     * sign-in lasts the transaction, so persistent connections and poolers in transaction mode are safe; and a
     * transaction is one principal's. Inside a transaction transaction() began already, work for the same principal
     * runs as it is, in a savepoint (its failure rolls back its own part alone); work for someone else is refused
     * before anything is sent (signedInAlready), and so is work in a transaction transaction() didn't begin, whose
     * sign-in it can't know. A database error comes out as rowstile's when it is one: Refused, NotSignedIn,
     * CallError (translate).
     *
     * @template T
     * @param Closure(PDO): T $fn
     * @return T
     */
    public static function transactionAs(PDO $pdo, Principal|int|string|null $who, Closure $fn): mixed
    {
        $who = Principal::from($who);
        $signed = self::$signed ??= new WeakMap();
        $inside = $pdo->inTransaction();
        if ($inside) {
            $outer = $signed[$pdo] ?? throw new LogicException('this connection is in a transaction Rowstile::transaction() '
                ."didn't begin: who it is signed in as can't be known, and a sign-in lasts the database transaction. "
                .'Begin it with Rowstile::transaction(), or run this after it');
            if (!$outer->equals($who)) {
                throw self::signedInAlready($outer, $who);
            }
        }
        try {
            if ($inside) {
                $pdo->exec('SAVEPOINT rowstile'); // (the sign-in is before it: rolled back to it, it stays)
            } else {
                $pdo->beginTransaction();
                self::signIn($pdo, $who);
                $signed[$pdo] = $who;
            }
            $result = self::actingAs($who, static fn (): mixed => $fn($pdo));
            if ($inside) {
                $pdo->exec('RELEASE SAVEPOINT rowstile');
            } else {
                $pdo->commit();
            }
            return $result;
        } catch (Throwable $e) {
            // (a COMMIT that failed has ended the transaction already)
            if ($inside) {
                $pdo->exec('ROLLBACK TO SAVEPOINT rowstile; RELEASE SAVEPOINT rowstile');
            } elseif ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw self::translate($e);
        } finally {
            if (!$inside) {
                unset($signed[$pdo]);
            }
        }
    }

    /**
     * The error for work that would run as someone else inside a transaction signed in already: a transaction is
     * one principal's (a sign-in lasts the database transaction, and checks deferred to the commit run as whoever is
     * signed in then). Nothing has been sent for it; the transaction is as it was.
     *
     * @internal
     */
    public static function signedInAlready(Principal $signed, ?Principal $who): LogicException
    {
        $whose = $who === null ? "the work of code that acts for no one can't" : "{$who->name()}'s work can't";
        return new LogicException("this transaction is signed in as {$signed->name()} already, and a sign-in lasts the "
            ."database transaction: {$whose} run inside it. Run it after, or in a transaction of its own (another "
            .'connection)');
    }

    private static function signIn(PDO $pdo, Principal $who): void
    {
        $pdo->prepare('SELECT authz.act_as(?, ?)')->execute($who->actAsArguments());
    }

    /**
     * $affected when an UPDATE or DELETE changed rows. When it changed none, row-level security left the row out:
     * asks the database why, in the same transaction, and throws NotFound (the user can't see the row, or the
     * statement matched nothing for another reason, such as a WHERE with more than the key) or Refused, worded as the
     * database words a refused insert: "permission denied: user 2 may not update row 7 of app.notes".
     *
     * @param int|string|list<int|string|null> $key the row's key, or a list of its columns for a key of several
     */
    public static function expect(Querier|PDO $db, int $affected, string $table, string $command, int|string|array $key): int
    {
        if ($affected > 0) {
            return $affected;
        }
        $db = $db instanceof PDO ? new PdoQuerier($db) : $db;
        $text = self::keyText($key);
        $row = $db->select(self::EXPLAIN, [$command, $text, $table, $table, $table])[0] ?? [];
        $lines = json_decode(self::text($row['lines'] ?? null), true);
        $named = self::text($row['tbl'] ?? null);
        if (!is_array($lines) || str_starts_with(ltrim(self::text($lines[0] ?? null)), 'yes')) {
            throw new NotFound($named, $text);
        }
        throw new Refused(
            sprintf('permission denied: %s may not %s row %s of %s', self::text($row['who'] ?? null), $command, $text, $named),
            $named,
            $command,
            array_values(array_map(self::text(...), $lines)),
        );
    }

    /**
     * A row's key as Postgres writes it: 7, or (1,2) for a key of several columns, a field quoted only where Postgres
     * would (empty, or holding a comma, a quote, a backslash, a parenthesis or a space). What a message shows, and
     * what authz.explain_rule and authz.can read back.
     *
     * @param int|string|list<int|string|null> $key
     */
    public static function keyText(int|string|array $key): string
    {
        if (!is_array($key)) {
            return (string) $key;
        }
        if (count($key) === 1) {
            return (string) $key[0];
        }
        $fields = array_map(static function (int|string|null $field): string {
            $text = (string) $field;
            if ($field !== null && ($text === '' || strpbrk($text, "\",\\() \t\n\r\v\f") !== false)) {
                return '"'.str_replace(['\\', '"'], ['\\\\', '""'], $text).'"';
            }
            return $text;
        }, $key);
        return '('.implode(',', $fields).')';
    }

    /**
     * Throws ConnectionProblem on a connection that skips row-level security (a superuser, BYPASSRLS, the tables'
     * owner): call it before the app serves, and refuse to start on it. As nobody: there is no request yet to ask who
     * is signed in.
     */
    public static function check(Querier|PDO $db): void
    {
        $rows = $db instanceof PDO
            ? self::transactionAs($db, null, static fn (PDO $pdo): array => (new PdoQuerier($pdo))->select(self::CHECK))
            : self::actingAs(null, static fn (): array => $db->select(self::CHECK));
        $problems = array_map(static fn (array $row): string => self::text($row['problem'] ?? null), $rows);
        if ($problems !== []) {
            throw new ConnectionProblem($problems);
        }
    }

    private const CHECK = "SELECT problem FROM authz.connection_check() WHERE severity = 'error'";

    /**
     * The error as rowstile's when it is one: a refusal Refused, the not-signed-in error (AZ701) NotSignedIn, a call
     * turned down CallError (with its status); any other as it is.
     */
    public static function translate(Throwable $error): Throwable
    {
        $said = Said::of($error);
        if ($said === null || $error instanceof Refused || $error instanceof NotSignedIn || $error instanceof CallError) {
            return $error;
        }
        $code = $said->code();
        return match (true) {
            ($refused = self::refusal($error)) !== null => $refused,
            $code !== null && isset(CallError::CODES[$code]) => new CallError($said->message, $code, $error),
            // a login refused (AZ703) and settings changed by hand (AZ702) share its SQLSTATE, and are no such thing
            self::notSignedIn($error) => new NotSignedIn($error),
            default => $error,
        };
    }

    /**
     * A Refused for an error that is the database refusing a write (SQLSTATE 42501, raised by rowstile's policies
     * with the rule and why, or Postgres's own words for a check no rule's refusal covers), else null. Another 42501
     * (a table the app role was never granted) is the app's mistake, not a refusal.
     */
    public static function refusal(Throwable $error): ?Refused
    {
        if ($error instanceof Refused) {
            return $error;
        }
        $said = Said::of($error);
        if ($said === null || $said->sqlstate !== '42501') {
            return null;
        }
        $generic = preg_match('/^(new|target) row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"/', $said->message, $m) === 1;
        if ($generic) {
            return self::genericRefusal($said->message, $m[1], $m[2] !== '', $m[3], $error);
        }
        $code = $said->code();
        if ($code === null || isset(CallError::CODES[$code])) { // sign in first (AZ714) is a 42501 too, but no refusal
            return null;
        }
        [$table, $command] = self::rule($said->message);
        return new Refused($said->message, $table, $command, $said->detail === null ? [] : explode("\n", $said->detail), $code, $error);
    }

    /**
     * The table and the command a refusal names, in the words rowstile's refusals use (pdo_pgsql gives no field
     * that names them): "may not insert this row into app.notes", "may not update this row of app.notes to these
     * values", "changing owner_id of app.folders 7 needs: ..."; [null, null] for a refusal that names no rule.
     *
     * @return array{?string, ?string}
     */
    private static function rule(string $message): array
    {
        if (preg_match('/ may not insert this row into (\S+)$/', $message, $m) === 1) {
            return [$m[1], 'insert'];
        }
        if (preg_match('/ may not update this row of (\S+) to these values$/', $message, $m) === 1) {
            return [$m[1], 'update'];
        }
        if (preg_match('/^changing .+? of (\S+) .* needs: /', $message, $m) === 1) {
            return [$m[1], 'update'];
        }
        return [null, null];
    }

    private static function genericRefusal(string $message, string $row, bool $existing, string $table, Throwable $error): Refused
    {
        if ($row === 'target') { // MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
            return new Refused("{$message}: MERGE matched a row the update or delete rule doesn't let this user change", $table, null, [], 'AZ709', $error);
        }
        if ($existing) { // an upsert whose existing row this user may not update, or not see
            return new Refused("{$message}: the row is there already, and the update rule (or the select rule) doesn't "
                .'let this user change it (ON CONFLICT DO UPDATE)', $table, 'update', [], 'AZ709', $error);
        }
        // the select rule, on the row as written: an insert that reads it back, an upsert, or an update after which the
        // row would be out of this user's sight
        return new Refused("{$message}: ".self::UNSEEN, $table, 'select', [], 'AZ709', $error);
    }

    /**
     * The problem body for an error, or null when it is none of rowstile's answers (the app's to answer, a 500): a
     * refusal 403, a hidden row 404, and a call the database turned down as its code's page says (AZ703, AZ714: 401;
     * AZ708: 404; AZ710: 400; AZ713: 409), with the database's words. The not-signed-in error, a share the policy
     * doesn't declare, a name not in the policy and who is signed in changed by hand are the app's mistakes: null.
     */
    public static function problemOf(Throwable $error): ?Problem
    {
        $error = self::translate($error);
        return match (true) {
            $error instanceof Refused, $error instanceof NotFound, $error instanceof CallError => $error->problem(),
            default => null,
        };
    }

    /** rowstile's code for a database error (AZ709: `rowstile help AZ709` says what it means), null for one rowstile didn't raise. */
    public static function errorCode(Throwable $error): ?string
    {
        return Said::of($error)?->code();
    }

    /** The error's SQLSTATE, null for an error that isn't the database's. */
    public static function sqlstate(Throwable $error): ?string
    {
        return Said::of($error)?->sqlstate;
    }

    /**
     * Whether the error is strict sign-in's (rowstile help AZ701): a query that needs to know who is asking ran in a
     * transaction nobody signed in to. A login refused (AZ703) and settings changed by hand (AZ702) share its
     * SQLSTATE, 28000, but are no such thing.
     */
    public static function notSignedIn(Throwable $error): bool
    {
        $said = Said::of($error);
        return $error instanceof NotSignedIn || ($said?->sqlstate === '28000' && in_array($said->code(), [null, 'AZ701'], true));
    }

    /**
     * A value the database gave as text (a text column, JSON): itself, or '' for anything else.
     *
     * @internal
     */
    public static function text(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
