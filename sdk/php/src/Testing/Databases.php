<?php

declare(strict_types=1);

namespace Rowstile\Testing;

use InvalidArgumentException;
use PDO;
use PDOException;
use RuntimeException;

use function array_filter, explode, hash, ltrim, parse_url, preg_match, preg_replace, rawurldecode, rawurlencode, sprintf, str_replace, strlen, substr;

/**
 * A test database for each worker, copied from the migrated one (with the policy). Loading a dump into each can't
 * make one: a dump leaves out the grants and the policy's own rows.
 */
final class Databases
{
    /**
     * Copies the database $ownerUrl names (postgresql://owner:secret@host:5432/app_tests) for this worker, made again
     * if an earlier run left one, and gives the copy's name: the original's and the worker's (app_tests_2); a name
     * longer than Postgres's 63 bytes is shortened: its first 54 bytes (fewer, not to cut a character in two), `_`,
     * and the first 8 hex digits of the SHA-256 of the whole name. The copy is made by a role that may create
     * databases (the owner), while nothing is connected to the original.
     */
    public static function copy(string $ownerUrl, string $worker): string
    {
        $template = self::database($ownerUrl);
        $name = self::fitted("{$template}_{$worker}");
        $pdo = self::connect($ownerUrl, 'postgres');
        $ident = static fn (string $s): string => '"'.str_replace('"', '""', $s).'"';
        try {
            $pdo->exec('SET client_min_messages = warning');
            $pdo->exec('DROP DATABASE IF EXISTS '.$ident($name).' WITH (FORCE)');
            $pdo->exec('CREATE DATABASE '.$ident($name).' TEMPLATE '.$ident($template));
        } catch (PDOException $e) {
            if ($e->getCode() !== '55006') {
                throw $e;
            }
            throw new RuntimeException("rowstile: {$template} can't be copied while anything is connected to it: close what holds it (the app, a migration, a console). ({$e->getMessage()})", 0, $e);
        }
        return $name;
    }

    /**
     * A database's name within Postgres's 63 bytes (see copy): Postgres would cut a longer one at 63 bytes, where two
     * workers' names, or a copy's and its original's, can come out the same.
     */
    private static function fitted(string $name): string
    {
        if (strlen($name) <= 63) {
            return $name;
        }
        $cut = substr($name, 0, 54);
        while (preg_match('//u', $cut) !== 1) {
            $cut = substr($cut, 0, -1);
        }
        return $cut.'_'.substr(hash('sha256', $name), 0, 8);
    }

    /** The database a postgresql:// URL names; InvalidArgumentException if it names none. */
    public static function database(string $url): string
    {
        $path = ltrim((string) parse_url($url, PHP_URL_PATH), '/');
        if ($path === '') {
            throw new InvalidArgumentException('rowstile: a database per worker needs a database to copy, and this URL names none');
        }
        return rawurldecode($path);
    }

    /** The URL, naming another database. */
    public static function withDatabase(string $url, string $database): string
    {
        return (string) preg_replace('#^([^/]*//[^/]*)(/[^?]*)?#', '$1/'.rawurlencode($database), $url, 1);
    }

    /**
     * A PDO connection to the database a postgresql:// URL names (or to $database on the same server), with the URL's
     * settings (?sslmode=require&connect_timeout=5: libpq's).
     */
    public static function connect(string $url, ?string $database = null): PDO
    {
        $parts = (array) parse_url($url) + ['host' => 'localhost', 'port' => 5432, 'user' => '', 'pass' => '', 'query' => ''];
        $quoted = static fn (string $value): string => "'".str_replace(['\\', "'"], ['\\\\', "\\'"], $value)."'";
        $dsn = sprintf('pgsql:host=%s;port=%s;dbname=%s', $parts['host'], $parts['port'], $quoted($database ?? self::database($url)));
        foreach (array_filter(explode('&', sprintf('%s', $parts['query'])), static fn (string $s): bool => $s !== '') as $setting) {
            [$key, $value] = explode('=', $setting, 2) + [1 => ''];
            $dsn .= sprintf(';%s=%s', rawurldecode($key), $quoted(rawurldecode($value)));
        }
        $user = rawurldecode(sprintf('%s', $parts['user']));
        return new PDO($dsn, $user, rawurldecode(sprintf('%s', $parts['pass'])), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    }
}
