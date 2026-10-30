<?php

declare(strict_types=1);

namespace Rowstile;

use RuntimeException;
use Throwable;

/**
 * A call the database turned down that is no refusal, with the status its code's page gives (`rowstile help AZ708`):
 * a login refused or a call that needs someone signed in 401 (AZ703, AZ714), something it names that isn't there 404
 * (AZ708), an argument missing or wrong 400 (AZ710), a move inside itself 409 (AZ713). Its message is the database's
 * words.
 */
final class CallError extends RuntimeException
{
    /** The codes, and the problem type, title and status their pages give. */
    public const CODES = [
        'AZ703' => ['not-signed-in', 'Unauthorized', 401],
        'AZ708' => ['not-found', 'Not Found', 404],
        'AZ710' => ['bad-argument', 'Bad Request', 400],
        'AZ713' => ['conflict', 'Conflict', 409],
        'AZ714' => ['not-signed-in', 'Unauthorized', 401],
    ];

    /** @param key-of<self::CODES> $rowstileCode */
    public function __construct(string $message, public readonly string $rowstileCode, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    public function status(): int
    {
        return self::CODES[$this->rowstileCode][2];
    }

    /** Its problem body, with the database's words and the code. */
    public function problem(): Problem
    {
        [$type, $title, $status] = self::CODES[$this->rowstileCode];
        return new Problem($type, $title, $status, $this->getMessage(), $this->rowstileCode);
    }
}
