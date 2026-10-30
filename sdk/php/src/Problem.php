<?php

declare(strict_types=1);

namespace Rowstile;

use JsonSerializable;

/**
 * An RFC 9457 problem body (application/problem+json), as every rowstile SDK answers: a refusal's (403, with its
 * table, command, why and code), a hidden row's (404), or a call the database turned down (with its code). Its type
 * is https://rowstile.dev/problems/<kind>.
 */
final class Problem implements JsonSerializable
{
    public const TYPE = 'https://rowstile.dev/problems/';

    /** @param array<string, mixed> $extra a refusal's table, command and why */
    public function __construct(
        public readonly string $kind,
        public readonly string $title,
        public readonly int $status,
        public readonly string $detail,
        public readonly ?string $code = null,
        public readonly array $extra = [],
    ) {
    }

    /**
     * The body, its members in the other SDKs' order: type, title, status, detail, then a refusal's table, command
     * and why, and the code.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $body = ['type' => self::TYPE.$this->kind, 'title' => $this->title, 'status' => $this->status, 'detail' => $this->detail];
        return [...$body, ...$this->extra, ...($this->code === null ? [] : ['code' => $this->code])];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
