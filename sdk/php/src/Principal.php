<?php

declare(strict_types=1);

namespace Rowstile;

/**
 * Who a transaction acts for: a user (type "user"), another principal type the policy declares (a service, a bot),
 * or nobody (id null: only what `anyone` may see).
 *
 *     Principal::user(42); Principal::of('service', 3); Principal::nobody();
 */
final class Principal
{
    private function __construct(public readonly string $type, public readonly ?string $id)
    {
    }

    /** The user whose id this is, whatever it holds ("service:3" too: ids come from outside). */
    public static function user(int|string $id): self
    {
        return new self('user', (string) $id);
    }

    /** A principal of another type the policy declares: Principal::of('service', 3). */
    public static function of(string $type, int|string $id): self
    {
        return new self($type, (string) $id);
    }

    /** No one signed in: only what `anyone` may see. */
    public static function nobody(): self
    {
        return new self('user', null);
    }

    /** A Principal as it is, a user's id (42, "42"), or null for nobody. */
    public static function from(self|int|string|null $who): self
    {
        return match (true) {
            $who instanceof self => $who,
            $who === null => self::nobody(),
            default => self::user($who),
        };
    }

    /** Whether this is the same principal as $other. */
    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id;
    }

    public function isNobody(): bool
    {
        return $this->id === null;
    }

    /**
     * authz.act_as's arguments: ['user', '42'], or [null, null] for nobody.
     *
     * @return array{?string, ?string}
     */
    public function actAsArguments(): array
    {
        return $this->id === null ? [null, null] : [$this->type, $this->id];
    }
}
