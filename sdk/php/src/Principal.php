<?php

declare(strict_types=1);

namespace Rowstile;

use function str_contains, str_starts_with, strpos, substr;

/**
 * Who a transaction acts for: a user (type "user"), another principal type the policy declares (a service, a bot),
 * or nobody (id null: only what `anyone` may see). Nobody has one spelling: a principal made without an id (''),
 * whatever its type, is nobody, as the database signs it in.
 *
 *     Principal::user(42); Principal::of('service', 3); Principal::nobody();
 */
final class Principal implements \Stringable
{
    private function __construct(public readonly string $type, public readonly ?string $id)
    {
    }

    /** The user whose id this is, whatever it holds ("service:3" too: ids come from outside); nobody for ''. */
    public static function user(int|string $id): self
    {
        return self::of('user', $id);
    }

    /** A principal of another type the policy declares: Principal::of('service', 3); nobody without an id (''). */
    public static function of(string $type, int|string $id): self
    {
        return $id === '' ? self::nobody() : new self($type, (string) $id);
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

    /**
     * What __toString() wrote, read back: "service:3" is service 3, "42" and "user:42" user 42, "nobody" nobody. For
     * text your own code wrote (a job's argument) and for who acted in the audit trail (its user_id, a share's
     * created_by), which the database writes the same way; not for an id that came from outside (user()).
     */
    public static function parse(string $text): self
    {
        if ($text === 'nobody') {
            return self::nobody();
        }
        $colon = strpos($text, ':');
        if ($colon !== false && $colon > 0 && !str_starts_with($text, '(')) {
            return self::of(substr($text, 0, $colon), substr($text, $colon + 1));
        }
        return self::user($text);
    }

    /**
     * As every SDK writes a principal, and as the audit trail and created_by name who acted: "42" for a user,
     * "service:3", or "nobody"; a user whose id holds ":" or is "nobody" is "user:<id>" ("user:a:b"), so that parse()
     * reads every principal back as itself.
     */
    public function __toString(): string
    {
        $id = $this->id;
        if ($id === null) {
            return 'nobody';
        }
        if ($this->type !== 'user') {
            return "{$this->type}:{$id}";
        }
        return str_contains($id, ':') || $id === 'nobody' ? "user:{$id}" : $id;
    }

    /** Whether this is the same principal as $other. */
    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id;
    }

    /** As the database's refusals name it: "user 42", "service 3", or "nobody". */
    public function name(): string
    {
        return $this->id === null ? 'nobody' : "{$this->type} {$this->id}";
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
