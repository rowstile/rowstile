<?php

declare(strict_types=1);

namespace Rowstile;

use BackedEnum;

/**
 * A permission of a type the policy declares, as `rowstile client php` writes them: Authz\NotePermission::Edit, a
 * case of an enum whose objectType() is "note". A plain string is none, so a misspelled name fails PHPStan, and PHP
 * when the line runs.
 */
interface Permission extends BackedEnum
{
    /** The type the enum's permissions are of: note. */
    public static function objectType(): string;
}
