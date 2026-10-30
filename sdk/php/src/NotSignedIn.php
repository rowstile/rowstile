<?php

declare(strict_types=1);

namespace Rowstile;

use LogicException;
use Throwable;

/**
 * A query that needs to know who is asking ran in a transaction nobody signed in to (rowstile help AZ701): the app's
 * bug, not the user's doing. Every transaction must begin with authz.act_as(), as Rowstile::transaction() and the
 * Laravel connection do.
 */
final class NotSignedIn extends LogicException
{
    public function __construct(Throwable $previous)
    {
        parent::__construct('a query ran in a transaction nobody signed in to: every transaction must begin with '
            .'authz.act_as() (Rowstile::transaction() does it, and the Laravel connection while the code acts for '
            .'someone: a request, a job, Rowstile::actingAs()): '.$previous->getMessage(), 0, $previous);
    }
}
