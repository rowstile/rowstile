<?php

declare(strict_types=1);

namespace Rowstile\Laravel;

use Illuminate\Database\PostgresConnection;

/**
 * Laravel's Postgres connection, signing in every transaction it runs while the code acts for someone
 * (Rowstile::current(): a request, a job, Rowstile::actingAs()), before the transaction's first statement. A statement
 * outside a transaction is a transaction of its own (BEGIN, the sign-in, the statement, COMMIT), as Postgres would run
 * it alone. A transaction is one principal's: once it is signed in, a statement while the code acts for someone else,
 * or for no one, is refused before it is sent (a LogicException, Rowstile::signedInAlready), the transaction as it
 * was. While the code acts for no one (the owner's migrations, an artisan command) nothing is signed in, and the
 * database refuses what needs to know who asks (AZ701). A sign-in lasts one transaction, so a persistent connection
 * carries no one into the next request. The service provider makes every pgsql connection one (SignsIn: for another
 * package's connection class).
 */
class Connection extends PostgresConnection
{
    use SignsIn;
}
