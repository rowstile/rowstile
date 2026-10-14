# Identity

Three ways to say who is asking, all per transaction:

1. **A trusted backend** calls `SELECT authz.act_as('user', '42')`. Simple, but anything
   that runs as the app role can then claim to be anyone.
2. **API keys** that users create for themselves (`authz.create_api_key`). Only a
   SHA-256 hash of each is stored, with its first ten characters to tell keys apart. <!-- checked: tests/identity.sh "only the key's hash is kept, and its first ten characters" -->
   A key can carry **scopes**: `read` (built in) or the
   policy's own (`scope files = ...`) limit which commands and permissions the
   transaction gets. <!-- checked: tests/identity.sh "read-only key: may view file 11, not edit it"; tests/identity.sh "files key: sees no folders (not in its scope)" -->
   A read-only session can't share, approve, or mint broader keys. <!-- checked: tests/identity.sh "read-only key: cannot share"; tests/identity.sh "read-only key: cannot approve a request"; tests/identity.sh "a read-only session cannot mint a broader key" -->
   Pass the key as a parameter (`SELECT authz.login_key($1)`, as the SDKs and the generated clients do), not
   written into the statement, or it ends up in the server's statement log; the same for a JWT.
   `authz.login_key(key)` works in read-only transactions too (a replica), and requests with
   the same key never wait for each other: when a key was last used (`last_used_at`) is kept to
   the minute, and not by read-only transactions. <!-- checked: tests/identity.sh "a key signs in to a read-only transaction (a replica, a GET)"; tests/identity.sh "and requests with one key don't wait for each other"; tests/identity.sh "last_used_at is kept, to the minute" -->
3. **JWTs** from your identity provider: `authz.login_jwt(token)` checks an HS256
   signature, a required `exp` and optional `nbf`, and the issuer and the audience once the settings
   `jwt_issuer` and `jwt_audience` name them (a token that names none is then refused); a `scope` claim limits
   the transaction. <!-- checked: tests/identity.sh "wrong signature"; tests/identity.sh "alg none"; tests/identity.sh "no expiry"; tests/identity.sh "not valid yet (nbf in an hour)"; tests/identity.sh "another issuer"; tests/identity.sh "a token that names no issuer, once one is asked"; tests/identity.sh "a token for no audience, once one is asked"; tests/identity.sh "a valid token signs in as bob, with its scope" -->
   The settings are rows of `authz.settings`, which the owner writes and the app role
   can't read: <!-- checked: tests/sessions.sh "the key is out of the app role's reach"; tests/reference.sh "the settings identity.md sets: a token signed with that secret, from that issuer, signs in" -->

   ```sql
   INSERT INTO authz.settings VALUES ('jwt_secret', '...'), ('jwt_issuer', 'https://id.example')
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
   ```

   `jwt_secret` is required: without it `login_jwt` signs nobody in. <!-- checked: tests/identity.sh "no secret, no JWT login" -->
   It is the secret your identity
   provider signs with, and HS256 asks for 32 random bytes or more (RFC 7518): a short one can be
   guessed from any token. The other settings: `jwt_audience`, `jwt_user_claim` (the claim that holds
   the user's id, `sub` by default) and `jwt_type_claim` (below).

What a scope leaves a key able to do can be said in the policy's tests: a line with `with scope read`
is checked as a key limited to that scope would be
([the language's tests](language.md), [API keys with scopes](../cookbook/api-keys-with-scopes.md)). <!-- checked: tests/devx.sh "with scope: a line is checked as a key limited to those scopes, and the next line is not" -->

**Services** (principal types) sign in the same three ways. The backend names the type
(`SELECT authz.act_as('service', '7')`);
`authz.create_api_key('deploy', '', NULL, 'service', '7')` makes service 7 a key, for someone
holding `manage_keys` on it (`can manage_keys = owner`); a JWT names the type in the claim the
setting `jwt_type_claim` says. <!-- checked: tests/principals.sh "its owner makes service 7 a key"; tests/principals.sh "someone else may not"; tests/principals.sh "a token for service 8" -->
While a service is signed in, `authz.uid()` is NULL and
`authz.principal()` returns `('service', '7')`; the audit trail and `created_by` say `service:7`. <!-- checked: tests/principals.sh "authz.uid() is no one; authz.principal() is service 7"; tests/principals.sh "it shares as itself: created_by says so"; tests/principals.sh "the audit trail says so too" -->
`authz.who` lists users. <!-- checked: tests/principals.sh "authz.who lists users" -->
Some calls are for users only: the custom roles API (`create_role`, `set_role_permissions`, `delete_role`,
`roles_of`), access requests (`request_access`, `pending_requests`, `decide_request`, `cancel_request`),
access reviews (`start_review`, `review_decide`, `close_review`), `break_glass`, a key for oneself
(`create_api_key` without a principal) and `view_as`. <!-- checked: tests/principals.sh "authz.create_role is for users: a service is told so"; tests/principals.sh "authz.set_role_permissions is for users: a service is told so"; tests/principals.sh "authz.delete_role is for users: a service is told so"; tests/principals.sh "authz.roles_of is for users: a service is told so"; tests/principals.sh "authz.request_access is for users: a service is told so"; tests/principals.sh "authz.pending_requests is for users: a service is told so"; tests/principals.sh "authz.decide_request is for users: a service is told so"; tests/principals.sh "authz.cancel_request is for users: a service is told so"; tests/principals.sh "authz.start_review is for users: a service is told so"; tests/principals.sh "authz.review_decide is for users: a service is told so"; tests/principals.sh "authz.close_review is for users: a service is told so"; tests/principals.sh "authz.break_glass is for users: a service is told so"; tests/principals.sh "authz.create_api_key for oneself is for users: a service is told so"; tests/principals.sh "authz.view_as is for users: a service is told so" -->
A service signed in is refused there, even one the policy gives the permission the call asks for, and the
error says so: "authz.create_role is for users, not services (service 8 is signed in)", AZ715. <!-- checked: tests/principals.sh "service 8 holds manage_roles on team 1"; tests/principals.sh "authz.create_role is for users: a service is told so"; tests/principals.sh "with its code, AZ715"; tests/principals.sh "and nothing changed: the role and the request are as they were" -->
A service shares and unshares as itself, and a user holding `manage_keys` on it makes its keys. <!-- checked: tests/principals.sh "it shares as itself: created_by says so"; tests/principals.sh "its owner makes service 7 a key" -->

**Whoever signs in is a row of their type.** An id the type's table doesn't have (a user deleted since, an id
the app made up) is nobody: `authz.uid()` is NULL and `authz.principal()` returns no row, as for a row that
fails the type's `where`. <!-- checked: tests/principals.sh "an id the user table doesn't have is nobody: no uid, no principal"; tests/principals.sh "a service failing the type's where is nobody" -->
So a deleted user's leftover `owner_id` grants nothing, and an app inserts a new
user's row before it signs in as them. <!-- checked: tests/principals.sh "so a column that still names it grants nothing, nor does user:*"; tests/principals.sh "once the row is there, they are someone" -->
A principal's API keys go with its row: deleting the row, giving it a new id (as its shares do) or emptying its
table deletes them, each with a line in the audit trail, so a row that later has that id signs in with none of
them. <!-- checked: tests/principals.sh "deleting a user deletes their keys"; tests/principals.sh "a service given a new id loses its keys, as its shares"; tests/principals.sh "each in the audit trail"; tests/principals.sh "a new user with the old one's id signs in with none of its keys"; tests/principals.sh "emptying the services' table deletes every service's keys"; tests/children.sh "a bot's keys go when its id changes, inside its partition or to another, and with its row"; tests/children.sh "so a person stored there loses their keys with a new id" -->
A key made while its principal is deleted waits for the delete and is refused; a delete in REPEATABLE READ or
SERIALIZABLE whose snapshot is older than a key made since fails with a serialization error (40001), to retry. <!-- checked: tests/principals.sh "a key made while its user is deleted waits for the delete, then is refused"; tests/principals.sh "and no key is left behind"; tests/principals.sh "a delete with an older snapshot than a key made for the service gets a serialization error" -->
Applying the policy deletes the keys of principals whose rows went while nothing watched them. <!-- checked: tests/principals.sh "applying the policy deletes the keys of a principal whose row is gone" -->

**Every sign-in is signed**. `act_as` and the logins put an HMAC in `authz.session`, over
who is signed in, the scopes, the backend and the transaction, with a key the app role can't read. <!-- checked: tests/sessions.sh "the key is out of the app role's reach"; tests/sessions.sh "and so is the signing" -->
The
settings are believed only with it, so nothing but `act_as` and the logins can change who is signed
in, widen a key's scopes, or leave view-as, on any Postgres: setting `authz.user_id` is an error, and so is
a signature from another transaction or connection. <!-- checked: tests/sessions.sh "and so is a user set directly"; tests/sessions.sh "clearing its scopes is an error, not a way to write"; tests/sessions.sh "authz.acting_user too"; tests/sessions.sh "a signature from an earlier transaction is refused in the next one"; tests/sessions.sh "and one from another connection too" -->
A transaction in which nobody signed in gets an error
too, not an empty result (`act_as(NULL, NULL)` says "nobody" on purpose). <!-- checked: tests/sessions.sh "but nobody signed in is an error, not an empty result"; tests/sessions.sh "act_as(NULL, NULL): nobody, on purpose, no error" -->
Sessions of the policy's owner
and superusers are believed without a signature (psql, migrations, tests). <!-- checked: tests/sessions.sh "the owner's session sets authz.user_id and is believed" -->
`core/tests/sessions.sh` checks all
of it, on the stock Postgres image.

**Signing in turns JIT off** until the transaction ends (`act_as`, the logins and `view_as`). The rules' lookups
are hashed once per read but estimated once per row, so a read of a few thousand rows through them passes
Postgres's `jit_above_cost`, and JIT spends most of a second compiling a read that runs in a few milliseconds
([Speed and limits](limits.md)). The next transaction has the session's own setting again, and the app may turn
JIT back on after signing in (`SET LOCAL jit = on`). <!-- checked: tests/sessions.sh "signing in turns JIT off until the transaction ends"; tests/sessions.sh "and the next transaction has the session's own setting"; tests/sessions.sh "which the app may turn back on after signing in"; tests/identity.sh "and turns JIT off for the transaction" -->

Who may call `act_as`: the app role and its members (the policy grants it), so a compromised app can still
choose users. <!-- checked: tests/sessions.sh "a role that isn't the app role can't act_as"; tests/sessions.sh "authz.act_as signs carol in: she sees her files" -->
Keep the app role's credentials in the backend.
