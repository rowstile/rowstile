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
   A session limited by scopes makes, and revokes, only a key no wider than itself: one that has scopes, each
   of them the session's (AZ704 otherwise). <!-- checked: tests/identity.sh "a session limited to a scope cannot make a key with another"; tests/identity.sh "a session limited to a scope cannot revoke its user's key with every scope"; tests/identity.sh "... nor one with another scope"; tests/identity.sh "... it revokes a key with its own scopes (itself), and the other is as it was" -->
   Pass the key as a parameter (`SELECT authz.login_key($1)`, as the generated clients do), not
   written into the statement, or it ends up in the server's statement log; the same for a JWT.
   `authz.login_key(key)` works in read-only transactions too (a replica), and requests with
   the same key never wait for each other: when a key was last used (`last_used_at`) is kept to
   the minute, and not by read-only transactions. <!-- checked: tests/identity.sh "a key signs in to a read-only transaction (a replica, a GET)"; tests/identity.sh "and requests with one key don't wait for each other"; tests/identity.sh "last_used_at is kept, to the minute" -->
3. **JWTs** from your identity provider: `authz.login_jwt(token)` checks the token's
   signature (HS256 with a secret, or RS256 with the provider's keys, below), a required `exp` and optional `nbf`, and the issuer and the audience once the settings
   `jwt_issuer` and `jwt_audience` name them (a token that names none is then refused); a `scope` claim limits
   the transaction. <!-- checked: tests/identity.sh "wrong signature"; tests/identity.sh "alg none"; tests/identity.sh "no expiry"; tests/identity.sh "not valid yet (nbf in an hour)"; tests/identity.sh "another issuer"; tests/identity.sh "a token that names no issuer, once one is asked"; tests/identity.sh "a token for no audience, once one is asked"; tests/identity.sh "a valid token signs in as bob, with its scope" -->
   The settings are rows of `authz.settings`, which the owner writes and the app role
   can't read: <!-- checked: tests/sessions.sh "the key is out of the app role's reach"; tests/reference.sh "the settings identity.md sets: a token signed with that secret, from that issuer, signs in" -->

   ```sql
   INSERT INTO authz.settings VALUES ('jwt_secret', '...'), ('jwt_issuer', 'https://id.example')
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
   ```

   `jwt_secret` is the secret your identity provider signs HS256 tokens with, and HS256 asks for 32 random
   bytes or more (RFC 7518): a short one can be guessed from any token. With no secret and no stored keys,
   `login_jwt` signs nobody in. <!-- checked: tests/identity.sh "no secret and no keys, no JWT login" -->
   The other settings: `jwt_audience`, `jwt_user_claim` (the claim that holds
   the user's id, `sub` by default) and `jwt_type_claim` (below).

   **A provider that signs with a key pair** (RS256) serves its public keys as a key set (a JWKS, RFC 7517).
   The owner stores the set, and `login_jwt` checks an RS256 token against the key its `kid` names: <!-- checked: tests/reference.sh "the key set identity.md stores: a token signed by that key, naming it, signs in" -->

   ```sql
   SELECT * FROM authz.set_jwks('{"keys": [{"kty": "RSA", "kid": "2026-11", "n": "...", "e": "AQAB"}]}');
   ```

   The set replaces the stored one, and a row for each key says what became of it: `added`, `replaced` (its
   `kid` has another key now), `kept`, `removed` (it left the set), or `skipped` and why. <!-- checked: tests/identity.sh "the owner stores the provider's key set: each key added, or skipped and why"; tests/identity.sh "the next key set replaces the stored one: a key that left is removed, one that stays is kept"; tests/identity.sh "a kid given another key: replaced" -->
   Stored are RSA keys for signatures, of 2048 to 4096 bits, with the exponent 65537. <!-- checked: tests/identity.sh "a key under 2048 bits signs nothing here"; tests/identity.sh "an exponent other than 65537 is refused" -->
   Store the set again when the provider's keys change: from then on, a token signed by a key that left the
   set is refused. <!-- checked: tests/identity.sh "a token signed by a key that left the set" -->
   The database fetches nothing itself. `rowstile jwks https://id.example/.well-known/jwks.json` fetches the
   set from the provider and stores it, for a scheduled job or a deploy step, and with `--check` says whether
   the stored keys are still the provider's ([Tools](tools.md)). <!-- checked: tests/cli.sh "jwks stores the key set the provider serves: each key added, or skipped and why"; tests/cli.sh "once stored: nothing would change, exit 0" -->
   A set that leaves no key is refused, saying why each key was skipped, and the stored keys stay (AZ719): a
   fetch that failed signs nobody out. <!-- checked: tests/identity.sh "a key set that leaves no key is refused"; tests/identity.sh "... saying why each key was skipped"; tests/identity.sh "... and the stored keys stay as they were" -->
   `authz.set_jwks` is the owner's, as the settings are: whoever stores a key signs in as anyone. The app
   role can't call it or read the keys, and the audit trail says when the keys were set. <!-- checked: tests/identity.sh "the app role cannot store keys"; tests/identity.sh "... nor read them"; tests/identity.sh "the audit trail says the keys were set, and which" -->

   What a token says of itself (`alg`) chooses its check, and nothing else does. An HS256 token is checked
   against `jwt_secret` alone and an RS256 token against the stored keys alone, so a public key, which anyone
   has, is never taken for the secret. <!-- checked: tests/identity.sh "an HS256 token signed with the public key as its secret"; tests/identity.sh "a token that says RS256, signed with the secret"; tests/identity.sh "alg none, naming a stored key" -->
   A token whose `kid` names no stored key is refused, and one that names no key is checked against the
   stored key when there is one only. <!-- checked: tests/identity.sh "a token that names a key nobody stored"; tests/identity.sh "a token that names no key, with one stored: checked against that one"; tests/identity.sh "an RS256 token that names no key, with two stored" -->
   The signature is checked in plain SQL, which takes a few milliseconds a sign-in, more with a longer key
   ([Limits](limits.md)). A connection checks a token's signature once: `login_jwt` leaves a note of the check
   in a setting of the connection (`authz.checked_tokens`), and the same token signing in there again costs
   what an HS256 token does. <!-- checked: tests/sessions.sh "a token's first sign-in on a connection leaves its note there, and its next one adds none"; tests/sessions.sh "the same token signing in again on a connection costs under a quarter of its first sign-in" -->
   A note says what the check did, that this key signed this token, and no more: the token's time, issuer,
   audience and user are read at every sign-in. <!-- checked: tests/sessions.sh "a token with a note is still held to the issuer asked for, at every sign-in" -->
   The app role may read and set that setting, as any, so a note is believed only as the database made it,
   with the key that signs sessions: for that token, that key and that connection. <!-- checked: tests/sessions.sh "... nor one made up: the token's hash, hashes of what the app role knows"; tests/sessions.sh "a note copied from another connection is not believed"; tests/sessions.sh "a note kept after its kid was given another key is not believed"; tests/sessions.sh "... nor one kept after its key left the set" -->
   A connection keeps the notes of the 64 tokens it checked last, from the commit of the transaction that
   checked each (a pooler's connection serves many tokens). <!-- checked: tests/sessions.sh "65 tokens on one connection: the newest 64 notes are kept, and the first token's is made again"; tests/sessions.sh "... and a note made in a transaction that is rolled back goes with it, as any setting" -->
   Tokens signed another way (ES256, EdDSA) aren't checked in the database: check
   them in your backend, and sign in with `authz.act_as`. <!-- checked: tests/identity.sh "a token that says ES256: neither a secret nor a stored key checks it" -->

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
They name a user by their id (`42`), or as `user:<id>` when the id holds `:` or is `nobody` (`user:service:7`), so
no user reads as a service or as nobody; the SDKs write a principal the same way, and read these back. <!-- checked: tests/principals.sh "the audit trail names them the same way, each as itself"; tests/principals.sh "the user whose id is service:1 shares: created_by says user:service:1"; tests/principals.sh "... and the user whose id is nobody: user:nobody"; tests/principals.sh "... a user whose id is plain stays their id: 42" -->
`authz.who` lists users. <!-- checked: tests/principals.sh "authz.who lists users" -->
Some calls are for users only: the custom roles API (`create_role`, `set_role_permissions`, `delete_role`,
`roles_of`), access requests (`request_access`, `pending_requests`, `decide_request`, `cancel_request`),
access reviews (`start_review`, `review_items`, `review_decide`, `close_review`), `break_glass`, a key for
oneself (`create_api_key` without a principal) and `view_as`. <!-- checked: tests/principals.sh "authz.create_role is for users: a service is told so"; tests/principals.sh "authz.set_role_permissions is for users: a service is told so"; tests/principals.sh "authz.delete_role is for users: a service is told so"; tests/principals.sh "authz.roles_of is for users: a service is told so"; tests/principals.sh "authz.request_access is for users: a service is told so"; tests/principals.sh "authz.pending_requests is for users: a service is told so"; tests/principals.sh "authz.decide_request is for users: a service is told so"; tests/principals.sh "authz.cancel_request is for users: a service is told so"; tests/principals.sh "authz.start_review is for users: a service is told so"; tests/principals.sh "authz.review_items is for users: a service is told so"; tests/principals.sh "authz.review_decide is for users: a service is told so"; tests/principals.sh "authz.close_review is for users: a service is told so"; tests/principals.sh "authz.break_glass is for users: a service is told so"; tests/principals.sh "authz.create_api_key for oneself is for users: a service is told so"; tests/principals.sh "authz.view_as is for users: a service is told so" -->
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

**Every sign-in is signed**. `act_as`, the logins and `view_as` put an HMAC in `authz.session`, over
who is signed in, the scopes, the backend and the transaction, with a key the app role can't read. <!-- checked: tests/sessions.sh "the key is out of the app role's reach"; tests/sessions.sh "and so is the signing"; tests/sessions.sh "view_as signs who it shows" -->
The
settings are believed only with it, so nothing but rowstile's own functions (`act_as`, the logins, `view_as`,
`sign_out`, and `who`, `explain` and the like for the length of their call) can say who is signed in, with which
scopes, viewing as whom, on any Postgres: setting `authz.user_id` is an error, and so is
a signature from another transaction or connection. <!-- checked: tests/sessions.sh "and so is a user set directly"; tests/sessions.sh "settings that differ never sign alike"; tests/sessions.sh "clearing its scopes is an error, not a way to write"; tests/sessions.sh "authz.acting_user too"; tests/sessions.sh "a signature from an earlier transaction is refused in the next one"; tests/sessions.sh "and one from another connection too" -->
A signature is for its transaction: what an earlier sign-in of the same transaction signed, put back with that
signature, is believed again (the transaction as it was before a `view_as`, say). The backend, which may sign
out and in, gets nothing more from it. <!-- checked: tests/sessions.sh "an earlier sign-in of the same transaction, put back with its signature, is believed"; tests/sessions.sh "... but not with the user view-as shows" -->
A transaction in which nobody signed in gets an error
too, not an empty result (`act_as(NULL, NULL)` says "nobody" on purpose). <!-- checked: tests/sessions.sh "but nobody signed in is an error, not an empty result"; tests/sessions.sh "act_as(NULL, NULL): nobody, on purpose, no error" -->
Sessions of the policy's owner
and superusers are believed without a signature (psql, migrations, tests). <!-- checked: tests/sessions.sh "the owner's session sets authz.user_id and is believed" -->
[`core/tests/sessions.sh`](../../core/tests/sessions.sh) checks all
of it, on the stock Postgres image.

**A transaction is one principal's**. Once someone is signed in, `act_as`, `login_key` and `login_jwt` refuse to
sign the transaction in as anyone else, nobody included (AZ716). <!-- checked: tests/sessions.sh "act_as in a transaction signed in as carol, for alice: refused"; tests/sessions.sh "and for nobody: refused too"; tests/sessions.sh "login_key in a transaction signed in as carol, with alice's key: refused"; tests/sessions.sh "login_jwt in a transaction signed in as carol, with alice's token: refused"; tests/sessions.sh "with its code, AZ716" -->
While the transaction views as someone or is limited by scopes, they refuse to sign it in again at all, even as
the same principal: that would end what limits it. <!-- checked: tests/sessions.sh "act_as after a key's sign-in limited by scopes, even as its user: refused"; tests/sessions.sh "act_as while viewing as someone, even as the one viewed: refused" -->
A first sign-in after `act_as(NULL, NULL)` is fine, and so is the same principal again (a key of theirs too,
whose scopes then limit the transaction). A refusal caught at a savepoint leaves the transaction as it was. <!-- checked: tests/sessions.sh "nobody, then carol: a sign-in, no error"; tests/sessions.sh "nobody, then a key's sign-in: no error"; tests/sessions.sh "nobody, then a token's sign-in: no error"; tests/sessions.sh "the same principal again: no error"; tests/sessions.sh "carol, then her own read-only key: no error, and read-only"; tests/sessions.sh "refused at a savepoint, the transaction goes on as carol" -->
`view_as` isn't held to it (it is read-only, with a reason on record), nor are rowstile's own functions that ask
as others and put back the caller (`who`, `explain`, `who_among`, the invariants). <!-- checked: tests/sessions.sh "view_as signs who it shows"; tests/sessions.sh "who_among asks each one in turn"; tests/sessions.sh "and leaves carol signed in"; tests/sessions.sh "explain for carol, then alice again" -->
A test's transaction that acts for one person, then another (rolled back at the end), calls `authz.sign_out()`
between them: nobody is signed in then, as after `act_as(NULL, NULL)`, and the next sign-in may be anyone. The
SDKs' test modes do it. <!-- checked: tests/sessions.sh "sign_out, then alice: a test's transaction acting for one, then another"; tests/sessions.sh "and signed out, nobody is signed in"; tests/sessions.sh "which ends view-as and scopes too" -->
Sessions of the policy's owner and superusers, which may say who is signed in by hand, aren't held to it. <!-- checked: tests/sessions.sh "the owner's session signs in one, then another" -->
The SDKs refuse such a sign-in earlier, in their own words, before anything is sent ([App code](app-code.md)).

**Is the session limited?** `authz.session_limited()` is true while the transaction is limited, by a key's or a
token's scopes or by viewing as someone, and false for a plain sign-in, a key without scopes and nobody. <!-- checked: tests/sessions.sh "session_limited: a plain sign-in isn't limited"; tests/sessions.sh "session_limited: nobody signed in isn't either"; tests/sessions.sh "session_limited: a key without scopes isn't"; tests/sessions.sh "session_limited: a key with scopes is"; tests/sessions.sh "session_limited: viewing as someone is" -->
An app asks it before it serves what scopes can't limit, such as a sync engine's shapes
([Electric's route](sync.md#the-route-electricshape) refuses such a session). <!-- checked: integrations/electric/tests/shapes.test.ts "E15: a session limited by scopes is refused, 403"; integrations/electric/tests/proxy.test.ts "E15: viewing as someone is a session limited too: refused" -->
Like the rest, it believes the settings only when they are signed: settings set by hand are an error, as in any
other read. <!-- checked: tests/sessions.sh "session_limited: settings set by hand aren't believed, an error"; tests/sessions.sh "session_limited: ... nor scopes cleared after a key's sign-in" -->

**Signing in turns JIT off** until the transaction ends (`act_as`, the logins and `view_as`). The rules' lookups
are hashed once per read but estimated once per row, so a read of a few thousand rows through them passes
Postgres's `jit_above_cost`, and JIT spends most of a second compiling a read that runs in a few milliseconds
([Speed and limits](limits.md)). The next transaction has the session's own setting again, and the app may turn
JIT back on after signing in (`SET LOCAL jit = on`). <!-- checked: tests/sessions.sh "signing in turns JIT off until the transaction ends"; tests/sessions.sh "and the next transaction has the session's own setting"; tests/sessions.sh "which the app may turn back on after signing in"; tests/identity.sh "and turns JIT off for the transaction" -->

Who may call `act_as`: the app role and its members (the policy grants it), so a compromised app can still
choose users. <!-- checked: tests/sessions.sh "a role that isn't the app role can't act_as"; tests/sessions.sh "authz.act_as signs carol in: she sees her files" -->
Keep the app role's credentials in the backend.

## Users and groups from an identity provider (SCIM)

An identity provider (Okta, Microsoft Entra ID) writes its directory's users and groups to an app by sending SCIM
requests (RFC 7644), and the database answers them: `authz.scim(method, path, query, body, token)` takes a
request's parts and answers a `status`, a `body` and a `location`. The app's part is a route that passes on the
request's method, its path below the route (`Groups/10`), its query string and its body as they were sent and its
bearer token, and answers what comes back. The Python SDK has that route for FastAPI
([FastAPI](../stacks/fastapi.md#users-and-groups-from-an-identity-provider-scim)) and the TypeScript SDK for
Next.js ([Next.js](../stacks/nextjs.md#users-and-groups-from-an-identity-provider-scim)); the other SDKs' routes
are not there yet. A body that is no JSON is answered 400, once the key says who asks. <!-- checked: tests/scim.sh "a body that is no JSON"; tests/scim.sh "without the provider's key such a body is not read: the key is refused" -->

**The owner says what the endpoint reads**, in one call that replaces the stored settings (`'{}'` turns the
endpoint off): <!-- checked: tests/scim.sh "the next settings replace the stored ones: a setting left out is gone"; tests/scim.sh "with no settings the endpoint is nobody's: the provider's key is refused"; tests/reference.sh "the settings identity.md gives the endpoint: the provider's key finds a team by its name, and adds a member to it" -->

```sql
SELECT authz.set_scim('{
  "principal": "user:1",
  "group": "team.member", "group_name": "name",
  "user_name": "name"
}');
```

- `principal`: whose API key signs the provider in, as `type:id`: a user the app holds for the provider, or a row
  of a type that signs in (a service, above). The provider's bearer token is an API key of that principal, made as
  any of its keys is (`authz.create_api_key`).
- `group`: the groups, as `type.relation`: a relation `authz.sync_members` takes ([App code](app-code.md)).
  `group_name` and `group_external_id` name the columns of the groups' table that hold a group's `displayName` and
  its `externalId`.
- `user_name`, `user_external_id` and `user_active`: the columns of the users' table that hold a user's `userName`,
  its `externalId` and whether it is active (a boolean).
- `user_resource`: a jsonb column where the app's function puts the user as the provider wrote it. A GET then
  answers that, with what the three columns say now. <!-- checked: tests/scim.sh "... and a GET answers what the provider wrote, from the column the settings name for it" -->
  Name one: without it a user is what the three columns say, and Microsoft Entra ID's validator checks that
  "Returned values from GET match the passed values from the POST request" (Microsoft's provisioning docs, read
  2026-11-16).
- `group_function` and `user_function`: the app's functions that make, change and delete a group and a user
  (below).
- `page`: the most a list answers. <!-- checked: tests/scim.sh "a list answers a page at most (the setting page, 3 here), and says how many there are" -->

Each setting is checked when set (AZ720), and `authz.lint()` says when one no longer holds (a column dropped, a
function given to another role): a request that meets it is an error (AZ722). <!-- checked: tests/scim.sh "a column the settings name that is gone"; tests/scim.sh "a function that is gone"; tests/scim.sh "a function the settings name that another role owns now" -->
`authz.set_scim` is the owner's, as the principal it names writes users and groups: the app role can't call
it. <!-- checked: tests/scim.sh "the app role cannot set the endpoint up" -->

**The app's functions make the rows.** Users and groups are rows of the app's own tables, with columns rowstile
doesn't know, so the app gives a function for each, `(p_id text, p_resource jsonb) RETURNS text`: the row's key
and the user or the group as the request leaves it come in, and the key goes out. A NULL `p_id` is a row to make,
a NULL `p_resource` one to delete. The function runs as the owner, so it is the owner's own: one that another
role owns is refused when set, and is an error from then on if it is given away later. <!-- checked: tests/scim.sh "... and one another role owns, which could then run its own code as the owner"; tests/scim.sh "a function the settings name that another role owns now" -->
The function says no by raising: a row whose key or name another row has (a unique constraint) is answered 409,
and what the function raises itself, or a constraint refuses, 400, each with the database's words. <!-- checked: tests/scim.sh "a group whose name another has: 409, uniqueness, with the database's words"; tests/scim.sh "a group the app's function refuses: 400, with its words" -->
With no function, a request that makes or deletes a user or a group, changes a user or renames a group is
answered 501. A group's members are written all the same, and the users and the groups the app has are read and
matched. <!-- checked: tests/scim.sh "with no function, a group can't be made"; tests/scim.sh "... nor a PATCH that changes the name"; tests/scim.sh "with no function, a user can't be made"; tests/scim.sh "... nor changed" -->
A user comes as a POST's or a PUT's body, or as a PATCH's operations applied to the user as it is, never with a
password (Okta's docs: "Okta sends the `password` parameter in a create user request, even if password sync isn't
enabled"). <!-- checked: tests/scim.sh "Entra ID makes a user: 201, the user as it wrote it, where it is"; tests/scim.sh "Entra ID changes the userName (op Replace, the path userName)"; tests/scim.sh "... nor given to the app's function, which kept the rest" -->
A request may say less of a user than the app has (a PUT without an email, a PATCH of a user the app made by
itself): write the function so that what `p_resource` says nothing of stays, `coalesce(p_resource->>'displayName',
name)`. The stack pages each show one.

**Groups** are read, listed, found by `displayName`, `externalId` or `id`, patched (members added, removed and
replaced, as Microsoft Entra ID and Okta write a PATCH), replaced, and made, renamed and deleted through the
app's function. <!-- checked: tests/scim.sh "a group found by its displayName, the query string as it is sent"; tests/scim.sh "one PATCH that adds a member and removes another"; tests/scim.sh "a PUT with the group's name and its members: answered with the group"; tests/scim.sh "Entra ID renames a group (op Replace, the path displayName)"; tests/scim.sh "a group deleted: 204, no body" -->
Members are written as `authz.sync_members` writes them, with its line in the audit trail, the provider's
principal as who did it. <!-- checked: tests/scim.sh "... changes the rows as authz.sync_members would, in one line of the audit" -->

**Users** are read, listed and found by `userName`, `externalId` or `id`, and made, changed and deleted through
the app's function. <!-- checked: tests/scim.sh "a user found by its id"; tests/scim.sh "Okta asks whether a user is there before it makes one"; tests/scim.sh "a user deleted: 204, no body" -->
A user the provider deactivates stays, answered as not active: what such a user may do is the policy's to say
(`type user = app.users where {active}` makes one nobody). A `userName` another user has is answered 409. <!-- checked: tests/scim.sh "Okta deactivates a user (op replace, no path, active false in the value)"; tests/scim.sh "... and the policy follows (type user ... where {active}): bob reads nothing now"; tests/scim.sh "the same user made again: 409, uniqueness" -->

**A list answers a page**: `startIndex` and `count` as the provider sends them, the setting `page` at most, with
how many there are in all. `ServiceProviderConfig`, `ResourceTypes` and `Schemas` say what the endpoint serves:
PATCH and filters; no Bulk, no sorting, no ETags, no password change, no `/Me`, no search by POST, each answered
501. <!-- checked: tests/scim.sh "the next page"; tests/scim.sh "a startIndex under 1 is 1, and a count over the setting page is the page"; tests/scim.sh "what it serves: PATCH and filters (the page at most); no Bulk, no sorting, no ETags, no password change; a bearer token"; tests/scim.sh "the resource types: users and groups, where each is served and its schema"; tests/scim.sh "Bulk is not served"; tests/scim.sh "... nor /Me" -->

**The key alone says who asks.** The app role may call `authz.scim`, and nothing in it trusts the caller: a
request whose token isn't a key of the settings' principal is answered 401, and a key limited to scopes that write
nothing only reads. <!-- checked: tests/scim.sh "no bearer token"; tests/scim.sh "another service's key"; tests/scim.sh "a key limited to reading reads"; tests/scim.sh "... and changes nothing" -->
An answered request's transaction is signed in as that principal, as `authz.login_key` signs one in, so call
`authz.scim` in a transaction of its own; a refused one signs nobody in. <!-- checked: tests/scim.sh "an answered one is the principal's: its transaction is signed in as the service"; tests/scim.sh "a refused request signs nobody in" -->
A refusal is an answer with SCIM's error body (AZ721) and changes nothing; a request is done whole or not at
all. <!-- checked: tests/scim.sh "with no function, a group can't be made"; tests/scim.sh "... and the operation before it in the same PATCH changed nothing: a PATCH is whole or not at all" -->
An error stays an error, for the app to see: settings that no longer hold (AZ722), the app's function failing.
The SDKs' routes answer those 500 in SCIM's words and log them.
