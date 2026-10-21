# rowstile

Access rules for Postgres: developers write them in a policy language, the `rowstile` command compiles them, and the database enforces them with row-level security, using permission data that already lives in its tables.

## Language

### Policy

**Policy**:
The `.authz` files that say who may do what; compiled and applied to one database as a whole.
_Avoid_: config, schema, model

**Object**:
A row of an application table that the policy declares as a type, such as one folder or one file.
_Avoid_: resource, entity

**Subject**:
Whoever holds a relation on an object: a principal, a group's members (`team#member`), every signed-in principal of a type (`user:*`, `service:*`), anyone, or a link holder.
_Avoid_: actor, grantee

**Principal**:
Something that signs in and holds access itself: a user, or an object of a type marked `principal` (a service, an API client, an agent). One is signed in at a time.
_Avoid_: fake user, service account (for a user row standing in for a service)

**Relation**:
A named link from an object to subjects, read live from the app's own columns or tables, or from shares.
_Avoid_: relationship, role (for this meaning)

**Permission**:
A named capability on an object (`can edit`), defined by combining relations, other permissions and SQL conditions.
_Avoid_: privilege, right, action

**Share**:
A stored row giving one subject one relation on one object, whether made by a person, an approved request or break-glass.
_Avoid_: grant, tuple, relationship, ACL entry

**Role**:
A set of permissions that people define at runtime on an object (such as "reviewer" in one org) and then share like a relation.
_Avoid_: custom role (in prose, once introduced), permission set; never use for the database role or for owner/editor/viewer

**Rule**:
What a table command (select, insert, update, delete) requires, stated per table and enforced by row-level security.
_Avoid_: policy (that word means the whole file), RLS policy (in prose)

**Tree**:
Objects linked by relations that pass permissions down (a folder inside a folder, a folder linked into another), however deep.
_Avoid_: hierarchy, graph

**Tree write**:
Any change that alters who is above whom in a tree: creating, moving or deleting an object in it, or changing a link.
_Avoid_: structural write

**Change feed**:
The ordered record of objects whose access may have changed, which consumers (caches, search indexes) follow by position.
_Avoid_: event stream, notifications, change log

### Release

**Public surface**:
What 1.0 promises not to break without a major version: the policy syntax and meaning, the `authz` functions and settings, the generated client's names, the data in the persistent tables, and what each error code means (not the wording of messages).
_Avoid_: API (alone)

**Error code**:
The name of one kind of mistake (`AZ201`), at the end of its message, with a page saying what it means and how to fix it.
_Avoid_: error number, error ID

**Beta**:
A version complete enough to use before it is released (`0.1.0-beta.1`): it may still change where using it shows a need. Said of a release, never of a feature.
_Avoid_: preview (for a release)

**Preview**:
Shipped and tested, but outside the public surface; it may change in any release. Said of a feature, never of a release.
_Avoid_: beta (a release's stage), experimental

### Deployment

**App role**:
The Postgres role the application connects as; every policy applies to it and it is never trusted to choose its own user.
_Avoid_: app user, service account, role (alone)

**Trusted backend**:
The application server that authenticates people itself and tells the database who is asking in each transaction.
_Avoid_: server, API

**Migration**:
The SQL that takes a database from the policy the lock file recorded to the policy now, written by `rowstile
migrate` for the app's migration tool. A policy change ships as one (two when an inheritance tree is
built beside the one in use first).
_Avoid_: apply script, upgrade script

**Lock file**:
`policy.lock`, committed next to the policy: the policy's lines and everything the migrations so far have made,
with a hash each. The next migration starts from it.
_Avoid_: snapshot, state file

**Push**:
Bringing a development database to the policy with the migration `rowstile migrate` would write, straight away.
Production takes migrations.

**Development database**:
A database marked as one, which push may change: marked by the first push to it while it has no policy, or by
a person, once. Any other database with a policy takes only migrations.
_Avoid_: dev DB, local database (it may be remote), test database

**The command**:
`rowstile`, which compiles a policy and applies the SQL it writes to a database, as the owner of the tables. rowstile is not a Postgres extension: nothing is installed in the database first.
_Avoid_: extension, CLI tool, plugin

**First adopter**:
The file management app that uses rowstile as an ordinary user would and tests each feature before release.
_Avoid_: pilot, customer, design partner, "our app"
