# Error codes

What the command, the editor or a migration reports ends with its code: `line 4: folder.owner: unknown type 'person' [AZ201]`. An error the app meets at run time carries its code in its HINT instead: `rowstile help AZ709`. `rowstile help AZ201` prints a code's page in the terminal.

## Reading the policy

- [AZ101](AZ101.md): A line the language doesn't read
- [AZ102](AZ102.md): An expression that doesn't parse
- [AZ103](AZ103.md): A relation written wrongly
- [AZ104](AZ104.md): A permission written wrongly
- [AZ105](AZ105.md): A rule written wrongly
- [AZ106](AZ106.md): A test or an invariant written wrongly
- [AZ107](AZ107.md): A name the policy can't use
- [AZ108](AZ108.md): An included file that can't be read
- [AZ109](AZ109.md): Declared twice
- [AZ110](AZ110.md): A dollar-quote tag in a condition
- [AZ111](AZ111.md): No app role
- [AZ112](AZ112.md): `this` where there is no row
- [AZ113](AZ113.md): A name rowstile keeps for itself

## Types and relations

- [AZ201](AZ201.md): Unknown type
- [AZ202](AZ202.md): No user type
- [AZ203](AZ203.md): A relation or permission that isn't there
- [AZ204](AZ204.md): anyone, link and type:*
- [AZ205](AZ205.md): A source that can't hold these subjects
- [AZ206](AZ206.md): A key written wrongly, or of the wrong shape
- [AZ207](AZ207.md): Sharing needs a permission
- [AZ208](AZ208.md): A relation nothing uses
- [AZ209](AZ209.md): A group made only of itself
- [AZ210](AZ210.md): Custom roles written where they can't be
- [AZ211](AZ211.md): Custom roles from a relation that can't name their owner

## Permissions and inheritance

- [AZ301](AZ301.md): Following a relation that can't be followed
- [AZ302](AZ302.md): A permission that depends on itself
- [AZ303](AZ303.md): Inheritance with no starting point
- [AZ304](AZ304.md): Inheritance limited by something other than a condition
- [AZ305](AZ305.md): A condition inheritance can't store
- [AZ306](AZ306.md): A deny that doesn't fit its inheritance
- [AZ307](AZ307.md): A permission the runtime asks for, where it doesn't

## Rules, masks and scopes

- [AZ401](AZ401.md): Rules for a table no type maps to
- [AZ402](AZ402.md): Masks need a view
- [AZ403](AZ403.md): An update refinement without an update rule
- [AZ404](AZ404.md): A scope written wrongly

## Tests

- [AZ501](AZ501.md): A $name used before it is given
- [AZ502](AZ502.md): A test acting as a type that doesn't sign in
- [AZ503](AZ503.md): A test names a scope the policy doesn't have

## Applying and deploying

- [AZ601](AZ601.md): A table or column that isn't there
- [AZ602](AZ602.md): A key of another type
- [AZ603](AZ603.md): An inheritance condition that isn't the same for everyone at any time
- [AZ604](AZ604.md): An inheritance condition reading a view
- [AZ605](AZ605.md): Links used for inheritance can't expire
- [AZ606](AZ606.md): authz.uid() returns another type
- [AZ607](AZ607.md): The database holds the migration already, or isn't where it starts
- [AZ608](AZ608.md): A tree swapped in that wasn't built
- [AZ609](AZ609.md): No policy is applied
- [AZ610](AZ610.md): Not a development database
- [AZ611](AZ611.md): Masked columns still readable
- [AZ612](AZ612.md): A schema on the search path others may create in
- [AZ613](AZ613.md): A condition that doesn't run
- [AZ614](AZ614.md): Something uses a function this policy no longer makes
- [AZ615](AZ615.md): A migration run outside a transaction
- [AZ616](AZ616.md): An older command, a newer database
- [AZ617](AZ617.md): Something is built on a masked view that can't be replaced in place
- [AZ618](AZ618.md): The owner may not switch to the app role
- [AZ619](AZ619.md): A lock file rowstile can't read
- [AZ620](AZ620.md): No tables to draft a policy from
- [AZ621](AZ621.md): Which table holds the users?
- [AZ622](AZ622.md): A user table the draft can't use
- [AZ623](AZ623.md): Too many people for a snapshot
- [AZ624](AZ624.md): The app role is the policy's owner
- [AZ625](AZ625.md): A cascade line that names no foreign key
- [AZ626](AZ626.md): A policy applied by another version of rowstile

## What apps see

- [AZ701](AZ701.md): Nobody signed in
- [AZ702](AZ702.md): Who is signed in was changed
- [AZ703](AZ703.md): Login refused
- [AZ704](AZ704.md): A read-only session
- [AZ705](AZ705.md): Not allowed
- [AZ706](AZ706.md): The policy doesn't allow this share
- [AZ707](AZ707.md): Not in the policy
- [AZ708](AZ708.md): No such thing
- [AZ709](AZ709.md): A write refused by a rule
- [AZ710](AZ710.md): A missing or wrong argument
- [AZ711](AZ711.md): The audit trail can't be changed
- [AZ712](AZ712.md): The change feed was trimmed
- [AZ713](AZ713.md): Moved inside itself
- [AZ714](AZ714.md): Sign in first
- [AZ715](AZ715.md): For users only

## The sync index (a preview)

- [AZ801](AZ801.md): A sync line that names nothing to sync
- [AZ802](AZ802.md): Sync lines and no sync role, or a sync role and nothing synced
- [AZ803](AZ803.md): The sync role is the app role
- [AZ804](AZ804.md): A synced permission reads the clock
- [AZ805](AZ805.md): A synced permission reads who asks
- [AZ806](AZ806.md): A synced permission reads other rows
- [AZ807](AZ807.md): A nested group the sync index can't hold
- [AZ808](AZ808.md): The sync role isn't one of its own
- [AZ809](AZ809.md): The sync role may read a masked column
- [AZ810](AZ810.md): A sync line keyed by a type it can't be keyed by
- [AZ811](AZ811.md): A mirrored sync line that can't be mirrored

These pages are written from `core/authzlib/errors.py`; edit it, then `python3 core/tests/unit_test.py --update`.
