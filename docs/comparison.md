# rowstile and the alternatives

There are good ways to do authorization that aren't rowstile. Most of what separates them is one question:
**where does the data that decides access live?** This page says how each alternative answers it, what that
means in practice, and when it is the better choice. What it says of other projects is from their own
documentation, read on 2026-10-06 and linked; if a line here is wrong or out of date, an issue is welcome.

| | where the rules are | where the facts are | who enforces |
|---|---|---|---|
| **rowstile** | a policy file, compiled to SQL | the app's own tables | Postgres, on every query |
| **an authorization service** (OpenFGA, SpiceDB) | a model in the service | copied into the service by the app | the app, by asking the service |
| **a policy engine** (Cerbos, Open Policy Agent) | policy files beside the engine | sent by the app with each question | the app, by asking the engine |
| **rules in the ORM** (ZenStack) | the ORM's schema | the app's own tables | the ORM, in the queries it writes |
| **row-level security by hand** | `CREATE POLICY` statements | the app's own tables | Postgres, on every query |
| **checks in app code** (CASL, Casbin, Pundit) | the code | wherever the code looks | each handler that remembers to |

## An authorization service: OpenFGA, SpiceDB

These follow Google's Zanzibar. The service keeps relationships ("user 4 is a viewer of document 7") in a store
of its own, and answers whether a relationship holds
([OpenFGA's concepts](https://openfga.dev/docs/concepts),
[SpiceDB](https://authzed.com/docs/spicedb/getting-started/discovering-spicedb)). The app writes a relationship
to the service whenever the fact changes in its own database, and asks the service before it acts.

With rowstile the row is the fact. `owner : user = owner_id` reads the column the table already has, and a
team's members are the rows of the membership table. So:

- **Nothing is written twice.** There is no second copy to keep in step, and no moment at which the two
  disagree: a share and the row it is about commit in one transaction, or neither does.
- **A list is a query.** "The folders I may see, by name, page 3" is a `SELECT` with a sort and a limit.
  A service is asked for the ids someone may see, and the app then fetches and sorts those rows itself.
- **Nothing extra runs.** What rowstile leaves in the database is SQL. There is no service to deploy, scale
  and watch.

**They are the better choice when** what decides access is spread over several databases or services, or
isn't in Postgres at all: a service is then the one place that can know everything. Also when many services
in several languages must ask the same questions, or when you need a company behind it, with support and a
hosted offering.

The same model in both, and each point above with their docs quoted:
[rowstile and OpenFGA](compare/openfga.md), [rowstile and SpiceDB](compare/spicedb.md).

## A policy engine: Cerbos, Open Policy Agent

A policy engine holds no facts. The app gathers what it knows about the person and the thing, sends it with
the question, and gets a decision ([Cerbos](https://docs.cerbos.dev/cerbos/latest/index.html),
[Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)). The rules live in their own files, are
versioned and tested like code, and can be about anything: a request, a deployment, a row.

rowstile's rules are only about rows in one database, and the app doesn't have to ask: Postgres applies them
to whatever query arrives, including the one a developer forgot to guard, and filters lists as it reads them.

**They are the better choice when** the rules are not about rows: who may call an API, what may be deployed
where. And when the same rules must hold in systems that share no database.

## Rules in the ORM: ZenStack

ZenStack puts access policies in its schema language, and its engine adds them as filters to the queries it
writes, in the application, for any database it supports
([ZenStack's access control](https://zenstack.dev/docs/orm/access-control)). The rules sit beside the models,
in TypeScript's world.

rowstile's rules are enforced by the database, so they also hold for what doesn't go through the ORM: raw SQL,
a second service on the same database, a migration script that connects as the app. They need Postgres.

**It is the better choice when** the app is TypeScript only, wants its models, its API and its rules from one
schema, or isn't on Postgres.

Their example in both, and what each stops: [rowstile and ZenStack](compare/zenstack.md).

## Row-level security by hand

What rowstile writes is row-level security: the enforcement is the same. What it adds is what gets hard by
hand:

- **inheritance**: "whoever may edit a folder may edit what is inside it", kept in tables by triggers so that
  reads stay fast in deep trees;
- **groups inside groups**, shares that start and end, share links;
- **a write that says why it was refused**, where Postgres says "new row violates row-level security policy";
- **tests** beside the policy, invariants checked in many small worlds, and a review of each change that says
  who gains or loses access;
- **each change as a migration**, for the tool the app already uses.

**By hand is the better choice** for a handful of flat rules that will not change: `tenant_id = ...` on every
table needs no compiler.

One note for Supabase: its Data API reaches the database as its own roles, which are not rowstile's app role.
rowstile is for apps whose backend connects to Postgres.

The same rule as `CREATE POLICY` and as a policy file, and where a tree stops being easy:
[rowstile and row-level security by hand](compare/hand-written-rls.md).

## Checks in app code: CASL, Casbin, Pundit

An `if` in each handler is where most apps start, and for a few roles it is enough. It gets hard in two
places: every new handler must remember the check, and a list must be filtered after it is read, or the rule
written a second time as a `WHERE`.

**It is the better choice** for a small app with a few roles and no sharing between users.

What changes in a handler, and what it costs: [rowstile and checks in app code](compare/app-code.md).

## When not to use rowstile

- What decides access is in several databases, or outside Postgres.
- A browser reads your tables through Supabase's Data API.
- One tree takes many moves and links a second: they wait for each other
  ([Speed and limits](reference/limits.md)).
- You need an outside audit or a vendor behind it today. rowstile is in beta, with one maintainer, and
  nobody outside has audited it. [How rowstile is checked](how-it-is-checked.md) says what does check it.
