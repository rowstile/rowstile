# Helpdesk

Several companies' support desks on one database, built to show rowstile in a multi-tenant app. Each company
has a **workspace**: its agents, its teams (inside each other), its customers and their companies, its tickets,
and roles of its own. The vendor that runs the service has staff of its own, who see nothing of a workspace
unless it lets them in.

Every rule about who may do what lives in one file, [`db/policy.authz`](db/policy.authz). rowstile turns it into
row-level security on the app's tables. The route handlers ([`app/api/`](app/api/)) have **no permission checks
at all**: they sign each transaction in as the person asking, run Prisma queries, and pass the database's
refusals on as 403s that say why.

![The inbox as Al, in Billing: every ticket of Acme's workspace, and the one Billing works marked his](docs/inbox.png)

![The same ticket as Al: the internal note shows, and authz.perms says he may work it](docs/ticket.png)

![The ticket as Peter, who asked: no internal note, Al's reply signed; closing it is refused, and "why?" shows the rule](docs/refused.png)

```
./test.sh                      # everything below, from an empty database in Docker (Postgres 16; PG_MAJOR=17 or 18)
```

For development, the database in Docker (`KEEP=1 ./test.sh` leaves it running on localhost:25434), then:

```
export DATABASE_URL=postgresql://hd_owner:hd_owner@localhost:25434/helpdesk     # the tables' owner: migrations
export HD_APP_URL=postgresql://hd_app:hd_app@localhost:25434/helpdesk          # the app: row-level security applies
export HD_SESSION_SECRET=a-secret-of-thirty-two-characters-or-more
npm run dev                    # http://localhost:8002: sign in as any of the demo's people (db/seed.sql)
npm run tick                   # beside it, as the owner (DATABASE_URL): the sync index's clock (Live, below)
```

While changing the policy, `rowstile dev` applies it on every save, runs its tests and rewrites the client
(`src/authz_client.ts`); `rowstile migrate --name what_changed` writes the migration Prisma runs.

## The tenant boundary, in the policy

A workspace's people, tickets and roles are its own. The schema holds that once: every row of a workspace names
it, and a row that points at another names the same workspace in its foreign key (`(workspace_id, team_id)` to
`teams (workspace_id, id)`). The policy says it again, in the permissions themselves:

```authz
can work  = ((assignee or team.member or team.oversee or roles) and workspace.agent) or workspace.work_all or responder
can reply = work or ((requester or cc) and workspace.member)
```

Why twice: `rowstile prove` and the review read the policy, not the schema. Written there, the boundary is
something they can check. The four invariants at the end of the policy (no one sees a ticket of a workspace they
aren't in, but for the vendor's staff by break glass and the workspace's own integrations) hold in every world
`prove` tries. Without the `and workspace...` parts, it finds an assignee, a requester or a custom role from
another workspace in a few worlds: rows the keys forbid, but a policy that would allow them.

## The rules, and where they are

| What the app does | How the policy says it |
|---|---|
| A workspace's tickets, people and teams are its own | `and workspace.agent` / `and workspace.member` in `work` and `reply`, the invariants, and the schema's composite keys |
| Agents see the workspace's tickets, and work those of their teams | `can view = reply or workspace.agent or ...`, `can work = ((assignee or team.member or team.oversee or roles) and workspace.agent) or ...` |
| A team's lead works the teams inside theirs | `can oversee = lead or parent.oversee` on teams (inheritance, kept in a closure table) |
| A workspace may open its queue to every agent | `can work_all = admin or (agent and {open_queue})` |
| Agents hand tickets on, and still see them after | `update after : workspace.work or requester`: the row after the change, as Postgres also asks that its author may read it (see below) |
| Customers open tickets in their workspace, unassigned; they solve and reopen theirs, never a closed one | the insert rule's `requester and {status = 'open' and team_id is null and assignee_id is null}`; `update status : work or (requester and {status <> 'closed'})`, `update status after : work or {status in ('open', 'solved')}` |
| Internal notes are for those who work the ticket | `can view = ticket.work or (ticket.view and {not internal})` on comments, and the insert rule |
| A customer org's people see each other's tickets, if it says so | `can see_tickets = member and {shared_tickets}`, and `requester.org_tickets` in the ticket's `view` |
| Copying a colleague in: only someone of the ticket's workspace | `cc : user shared by reply if {hd.same_workspace(this.object_id, this.subject_id)}` |
| A workspace's people see its agents (a customer sees who answered them), and customers see only themselves and their org's people | `can view = self or workspace.work or (org.member and workspace.member) or (workspace.member and {kind = 'agent'}) or ...` on users |
| The agents' notes on a customer: no one else reads them | `rules hd.users view hd.users_visible`, `mask notes : see_notes`: the column is null in the view for anyone else, and the table refuses it to everyone |
| Custom roles, made by a workspace's admins, count for its own agents only | `roles : user, team#member from workspace`, and `roles and workspace.agent`: a role given to someone of another workspace gives nothing |
| The vendor's staff come in by break glass, where a workspace lets them | `support : user = hd.support_access(...) where {until > now()}`, `can break_glass = workspace.support`, and `responder`'s `shared if {hd.is_staff(...)}`, which break glass asks too |
| An admin views the app as someone of their workspace | `can impersonate = workspace.admin` on users; every transaction goes through `authz.view_as` while they do ([`src/db.ts`](src/db.ts)): read-only, on the record |
| The email intake signs in as itself, with a key that can do nothing else | `type integration = hd.integrations (id uuid) principal`, `scope intake = ...`, and a key made by an admin (`can manage_keys = workspace.manage`) |
| It knows a mail's sender by their address, which only an admin changes; a reply by mail is from someone who may reply | `update email : workspace.manage`; the intake ([`app/api/intake/route.ts`](app/api/intake/route.ts)) asks `authz.can(..., 'reply')` as the sender, and writes the reply as itself, the sender as its author |

Each row of this table is checked in [`db/tests/rules.authz`](db/tests/rules.authz) (`rowstile test`), and the
app's routes again in [`tests/api.test.ts`](tests/api.test.ts), over HTTP, as the demo's people.

## Live

The inbox and the ticket page update as tickets and comments arrive, change or leave, through
[Electric](https://electric-sql.com) (a preview in rowstile, [`docs/stacks/electric.md`](../../docs/stacks/electric.md)).
Electric reads Postgres by logical replication, where row-level security doesn't run, so the policy's sync lines
keep an index of who may read each ticket and comment:

```authz
sync role hd_electric
sync hd.tickets : view
sync hd.comments : view
```

The app's route [`app/api/shapes/[table]/route.ts`](app/api/shapes/[table]/route.ts) stands in front of Electric:
it asks the database who the request is, and hands Electric that person's shape, whatever the browser sent.
A request with no one signed in gets a 401; an admin viewing the app as someone gets a 403 (the index holds what each person may read,
not what a limited session may). When a share ends or a ticket is handed on, Electric sends a move-out rather
than a delete, which its own client doesn't apply: [`src/live.ts`](src/live.ts) does. Electric's role and its
publication are in [`db/electric.sql`](db/electric.sql) and the migration `electric_publication`.

A share that ends with time, as break glass's does after its hour, changes who may read the ticket with no write,
so nothing tells the index. The database refuses the staff at once; the index learns of it at the next
`authz.sync_tick()`, and Electric then sends the move-out. That function is an administrator's, which the app role
can't call: [`jobs/sync-tick.ts`](jobs/sync-tick.ts) runs it every minute, as the tables' owner, in a process of
its own beside the app (`npm run tick`), so the web server never holds the owner's password. Until it runs, the
staff member's shapes keep the ticket, its internal notes and its changes: run it as often as break glass should
end live.

[`tests/live.test.ts`](tests/live.test.ts) follows the shapes as the demo's people: a ticket someone is copied in
on arrives, and leaves when the share does; an internal note reaches those who work the ticket and never the
customer; a ticket arrives for the vendor's staff when they break the glass, and leaves with its internal notes
when the break glass ends (test.sh ticks every second).

What it costs: every agent of a workspace sees its tickets, so each ticket's readers are one key a person (51 for
a workspace of 50 agents), and inserting a ticket keeps them (about 19 ms a ticket there, on a development
machine).

## Two things Postgres asks

- **An update its author could no longer see is refused.** An `UPDATE` with a `WHERE` reads the row, so Postgres
  checks the new row against the select rule too. A helpdesk where agents saw only their teams' tickets couldn't
  let one hand a ticket to another team. Here every agent of a workspace sees its tickets, and works only some.
- **Prisma reads what it writes.** `create` and `update` return the row, so the select rule must hold on the new
  row, and a key's scope must list the table's `select` as well as its `insert`: `scope intake` names
  `hd.users.select` beside `hd.users.insert`.

## Signing in

The example has no identity provider. Its sign-in page picks one of the demo's people by email
([`app/api/session/route.ts`](app/api/session/route.ts)), through `hd.logins`, which the policy doesn't govern
(it says who someone is, not what they may do), and keeps the person in a cookie signed with
`HD_SESSION_SECRET`. A real app checks a password or an identity provider's token there, and nothing else
changes.
