# rowstile

Authorization for Postgres apps: access rules in a policy language that the `rowstile` command compiles into
row-level security, and ships as migrations for your app's tool (Prisma, Drizzle Kit, Alembic, SQL files).
Sharing, groups, nested folders and tenants, with no service to run beside the database.

    npx rowstile init        # a first policy from your tables, rowstile.toml, the SDK for your stack
    npx rowstile dev         # on each save: check, apply to the development database, test, write the types

The command runs on the Python that comes with it (the package for your platform, `@rowstile/cli-<platform>`):
a TypeScript app needs no Python. For app code, the SDK: `@rowstile/prisma`, `/next`, `/react`, `/drizzle`,
`/pg`, `/postgres`, `/vitest`, `/jest`.
