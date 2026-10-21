# Security

rowstile decides who may read and change which rows. A flaw in it can expose data, so please report one
privately, not in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the repository's **Security** tab, then **Report a
vulnerability**, or directly https://github.com/rowstile/rowstile/security/advisories/new. Only you and the
maintainers see the report. Once it's fixed, it can be published as an advisory, with credit to you if you
want it. The advisories published so far are at https://github.com/rowstile/rowstile/security/advisories.

A report is easiest to act on with:

- the smallest policy, schema and data that show it;
- what you ran, as which role, and who was signed in (`authz.act_as`, an API key or a JWT);
- what happened, and what the policy says should have;
- the rowstile and PostgreSQL versions (`rowstile --version`, `SELECT version()`).

## What counts

[The threat model](docs/threat-model.md) draws the line: what rowstile protects, who is trusted, and the
limits it accepts. In short, a vulnerability is anything that lets the app role, or someone signed in with an
API key or a JWT, do more than the policy allows. Some examples:

- read, change or delete a row the rules don't allow, read a column a mask hides, or change one a column rule
  protects;
- act as someone else, widen a key's scopes, or write during "view as";
- share more than they hold, approve their own request, or reach rowstile's internal tables and functions;
- a policy that compiles and applies without an error, but grants more than it says.

The limits listed in the threat model are known and accepted (side channels such as `EXPLAIN ANALYZE`, tables
without rules, `SECURITY DEFINER` functions the app adds). A way around one of them that the threat model
doesn't describe is still worth a report.

## Supported versions

Before 1.0, fixes go into the newest version only. While no final release exists, a fix comes out as the next
pre-release (`0.1.0-beta.2` after `0.1.0-beta.1`); after that, as a patch of the newest minor release
(`0.1.1`). Older versions, older pre-releases among them, get none: move to the one with the fix.
