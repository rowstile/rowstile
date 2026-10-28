# Blog

Notes from building rowstile: how row-level security in Postgres behaves at scale, how the generated SQL is
checked, what was measured and what went wrong. Each post links to the files and the numbers it speaks of.

The feed: <https://rowstile.dev/blog/feed.xml>.

<!-- The posts, newest first, each a line: its date, then a link to its file with its title as the words.
     A post is docs/blog/<date>-<slug>.md: its title, then "*Author's Name, <date>*", then a first paragraph,
     which is its summary. The site's build fails on a post that isn't listed here. The blog is on the site
     from its first post. -->

- 2026-10-28: [Why a query through row-level security runs on one CPU](2026-10-28-row-level-security-on-one-cpu.md)
- 2026-10-07: [Why a recursive row-level security policy is slow, and what fixes it](2026-10-07-recursive-row-level-security.md)
