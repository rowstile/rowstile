# Reviewing a policy change

A one-line change can widen access across many permissions, and its text doesn't show that. `rowstile review`
says what a change does, in plain words, for the pull request:

    rowstile review --base main                          # in a terminal
    rowstile review --base main --markdown --db "$URL"   # the comment CI posts

- **Meaning**: each declaration that changed, before and after, and every permission and rule that changes
  through something it uses. <!-- checked: tests/review.sh "Meaning: what changed, and what changes through it"; tests/unit_test.py "test_what_changes_through_it" -->
  When only permissions and rules changed, each is checked against the base in
  many small worlds (made-up users, objects and links, `core/authzlib/evaluate.py`; among them the ones where
  every condition holds, or where most links do, so a change behind a long `and` shows, and chains of objects
  one link longer than the policies read): if they all grant the same, the review says
  "Meaning unchanged". <!-- checked: tests/review.sh "a refactor: meaning unchanged, checked in small worlds"; tests/unit_test.py "test_a_refactor_is_checked_in_small_worlds"; tests/unit_test.py "test_a_long_and_of_links_widened_is_found"; tests/unit_test.py "test_a_chain_deeper_than_the_drawn_worlds_is_found" -->
  Formatting and comments are "unchanged" too; text inside quotes is not formatting. <!-- checked: tests/unit_test.py "test_comments_only"; tests/unit_test.py "test_text_in_quotes_is_compared_as_written" -->
  A
  condition the worlds can't read (a subquery, a function: anything beyond the row's own columns and
  `authz.uid()`) is a set of rows of its own there, so when a permission or rule changed only in such
  conditions, the review says it can't compare them and names them, instead of guessing. <!-- checked: tests/unit_test.py "test_a_condition_it_cannot_read_reworded"; tests/unit_test.py "test_what_changes_beside_a_condition_it_cannot_read" -->
- **Access**: with `--db`, a database at the base branch's state (its migrations, then the review data,
  prepared by CI; never production), who gains and who loses what if the pull request's policy were in
  force, with examples and how each is granted. <!-- checked: tests/review.sh "Access: who gains what, on the review data"; tests/review.sh "and how it gains, asked as the bot, from what grants it alone"; tests/unit_test.py "test_how_someone_gains_is_what_grants_it" -->
  The database is left as it was. <!-- checked: tests/review.sh "the review database is left as it was" -->
- **Risk**: what to look at twice: access widened to `anyone`, `link` or `user:*`; a deny removed; a new
  inheritance path or a new way to reach a type; a relation newly shared or shared by another permission; a
  permission or a rule (`select` too) that allows more than before, with an example: because its own line
  changed, because it is new on a table that had rules, through a relation that changed (another column, a
  `where` taken off a link table), or because a type's `where` changed; a mask, a column rule or an invariant
  removed; a scope changed. <!-- checked: tests/unit_test.py "test_risk_flags"; tests/unit_test.py "test_each_change_the_review_warns_of"; tests/unit_test.py "test_a_widening_is_flagged_however_it_is_made"; tests/review.sh "Risk: the permission widened, with an example" -->
  Each names its policy line; `--annotations` writes them for GitHub, on the file
  the line is in. <!-- checked: tests/review.sh "on the policy line, its path from the repository's top folder"; tests/unit_test.py "test_a_flag_in_an_included_file_is_annotated_there" -->
  "Nothing flagged" means none of these was found in the worlds tried, not a proof.
- **Tests**: checks whose expectation flipped (the author saying "I meant this"), checks removed, new
  permissions no test names. <!-- checked: tests/unit_test.py "test_tests_that_flip"; tests/unit_test.py "test_a_new_permission_no_test_names"; tests/review.sh "Tests: the tests of the pull request ran, and the flipped check is named" -->
  A test that only changed its name is said to be renamed, and its checks are
  compared under the new name: a new name alone removes nothing. <!-- checked: tests/unit_test.py "test_a_renamed_test_is_not_its_checks_removed" -->
  With `--db`, the pull request's tests run
  on the review data after its migrations. <!-- checked: tests/review.sh "a pull request that changes the tests alone: nothing to migrate, and they run on the review data" -->
  The checks are listed whatever Meaning says. A test file of the pull request that doesn't parse
  is named, with its mistake: its checks are not compared. <!-- checked: tests/unit_test.py "test_a_test_file_that_doesnt_parse_is_said" -->
- **Deploy**: the migrations the change needs (from the base branch's lock file), their statements, the
  app tables they lock and in which mode, the inheritance tables they rebuild or build beside; with
  `--db`, how long they took on the review data. <!-- checked: tests/review.sh "Deploy: two migrations, the tree built beside, applied on the review data" -->
  A lock file behind the policy is called out. With no lock
  file on either side, the project applies its policy (`rowstile apply`) and keeps no migrations: Deploy says so. <!-- checked: tests/unit_test.py "test_no_lock_file_is_no_migration"; tests/review.sh "a project without migrations: the policy applied whole on the review data, its tests run there, all undone" -->

A pull request that upgrades rowstile across a change to the language rewrites the policy too, and the
base's policy is in the language before. The review reads it as that version meant it (`role app_user` as
`app role app_user`, `grant view, edit` as `roles` written where the role joined, and so on), and says so
at the top, with the old forms it found (`--json` lists them all). <!-- checked: tests/review.sh "a base in the language before: read as that version meant it, and said"; tests/unit_test.py "test_a_base_in_the_language_before_is_read_as_it_meant" -->
Meaning then says whether the rewrite
grants the same.

The pull request that adds the policy has none at the base. Each declaration is listed as added, the app role
and the user type too, and the review compares with a policy that allows nothing. <!-- checked: tests/review.sh "the pull request that adds the policy: each declaration added, its own app role and user type too"; tests/unit_test.py "test_a_new_policy_is_added_whole" -->

[`review-ci/github/action.yml`](../../review-ci/github/action.yml) runs it on each pull request and keeps one comment up to date (and the annotations);
[`review-ci/gitlab/rowstile-review.gitlab-ci.yml`](../../review-ci/gitlab/rowstile-review.gitlab-ci.yml) does the same for merge requests. <!-- unchecked: the action runs on this repository's pull requests (the review job in ci.yml), but no check asks what it does with the comment; the GitLab template runs on no CI here -->
`rowstile fmt --check` in CI
keeps text diffs to real changes. <!-- checked: tests/review.sh "exit 1, and which file"; tests/unit_test.py "test_the_repositorys_policies_are_laid_out_as_fmt_writes_them" -->
On GitHub, the workflow may post the comment once it has
`pull-requests: write`, and checks out the history the base branch's policy is read from:

<!-- not run: a GitHub workflow runs on GitHub; the review job in .github/workflows/ci.yml runs this action on each pull request -->
```yaml
on: pull_request
permissions: {contents: read, pull-requests: write}
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: {fetch-depth: 0}
      - uses: rowstile/rowstile/review-ci/github@v0.1.0-dev   # the release you use
```

The review reads the base's policy, the files it includes, its tests and its lock file with git. A file the
base doesn't have is new: a policy, or a test file added since. <!-- checked: tests/review.sh "the pull request that adds the policy: each declaration added"; tests/review.sh "a test file the base doesn't have: its checks are added, and the review goes on" -->
But when git can't read one the base has, or
can't list the base's folders (a partial clone that can't fetch them, a repository missing objects), the
review stops, exit 2, and says what git can't read and how to fetch it. <!-- checked: tests/review.sh "a policy git lists at the base and can't read: the review stops, exit 2, and says how to fetch it"; tests/review.sh "a file it includes (not a mistake of the base's)"; tests/review.sh "its lock file (not Deploy as if the base had none)"; tests/review.sh "a test file (not the base's tests without it)"; tests/review.sh "a folder git can't list (which test files it holds is unknown)"; tests/review.sh "the folder the policy is in (whether the policy is there is unknown)"; tests/unit_test.py "test_review_stops_where_git_cant_read_the_base" -->
Read as missing, the policy would be
reviewed as new and the base's tests left out. So check out the whole history, with no `filter`, as above.

The review reports; it doesn't gate. It exits 0 whatever it finds: a widened permission, a failing test and a
lock file behind the policy are all in what it prints, for a person to read. <!-- checked: tests/review.sh "rowstile review runs, and exits 0 whatever it found (it reports, the tests gate)" -->
(It exits 1 for a policy that
doesn't compile, 2 when it can't run: no `--base` where there is no `main` or `master` to compare with, a commit
git doesn't know, a file at the base git can't read, a database it can't reach.) <!-- checked: tests/review.sh "a mistake in the pull request's policy: check's message, exit 1"; tests/review.sh "and where there is no main or master, asks which commit"; tests/review.sh "a base git doesn't know: said, exit 2 (not the whole policy as new)"; tests/review.sh "a policy git lists at the base and can't read: the review stops, exit 2"; tests/review.sh "a review database that isn't there: can't connect, exit 2" -->
What
fails a pull request is the other two commands CI runs: `rowstile test`, which exits 1 when a check fails, and
`rowstile migrate --check`, which exits 1 when the policy changed and no migration was written. <!-- checked: tests/cli.sh "a failing test fails the command, exit 1"; tests/migrations.sh "exit 1, and what changed" -->
