# Hiding a column from some users: a masked salary

Row-level security decides which rows someone sees. A mask decides one column: everyone signed in sees the
staff directory, and a salary is seen by the person it is paid to and by their manager.

```authz
type employee = app.employees
  self    : user = user_id
  manager : user = manager_id

  can see_salary = self or manager

rules app.employees view app.employees_visible
  select      : signed_in
  mask salary : see_salary
```

- `view app.employees_visible` makes a view with the rows `select` allows.
- `mask salary : see_salary`: in that view `salary` is NULL unless the rule holds for the row.
- Applying the policy takes the app role's `SELECT` on `salary` in the table itself away, so the view is the
  only way to read it. The other columns of the table stay readable.
- Applying refuses to go on if the column would still be readable through another role, and `authz.lint()`
  reports a later `GRANT` that makes it readable again.

## Tested

Ann manages Bo; Cy is a colleague:

```authz
test "everyone sees the directory; a salary, only the person and their manager"
  as user $cy sees 1 {SELECT FROM app.employees_visible WHERE id = $e AND title = 'Engineer' AND salary IS NULL}
  as user $bo sees 1 {SELECT FROM app.employees_visible WHERE id = $e AND salary = 5000}
  as user $ann sees 1 {SELECT FROM app.employees_visible WHERE id = $e AND salary = 5000}
  as user $cy refused {SELECT salary FROM app.employees WHERE id = $e}
  as user $cy sees 1 {SELECT title FROM app.employees WHERE id = $e}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=hiding-a-column): the tables, the policy and the
tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/hiding-a-column/`](hiding-a-column/). CI takes them on every change ([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and
checks that every line of policy and tests shown here is in those files.

More: [masked columns](../reference/language.md#masked-columns), [the other recipes](../cookbook.md).
