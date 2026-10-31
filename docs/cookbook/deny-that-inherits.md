# Hiding a page and everything under it

`and not` takes a permission away, even from people who hold it higher up. The deny inherits the same way as
what it takes away, so it covers everything below: a hidden page hides its whole subtree.

```authz
type page = app.pages
  parent : page = parent_id
  reader : user = app.page_readers(page_id -> user_id)

  can hidden = {hidden} or parent.hidden
  can read   = (reader or parent.read) and not hidden
```

- `can hidden = {hidden} or parent.hidden`: a page is hidden when its own column says so, or when the page
  above it is.
- `can read = (reader or parent.read) and not hidden`: readers of a page read what is below it, except what
  is hidden. Being named a reader of a page inside a hidden part doesn't bring it back.
- There is no `deny` keyword. A deny that doesn't inherit the same way as the permission it takes away is
  refused when the policy is compiled, with what to write.

## Tested

Ann reads the handbook. Drafts is hidden, and a draft below it names her as a reader:

```authz
test "a hidden page hides everything below it"
  user $ann can read page $top
  user $ann can read page $side
  user $ann cannot read page $mid
  user $ann cannot read page $low
  as user $ann sees 2 {SELECT FROM app.pages WHERE id IN ($top, $mid, $low, $side)}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=deny-that-inherits): the tables, the policy and the
test, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/deny-that-inherits/`](deny-that-inherits/). CI takes them on every change
([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and checks that every line of policy and tests shown here is in those files.

More: [denies](../reference/language.md), [folders that inherit](folders-that-inherit.md),
[the other recipes](../cookbook.md).
