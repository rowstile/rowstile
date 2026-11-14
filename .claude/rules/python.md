---
paths:
  - "**/*.py"
  - "ty.toml"
  - "ruff.toml"
  - "**/pyproject.toml"
---

# Python

How the Python is typed and laid out, everywhere in the repository.

- Types: all Python is strongly typed. `uvx ty@0.0.56 check && uvx ruff@0.15.12 check && uvx ruff@0.15.12
  format --check` from the root (CI's `unit` job): ty checks the types (`ty.toml`, every rule an error), Ruff
  the lint, that every function is annotated (`ruff.toml`, `ANN`, no exceptions), and the layout: run `uvx
  ruff@0.15.12 format` before a commit (120 columns; what the command generates, the apps' clients and the
  Alembic revisions, is left as generated). `.githooks/pre-commit` refuses staged Python that isn't laid out
  (on in a clone after `git config core.hooksPath .githooks`); `Layout` in `unit_test.py` checks the hook, CI
  and these rules name one version of Ruff. A commit that only lays code out goes in `.git-blame-ignore-revs`
  once it is on `main` (its full hash; the same test checks). ty's root settings cover the standard-library code; what needs
  a package's environment has its own (`uv sync` it first), `--project` sdk/python (the fastapi app's
  environment), integrations/fastapi, integrations/django (with sdk/python/rowstile/django, the SDK's Django
  module), examples/filemanager and examples/messenger (their backends'); CI's `unit` job runs them all. Test code
  types the JSON it checks as `Answer = Any`, one alias, named; app code types rows as psycopg's `DictRow`.
  Python 3.11 syntax, standard library only (no `typing.override`, 3.12). A policy expression is a frozen dataclass
  per kind (`parse.Expr`: `Or`, `And`, `Not`, `Cond`, `Ref`, `Arrow`, `ArrowOn`):
  build them with the class, and take them apart with `match`/`isinstance` (they have no `node[0]`).
