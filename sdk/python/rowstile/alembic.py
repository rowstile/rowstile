"""rowstile with Alembic: autogenerate leaves what rowstile made alone.

In migrations/env.py:

    from rowstile.alembic import include_name, include_object
    context.configure(..., include_name=include_name, include_object=include_object)

A model of a masked view (`rules app.files view app.files_visible`: the view rowstile makes, and the only way to
read the masked column) says so, or autogenerate would create a table for it:

    __table_args__ = {"schema": "app", "info": {"rowstile": True}}

rowstile's migrations themselves are written by `rowstile migrate` (tool = "alembic" in rowstile.toml):
a revision after the current head, with its SQL beside it.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from sqlalchemy.schema import SchemaItem

SCHEMAS = frozenset({"authz", "authz_int", "authz_gen"})
# Alembic's names (alembic.runtime.environment), which its configure() calls these with
ParentNames = MutableMapping[Literal["schema_name", "table_name", "schema_qualified_table_name"], "str | None"]


def include_name(name: str | None, type_: str, parent_names: ParentNames) -> bool:
    """Leaves out rowstile's schemas (with include_schemas=True)."""
    if type_ == "schema":
        return name not in SCHEMAS
    return parent_names.get("schema_name") not in SCHEMAS


def include_object(
    obj: SchemaItem, name: str | None, type_: str, reflected: bool, compare_to: SchemaItem | None
) -> bool:
    """Leaves out rowstile's tables and indexes, and a model whose table's info says "rowstile" (a model of a
    masked view, which rowstile makes)."""
    schema = getattr(obj, "schema", None) or getattr(getattr(obj, "table", None), "schema", None)
    if schema in SCHEMAS:
        return False
    info = getattr(obj, "info", None) or {}
    return not info.get("rowstile")
