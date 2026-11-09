"""authzlib: compile a .authz policy file into PostgreSQL (views, closure tables,
triggers, row-level security policies and an API for app code)."""

from typing import TYPE_CHECKING

from .parse import Loc, PolicyError, parse_policy

if TYPE_CHECKING:
    from .assembled import Compiler

    BUILD: str

# set with packaging/version.py (the packages copy it); authz.policy_versions records it on each apply
__version__ = "0.1.0-dev"


def _build() -> str:
    """The version apply records and trusts: a release's own, and for a build of the next one (X.Y.Z-dev)
    the version with a hash of the compiler's sources, since two such builds may make different SQL."""
    if not __version__.endswith("-dev"):
        return __version__
    import hashlib
    import os

    here, h = os.path.dirname(os.path.abspath(__file__)), hashlib.sha256()
    for name in sorted(os.listdir(here)):
        if name.endswith(".py"):
            with open(os.path.join(here, name), "rb") as fh:
                h.update(name.encode() + b"\0" + fh.read().replace(b"\r\n", b"\n") + b"\0")
    return f"{__version__}+{h.hexdigest()[:12]}"


def __getattr__(name: str) -> object:
    """Compiler and BUILD, made when first asked for: a command that compiles nothing (--version, help, can, fmt)
    doesn't import the compiler, and only one that records or compares the version reads every source file."""
    if name == "Compiler":
        from .assembled import Compiler as value
    elif name == "BUILD":
        value = _build()
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


__all__ = ["BUILD", "Compiler", "Loc", "PolicyError", "__version__", "parse_policy"]
