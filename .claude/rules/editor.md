---
paths:
  - "editor/**"
---

# editor/: the editors

What `editor/` holds and how it is tested.

- `editor/` — `test.sh` (in containers: the grammar, the Zed build, the VS Code extension built as its README says
  and `extension_test.js` against stand-ins for VS Code, Neovim set up as the README says); the VS Code extension:
  TextMate grammar (the site highlights ```authz with it too), and `extension.js` starting `rowstile lsp`;
  `publish/` (the vsce and ovsx the release packages and publishes it with, from their lock file);
  `tree-sitter-authz/` (the Tree-sitter grammar and its queries, for Zed, Helix and Neovim; `src/` is generated and
  committed, editors build from it, but for `src/scanner.c`, written by hand: dollar quotes and nested comments);
  `zed/` (the Zed extension: its queries are copies of the grammar's, `Editors` in `unit_test.py`);
  `images/Dockerfile` (the toolchains `test.sh` runs in, pinned by digest, never built)
