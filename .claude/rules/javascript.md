---
paths:
  - "**/*.js"
  - "**/*.mjs"
  - "**/*.ts"
  - "**/*.tsx"
  - "**/tsconfig*.json"
---

# JavaScript and TypeScript

How the JavaScript is typed, everywhere in the repository.

- JavaScript is typed too: JSDoc, checked by `tsc` with `checkJs` and `strict`, one `tsconfig.json` per folder with its
  environment's types (playground, site, editor, editor/tree-sitter-authz, packaging/npm, core/tests; Studio's
  page: `core/cli/tsconfig.studio.json`); CI's `javascript` job runs them after `npm ci` in each. The page's API answers
  are typedefs matching what the Python sends (`studio.py`, `core.mjs`); keep them in step.
