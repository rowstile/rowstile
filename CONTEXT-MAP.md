# Context Map

## Contexts

- [rowstile](./core/CONTEXT.md): a policy language, its compiler (the `rowstile` command), and enforcement inside Postgres.
- File manager (`examples/filemanager/`): the first adopter. A standalone product for storing and sharing files (FastAPI backend, React frontend, RustFS object storage). Its glossary is created with its first term.
- Messenger (`examples/messenger/`): the second adopter, a WhatsApp-style app (chats, groups, invite links, blocking, bots) built to show what rowstile takes off an application. Same stack and same boundary as the file manager.
- Helpdesk (`examples/helpdesk/`): the third adopter, several companies' support desks on one database (workspaces, teams inside teams, custom roles, the vendor's staff by break glass, an email intake with a scoped key). Next.js, Prisma and the TypeScript SDK; the same boundary.

## Relationships

- **File manager, messenger, helpdesk → rowstile**: each is an ordinary user of rowstile. It writes its own policy file against its own tables, applies it from its migrations, and calls only the public surface (the `rowstile` command, the `authz` functions and settings, and the generated Python or TypeScript client). rowstile never names anything from the file manager.
- **Shared terms**: the file manager's folders and files, and the messenger's chats and messages, are rowstile **objects**; their users (and the file manager's groups, the messenger's bots) are **subjects**; the file manager's sharing screens and the messenger's invite links create **shares**. Use the rowstile words for those concepts in every context.
