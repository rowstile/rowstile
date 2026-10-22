# Examples

Complete apps that use rowstile as any outside app would: their own policy, applied from their own
migrations, and only the public surface (`check_public_surface.py` in each, which runs the check they share,
[`public_surface.py`](public_surface.py)). Their backends have no permission checks. Each one's `test.sh` runs
its tests in Docker, and CI runs them on every change.

- [`filemanager/`](filemanager/): storing and sharing files. Folders inside folders, sharing with people
  and groups, links, file versions. FastAPI, React, RustFS for the file contents.
- [`messenger/`](messenger/): a WhatsApp-style app. Direct chats and groups, admins, invite links,
  blocking, bots with their own API keys, live updates. FastAPI, React.
