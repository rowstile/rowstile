# The demo, about eighty seconds: a policy, its tests, a one-word change and what the review says of it, a refusal
# that says why, and what would grant it. A tape for VHS (github.com/charmbracelet/vhs); record.sh runs it in a
# container, against the app of docs/getting-started.md. Everything typed here is typed for real: what the
# recording shows is what the commands printed.

Output demo.gif
Output demo.mp4

Set Shell bash
Set FontSize 15
Set Width 1180
Set Height 500
Set Padding 18
Set Framerate 20
Set TypingSpeed 28ms
Set Theme { "name": "rowstile", "black": "#1b1f24", "red": "#e5534b", "green": "#57ab5a", "yellow": "#c69026", "blue": "#539bf5", "magenta": "#b083f0", "cyan": "#39c5cf", "white": "#adbac7", "brightBlack": "#636e7b", "brightRed": "#ff938a", "brightGreen": "#6bc46d", "brightYellow": "#daaa3f", "brightBlue": "#6cb6ff", "brightMagenta": "#dcbdfb", "brightCyan": "#56d4dd", "brightWhite": "#cdd9e5", "background": "#1b1f24", "foreground": "#adbac7", "selection": "#2d333b", "cursor": "#539bf5" }

Hide
Type "export PATH=/repo/core/cli:$PATH PS1='\[\e[32m\]$\[\e[0m\] ' && git config --global --add safe.directory /work && cd /work && clear" Enter
Sleep 500ms
Show

Type "# Notes in projects. Who may see or change a row is written in one file:" Enter
Sleep 800ms
Type "sed -n '9,22p' db/policy.authz" Enter
Sleep 6s

Type "clear" Enter
Type "# It compiles to row-level security in Postgres. Its tests say who may do what:" Enter
Sleep 600ms
Type "rowstile test" Enter
Sleep 7s

Type "clear" Enter
Type "# A pull request changes one word: a project's viewers may now edit its notes." Enter
Sleep 600ms
Type "sed -i 's/author or project.edit/author or project.view/' db/policy.authz && git diff -U0 | tail -2" Enter
Sleep 3s
Type "# The review says what that does, on the pull request:" Enter
Sleep 600ms
Type "rowstile review --base main --db $DATABASE_URL | head -4" Enter
Sleep 11s

Type "clear" Enter
Type "git checkout -q db/policy.authz   # not what we meant" Enter
Sleep 800ms
Type "# In the app, Postgres refuses what the rules don't allow, and says why:" Enter
Sleep 600ms
Type `rowstile sql --as user:3 "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 3, 'hi')"` Enter
Sleep 8s

Type "# ... and what would grant it:" Enter
Sleep 600ms
Type "rowstile why --as user:3 note 1 edit | tail -4" Enter
Sleep 8s

Type "# rowstile.dev: try a policy and its tests in your browser, with nothing to install." Enter
Sleep 4s
