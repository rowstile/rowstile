//! rowstile for Zed: starts the rowstile language server (`rowstile lsp`) for .authz files.
//!
//! It runs `rowstile` from the PATH the shell gives the project, or what Zed's settings name (an install in the
//! project, node_modules/.bin or a .venv, isn't on that PATH):
//!
//!     "lsp": { "rowstile": { "binary": { "path": "/path/to/rowstile", "arguments": ["lsp"] } } }
use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

struct Rowstile;

impl zed::Extension for Rowstile {
    fn new() -> Self {
        Rowstile
    }

    fn language_server_command(&mut self, id: &LanguageServerId, worktree: &zed::Worktree) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.binary);
        let args = binary
            .as_ref()
            .and_then(|b| b.arguments.clone())
            .unwrap_or_else(|| vec!["lsp".into()]);
        let command = match binary.and_then(|b| b.path) {
            Some(path) => path,
            None => worktree.which("rowstile").ok_or(
                "rowstile isn't on the PATH (https://rowstile.dev/installing). An install in the project \
                 isn't on it either: set lsp.rowstile.binary.path in Zed's settings to its full path \
                 (node_modules/.bin/rowstile or .venv/bin/rowstile in the project)",
            )?,
        };
        Ok(zed::Command { command, args, env: worktree.shell_env() })
    }
}

zed::register_extension!(Rowstile);
