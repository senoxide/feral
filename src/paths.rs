// Where feral keeps its persistent files. Linux: ~/feral/. Windows:
// %APPDATA%\feral. Resolved once and cached; the directory is created
// (and, on Linux, locked to the owner) on first access.
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

#[cfg(target_os = "windows")]
fn base_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(not(target_os = "windows"))]
fn base_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub fn data_dir() -> &'static Path {
    DATA_DIR.get_or_init(|| {
        let dir = base_dir().join("feral");
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("Warning: could not create {}; falling back to the current directory.", dir.display());
            return PathBuf::from(".");
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        dir
    })
}

pub fn file(name: &str) -> PathBuf {
    data_dir().join(name)
}

/// Expands a leading `~` or `~/` to the user's home directory. Only our
/// own command REPL ever sees these paths (they don't pass through a
/// shell), so without this a path like `~/test/test.txt` typed at the
/// `/sendfile` prompt fails to resolve -- `~` is shell syntax, not
/// something the filesystem or std::fs understands on its own.
pub fn expand_tilde(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if trimmed == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    } else if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_when_present() {
        if let Some(home) = dirs::home_dir() {
            let expanded = expand_tilde("~/test/test.txt");
            assert_eq!(expanded, home.join("test/test.txt"));
        }
    }

    #[test]
    fn non_tilde_path_untouched() {
        assert_eq!(expand_tilde("/tmp/test/test.txt"), PathBuf::from("/tmp/test/test.txt"));
        assert_eq!(expand_tilde("relative/path.txt"), PathBuf::from("relative/path.txt"));
    }
}
