// 12 standard ANSI SGR color codes; rendering follows the terminal's own
// theme rather than fixed RGB values.
pub const COLORS: [&str; 12] = [
    "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[91m",
    "\x1b[92m", "\x1b[93m", "\x1b[94m", "\x1b[95m", "\x1b[96m",
];
pub const RESET: &str = "\x1b[0m";
pub const REVERSE: &str = "\x1b[7m";
pub const UNREVERSE: &str = "\x1b[27m";

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(true);

/// Priority: --no-color flag > NO_COLOR env var > tty auto-detect.
pub fn init_color_mode(no_color_flag: bool) {
    let enabled = if no_color_flag {
        false
    } else if std::env::var_os("NO_COLOR").map(|v| !v.is_empty()).unwrap_or(false) {
        false
    } else {
        std::io::stdout().is_terminal()
    };
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn color_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

pub fn code(idx: usize) -> &'static str {
    if !color_enabled() {
        return "";
    }
    COLORS.get(idx % COLORS.len()).copied().unwrap_or("")
}

pub fn reset() -> &'static str {
    if color_enabled() { RESET } else { "" }
}

pub fn reverse() -> &'static str {
    if color_enabled() { REVERSE } else { "" }
}

pub fn unreverse() -> &'static str {
    if color_enabled() { UNREVERSE } else { "" }
}
