// Terminal I/O. Two modes:
//
// - Interactive (stdin is a real tty): raw mode via crossterm, with our
//   own minimal line editor. This exists so an incoming message from a
//   networking thread can interrupt mid-typing without destroying what
//   you'd already typed -- we track the in-progress line ourselves,
//   erase it, print the message, then redraw the prompt with your text
//   and cursor exactly where they were.
// - Non-interactive (stdin is piped/redirected): plain line-buffered
//   read_line, no raw mode, no redraw dance -- there's no terminal to
//   preserve anyway, and this keeps scripted/piped usage working.
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static RAW_MODE_ACTIVE: AtomicBool = AtomicBool::new(false);

struct LineState {
    buffer: Vec<char>,
    cursor: usize,
}

static LINE: Mutex<LineState> = Mutex::new(LineState { buffer: Vec::new(), cursor: 0 });

fn newline() -> &'static str {
    // Raw mode disables output post-processing, so a bare "\n" no
    // longer implies a carriage return -- without this, every line
    // after the first would drift one column further right.
    if RAW_MODE_ACTIVE.load(Ordering::Relaxed) {
        "\r\n"
    } else {
        "\n"
    }
}

pub fn println_out(s: &str) {
    print!("{}{}", s, newline());
    let _ = io::stdout().flush();
}

pub fn print_out(s: &str) {
    print!("{}", s);
    let _ = io::stdout().flush();
}

/// Redraws "> " + the in-progress buffer and puts the cursor back where
/// it belongs. Must be called with LINE already locked.
fn redraw_locked(state: &LineState) {
    let text: String = state.buffer.iter().collect();
    print!("\r\x1b[2K> {}", text);
    let back = state.buffer.len() - state.cursor;
    if back > 0 {
        print!("\x1b[{}D", back);
    }
    let _ = io::stdout().flush();
}

/// Prints a message that arrived asynchronously (from a networking
/// thread) without clobbering whatever the person is mid-typing: erase
/// the current prompt line, print the message, redraw the prompt with
/// their text restored.
pub fn notify(s: &str) {
    if RAW_MODE_ACTIVE.load(Ordering::Relaxed) {
        let line = LINE.lock().unwrap();
        print!("\r\x1b[2K{}\r\n", s);
        redraw_locked(&line);
    } else {
        print!("\n{}\n> ", s);
        let _ = io::stdout().flush();
    }
}

pub enum InputResult {
    Line(String),
    Quit,
}

/// Blocks until the person submits a line (Enter), or requests to quit
/// (Ctrl+C, Ctrl+D on an empty line, or a terminal/read error).
/// Interactive path: raw mode, our own editor (printable chars,
/// Backspace/Delete, Left/Right/Home/End). No history or multi-line
/// paste handling -- kept intentionally small.
fn read_line_interactive() -> InputResult {
    {
        let mut line = LINE.lock().unwrap();
        line.buffer.clear();
        line.cursor = 0;
        redraw_locked(&line);
    }
    loop {
        let ev = match event::read() {
            Ok(ev) => ev,
            Err(_) => return InputResult::Quit,
        };
        let Event::Key(KeyEvent { code, modifiers, kind, .. }) = ev else { continue };
        if kind != KeyEventKind::Press {
            continue; // avoid double-handling key-release events (e.g. on Windows)
        }

        let mut line = LINE.lock().unwrap();
        match code {
            KeyCode::Enter => {
                let text: String = line.buffer.iter().collect();
                line.buffer.clear();
                line.cursor = 0;
                print!("\r\n");
                let _ = io::stdout().flush();
                return InputResult::Line(text);
            }
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return InputResult::Quit;
            }
            KeyCode::Char('d') if modifiers.contains(KeyModifiers::CONTROL) && line.buffer.is_empty() => {
                return InputResult::Quit;
            }
            KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => {
                line.buffer.clear();
                line.cursor = 0;
                redraw_locked(&line);
            }
            KeyCode::Backspace => {
                if line.cursor > 0 {
                    line.cursor -= 1;
                    let idx = line.cursor;
                    line.buffer.remove(idx);
                    redraw_locked(&line);
                }
            }
            KeyCode::Delete => {
                if line.cursor < line.buffer.len() {
                    let idx = line.cursor;
                    line.buffer.remove(idx);
                    redraw_locked(&line);
                }
            }
            KeyCode::Left => {
                if line.cursor > 0 {
                    line.cursor -= 1;
                    redraw_locked(&line);
                }
            }
            KeyCode::Right => {
                if line.cursor < line.buffer.len() {
                    line.cursor += 1;
                    redraw_locked(&line);
                }
            }
            KeyCode::Home => {
                line.cursor = 0;
                redraw_locked(&line);
            }
            KeyCode::End => {
                line.cursor = line.buffer.len();
                redraw_locked(&line);
            }
            KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
                let idx = line.cursor;
                line.buffer.insert(idx, c);
                line.cursor += 1;
                redraw_locked(&line);
            }
            _ => {}
        }
    }
}

fn read_line_piped() -> InputResult {
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => InputResult::Quit, // EOF
        Ok(_) => InputResult::Line(line.trim_end_matches(['\r', '\n']).to_string()),
        Err(_) => InputResult::Quit,
    }
}

/// True if we're in an interactive terminal and raw mode is active for
/// the rest of the session.
pub fn start_interactive_session() -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    if terminal::enable_raw_mode().is_err() {
        return false;
    }
    RAW_MODE_ACTIVE.store(true, Ordering::Relaxed);
    true
}

pub fn end_interactive_session() {
    if RAW_MODE_ACTIVE.swap(false, Ordering::Relaxed) {
        let _ = terminal::disable_raw_mode();
    }
}

pub fn read_line(interactive: bool) -> InputResult {
    if interactive {
        read_line_interactive()
    } else {
        read_line_piped()
    }
}
