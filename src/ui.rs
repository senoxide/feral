use std::io::{self, Write};

pub fn println_out(s: &str) {
    println!("{}", s);
}

pub fn print_out(s: &str) {
    print!("{}", s);
    let _ = io::stdout().flush();
}

/// Prints an async message (from a networking thread) and redraws the
/// input prompt afterward.
pub fn notify(s: &str) {
    print!("\n{}\n> ", s);
    let _ = io::stdout().flush();
}
