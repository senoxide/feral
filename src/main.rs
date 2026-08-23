mod colors;
mod commands;
mod crypto;
mod identity;
mod net;
mod paths;
mod protocol;
mod state;
mod ui;

#[cfg(target_os = "macos")]
compile_error!("feral supports Linux and Windows only; macOS is not supported.");

use state::AppState;
use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const CURRENT_VERSION: &str = "2.2.0";

fn load_saved_name(my_id: &str) -> String {
    std::fs::read_to_string(paths::file(state::NAME_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| my_id.to_string())
}

fn load_saved_colors() -> std::collections::HashMap<String, usize> {
    let mut result = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string(paths::file(state::COLOR_FILE)) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || !line.contains('=') {
                continue;
            }
            if let Some((name, idx)) = line.split_once('=') {
                if let Ok(idx) = idx.parse::<usize>() {
                    result.insert(name.to_string(), idx);
                }
            }
        }
    }
    result
}

fn show_recent_history() {
    let Ok(content) = std::fs::read_to_string(paths::file(state::LOG_FILE)) else { return };
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return;
    }
    let start = lines.len().saturating_sub(state::HISTORY_LINES_TO_SHOW);
    let recent = &lines[start..];
    ui::println_out(&format!("--- Last {} message(s) ---", recent.len()));
    for line in recent {
        ui::println_out(&protocol::sanitize_for_display(line));
    }
    ui::println_out("--- End of history ---");
}

fn print_banner(state: &AppState) {
    ui::println_out(r"  __                _ ");
    ui::println_out(r" / _| ___ _ __ __ _| |");
    ui::println_out(r"| |_ / _ \ '__/ _` | |");
    ui::println_out(r"|  _|  __/ | | (_| | |");
    ui::println_out(r"|_|  \___|_|  \__,_|_|");
    ui::println_out("");
    ui::println_out(&format!("Welcome to feral version {}!", CURRENT_VERSION));
    ui::println_out(&format!("Your id: {}", state.my_id));
    ui::println_out(&format!("Data directory: {}", paths::data_dir().display()));
    ui::println_out("Every connection is end-to-end encrypted with a fresh session key -- see README for the threat model.");
    ui::println_out("Quick start: /who (list peers)  /name <n>  /msg <n> <text>  /sendfile <n> <path>  /help (full list)");
    ui::println_out("Looking for other users...");
}

fn print_help_flag() {
    println!("feral {} - a peer-to-peer mesh LAN chat", CURRENT_VERSION);
    println!();
    println!("USAGE:");
    println!("    feral [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --no-color    Disable ANSI color output (also honors the NO_COLOR env var,");
    println!("                  and auto-detects when stdout isn't a terminal)");
    println!("    -h, --help    Print this help and exit");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let no_color_flag = args.iter().any(|a| a == "--no-color");
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help_flag();
        return;
    }
    colors::init_color_mode(no_color_flag);

    let signing_key = identity::load_or_create();
    let my_id_preview = protocol::short_id(&protocol::fingerprint(&signing_key.verifying_key())).to_string();
    let my_name = load_saved_name(&my_id_preview);

    let state = Arc::new(AppState::new(signing_key, my_name.clone()));
    *state.name_to_color.lock().unwrap() = load_saved_colors();

    for (short_id, (fp, pubkey_hex)) in identity::load_known_peers() {
        if let Some(pubkey) = identity::pubkey_from_hex(&pubkey_hex) {
            if protocol::fingerprint(&pubkey) == fp {
                state.peer_keys.lock().unwrap().insert(short_id, state::PeerKey { pubkey, fingerprint: fp });
            }
        }
    }

    // Bind the chat TCP listener up front so a port-in-use failure is
    // reported before printing the banner or starting any threads.
    let listener = match TcpListener::bind(("0.0.0.0", protocol::CHAT_PORT)) {
        Ok(l) => l,
        Err(_) => {
            eprintln!(
                "Could not start feral: port {} is already in use.\nAnother instance of feral may already be running on this machine.",
                protocol::CHAT_PORT
            );
            std::process::exit(1);
        }
    };

    let interactive = ui::start_interactive_session();

    print_banner(&state);
    show_recent_history();

    let preferred = state.name_to_color.lock().unwrap().get(&my_name).copied();
    match preferred {
        Some(idx) => state.set_color_for_id(&state.my_id, idx),
        None => {
            state.color_for_id(&state.my_id);
        }
    }

    {
        // Backstop for non-interactive termination (SIGINT from `kill`,
        // a controlling process, etc). Interactive Ctrl+C is handled by
        // the raw-mode line editor itself, since raw mode suppresses
        // the terminal's normal signal generation.
        let state = Arc::clone(&state);
        ctrlc::set_handler(move || {
            ui::end_interactive_session();
            state.running.store(false, Ordering::Relaxed);
            println!("\nGoodbye!");
            std::process::exit(0);
        })
        .ok();
    }

    {
        let state2 = Arc::clone(&state);
        let listener2 = listener.try_clone().expect("clone listener");
        *state.server_socket.write().unwrap() = Some(listener);
        std::thread::spawn(move || net::accept_connections(state2, listener2));
    }
    {
        let state2 = Arc::clone(&state);
        std::thread::spawn(move || net::discovery(state2));
    }
    {
        let state2 = Arc::clone(&state);
        std::thread::spawn(move || net::reaper(state2));
    }

    loop {
        if !interactive {
            ui::print_out("> ");
        }
        match ui::read_line(interactive) {
            ui::InputResult::Line(line) => {
                if !commands::process_command(&state, &line) {
                    break;
                }
            }
            ui::InputResult::Quit => break,
        }
    }

    shutdown(&state);
}

fn shutdown(state: &Arc<AppState>) {
    ui::end_interactive_session();
    state.running.store(false, Ordering::Relaxed);
    if let Some(sock) = state.discovery_socket.write().unwrap().take() {
        drop(sock);
    }
    {
        let mut peers = state.peers.lock().unwrap();
        for (_, link) in peers.drain() {
            let _ = link.stream.shutdown(std::net::Shutdown::Both);
        }
    }
    if let Some(server) = state.server_socket.write().unwrap().take() {
        drop(server);
    }
    println!("\nGoodbye!");
    let _ = std::io::stdout().flush();
}
