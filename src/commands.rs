use crate::colors;
use crate::net;
use crate::paths;
use crate::protocol::escape_field;
use crate::state::AppState;
use crate::ui;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let secs_today = now % 86400;
    format!("{:02}:{:02}", (secs_today / 3600) % 24, (secs_today / 60) % 60)
}

fn human_size(num_bytes: u64) -> String {
    let mut size = num_bytes as f64;
    let units = ["B", "KB", "MB", "GB"];
    for (i, unit) in units.iter().enumerate() {
        let is_last = i == units.len() - 1;
        if size < 1024.0 || is_last {
            return if *unit == "B" { format!("{:.0} {}", size, unit) } else { format!("{:.1} {}", size, unit) };
        }
        size /= 1024.0;
    }
    unreachable!()
}

fn new_msg_id() -> String {
    crate::protocol::new_msg_id()
}

pub fn send_chat_message(state: &Arc<AppState>, message: &str, reply_id: &str) {
    let my_color = state.color_for_id(&state.my_id);
    let msg_id = new_msg_id();
    let my_name = state.my_name.lock().unwrap().clone();
    state.msg_history.lock().unwrap().remember(&msg_id, &my_name, message);

    let mut reply_tag = String::new();
    if !reply_id.is_empty() {
        if let Some((rname, _)) = state.msg_history.lock().unwrap().get(reply_id) {
            reply_tag = format!(" (reply to {} [{}])", rname, reply_id);
        }
    }

    let id_tag = format!("[{}]", msg_id);
    let c = colors::code(my_color);
    ui::println_out(&format!("{} {}{} {}{}{}: {}", timestamp(), id_tag, reply_tag, c, my_name, colors::reset(), message));

    net::log_message(state, &format!("{} [{}]{} {}: {}", timestamp(), msg_id, reply_tag, my_name, message));

    if state.peers.lock().unwrap().is_empty() {
        ui::println_out("(No peers connected yet - message saved locally but not delivered to anyone.)");
    }

    let inner = format!(
        "MSG|{}|{}|{}|{}|{}|{}",
        state.my_id,
        my_color,
        escape_field(&my_name),
        escape_field(message),
        escape_field(&msg_id),
        escape_field(reply_id)
    );
    net::wrap_and_broadcast(state, &inner);
}

fn send_private_message(state: &Arc<AppState>, target: &str, text: &str) {
    let Some(peer_id) = state.resolve_peer_id(target) else { return };
    let my_color = state.color_for_id(&state.my_id);
    let my_name = state.my_name.lock().unwrap().clone();
    let line = format!(
        "{} [private to {}] {}{}{}: {}",
        timestamp(),
        target,
        colors::code(my_color),
        my_name,
        colors::reset(),
        text
    );
    net::log_message(state, &format!("{} [private to {}] {}: {}", timestamp(), target, my_name, text));
    ui::println_out(&line);

    let inner = format!("PRIV|{}|{}|{}|{}|{}", peer_id, state.my_id, my_color, escape_field(&my_name), escape_field(text));
    if !net::send_to_peer_id(state, &inner) {
        ui::println_out("Failed to send private message (no peers connected).");
    }
}

fn send_ping(state: &Arc<AppState>, target: &str) {
    let Some(peer_id) = state.resolve_peer_id(target) else { return };
    let sent = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
    state.pending_pings.lock().unwrap().insert(peer_id.clone(), sent);
    let inner = format!("PING|{}|{}|{}", peer_id, state.my_id, sent);
    if net::send_to_peer_id(state, &inner) {
        ui::println_out(&format!("Pinging {}...", target));
    } else {
        state.pending_pings.lock().unwrap().remove(&peer_id);
        ui::println_out("Failed to send ping (no peers connected).");
    }
}

fn list_peers(state: &Arc<AppState>) {
    let ips: Vec<String> = state.peers.lock().unwrap().keys().cloned().collect();
    if ips.is_empty() {
        ui::println_out("No peers connected.");
        return;
    }
    ui::println_out("Connected peers:");
    for ip in ips {
        let peer_id = state.ip_to_id.lock().unwrap().get(&ip).cloned();
        if let Some(peer_id) = peer_id {
            let name = state.peer_names.lock().unwrap().get(&peer_id).cloned();
            let color_idx = state.id_colors.lock().unwrap().get(&peer_id).copied();
            let c = colors::code(color_idx.unwrap_or(0));
            let display_name = name.unwrap_or_else(|| "(unknown)".to_string());
            let color_str = color_idx.map(|c| c.to_string()).unwrap_or_else(|| "?".to_string());
            ui::println_out(&format!("  {}{}{}  id={}  ip={}  color={}", c, display_name, colors::reset(), peer_id, ip, color_str));
        } else {
            ui::println_out(&format!("  (unidentified)  ip={}", ip));
        }
    }
}

fn list_ignored(state: &Arc<AppState>) {
    let ids: Vec<String> = state.ignored_ids.lock().unwrap().iter().cloned().collect();
    if ids.is_empty() {
        ui::println_out("Not ignoring anyone.");
        return;
    }
    ui::println_out("Ignored peers:");
    for pid in ids {
        let name = state.peer_names.lock().unwrap().get(&pid).cloned().unwrap_or_else(|| pid.clone());
        ui::println_out(&format!("  {} ({})", name, pid));
    }
}

fn list_recent_messages(state: &Arc<AppState>, count: usize) {
    let items = state.msg_history.lock().unwrap().recent(count);
    if items.is_empty() {
        ui::println_out("No recent messages to show.");
        return;
    }
    ui::println_out(&format!("Last {} message(s):", items.len()));
    for (msg_id, (sender_name, text)) in items {
        ui::println_out(&format!("  [{}] {}: {}", msg_id, sender_name, text));
    }
}

fn print_help() {
    ui::println_out("Commands:");
    ui::println_out("  /quit                     exit the chat");
    ui::println_out("  /who                      list connected peers with id, ip, and color");
    ui::println_out("  /connect <ip>             manually connect to a peer by IP");
    ui::println_out("  /recent [count]           show recent messages with their ids (default 10)");
    ui::println_out("  /reply <msg_id> <text>    reply to a specific message (pings its sender)");
    ui::println_out("  Tip: typing @name in a message pings that user");
    ui::println_out("  /name <newname>           change your display name (saved for next time)");
    ui::println_out("  /colors                   list available color numbers");
    ui::println_out("  /color <n>                change your color to number n");
    ui::println_out("  /color random             pick a random free color");
    ui::println_out("  /showid                   toggle showing peer IDs instead of names");
    ui::println_out("  /clear                    clear the screen");
    ui::println_out("  /ping <name|id>           measure round-trip latency to a peer");
    ui::println_out("  /sendfile <name|id> <path> upload a file to catbox.moe and DM the link");
    ui::println_out("  /msg <name|id> <text>     send a private message to one peer");
    ui::println_out("  /ignore <name|id>         stop showing messages from a peer");
    ui::println_out("  /unignore <name|id>       resume showing messages from a peer");
    ui::println_out("  /ignored                  list currently ignored peers");
    ui::println_out("  /fingerprint [name|id]    show the full identity key fingerprint (yours or a peer's)");
    ui::println_out("                             compare it over a trusted channel to verify identity");
    ui::println_out("  /help                     show this message");
}

fn print_colors(state: &Arc<AppState>) {
    let mine = state.id_colors.lock().unwrap().get(&state.my_id).copied();
    ui::println_out(&format!("You have {} colors to choose from (0-{}).", colors::COLORS.len(), colors::COLORS.len() - 1));
    if let Some(mine) = mine {
        ui::println_out(&format!("Your current color: {}{}{}", colors::code(mine), mine, colors::reset()));
    }
    ui::println_out("Use /color <n> to change, or /color random for a random free one.");
}

fn save_name(name: &str) {
    let _ = std::fs::write(paths::file(crate::state::NAME_FILE), name);
}

fn remember_color_for_name(state: &Arc<AppState>, name: &str, idx: usize) {
    state.name_to_color.lock().unwrap().insert(name.to_string(), idx);
    save_colors(state);
}

fn save_colors(state: &Arc<AppState>) {
    let items: Vec<(String, usize)> = state.name_to_color.lock().unwrap().iter().map(|(k, v)| (k.clone(), *v)).collect();
    let mut out = String::new();
    for (name, idx) in items {
        out.push_str(&format!("{}={}\n", name, idx));
    }
    let _ = std::fs::write(paths::file(crate::state::COLOR_FILE), out);
}

/// Uploads a file to catbox.moe and returns the resulting URL, used in
/// place of dechat's chunked file-transfer protocol (see README).
/// Streams from disk via Part::file rather than reading the whole file
/// into memory.
fn upload_to_catbox(filepath: &std::path::Path) -> Result<String, String> {
    let part = reqwest::blocking::multipart::Part::file(filepath).map_err(|e| format!("Could not read file: {}", e))?;
    let form = reqwest::blocking::multipart::Form::new().text("reqtype", "fileupload").part("fileToUpload", part);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("feral/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post("https://catbox.moe/user/api.php")
        .multipart(form)
        .send()
        .map_err(|e| format!("upload request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("catbox.moe returned HTTP {}", resp.status()));
    }
    let body = resp.text().map_err(|e| e.to_string())?;
    let url = body.trim().to_string();
    if !url.starts_with("http") {
        return Err(format!("unexpected response from catbox.moe: {}", url));
    }
    Ok(url)
}

fn send_file(state: &Arc<AppState>, target: &str, filepath: &str) {
    let Some(_peer_id) = state.resolve_peer_id(target) else { return };
    let resolved = paths::expand_tilde(filepath);
    let filesize = match std::fs::metadata(&resolved) {
        Ok(m) if m.is_dir() => {
            ui::println_out(&format!("'{}' is a directory, not a file.", resolved.display()));
            return;
        }
        Ok(m) => m.len(),
        Err(e) => {
            ui::println_out(&format!("Could not read '{}': {}", resolved.display(), e));
            if filepath != resolved.to_string_lossy() {
                ui::println_out(&format!("(expanded from '{}')", filepath));
            }
            return;
        }
    };
    if filesize > crate::state::MAX_SENDFILE_BYTES {
        ui::println_out(&format!(
            "'{}' is {}, which is over the {} limit.",
            resolved.display(),
            human_size(filesize),
            human_size(crate::state::MAX_SENDFILE_BYTES)
        ));
        return;
    }
    ui::println_out(&format!("Uploading '{}' ({}) to catbox.moe...", resolved.display(), human_size(filesize)));
    let state2 = Arc::clone(state);
    let target = target.to_string();
    std::thread::spawn(move || match upload_to_catbox(&resolved) {
        Ok(url) => {
            let filename = resolved.file_name().and_then(|f| f.to_str()).unwrap_or("file").to_string();
            ui::notify(&format!("Uploaded '{}'. Sending link to {}...", filename, target));
            send_private_message(&state2, &target, &format!("sent you a file: {} ({})", filename, url));
        }
        Err(e) => {
            ui::notify(&format!("Failed to send file: {}", e));
        }
    });
}

/// Handles one line of input. Returns false if the app should quit.
pub fn process_command(state: &Arc<AppState>, message: &str) -> bool {
    if message == "/quit" {
        return false;
    } else if message == "/who" {
        list_peers(state);
    } else if message == "/help" {
        print_help();
    } else if message == "/colors" {
        print_colors(state);
    } else if message == "/color" || message.starts_with("/color ") {
        let arg = message["/color".len()..].trim();
        let (used, current) = {
            let colors_map = state.id_colors.lock().unwrap();
            let used: std::collections::HashSet<usize> =
                colors_map.iter().filter(|(pid, _)| pid.as_str() != state.my_id).map(|(_, &idx)| idx).collect();
            let current = colors_map.get(&state.my_id).copied();
            (used, current)
        };
        if arg == "random" {
            let free: Vec<usize> = (0..colors::COLORS.len()).filter(|i| !used.contains(i) && Some(*i) != current).collect();
            if free.is_empty() {
                ui::println_out("No free colors left.");
            } else {
                let mut remaining = free;
                let mut claimed = None;
                while !remaining.is_empty() && claimed.is_none() {
                    let idx = rand::random::<usize>() % remaining.len();
                    let candidate = remaining.remove(idx);
                    if state.claim_color_for_id(&state.my_id, candidate) {
                        claimed = Some(candidate);
                    }
                }
                match claimed {
                    Some(claimed) => {
                        let my_name = state.my_name.lock().unwrap().clone();
                        remember_color_for_name(state, &my_name, claimed);
                        net::wrap_and_broadcast(state, &format!("COLOR|{}|{}", state.my_id, claimed));
                        ui::println_out(&format!("Color set to {}{}{}", colors::code(claimed), claimed, colors::reset()));
                    }
                    None => ui::println_out("No free colors left."),
                }
            }
        } else if let Ok(chosen) = arg.parse::<usize>() {
            if chosen >= colors::COLORS.len() {
                ui::println_out(&format!("Pick a number from 0 to {}.", colors::COLORS.len() - 1));
            } else if !state.claim_color_for_id(&state.my_id, chosen) {
                let still_used: std::collections::HashSet<usize> = state
                    .id_colors
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(pid, _)| pid.as_str() != state.my_id)
                    .map(|(_, &idx)| idx)
                    .collect();
                let free_now: Vec<String> = (0..colors::COLORS.len()).filter(|i| !still_used.contains(i)).map(|i| i.to_string()).collect();
                if free_now.is_empty() {
                    ui::println_out("That color is already taken, and no colors are currently free.");
                } else {
                    ui::println_out(&format!("That color is already taken. Free colors: {} (or /color random).", free_now.join(", ")));
                }
            } else {
                let my_name = state.my_name.lock().unwrap().clone();
                remember_color_for_name(state, &my_name, chosen);
                net::wrap_and_broadcast(state, &format!("COLOR|{}|{}", state.my_id, chosen));
                ui::println_out(&format!("Color set to {}{}{}", colors::code(chosen), chosen, colors::reset()));
            }
        } else {
            ui::println_out("Usage: /color <n> or /color random");
        }
    } else if message == "/showid" {
        let new_val = !state.show_id.load(Ordering::Relaxed);
        state.show_id.store(new_val, Ordering::Relaxed);
        ui::println_out(&format!("Show IDs instead of names: {}", if new_val { "on" } else { "off" }));
    } else if let Some(rest) = message.strip_prefix("/name ") {
        let new_name = rest.trim();
        if !new_name.is_empty() {
            *state.my_name.lock().unwrap() = new_name.to_string();
            save_name(new_name);
            net::wrap_and_broadcast(state, &format!("NAME|{}|{}", state.my_id, escape_field(new_name)));
            ui::println_out(&format!("Name set to: {}", new_name));
        }
    } else if message == "/clear" {
        print!("\x1b[2J\x1b[H");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    } else if let Some(target) = message.strip_prefix("/ping ") {
        let target = target.trim();
        if target.is_empty() {
            ui::println_out("Usage: /ping <name|id>");
        } else {
            send_ping(state, target);
        }
    } else if let Some(rest) = message.strip_prefix("/sendfile ") {
        let rest = rest.trim();
        if let Some((target, path)) = rest.split_once(' ') {
            send_file(state, target, path);
        } else {
            ui::println_out("Usage: /sendfile <name|id> <path>");
        }
    } else if let Some(rest) = message.strip_prefix("/msg ") {
        let rest = rest.trim();
        if let Some((target, text)) = rest.split_once(' ') {
            send_private_message(state, target, text);
        } else {
            ui::println_out("Usage: /msg <name|id> <text>");
        }
    } else if let Some(target) = message.strip_prefix("/ignore ") {
        let target = target.trim();
        if target.is_empty() {
            ui::println_out("Usage: /ignore <name|id>");
        } else if let Some(peer_id) = state.resolve_peer_id(target) {
            state.ignored_ids.lock().unwrap().insert(peer_id);
            ui::println_out(&format!("Ignoring messages from {}.", target));
        }
    } else if let Some(target) = message.strip_prefix("/unignore ") {
        let target = target.trim();
        if target.is_empty() {
            ui::println_out("Usage: /unignore <name|id>");
        } else {
            match state.resolve_peer_id(target) {
                Some(peer_id) => {
                    state.ignored_ids.lock().unwrap().remove(&peer_id);
                    ui::println_out(&format!("No longer ignoring {}.", target));
                }
                None => {
                    let was_ignored = state.ignored_ids.lock().unwrap().remove(target);
                    if was_ignored {
                        ui::println_out(&format!("No longer ignoring '{}'.", target));
                    } else {
                        ui::println_out(&format!("'{}' was not being ignored.", target));
                    }
                }
            }
        }
    } else if message == "/ignored" {
        list_ignored(state);
    } else if message == "/fingerprint" {
        ui::println_out(&format!("Your fingerprint ({}): {}", state.my_id, state.my_fingerprint));
        ui::println_out("Read this over a trusted channel (in person, voice call) to someone else so they can confirm it matches what their client shows for you.");
    } else if let Some(target) = message.strip_prefix("/fingerprint ") {
        let target = target.trim();
        match state.resolve_peer_id(target) {
            Some(peer_id) => match state.peer_keys.lock().unwrap().get(&peer_id).cloned() {
                Some(pk) => ui::println_out(&format!("Fingerprint for {} ({}): {}", target, peer_id, pk.fingerprint)),
                None => ui::println_out(&format!("No verified identity key for {} yet.", target)),
            },
            None => {}
        }
    } else if let Some(target_ip) = message.strip_prefix("/connect ") {
        let target_ip = target_ip.trim();
        if target_ip.is_empty() {
            ui::println_out("Usage: /connect <ip>");
        } else {
            ui::println_out(&format!("Connecting to {}...", target_ip));
            let state2 = Arc::clone(state);
            let ip = target_ip.to_string();
            std::thread::spawn(move || net::connect_to_peer(&state2, &ip, None));
        }
    } else if message == "/recent" || message.starts_with("/recent ") {
        let arg = message["/recent".len()..].trim();
        let count = if arg.is_empty() {
            10
        } else {
            match arg.parse::<usize>() {
                Ok(n) => n.clamp(1, crate::state::MAX_MSG_HISTORY),
                Err(_) => {
                    ui::println_out("Usage: /recent [count]");
                    0
                }
            }
        };
        if count > 0 {
            list_recent_messages(state, count);
        }
    } else if let Some(rest) = message.strip_prefix("/reply ") {
        let rest = rest.trim();
        if let Some((reply_id, text)) = rest.split_once(' ') {
            let reply_id = reply_id.trim_start_matches('[').trim_end_matches(']');
            if state.msg_history.lock().unwrap().get(reply_id).is_none() {
                ui::println_out(&format!("No known message with id '{}'. It may be too old or invalid.", reply_id));
            } else {
                send_chat_message(state, text, reply_id);
            }
        } else {
            ui::println_out("Usage: /reply <msg_id> <text>");
        }
    } else if message.starts_with('/') {
        ui::println_out(&format!("Unknown command: {}. Type /help for a list of commands.", message));
    } else if !message.is_empty() {
        send_chat_message(state, message, "");
    }

    true
}
