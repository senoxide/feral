use crate::colors;
use crate::crypto;
use crate::identity;
use crate::protocol::{
    self, escape_field, sanitize_for_display, unescape_field, CHAT_PORT, DISCOVERY_PORT,
    MAX_CLOCK_SKEW_SECS, MAX_PEER_DEGREE, RELAY_TTL,
};
use crate::state::{AppState, PeerKey, PeerLink};
use crate::ui;
use ed25519_dalek::Signature;
use rand::Rng;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_epoch_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

fn timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let secs_today = now % 86400;
    format!("{:02}:{:02}", (secs_today / 3600) % 24, (secs_today / 60) % 60)
}

pub fn log_message(state: &AppState, line: &str) {
    let _g = state.log_lock.lock().unwrap();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(crate::paths::file(crate::state::LOG_FILE)) {
        let _ = writeln!(f, "{}", line);
    }
}

/// Reads until `buf` is full, retrying on read-timeout wakeups (used so
/// the loop can periodically check state.is_running()) but treating any
/// other error, or a clean EOF partway through a frame, as fatal.
fn read_full(stream: &mut TcpStream, buf: &mut [u8], state: &Arc<AppState>) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(n) => filled += n,
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    WouldBlock | TimedOut => {
                        if !state.is_running() {
                            return Err(e);
                        }
                        continue;
                    }
                    _ => return Err(e),
                }
            }
        }
    }
    Ok(filled)
}

fn drop_peer(state: &Arc<AppState>, ip: &str) {
    let dead = state.peers.lock().unwrap().remove(ip);
    drop(dead);
}

/// Encrypts one plaintext line and sends it as a length-prefixed frame
/// on this peer's link. Frame boundaries replace newline-delimiting now
/// that payloads are ciphertext.
fn send_line_to_peer(state: &Arc<AppState>, ip: &str, text: &str) -> bool {
    let mut peers = state.peers.lock().unwrap();
    let Some(link) = peers.get_mut(ip) else { return false };
    let ciphertext = crypto::encrypt(&link.send_key, link.send_counter, text.as_bytes());
    let len = (ciphertext.len() as u32).to_be_bytes();
    let ok = link.stream.write_all(&len).and_then(|_| link.stream.write_all(&ciphertext)).is_ok();
    if ok {
        link.send_counter += 1;
        true
    } else {
        drop(peers);
        drop_peer(state, ip);
        false
    }
}

/// Sends to every directly-connected neighbor; relay_onward carries it
/// the rest of the way across the mesh.
pub fn send_to_all(state: &Arc<AppState>, message: &str, exclude_ip: Option<&str>) {
    let ips: Vec<String> = {
        let peers = state.peers.lock().unwrap();
        peers.keys().cloned().collect()
    };
    for ip in ips {
        if Some(ip.as_str()) == exclude_ip {
            continue;
        }
        send_line_to_peer(state, &ip, message);
    }
}

/// Wraps and floods a point-to-point packet (PRIV, PING, PONG, ...) to
/// every neighbor. Fire-and-forget: no delivery ack.
pub fn send_to_peer_id(state: &Arc<AppState>, inner_line: &str) -> bool {
    if state.peers.lock().unwrap().is_empty() {
        return false;
    }
    let (packet_id, line) = protocol::wrap_relay(&state.identity, inner_line);
    state.mark_seen(&packet_id);
    send_to_all(state, &line, None);
    true
}

pub fn wrap_and_broadcast(state: &Arc<AppState>, inner_line: &str) {
    let (packet_id, line) = protocol::wrap_relay(&state.identity, inner_line);
    state.mark_seen(&packet_id);
    send_to_all(state, &line, None);
}

fn relay_onward(state: &Arc<AppState>, packet_id: &str, ttl: u32, ts: i64, sig_hex: &str, inner_line: &str, from_ip: &str) {
    if ttl == 0 {
        return;
    }
    let line = format!("RELAY|{}|{}|{}|{}|{}", packet_id, ttl - 1, ts, sig_hex, inner_line);
    send_to_all(state, &line, Some(from_ip));
}

/// Binds an IP to the peer_id its handshake proved it controls; rejects
/// a later claim of a different peer_id on the same connection, and
/// drops a duplicate connection when the same identity shows up from a
/// second IP.
fn claim_identity(state: &Arc<AppState>, ip: &str, peer_id: &str) -> bool {
    let mut ip_to_id = state.ip_to_id.lock().unwrap();
    if let Some(bound) = ip_to_id.get(ip) {
        return bound == peer_id;
    }
    if ip_to_id.len() >= crate::state::MAX_TRACKED_PEERS {
        return false;
    }
    let existing_ip = ip_to_id.iter().find(|(_, id)| id.as_str() == peer_id).map(|(ip, _)| ip.clone());
    if let Some(existing_ip) = existing_ip {
        let still_connected = state.peers.lock().unwrap().contains_key(&existing_ip);
        if still_connected {
            let state2 = Arc::clone(state);
            let ip_owned = ip.to_string();
            std::thread::spawn(move || drop_peer(&state2, &ip_owned));
            return false;
        }
    }
    ip_to_id.insert(ip.to_string(), peer_id.to_string());
    true
}

/// TOFU-pins a peer's public key the first time its handshake proves
/// possession of the matching private key. A later handshake claiming
/// the same short id with a *different* key is rejected, not silently
/// overwritten -- the short id is only 32 bits of the fingerprint, so
/// this pin (not the id itself) is the actual protection against a
/// ground/colliding-key impersonation attempt.
fn pin_identity(state: &Arc<AppState>, peer_id: &str, fp: &str, pubkey: ed25519_dalek::VerifyingKey) -> bool {
    let mut keys = state.peer_keys.lock().unwrap();
    if let Some(existing) = keys.get(peer_id) {
        if existing.fingerprint != fp {
            drop(keys);
            ui::notify(&format!(
                "WARNING: peer id {} presented a different identity key than previously recorded. Rejecting the connection -- this could be an impersonation attempt.",
                peer_id
            ));
            return false;
        }
        return true;
    }
    keys.insert(peer_id.to_string(), PeerKey { pubkey, fingerprint: fp.to_string() });
    drop(keys);
    identity::append_known_peer(peer_id, fp, &hex::encode(pubkey.as_bytes()));
    true
}

/// Verifies `inner_line` was actually signed by `peer_id`'s pinned key.
/// This is origin authentication for gossip content and is separate
/// from the transport encryption -- it's what lets a multi-hop relayed
/// packet still be checked against its original author, not just the
/// neighbor that happened to forward it.
fn verify_sender(state: &Arc<AppState>, peer_id: &str, ip: &str, is_direct: bool, ts: i64, inner_line: &str, sig_hex: &str) -> bool {
    if is_direct && !claim_identity(state, ip, peer_id) {
        return false;
    }
    if (protocol::now_epoch() - ts).abs() > MAX_CLOCK_SKEW_SECS {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(sig_hex) else { return false };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false };
    let sig = Signature::from_bytes(&sig_arr);
    let key = state.peer_keys.lock().unwrap().get(peer_id).cloned();
    match key {
        Some(pk) => protocol::verify(&pk.pubkey, ts, inner_line, &sig),
        None => false,
    }
}

fn mentions_me(state: &Arc<AppState>, text: &str) -> bool {
    let my_name = state.my_name.lock().unwrap().to_lowercase();
    text.to_lowercase().contains(&format!("@{}", my_name))
}

/// Peers could in principle claim an arbitrarily long name or message;
/// truncate defensively on receipt so a hostile peer can't force us to
/// store/print/log unbounded text sizes (see also the client-side caps
/// enforced in commands.rs for our own outgoing name/messages).
fn clamp_received_name(raw: String) -> String {
    raw.chars().take(crate::state::MAX_NAME_LEN).collect()
}

fn clamp_received_text(raw: String) -> String {
    raw.chars().take(crate::state::MAX_MESSAGE_LEN).collect()
}

/// Parses and dispatches one already-decrypted protocol line: unwraps a
/// RELAY envelope (dedup, freshness check, forward), then verifies and
/// acts on the inner packet if it's addressed to us or a broadcast.
pub fn handle_incoming(state: &Arc<AppState>, raw_in: &str, ip: &str) {
    if raw_in.is_empty() || raw_in.len() > 10_000 {
        return;
    }
    let mut raw = raw_in.to_string();
    let mut is_direct = true;
    let mut ts: i64 = 0;
    let mut sig_hex = String::new();

    if let Some(rest) = raw.strip_prefix("RELAY|") {
        let env: Vec<&str> = rest.splitn(5, '|').collect();
        if env.len() != 5 {
            return;
        }
        let packet_id = env[0];
        let Ok(ttl) = env[1].parse::<u32>() else { return };
        let Ok(env_ts) = env[2].parse::<i64>() else { return };
        let env_sig = env[3];
        let inner = env[4];
        if !(1..=64).contains(&packet_id.len()) || env_sig.len() != 128 {
            return;
        }
        is_direct = ttl == RELAY_TTL;
        if (protocol::now_epoch() - env_ts).abs() > MAX_CLOCK_SKEW_SECS {
            return; // stale or replayed well outside the freshness window
        }
        if !state.mark_seen(packet_id) {
            return;
        }
        relay_onward(state, packet_id, ttl, env_ts, env_sig, inner, ip);
        ts = env_ts;
        sig_hex = env_sig.to_string();
        raw = inner.to_string();
    }

    let signed_line = raw.clone();
    let packet_type = raw.split('|').next().unwrap_or("");
    let split_n: usize = match packet_type {
        "MSG" | "PRIV" => 5,
        "COLOR" | "NAME" => 3,
        "PING" | "PONG" => 4,
        "FILE_OFFER" => 7,
        "FILE_DECLINE" | "FILE_ACCEPT" => 4,
        "FILE" => 6,
        "FILE_ACK" => 5,
        _ => 5,
    };
    let parts: Vec<&str> = raw.splitn(split_n, '|').collect();

    match (packet_type, parts.len()) {
        ("MSG", 5) => {
            let peer_id = parts[1];
            let color_idx = parts[2];
            let name_raw = parts[3];
            let rest = parts[4];
            if peer_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            let (text_raw, msg_id_raw, reply_id_raw) = {
                let rp: Vec<&str> = rest.splitn(3, '|').collect();
                if rp.len() == 3 { (rp[0], rp[1], rp[2]) } else { (rest, "", "") }
            };
            let name = clamp_received_name(sanitize_for_display(&unescape_field(name_raw)));
            let text = clamp_received_text(sanitize_for_display(&unescape_field(text_raw)));
            let msg_id = unescape_field(msg_id_raw);
            let reply_id = unescape_field(reply_id_raw);
            if let Ok(idx) = color_idx.parse::<usize>() {
                state.set_color_for_id(peer_id, idx);
            }
            state.peer_names.lock().unwrap().insert(peer_id.to_string(), name.clone());
            let is_ignored = state.ignored_ids.lock().unwrap().contains(peer_id);

            if !msg_id.is_empty() {
                state.msg_history.lock().unwrap().remember(&msg_id, &name, &text);
            }

            let mut reply_tag = String::new();
            let mut pinged_by_reply = false;
            if !reply_id.is_empty() {
                if let Some((rname, _)) = state.msg_history.lock().unwrap().get(&reply_id) {
                    reply_tag = format!(" (reply to {} [{}])", rname, reply_id);
                    pinged_by_reply = rname == *state.my_name.lock().unwrap();
                }
            }

            let id_tag = if !msg_id.is_empty() { format!("[{}]", msg_id) } else { String::new() };
            log_message(state, &format!("{} {}{} {}: {}", timestamp(), id_tag, reply_tag, name, text));
            if is_ignored {
                return;
            }

            let c = colors::code(state.color_for_id(peer_id));
            let pinged = pinged_by_reply || mentions_me(state, &text);
            let shown_name = state.display_identity(peer_id, &name);
            let display = format!("{} {}{} {}{}{}: {}", timestamp(), id_tag, reply_tag, c, shown_name, colors::reset(), text);
            if pinged {
                // Reverse-video + bell are a nice touch when the
                // terminal supports them, but neither is guaranteed
                // (NO_COLOR, a piped/non-tty session, or a muted
                // terminal bell all silently no-op them) -- so the
                // ">>> ... <<<" text marker is what actually
                // guarantees a mention is visible, unconditionally.
                ui::notify(&format!(">>> {}{}{} <<<", colors::reverse(), display, colors::unreverse()));
            } else {
                ui::notify(&display);
            }
        }
        ("PRIV", 5) => {
            let target_id = parts[1];
            let sender_id = parts[2];
            let color_idx = parts[3];
            let rest = parts[4];
            if sender_id.len() != 8 || target_id.len() != 8 {
                return;
            }
            if !verify_sender(state, sender_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            if target_id != state.my_id {
                return;
            }
            let Some((name_raw, text_raw)) = rest.split_once('|') else { return };
            let name = clamp_received_name(sanitize_for_display(&unescape_field(name_raw)));
            let text = clamp_received_text(sanitize_for_display(&unescape_field(text_raw)));
            if let Ok(idx) = color_idx.parse::<usize>() {
                state.set_color_for_id(sender_id, idx);
            }
            state.peer_names.lock().unwrap().insert(sender_id.to_string(), name.clone());
            let is_ignored = state.ignored_ids.lock().unwrap().contains(sender_id);
            log_message(state, &format!("{} [private] {}: {}", timestamp(), name, text));
            if is_ignored {
                return;
            }
            let c = colors::code(state.color_for_id(sender_id));
            let shown_name = state.display_identity(sender_id, &name);
            ui::notify(&format!("{} [private] {}{}{}: {}", timestamp(), c, shown_name, colors::reset(), text));
        }
        ("COLOR", 3) => {
            let peer_id = parts[1];
            if peer_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            if let Ok(idx) = parts[2].parse::<usize>() {
                state.set_color_for_id(peer_id, idx);
            }
        }
        ("NAME", 3) => {
            let peer_id = parts[1];
            if peer_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            let name = clamp_received_name(sanitize_for_display(&unescape_field(parts[2])));
            let (is_new, duplicate) = {
                let mut names = state.peer_names.lock().unwrap();
                let is_new = !names.contains_key(peer_id);
                let duplicate = names.iter().any(|(pid, n)| pid != peer_id && n == &name);
                names.insert(peer_id.to_string(), name.clone());
                (is_new, duplicate)
            };
            if is_new && name != peer_id {
                let c = colors::code(state.color_for_id(peer_id));
                let mut msg = format!("{}{}{} has joined ({})", c, name, colors::reset(), peer_id);
                if duplicate {
                    msg.push_str(&format!(
                        "\nNote: '{}' is already in use by another connected peer; use the id ({}) with /msg, /ping, etc. to be sure you reach the right one.",
                        name, peer_id
                    ));
                }
                ui::notify(&msg);
            }
        }
        ("PING", 4) => {
            let target_id = parts[1];
            let peer_id = parts[2];
            if peer_id.len() != 8 || target_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            if target_id != state.my_id {
                return;
            }
            send_to_peer_id(state, &format!("PONG|{}|{}|{}", peer_id, state.my_id, parts[3]));
        }
        ("PONG", 4) => {
            let target_id = parts[1];
            let peer_id = parts[2];
            if peer_id.len() != 8 || target_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            if target_id != state.my_id {
                return;
            }
            let Ok(sent) = parts[3].parse::<f64>() else { return };
            let rtt_ms = (now_epoch_f64() - sent) * 1000.0;
            let name = state.peer_names.lock().unwrap().get(peer_id).cloned().unwrap_or_else(|| peer_id.to_string());
            ui::notify(&format!("Pong from {}: {:.1} ms", name, rtt_ms));
            state.pending_pings.lock().unwrap().remove(peer_id);
        }
        ("FILE_OFFER", 7) => {
            // feral doesn't implement the legacy chunked file-transfer
            // protocol; decline so the sender isn't left waiting.
            let target_id = parts[1];
            let peer_id = parts[2];
            let offer_id = parts[3];
            if peer_id.len() != 8 || target_id.len() != 8 {
                return;
            }
            if !verify_sender(state, peer_id, ip, is_direct, ts, &signed_line, &sig_hex) {
                return;
            }
            if target_id != state.my_id {
                return;
            }
            let filename = sanitize_for_display(&unescape_field(parts[4]));
            let name = state.peer_names.lock().unwrap().get(peer_id).cloned().unwrap_or_else(|| peer_id.to_string());
            ui::notify(&format!(
                "{} tried to send you a file ('{}'), but feral doesn't receive files over the legacy transfer -- declining automatically. Ask them to /sendfile instead (uploads to catbox.moe and sends a link).",
                name, filename
            ));
            send_to_peer_id(state, &format!("FILE_DECLINE|{}|{}|{}", peer_id, state.my_id, offer_id));
        }
        ("FILE_DECLINE", 4) | ("FILE_ACCEPT", 4) | ("FILE", 6) | ("FILE_ACK", 5) => {}
        _ => {
            ui::notify(&sanitize_for_display(raw_in));
        }
    }
}

/// Reads and decrypts one length-prefixed frame. Ok(None) is a clean
/// disconnect; Err is anything fatal to the connection (I/O error,
/// oversized/malformed frame, or a failed AEAD tag -- which means
/// either tampering or the two sides' counters have desynced, and
/// either way the link can no longer be trusted).
fn read_frame(stream: &mut TcpStream, key: &[u8; 32], counter: u64, state: &Arc<AppState>) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let n = read_full(stream, &mut len_buf, state)?;
    if n == 0 {
        return Ok(None);
    }
    if n != 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated frame length"));
    }
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > crate::state::MAX_FRAME_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len as usize];
    let n = read_full(stream, &mut body, state)?;
    if n != body.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated frame body"));
    }
    match crypto::decrypt(key, counter, &body) {
        Some(plaintext) => Ok(Some(plaintext)),
        None => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "decryption failed")),
    }
}

fn is_file_packet(line: &[u8]) -> bool {
    let target: &[u8] = if line.starts_with(b"RELAY|") {
        let parts: Vec<&[u8]> = line.splitn(6, |&b| b == b'|').collect();
        if parts.len() == 6 { parts[5] } else { line }
    } else {
        line
    };
    for prefix in [&b"FILE|"[..], b"FILE_OFFER|", b"FILE_ACCEPT|", b"FILE_DECLINE|", b"FILE_ACK|"] {
        if target.starts_with(prefix) {
            return true;
        }
    }
    false
}

fn receive(state: Arc<AppState>, mut stream: TcpStream, ip: String, recv_key: [u8; 32]) {
    let mut counter: u64 = 0;
    while state.is_running() {
        match read_frame(&mut stream, &recv_key, counter, &state) {
            Ok(None) => break,
            Ok(Some(line)) => {
                counter += 1;
                if line.is_empty() {
                    continue;
                }
                if !is_file_packet(&line) && state.rate_limited(&ip) {
                    continue;
                }
                let text = String::from_utf8_lossy(&line).to_string();
                handle_incoming(&state, &text, &ip);
            }
            Err(_) => break,
        }
    }

    drop_peer(&state, &ip);
    state.attempted_connections.lock().unwrap().remove(&ip);
    state
        .deferred_until
        .lock()
        .unwrap()
        .insert(ip.clone(), std::time::Instant::now() + crate::state::DISCONNECT_RETRY_COOLDOWN);
    state.rate_buckets.lock().unwrap().remove(&ip);

    let peer_id = state.ip_to_id.lock().unwrap().remove(&ip);
    if let Some(peer_id) = &peer_id {
        state.id_colors.lock().unwrap().remove(peer_id);
        state.peer_names.lock().unwrap().remove(peer_id);
        // peer_keys is intentionally NOT cleared: the pinned identity
        // persists so a reconnect can be verified against the same key.
    }

    ui::notify(&format!("Disconnected: {}", ip));

    let should_retry = {
        let known = state.known_ips.lock().unwrap();
        if !known.contains(&ip) {
            false
        } else {
            let mut reconnecting = state.reconnecting_ips.lock().unwrap();
            if reconnecting.contains(&ip) {
                false
            } else {
                reconnecting.insert(ip.clone());
                true
            }
        }
    };
    if should_retry && state.is_running() {
        let state2 = Arc::clone(&state);
        let ip2 = ip.clone();
        std::thread::spawn(move || reconnect_worker(state2, ip2));
    }
}

fn reconnect_worker(state: Arc<AppState>, ip: String) {
    let mut attempt = 0u32;
    while state.is_running() && attempt < crate::state::MAX_RECONNECT_ATTEMPTS {
        let delay = rand::thread_rng().gen_range(crate::state::RECONNECT_DELAY_MIN..=crate::state::RECONNECT_DELAY_MAX);
        std::thread::sleep(Duration::from_secs_f64(delay));
        if !state.is_running() {
            break;
        }
        if !state.known_ips.lock().unwrap().contains(&ip) {
            break;
        }
        if state.peers.lock().unwrap().contains_key(&ip) {
            break;
        }
        attempt += 1;
        connect_to_peer(&state, &ip, None);
        if state.peers.lock().unwrap().contains_key(&ip) {
            break;
        }
    }
    state.reconnecting_ips.lock().unwrap().remove(&ip);
}

/// Performs the authenticated ephemeral key exchange on a freshly
/// connected/accepted raw socket. Returns the peer's short id and the
/// two directional symmetric keys on success. Any failure (bad
/// signature, size mismatch, identity mismatch, timeout, I/O error)
/// returns None and the caller must drop the connection -- there is no
/// plaintext or unauthenticated fallback path.
fn perform_handshake(state: &Arc<AppState>, stream: &mut TcpStream, ip: &str) -> Option<(String, [u8; 32], [u8; 32])> {
    let _ = stream.set_read_timeout(Some(crate::state::HANDSHAKE_TIMEOUT));
    let init = crypto::start_handshake(&state.identity);
    stream.write_all(&init.message).ok()?;

    let mut buf = [0u8; crypto::HANDSHAKE_LEN];
    let n = read_full(stream, &mut buf, state).ok()?;
    if n != crypto::HANDSHAKE_LEN {
        return None;
    }
    let parsed = crypto::verify_handshake(&buf)?;

    let fp = protocol::fingerprint(&parsed.identity_pubkey);
    let peer_id = protocol::short_id(&fp).to_string();
    if !claim_identity(state, ip, &peer_id) {
        return None;
    }
    if !pin_identity(state, &peer_id, &fp, parsed.identity_pubkey) {
        return None;
    }

    let keys = crypto::derive_session_keys(init, &parsed.peer_ephemeral);
    Some((peer_id, keys.send_key, keys.recv_key))
}

fn send_handshake_followup(state: &Arc<AppState>, ip: &str) {
    let idx = state.color_for_id(&state.my_id);
    wrap_and_send_to(state, ip, &format!("COLOR|{}|{}", state.my_id, idx));
    let name = state.my_name.lock().unwrap().clone();
    wrap_and_send_to(state, ip, &format!("NAME|{}|{}", state.my_id, escape_field(&name)));
}

fn wrap_and_send_to(state: &Arc<AppState>, ip: &str, inner_line: &str) {
    let (packet_id, line) = protocol::wrap_relay(&state.identity, inner_line);
    state.mark_seen(&packet_id);
    send_line_to_peer(state, ip, &line);
}

fn at_degree_cap(state: &Arc<AppState>) -> bool {
    state.peers.lock().unwrap().len() >= MAX_PEER_DEGREE
}

fn note_connected(state: &Arc<AppState>, ip: &str) {
    state.deferred_until.lock().unwrap().remove(ip);
    state.known_ips.lock().unwrap().insert(ip.to_string());
    ui::notify(&format!("Connected (encrypted): {}", ip));
}

/// Shared tail end of both the inbound and outbound connection paths:
/// runs the handshake on a raw stream and, on success, registers the
/// link and spawns the read loop. Returns once the handshake phase is
/// done (success or failure) -- it does not block for the connection's
/// lifetime, so callers can call this synchronously.
fn establish_link(state: Arc<AppState>, mut stream: TcpStream, ip: String) -> bool {
    let result = perform_handshake(&state, &mut stream, &ip);
    let Some((_peer_id, send_key, recv_key)) = result else {
        state.attempted_connections.lock().unwrap().remove(&ip);
        state.deferred_until.lock().unwrap().remove(&ip);
        return false;
    };

    {
        let mut peers = state.peers.lock().unwrap();
        if peers.contains_key(&ip) {
            return false;
        }
        let Ok(clone) = stream.try_clone() else { return false };
        peers.insert(ip.clone(), PeerLink { stream: clone, send_key, send_counter: 0 });
    }

    note_connected(&state, &ip);
    send_handshake_followup(&state, &ip);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));

    let state2 = Arc::clone(&state);
    let ip2 = ip.clone();
    std::thread::spawn(move || receive(state2, stream, ip2, recv_key));
    true
}

pub fn accept_connections(state: Arc<AppState>, listener: TcpListener) {
    for conn in listener.incoming() {
        if !state.is_running() {
            break;
        }
        let Ok(stream) = conn else { break };
        let Ok(addr) = stream.peer_addr() else { continue };
        let ip = addr.ip().to_string();

        {
            let peers = state.peers.lock().unwrap();
            if peers.contains_key(&ip) {
                continue;
            }
            // Inbound gets a higher ceiling than MAX_PEER_DEGREE (which
            // mainly governs our own outbound dialing) so two nodes both
            // at the cap can still reach each other.
            if peers.len() >= MAX_PEER_DEGREE * 2 {
                continue;
            }
        }
        if !state.reserve_handshake_slot(&ip) {
            continue; // too many connections mid-handshake (globally or from this IP); shed load
        }

        let state2 = Arc::clone(&state);
        std::thread::spawn(move || {
            let ip2 = ip.clone();
            establish_link(Arc::clone(&state2), stream, ip);
            state2.release_handshake_slot(&ip2);
        });
    }
}

pub fn connect_to_peer(state: &Arc<AppState>, ip: &str, remote_id: Option<&str>) {
    if state.peers.lock().unwrap().contains_key(ip) {
        return;
    }

    // If the remote's id is "greater" than ours, defer and let them dial
    // us, so both sides don't race to connect simultaneously.
    if let Some(remote_id) = remote_id {
        if remote_id > state.my_id.as_str() {
            state
                .deferred_until
                .lock()
                .unwrap()
                .insert(ip.to_string(), std::time::Instant::now() + crate::state::DEFER_RETRY_COOLDOWN);
            return;
        }
    }

    let addr = format!("{}:{}", ip, CHAT_PORT)
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::new(ip.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0])), CHAT_PORT));
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(_) => {
            state.attempted_connections.lock().unwrap().remove(ip);
            state.deferred_until.lock().unwrap().remove(ip);
            return;
        }
    };
    let _ = stream.set_nodelay(true);

    if !state.reserve_handshake_slot(ip) {
        return;
    }
    establish_link(Arc::clone(state), stream, ip.to_string());
    state.release_handshake_slot(ip);
}

/// Enumerates local network interfaces to find LAN-facing IPv4
/// addresses and their broadcast addresses -- no packets sent, no
/// internet required, works fully offline.
fn local_broadcast_targets() -> Vec<String> {
    let mut targets = vec!["255.255.255.255".to_string()];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if let Some(bcast) = v4.broadcast {
                    let s = bcast.to_string();
                    if !targets.contains(&s) {
                        targets.push(s);
                    }
                }
            }
        }
    }
    targets
}

fn announce_interval_for_known_peers(state: &Arc<AppState>) -> f64 {
    let known = state.ip_to_id.lock().unwrap().len() as f64;
    (3.0 + known / 40.0).min(10.0)
}

/// If we've heard other peers announcing themselves but never managed
/// to connect to any of them, that's a strong signal of client
/// isolation or a firewall blocking peer-to-peer TCP, not just "no one
/// else is here yet".
fn maybe_warn_isolation(state: &Arc<AppState>) {
    if state.isolation_warned.load(Relaxed) {
        return;
    }
    if state.start_time.elapsed() < crate::state::ISOLATION_WARNING_AFTER {
        return;
    }
    let heard_someone = !state.announced_peer_ids.lock().unwrap().is_empty();
    let connected_to_anyone = !state.peers.lock().unwrap().is_empty();
    if heard_someone && !connected_to_anyone {
        state.isolation_warned.store(true, Relaxed);
        ui::notify(
            "Other peers are visible on this network but none could be reached directly. \
             Peers may be unable to reach each other -- check for Wi-Fi client isolation or a firewall blocking TCP port 5001.",
        );
    }
}

/// Dynamic discovery is the only way feral finds peers -- there is no
/// saved address book. On a DHCP LAN, IPs from a previous session are
/// unlikely to still belong to the same peer, so caching them would be
/// worse than useless; this rebroadcasts and relistens continuously
/// instead, which also means a peer that changes IP mid-session (e.g.
/// a lease renewal) gets rediscovered automatically.
pub fn discovery(state: Arc<AppState>) {
    let Ok(udp) = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)) else {
        ui::notify(&format!(
            "Could not bind UDP discovery port {}; automatic discovery is disabled. The TCP listener is still active -- use /connect <ip>.",
            DISCOVERY_PORT
        ));
        return;
    };
    let _ = udp.set_broadcast(true);
    let _ = udp.set_read_timeout(Some(Duration::from_secs(1)));
    if let Ok(clone) = udp.try_clone() {
        *state.discovery_socket.write().unwrap() = Some(clone);
    }

    let broadcast_targets = local_broadcast_targets();
    let mut last_announcement = std::time::Instant::now() - Duration::from_secs(60);
    let mut buf = [0u8; 1024];

    while state.is_running() {
        if last_announcement.elapsed().as_secs_f64() > announce_interval_for_known_peers(&state) {
            let msg = format!("CHAT:{}", state.my_id);
            for target in &broadcast_targets {
                let _ = udp.send_to(msg.as_bytes(), (target.as_str(), DISCOVERY_PORT));
            }
            last_announcement = std::time::Instant::now();
        }
        maybe_warn_isolation(&state);

        match udp.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                if !msg.starts_with("CHAT:") {
                    continue;
                }
                let peer_id = msg[5..].to_string();
                let ip = addr.ip().to_string();
                if peer_id == state.my_id || peer_id.len() != 8 || !peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }

                state.announced_peer_ids.lock().unwrap().insert(ip.clone(), peer_id.clone());

                {
                    let mut attempted = state.attempted_connections.lock().unwrap();
                    let deferred = state.deferred_until.lock().unwrap();
                    let still_deferred = deferred.get(&ip).map(|t| *t > std::time::Instant::now()).unwrap_or(false);
                    if attempted.contains(&ip) || still_deferred {
                        continue;
                    }
                    attempted.insert(ip.clone());
                }

                let known = state.peers.lock().unwrap().contains_key(&ip);

                let already_connected_elsewhere = {
                    let ip_to_id = state.ip_to_id.lock().unwrap();
                    ip_to_id.iter().any(|(other_ip, other_id)| other_id == &peer_id && other_ip != &ip)
                };
                if already_connected_elsewhere {
                    state.attempted_connections.lock().unwrap().remove(&ip);
                    continue;
                }

                let already_announced_elsewhere = {
                    let announced = state.announced_peer_ids.lock().unwrap();
                    announced.iter().any(|(other_ip, other_id)| other_id == &peer_id && other_ip != &ip)
                };
                if already_announced_elsewhere {
                    let preferred = {
                        let announced = state.announced_peer_ids.lock().unwrap();
                        let mut candidates: Vec<String> =
                            announced.iter().filter(|(_, id)| *id == &peer_id).map(|(a, _)| a.clone()).collect();
                        candidates.sort();
                        candidates.into_iter().next().unwrap_or_else(|| ip.clone())
                    };
                    if ip != preferred {
                        state.attempted_connections.lock().unwrap().remove(&ip);
                        continue;
                    }
                }

                if !known && at_degree_cap(&state) {
                    state.attempted_connections.lock().unwrap().remove(&ip);
                    continue;
                }

                if !known {
                    let state2 = Arc::clone(&state);
                    let ip2 = ip.clone();
                    std::thread::spawn(move || connect_to_peer(&state2, &ip2, Some(&peer_id)));
                }
            }
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    WouldBlock | TimedOut => {
                        let mut attempted = state.attempted_connections.lock().unwrap();
                        if attempted.len() > crate::state::ANTI_FLOOD_SET_MAX {
                            attempted.clear();
                        }
                        let mut deferred = state.deferred_until.lock().unwrap();
                        let now = std::time::Instant::now();
                        deferred.retain(|_, until| *until > now);
                        if deferred.len() > crate::state::ANTI_FLOOD_SET_MAX {
                            deferred.clear();
                        }
                    }
                    _ => break,
                }
            }
        }
    }
}

pub fn reaper(state: Arc<AppState>) {
    while state.is_running() {
        std::thread::sleep(Duration::from_secs(10));
        state.reap_seen();
        let now = now_epoch_f64();
        state.pending_pings.lock().unwrap().retain(|_, sent| now - *sent <= crate::state::PING_TIMEOUT.as_secs_f64());
    }
}
