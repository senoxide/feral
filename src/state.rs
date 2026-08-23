use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

pub const NAME_FILE: &str = "name";
pub const COLOR_FILE: &str = "colors";
pub const LOG_FILE: &str = "feral.log";
pub const HISTORY_LINES_TO_SHOW: usize = 20;

pub const MAX_SEEN_IDS: usize = 20_000;
pub const SEEN_ID_MAX_AGE: Duration = Duration::from_secs(300);
pub const MAX_MSG_HISTORY: usize = 200;
pub const MAX_TRACKED_PEERS: usize = 500;
pub const PING_TIMEOUT: Duration = Duration::from_secs(30);
pub const ANTI_FLOOD_SET_MAX: usize = 2000;
pub const DEFER_RETRY_COOLDOWN: Duration = Duration::from_secs(15);
pub const DISCONNECT_RETRY_COOLDOWN: Duration = Duration::from_secs(8);
pub const RATE_LIMIT_MAX_TOKENS: f64 = 40.0;
pub const RATE_LIMIT_REFILL_PER_SEC: f64 = 10.0;
pub const MAX_RECONNECT_ATTEMPTS: u32 = 5;
pub const RECONNECT_DELAY_MIN: f64 = 3.0;
pub const RECONNECT_DELAY_MAX: f64 = 9.0;
pub const MAX_SENDFILE_BYTES: u64 = 200 * 1024 * 1024;
pub const ISOLATION_WARNING_AFTER: Duration = Duration::from_secs(45);
pub const MAX_PENDING_HANDSHAKES: usize = crate::protocol::MAX_PEER_DEGREE * 3;
pub const MAX_PENDING_HANDSHAKES_PER_IP: usize = 2;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// Wire frames above this size are refused before any bytes are read
/// for them, so a forged length prefix can't force a large allocation.
pub const MAX_FRAME_BYTES: u32 = 20_000;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 2_000;

/// Bounded, insertion-ordered id set with age-based eviction. Used for
/// gossip dedup (seen_msg_ids).
pub struct SeenSet {
    seen: HashMap<String, Instant>,
    order: VecDeque<String>,
    max: usize,
}

impl SeenSet {
    fn new(max: usize) -> Self {
        Self { seen: HashMap::new(), order: VecDeque::new(), max }
    }

    /// True if newly seen (caller should act on it), false if duplicate.
    fn mark(&mut self, id: &str) -> bool {
        if self.seen.contains_key(id) {
            return false;
        }
        self.seen.insert(id.to_string(), Instant::now());
        self.order.push_back(id.to_string());
        if self.order.len() > self.max {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

    fn reap_old(&mut self, max_age: Duration) {
        let now = Instant::now();
        while let Some(front) = self.order.front() {
            match self.seen.get(front) {
                Some(t) if now.duration_since(*t) > max_age => {
                    let id = self.order.pop_front().unwrap();
                    self.seen.remove(&id);
                }
                _ => break,
            }
        }
    }
}

/// Bounded FIFO map of recent chat messages keyed by short msg_id, for
/// /reply and reply-tag lookups.
pub struct MsgHistory {
    map: HashMap<String, (String, String)>,
    order: VecDeque<String>,
    max: usize,
}

impl MsgHistory {
    fn new(max: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), max }
    }

    pub fn remember(&mut self, id: &str, sender_name: &str, text: &str) {
        if !self.map.contains_key(id) {
            self.order.push_back(id.to_string());
        }
        self.map.insert(id.to_string(), (sender_name.to_string(), text.to_string()));
        if self.order.len() > self.max {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<(String, String)> {
        self.map.get(id).cloned()
    }

    pub fn recent(&self, count: usize) -> Vec<(String, (String, String))> {
        self.order
            .iter()
            .rev()
            .take(count)
            .rev()
            .map(|id| (id.clone(), self.map.get(id).cloned().unwrap()))
            .collect()
    }
}

#[derive(Default)]
pub struct RateBucket {
    pub tokens: f64,
    pub last: Option<Instant>,
}

/// A verified peer public key: the full fingerprint is the actual trust
/// anchor (TOFU-pinned, persisted), the short id is just a display
/// convenience derived from it.
#[derive(Clone)]
pub struct PeerKey {
    pub pubkey: VerifyingKey,
    pub fingerprint: String,
}

/// A live, handshaked connection: the write half of the socket plus the
/// per-connection, per-direction symmetric key and frame counter used
/// to encrypt everything sent on it. Never persisted, never derived
/// from the identity key -- discarded when the connection closes.
pub struct PeerLink {
    pub stream: TcpStream,
    pub send_key: [u8; 32],
    pub send_counter: u64,
}

pub struct AppState {
    pub my_id: String,
    pub my_fingerprint: String,
    pub my_name: Mutex<String>,
    pub identity: SigningKey,
    pub show_id: AtomicBool,
    pub running: AtomicBool,

    pub peers: Mutex<HashMap<String, PeerLink>>,
    // short peer_id -> pinned pubkey/fingerprint, TOFU-learned only from
    // a completed, signature-verified handshake -- see crypto.rs
    pub peer_keys: Mutex<HashMap<String, PeerKey>>,
    // ip -> peer_id, bound the moment a connection's identity is claimed
    pub ip_to_id: Mutex<HashMap<String, String>>,
    // ip -> peer_id, heard from discovery broadcasts only
    pub announced_peer_ids: Mutex<HashMap<String, String>>,
    pub peer_names: Mutex<HashMap<String, String>>,
    pub id_colors: Mutex<HashMap<String, usize>>,
    // our own display name -> preferred color, persisted across restarts
    pub name_to_color: Mutex<HashMap<String, usize>>,

    pub seen_msg_ids: Mutex<SeenSet>,
    pub msg_history: Mutex<MsgHistory>,

    pub attempted_connections: Mutex<HashSet<String>>,
    pub deferred_until: Mutex<HashMap<String, Instant>>,
    pub known_ips: Mutex<HashSet<String>>,
    pub reconnecting_ips: Mutex<HashSet<String>>,
    pub rate_buckets: Mutex<HashMap<String, RateBucket>>,

    pub pending_pings: Mutex<HashMap<String, f64>>,
    pub ignored_ids: Mutex<HashSet<String>>,

    pub log_lock: Mutex<()>,
    pub start_time: Instant,
    pub isolation_warned: AtomicBool,
    pub pending_handshakes: std::sync::atomic::AtomicUsize,
    pub pending_handshakes_by_ip: Mutex<HashMap<String, usize>>,

    pub discovery_socket: RwLock<Option<std::net::UdpSocket>>,
    pub server_socket: RwLock<Option<std::net::TcpListener>>,
}

impl AppState {
    pub fn new(identity: SigningKey, my_name: String) -> Self {
        let my_fingerprint = crate::protocol::fingerprint(&identity.verifying_key());
        let my_id = crate::protocol::short_id(&my_fingerprint).to_string();
        Self {
            my_id,
            my_fingerprint,
            my_name: Mutex::new(my_name),
            identity,
            show_id: AtomicBool::new(false),
            running: AtomicBool::new(true),
            peers: Mutex::new(HashMap::new()),
            peer_keys: Mutex::new(HashMap::new()),
            ip_to_id: Mutex::new(HashMap::new()),
            announced_peer_ids: Mutex::new(HashMap::new()),
            peer_names: Mutex::new(HashMap::new()),
            id_colors: Mutex::new(HashMap::new()),
            name_to_color: Mutex::new(HashMap::new()),
            seen_msg_ids: Mutex::new(SeenSet::new(MAX_SEEN_IDS)),
            msg_history: Mutex::new(MsgHistory::new(MAX_MSG_HISTORY)),
            attempted_connections: Mutex::new(HashSet::new()),
            deferred_until: Mutex::new(HashMap::new()),
            known_ips: Mutex::new(HashSet::new()),
            reconnecting_ips: Mutex::new(HashSet::new()),
            rate_buckets: Mutex::new(HashMap::new()),
            pending_pings: Mutex::new(HashMap::new()),
            ignored_ids: Mutex::new(HashSet::new()),
            log_lock: Mutex::new(()),
            start_time: Instant::now(),
            isolation_warned: AtomicBool::new(false),
            pending_handshakes: std::sync::atomic::AtomicUsize::new(0),
            pending_handshakes_by_ip: Mutex::new(HashMap::new()),
            discovery_socket: RwLock::new(None),
            server_socket: RwLock::new(None),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// True the first time this packet_id is seen (caller should act on
    /// / relay it), false for a duplicate.
    pub fn mark_seen(&self, packet_id: &str) -> bool {
        self.seen_msg_ids.lock().unwrap().mark(packet_id)
    }

    pub fn reap_seen(&self) {
        self.seen_msg_ids.lock().unwrap().reap_old(SEEN_ID_MAX_AGE);
    }

    /// Bounds concurrent in-progress handshakes, both globally (so a
    /// flood of connections that never complete a handshake can't pin
    /// down an unbounded number of threads) and per source IP (so a
    /// single misbehaving address can't consume the entire global
    /// budget and deny legitimate peers a chance to connect).
    pub fn reserve_handshake_slot(&self, ip: &str) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let mut by_ip = self.pending_handshakes_by_ip.lock().unwrap();
        let count = by_ip.entry(ip.to_string()).or_insert(0);
        if *count >= MAX_PENDING_HANDSHAKES_PER_IP {
            return false;
        }
        loop {
            let cur = self.pending_handshakes.load(Relaxed);
            if cur >= MAX_PENDING_HANDSHAKES {
                return false;
            }
            if self.pending_handshakes.compare_exchange(cur, cur + 1, Relaxed, Relaxed).is_ok() {
                *count += 1;
                return true;
            }
        }
    }

    pub fn release_handshake_slot(&self, ip: &str) {
        self.pending_handshakes.fetch_sub(1, Ordering::Relaxed);
        let mut by_ip = self.pending_handshakes_by_ip.lock().unwrap();
        if let Some(count) = by_ip.get_mut(ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                by_ip.remove(ip);
            }
        }
    }

    /// Token-bucket check; true means the line should be dropped. Also
    /// bounds how many signature verifications an attacker can force us
    /// to perform per second.
    pub fn rate_limited(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.rate_buckets.lock().unwrap();
        let bucket = buckets.entry(ip.to_string()).or_insert(RateBucket {
            tokens: RATE_LIMIT_MAX_TOKENS,
            last: Some(now),
        });
        let elapsed = now.duration_since(bucket.last.unwrap_or(now)).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * RATE_LIMIT_REFILL_PER_SEC).min(RATE_LIMIT_MAX_TOKENS);
        bucket.last = Some(now);
        if bucket.tokens < 1.0 {
            true
        } else {
            bucket.tokens -= 1.0;
            false
        }
    }

    pub fn color_for_id(&self, peer_id: &str) -> usize {
        let mut colors = self.id_colors.lock().unwrap();
        if let Some(&idx) = colors.get(peer_id) {
            return idx;
        }
        let used: HashSet<usize> = colors.values().copied().collect();
        let n = crate::colors::COLORS.len();
        let idx = (0..n).find(|i| !used.contains(i)).unwrap_or_else(|| {
            (peer_id.bytes().map(|b| b as usize).sum::<usize>()) % n
        });
        colors.insert(peer_id.to_string(), idx);
        idx
    }

    pub fn set_color_for_id(&self, peer_id: &str, idx: usize) {
        if idx < crate::colors::COLORS.len() {
            self.id_colors.lock().unwrap().insert(peer_id.to_string(), idx);
        }
    }

    pub fn claim_color_for_id(&self, peer_id: &str, chosen: usize) -> bool {
        let mut colors = self.id_colors.lock().unwrap();
        let taken = colors.iter().any(|(pid, &idx)| pid != peer_id && idx == chosen);
        if taken {
            return false;
        }
        colors.insert(peer_id.to_string(), chosen);
        true
    }

    pub fn display_identity(&self, peer_id: &str, name: &str) -> String {
        if self.show_id.load(Ordering::Relaxed) {
            peer_id.to_string()
        } else {
            name.to_string()
        }
    }

    pub fn resolve_peer_id(&self, target: &str) -> Option<String> {
        let names = self.peer_names.lock().unwrap();
        if target.len() == 8 && names.contains_key(target) {
            return Some(target.to_string());
        }
        let matches: Vec<String> = names
            .iter()
            .filter(|(_, name)| name.as_str() == target)
            .map(|(pid, _)| pid.clone())
            .collect();
        drop(names);
        match matches.len() {
            1 => Some(matches[0].clone()),
            0 => {
                crate::ui::println_out(&format!("No known peer named or identified as '{}'.", target));
                None
            }
            _ => {
                let ids = matches.join(", ");
                crate::ui::println_out(&format!(
                    "'{}' matches more than one connected peer ({}). Use the exact id instead of the name to be sure you reach the right one.",
                    target, ids
                ));
                None
            }
        }
    }
}
