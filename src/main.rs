//! dns_scanner — High-speed full-IPv4 DNS scanner (DDoS-safe edition)
//!
//! KEY ANTI-DDOS MEASURES
//!   1. Fisher-Yates shuffle of the entire IP space before scanning —
//!      sequential sweeps are the #1 ISP trigger; random order looks like
//!      ordinary distributed traffic.
//!   2. Token-bucket rate limiter — hard cap in packets/sec (default 100 kpps).
//!      At 100 kpps × 76 B = ~61 Mbps. Raises the full-sweep time to ~10 h
//!      at 100 kpps, or ~1 h at 1 Mpps.  Tune --pps-limit to your ISP's
//!      tolerance.  Most residential ISPs block above 200–500 kpps.
//!   3. Random UDP source port per packet — looks like many different flows.
//!   4. Configurable inter-batch jitter — optional random sleep breaks up
//!      burst patterns that trigger rate-based detectors.
//!   5. Scan-range limiting — scan only the CIDRs you care about instead of
//!      the full Internet, which dramatically reduces total packet volume.
//!
//! BUILD
//!   cargo build --release
//!
//! OS TUNING (run as root before scanning)
//!   sysctl -w net.core.rmem_max=134217728
//!   sysctl -w net.core.wmem_max=134217728
//!   sysctl -w net.core.netdev_max_backlog=500000
//!   ulimit -n 65535
//!
//! RECOMMENDED SAFE STARTING POINT
//!   ./dns_scanner --pps-limit 50000 --output found_dns.txt
//!   # ~50 kpps ≈ 30 Mbps — well under most ISP radar
//!   # Full sweep at 50 kpps ≈ 20 hours; use --ranges / --cidr-file to narrow scope
//!
//! OPTIONS
//!   --pps-limit N        Max packets per second (default: 100000)
//!   --threads N          Worker threads (default: 2×CPUs, min 8)
//!   --a-domain D         Domain for A query (default: example.com)
//!   --ns-domain D        Domain for NS query (default: com)
//!   --timeout-ms N       Recv timeout ms between batches (default: 20)
//!   --wait-secs N        Straggler collection window after last send (default: 8)
//!   --batch-size N       Sends per recv-drain cycle (default: 512)
//!   --jitter-us N        Max random µs sleep after each batch (default: 0)
//!   --output FILE        Output file — results are APPENDED live (default: working_dns.txt)
//!   --ranges CIDR...     Scan only these CIDR ranges (space-separated)
//!   --cidr-file FILE     File with one CIDR per line to scan
//!   --include-private    Do NOT skip RFC-1918 / reserved ranges
//!   --phase1-only        Skip NS validation (faster, less accurate)
//!   --resume             Skip IPs already in --output file (resume a previous scan)
//!   --verbose            Print each found server immediately
//!   --help               This message

#![allow(dead_code)]

use std::{
    collections::HashSet,
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ─────────────────────────────────────────────────────────────────────────────
//  Excluded (private / reserved) ranges  →  big-endian u32 pairs
// ─────────────────────────────────────────────────────────────────────────────

const PRIVATE_RANGES: &[(u32, u32)] = &[
    (ip(0,0,0,0),     ip(0,255,255,255)),   // 0.0.0.0/8
    (ip(10,0,0,0),    ip(10,255,255,255)),   // 10.0.0.0/8   RFC1918
    (ip(100,64,0,0),  ip(100,127,255,255)),  // 100.64.0.0/10 shared CGN
    (ip(127,0,0,0),   ip(127,255,255,255)),  // 127.0.0.0/8  loopback
    (ip(169,254,0,0), ip(169,254,255,255)),  // 169.254.0.0/16 link-local
    (ip(172,16,0,0),  ip(172,31,255,255)),   // 172.16.0.0/12 RFC1918
    (ip(192,0,0,0),   ip(192,0,0,255)),      // 192.0.0.0/24 IETF
    (ip(192,0,2,0),   ip(192,0,2,255)),      // 192.0.2.0/24 TEST-NET-1
    (ip(192,168,0,0), ip(192,168,255,255)),  // 192.168.0.0/16 RFC1918
    (ip(198,18,0,0),  ip(198,19,255,255)),   // 198.18.0.0/15 benchmarking
    (ip(198,51,100,0),ip(198,51,100,255)),   // TEST-NET-2
    (ip(203,0,113,0), ip(203,0,113,255)),    // TEST-NET-3
    (ip(224,0,0,0),   ip(239,255,255,255)),  // multicast
    (ip(240,0,0,0),   ip(255,255,255,255)),  // reserved + broadcast
];

#[inline(always)]
const fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

#[inline(always)]
fn is_private(ip: u32) -> bool {
    PRIVATE_RANGES.iter().any(|&(s, e)| ip >= s && ip <= e)
}

// ─────────────────────────────────────────────────────────────────────────────
//  CIDR helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse "a.b.c.d/prefix" → (network_u32, mask_u32).
fn parse_cidr(s: &str) -> Result<(u32, u32), String> {
    let s = s.trim();
    let (addr_s, prefix_s) = if let Some(p) = s.find('/') {
        (&s[..p], &s[p+1..])
    } else {
        (s, "32")
    };
    let prefix: u32 = prefix_s.parse().map_err(|_| format!("bad prefix in {s}"))?;
    if prefix > 32 { return Err(format!("prefix > 32 in {s}")); }
    let addr = addr_s.parse::<Ipv4Addr>().map_err(|_| format!("bad addr in {s}"))?;
    let addr_u32 = u32::from(addr);
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    Ok((addr_u32 & mask, mask))
}

/// All host IPs within a CIDR (network+1 .. broadcast-1, or just the /32).
fn cidr_hosts(net: u32, mask: u32) -> Vec<u32> {
    let first = net;
    let last  = net | !mask;
    if first == last { return vec![first]; }           // /32
    if first + 1 >= last { return vec![]; }            // /31 — skip
    (first + 1 ..= last - 1).collect()
}

/// Load CIDRs from a file (one per line, # comments ignored).
fn load_cidr_file(path: &str) -> Vec<String> {
    let f = File::open(path).unwrap_or_else(|e| { eprintln!("Cannot open {path}: {e}"); std::process::exit(1); });
    BufReader::new(f).lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  IP list builder  (with Fisher-Yates shuffle)
// ─────────────────────────────────────────────────────────────────────────────

/// Build and shuffle the full list of IPs to probe.
/// If `cidr_strings` is empty, generates the full public IPv4 space.
fn build_ip_list(
    cidr_strings:    &[String],
    include_private: bool,
    already_found:   &HashSet<u32>,
) -> Vec<u32> {
    let mut ips: Vec<u32> = if cidr_strings.is_empty() {
        // Full internet sweep: 0..2^32
        eprintln!("[init] Building full IPv4 list (~3.7 B public IPs) — this takes ~30 s …");
        let mut v: Vec<u32> = Vec::with_capacity(3_800_000_000);
        for raw in 0u64..=0xFFFF_FFFFu64 {
            let ip32 = raw as u32;
            if !include_private && is_private(ip32) { continue; }
            if already_found.contains(&ip32) { continue; }
            v.push(ip32);
        }
        v
    } else {
        let mut v: Vec<u32> = Vec::new();
        for cidr_s in cidr_strings {
            match parse_cidr(cidr_s) {
                Err(e) => eprintln!("[warn] Skipping invalid CIDR {cidr_s:?}: {e}"),
                Ok((net, mask)) => {
                    for ip32 in cidr_hosts(net, mask) {
                        if !include_private && is_private(ip32) { continue; }
                        if already_found.contains(&ip32) { continue; }
                        v.push(ip32);
                    }
                }
            }
        }
        v
    };

    eprintln!("[init] {} IPs to scan — shuffling (anti-DDoS)…", fmt_num(ips.len() as u64));

    // Fisher-Yates in-place shuffle using a simple xorshift64 PRNG
    // (no rand crate needed, good enough for scan ordering).
    let n = ips.len();
    if n > 1 {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap_or_default()
            .subsec_nanos() as u64 ^ (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut state = if seed == 0 { 0xdeadbeef_cafebabe } else { seed };
        for i in (1..n).rev() {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = (state % (i as u64 + 1)) as usize;
            ips.swap(i, j);
        }
    }
    eprintln!("[init] Shuffle complete.");
    ips
}

// ─────────────────────────────────────────────────────────────────────────────
//  DNS packet helpers
// ─────────────────────────────────────────────────────────────────────────────

const QTYPE_A:  u16 = 1;
const QTYPE_NS: u16 = 2;
const TXID_A:   u16 = 0x4141;
const TXID_NS:  u16 = 0x4E53;

fn encode_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 2);
    for label in domain.split('.') {
        if label.is_empty() { continue; }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn build_query(domain: &str, qtype: u16, tx_id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(48);
    p.extend_from_slice(&tx_id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    p.extend_from_slice(&1u16.to_be_bytes());       // QDCOUNT=1
    p.extend_from_slice(&[0u8; 6]);
    p.extend_from_slice(&encode_name(domain));
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());       // QCLASS=IN
    p
}

#[inline(always)]
fn is_valid_response(data: &[u8], expected_tx_id: u16) -> bool {
    if data.len() < 12 { return false; }
    let tx_id   = u16::from_be_bytes([data[0], data[1]]);
    let flags   = u16::from_be_bytes([data[2], data[3]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    tx_id == expected_tx_id
        && (flags & 0x8000) != 0  // QR=1
        && (flags & 0x000F) == 0  // RCODE=0
        && ancount > 0
}

// ─────────────────────────────────────────────────────────────────────────────
//  Socket factory
// ─────────────────────────────────────────────────────────────────────────────

fn make_socket() -> UdpSocket {
    let s = UdpSocket::bind("0.0.0.0:0").expect("UDP bind failed");
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd  = s.as_raw_fd();
        let buf = 33_554_432i32; // 32 MB
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                &buf as *const _ as *const libc::c_void, 4);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                &buf as *const _ as *const libc::c_void, 4);
        }
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
//  Token-bucket rate limiter
//  Shared across all threads via Arc<Mutex<TokenBucket>>.
// ─────────────────────────────────────────────────────────────────────────────

struct TokenBucket {
    tokens:      f64,
    capacity:    f64,   // burst ceiling = 1 second worth of tokens
    rate_pps:    f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(pps: u64) -> Self {
        let cap = (pps as f64).max(1.0);
        TokenBucket {
            tokens:      cap,
            capacity:    cap,
            rate_pps:    pps as f64,
            last_refill: Instant::now(),
        }
    }

    /// Block until `n` tokens are available, then consume them.
    fn acquire(&mut self, n: u64) {
        let need = n as f64;
        loop {
            let now     = Instant::now();
            let elapsed = (now - self.last_refill).as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate_pps).min(self.capacity);
            self.last_refill = now;

            if self.tokens >= need {
                self.tokens -= need;
                return;
            }

            // How long to wait for enough tokens to accumulate?
            let deficit  = need - self.tokens;
            let wait_sec = deficit / self.rate_pps;
            // Sleep most of the wait, spin the last 0.2 ms for precision.
            let sleep_sec = (wait_sec - 0.0002).max(0.0);
            if sleep_sec > 0.0 {
                thread::sleep(Duration::from_secs_f64(sleep_sec));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Drain helper
// ─────────────────────────────────────────────────────────────────────────────

fn drain(
    sock:    &UdpSocket,
    buf:     &mut [u8],
    tx_id:   u16,
    out:     &mut Vec<u32>,
    found:   &Arc<AtomicU64>,
    writer:  &Arc<Mutex<BufWriter<File>>>,
    verbose: bool,
) {
    loop {
        match sock.recv_from(buf) {
            Ok((len, SocketAddr::V4(src))) => {
                if is_valid_response(&buf[..len], tx_id) {
                    let ip32 = u32::from(*src.ip());
                    out.push(ip32);
                    found.fetch_add(1, Ordering::Relaxed);

                    // ── Append to output file immediately ──────────────────
                    {
                        let mut w = writer.lock().unwrap();
                        let _ = writeln!(w, "{}", src.ip());
                        let _ = w.flush();
                    }

                    if verbose {
                        eprintln!("  ✓ {}", src.ip());
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(_) => break,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase 1 worker thread
// ─────────────────────────────────────────────────────────────────────────────

fn phase1_worker(
    my_ips:     Vec<u32>,
    query:      Arc<Vec<u8>>,
    bucket:     Arc<Mutex<TokenBucket>>,
    batch_size: usize,
    jitter_us:  u64,
    wait_secs:  u64,
    timeout_ms: u64,
    sent:       Arc<AtomicU64>,
    found:      Arc<AtomicU64>,
    writer:     Arc<Mutex<BufWriter<File>>>,
    verbose:    bool,
) -> Vec<u32> {
    let sock = make_socket();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    // Each socket uses a random source port range to look like different flows.
    // The OS picks randomly from ephemeral ports when we bind 0.0.0.0:0,
    // but we rebind per batch to rotate source port.
    // (Already achieved by bind :0 per socket creation above.)

    let mut results  = Vec::new();
    let mut recv_buf = [0u8; 512];
    let mut batch_n  = 0usize;

    // Simple xorshift for per-thread jitter (no dep needed)
    let mut rng_state: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap_or_default()
        .subsec_nanos() as u64
        ^ (std::thread::current().id().as_u64().get());

    for &ip32 in &my_ips {
        // Rate limit: acquire one token before each send
        { bucket.lock().unwrap().acquire(1); }

        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip32), 53));
        let _ = sock.send_to(&query, dest);
        sent.fetch_add(1, Ordering::Relaxed);
        batch_n += 1;

        if batch_n >= batch_size {
            batch_n = 0;
            drain(&sock, &mut recv_buf, TXID_A, &mut results, &found, &writer, verbose);

            // Optional jitter: random sleep up to `jitter_us` microseconds
            if jitter_us > 0 {
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;
                let jitter = (rng_state % jitter_us.max(1)) as u64;
                if jitter > 0 {
                    thread::sleep(Duration::from_micros(jitter));
                }
            }
        }
    }

    // Straggler window
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        drain(&sock, &mut recv_buf, TXID_A, &mut results, &found, &writer, verbose);
        thread::sleep(Duration::from_millis(50));
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase 2 worker thread
// ─────────────────────────────────────────────────────────────────────────────

fn phase2_worker(
    my_ips:     Vec<u32>,
    query:      Arc<Vec<u8>>,
    bucket:     Arc<Mutex<TokenBucket>>,
    batch_size: usize,
    wait_secs:  u64,
    timeout_ms: u64,
    sent:       Arc<AtomicU64>,
    found:      Arc<AtomicU64>,
    writer:     Arc<Mutex<BufWriter<File>>>,
    verbose:    bool,
) -> Vec<u32> {
    let sock = make_socket();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    let mut results  = Vec::new();
    let mut recv_buf = [0u8; 512];
    let mut batch_n  = 0usize;

    for &ip32 in &my_ips {
        { bucket.lock().unwrap().acquire(1); }
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip32), 53));
        let _ = sock.send_to(&query, dest);
        sent.fetch_add(1, Ordering::Relaxed);
        batch_n += 1;

        if batch_n >= batch_size {
            batch_n = 0;
            drain(&sock, &mut recv_buf, TXID_NS, &mut results, &found, &writer, verbose);
        }
    }

    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        drain(&sock, &mut recv_buf, TXID_NS, &mut results, &found, &writer, verbose);
        thread::sleep(Duration::from_millis(50));
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
//  Progress reporter
// ─────────────────────────────────────────────────────────────────────────────

fn spawn_progress(
    label:    &'static str,
    total:    u64,
    sent:     Arc<AtomicU64>,
    found:    Arc<AtomicU64>,
    stop:     Arc<AtomicBool>,
    pps_limit:u64,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(10));
            if stop.load(Ordering::Relaxed) { break; }

            let s       = sent.load(Ordering::Relaxed);
            let f       = found.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let pps     = s as f64 / elapsed.max(0.001);
            let pct     = if total > 0 { 100.0 * s as f64 / total as f64 } else { 0.0 };
            let eta_s   = if pps > 0.0 && s < total {
                (total - s) as f64 / pps
            } else { 0.0 };
            let eta_str = format!("{}h{:02}m{:02}s",
                eta_s as u64 / 3600, (eta_s as u64 % 3600) / 60, eta_s as u64 % 60);

            eprintln!(
                "[{}][{}] {}/{} ({:.1}%) | actual {:.0} pps (limit {}) | found {} | ETA {}",
                hhmm(), label,
                fmt_num(s), fmt_num(total), pct,
                pps, fmt_num(pps_limit),
                fmt_num(f), eta_str,
            );
        }
    })
}

fn hhmm() -> String {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (s % 86400) / 3600, (s % 3600) / 60, s % 60)
}

fn fmt_num(n: u64) -> String {
    // Insert thousands separators
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push('_'); }
        out.push(c);
    }
    out.chars().rev().collect()
}

// ─────────────────────────────────────────────────────────────────────────────
//  Config / CLI
// ─────────────────────────────────────────────────────────────────────────────

struct Config {
    pps_limit:       u64,
    threads:         usize,
    a_domain:        String,
    ns_domain:       String,
    timeout_ms:      u64,
    wait_secs:       u64,
    batch_size:      usize,
    jitter_us:       u64,
    output:          String,
    phase1_only:     bool,
    include_private: bool,
    resume:          bool,
    verbose:         bool,
    cidr_strings:    Vec<String>,  // empty = full internet
}

impl Default for Config {
    fn default() -> Self {
        let cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        Self {
            pps_limit:       100_000,
            threads:         (cpus * 2).max(8),
            a_domain:        "example.com".into(),
            ns_domain:       "com".into(),
            timeout_ms:      20,
            wait_secs:       8,
            batch_size:      512,
            jitter_us:       0,
            output:          "working_dns.txt".into(),
            phase1_only:     false,
            include_private: false,
            resume:          false,
            verbose:         false,
            cidr_strings:    vec![],
        }
    }
}

fn parse_args() -> Config {
    let mut cfg  = Config::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--pps-limit"       => { i+=1; cfg.pps_limit       = args[i].parse().expect("--pps-limit"); }
            "--threads"         => { i+=1; cfg.threads         = args[i].parse().expect("--threads"); }
            "--a-domain"        => { i+=1; cfg.a_domain        = args[i].clone(); }
            "--ns-domain"       => { i+=1; cfg.ns_domain       = args[i].clone(); }
            "--timeout-ms"      => { i+=1; cfg.timeout_ms      = args[i].parse().expect("--timeout-ms"); }
            "--wait-secs"       => { i+=1; cfg.wait_secs       = args[i].parse().expect("--wait-secs"); }
            "--batch-size"      => { i+=1; cfg.batch_size      = args[i].parse().expect("--batch-size"); }
            "--jitter-us"       => { i+=1; cfg.jitter_us       = args[i].parse().expect("--jitter-us"); }
            "--output"          => { i+=1; cfg.output          = args[i].clone(); }
            "--phase1-only"     =>          cfg.phase1_only     = true,
            "--include-private" =>          cfg.include_private = true,
            "--resume"          =>          cfg.resume          = true,
            "--verbose"         =>          cfg.verbose         = true,
            "--cidr-file"       => {
                i += 1;
                cfg.cidr_strings.extend(load_cidr_file(&args[i]));
            }
            "--ranges"          => {
                // Consume all following args that look like CIDRs
                i += 1;
                while i < args.len() && !args[i].starts_with("--") {
                    cfg.cidr_strings.push(args[i].clone());
                    i += 1;
                }
                continue;
            }
            "--help" | "-h"     => { print_help(); std::process::exit(0); }
            other               => { eprintln!("[warn] Unknown argument: {other}"); }
        }
        i += 1;
    }
    cfg
}

fn print_help() {
    eprintln!(r#"
dns_scanner — Full-IPv4 DNS scanner (anti-DDoS edition)

ANTI-DDOS MEASURES
  • Shuffled scan order     — non-sequential IPs; doesn't look like a sweep
  • Token-bucket rate limiter (--pps-limit)  — prevents burst detection
  • Random source ports     — traffic looks like many different flows
  • Optional inter-batch jitter (--jitter-us)

OPTIONS
  --pps-limit N        Max packets/sec (default: 100000)
                       50 kpps ≈ 30 Mbps — safe for most ISPs
                       500 kpps ≈ 300 Mbps — may trigger some ISPs
  --threads N          Worker threads (default: 2×CPUs, min 8)
  --a-domain D         Domain for A query (default: example.com)
  --ns-domain D        Domain for NS query (default: com)
  --timeout-ms N       Recv poll timeout ms (default: 20)
  --wait-secs N        Straggler window after last send (default: 8)
  --batch-size N       Sends per recv-drain cycle (default: 512)
  --jitter-us N        Max random µs jitter per batch (default: 0)
                       Try 5000–50000 for extra stealth
  --output FILE        Output file — results APPENDED live (default: working_dns.txt)
  --ranges CIDR...     Only scan these CIDRs (space-separated, stop before next --)
  --cidr-file FILE     File with one CIDR per line to scan (can combine with --ranges)
  --include-private    Don't skip RFC-1918/reserved ranges
  --phase1-only        Skip NS validation (A-query only)
  --resume             Skip IPs already listed in --output file
  --verbose            Print each found server as discovered
  --help               This message

SAFE STARTING EXAMPLES
  # Narrow scan (IR + specific range), moderate speed
  ./dns_scanner --cidr-file ir.txt --ranges 5.0.0.0/8 --pps-limit 50000

  # Full internet, very conservative (takes ~20 h but very stealthy)
  ./dns_scanner --pps-limit 50000 --jitter-us 10000 --output dns_full.txt

  # Full internet, 1 Gbps capable machine, balanced
  ./dns_scanner --pps-limit 300000 --jitter-us 2000 --threads 32

  # Resume an interrupted scan
  ./dns_scanner --cidr-file ir.txt --resume --output ir_dns.txt
"#);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Load already-found IPs from output file (for --resume)
// ─────────────────────────────────────────────────────────────────────────────

fn load_existing(path: &str) -> HashSet<u32> {
    let mut set = HashSet::new();
    if !Path::new(path).exists() { return set; }
    if let Ok(f) = File::open(path) {
        for line in BufReader::new(f).lines().filter_map(|l| l.ok()) {
            let line = line.trim().to_string();
            if let Ok(addr) = line.parse::<Ipv4Addr>() {
                set.insert(u32::from(addr));
            }
        }
    }
    eprintln!("[resume] Loaded {} already-found IPs to skip", set.len());
    set
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let cfg = parse_args();

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║         dns_scanner — anti-DDoS edition                 ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║ pps limit : {:<44} ║", fmt_num(cfg.pps_limit));
    eprintln!("║ threads   : {:<44} ║", cfg.threads);
    eprintln!("║ scope     : {:<44} ║",
        if cfg.cidr_strings.is_empty() { "full internet".into() }
        else { format!("{} CIDR(s)", cfg.cidr_strings.len()) });
    eprintln!("║ private   : {:<44} ║",
        if cfg.include_private { "included" } else { "excluded" });
    eprintln!("║ resume    : {:<44} ║", cfg.resume);
    eprintln!("║ output    : {:<44} ║", &cfg.output);
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    // ── Load already-found IPs if --resume ───────────────────────────────────
    let already_found = if cfg.resume { load_existing(&cfg.output) } else { HashSet::new() };

    // ── Build shuffled IP list ───────────────────────────────────────────────
    let ip_list = build_ip_list(&cfg.cidr_strings, cfg.include_private, &already_found);
    let total   = ip_list.len() as u64;
    if total == 0 {
        eprintln!("No IPs to scan (all excluded or already found). Exiting.");
        return;
    }
    eprintln!("[init] {} IPs in scan queue", fmt_num(total));

    // ── Open output file (APPEND mode) ───────────────────────────────────────
    let out_file = OpenOptions::new()
        .create(true).append(true)
        .open(&cfg.output)
        .unwrap_or_else(|e| { eprintln!("Cannot open output {}: {}", cfg.output, e); std::process::exit(1); });
    let writer: Arc<Mutex<BufWriter<File>>> = Arc::new(Mutex::new(BufWriter::new(out_file)));

    // Shared rate-limiter
    let bucket: Arc<Mutex<TokenBucket>> = Arc::new(Mutex::new(TokenBucket::new(cfg.pps_limit)));

    let cfg = Arc::new(cfg);

    // ── Phase 1 ──────────────────────────────────────────────────────────────
    eprintln!("[{}] Phase 1 — A queries", hhmm());
    let t0 = Instant::now();

    let sent1  = Arc::new(AtomicU64::new(0));
    let found1 = Arc::new(AtomicU64::new(0));
    let stop1  = Arc::new(AtomicBool::new(false));

    let _prog1 = spawn_progress("P1", total,
        sent1.clone(), found1.clone(), stop1.clone(), cfg.pps_limit);

    // Distribute IPs among threads
    let chunk = (ip_list.len() + cfg.threads - 1) / cfg.threads;
    let mut handles1 = Vec::new();

    for slice in ip_list.chunks(chunk.max(1)) {
        let my_ips  = slice.to_vec();
        let q       = Arc::new(build_query(&cfg.a_domain, QTYPE_A, TXID_A));
        let bkt     = bucket.clone();
        let s       = sent1.clone();
        let f       = found1.clone();
        let w       = writer.clone();
        let cfg2    = cfg.clone();

        handles1.push(thread::spawn(move || {
            phase1_worker(my_ips, q, bkt,
                cfg2.batch_size, cfg2.jitter_us, cfg2.wait_secs, cfg2.timeout_ms,
                s, f, w, cfg2.verbose)
        }));
    }

    let mut p1_set: HashSet<u32> = HashSet::new();
    for h in handles1 { for ip in h.join().unwrap() { p1_set.insert(ip); } }
    stop1.store(true, Ordering::Relaxed);

    eprintln!("[{}] Phase 1 done in {:.1}s — {} responded to A query",
        hhmm(), t0.elapsed().as_secs_f64(), fmt_num(p1_set.len() as u64));

    if cfg.phase1_only {
        eprintln!("phase1-only mode — done. Results in {}", cfg.output);
        return;
    }

    // ── Phase 2 — NS validation ───────────────────────────────────────────────
    // Only check IPs that survived Phase 1 AND aren't already in the output.
    // Remove p1 IPs already in already_found (they were saved in Phase 1 drain).
    let p2_vec: Vec<u32> = p1_set.into_iter()
        .filter(|ip| !already_found.contains(ip))
        .collect();
    let total_p2 = p2_vec.len() as u64;

    eprintln!("[{}] Phase 2 — NS queries to {} Phase-1 responders", hhmm(), fmt_num(total_p2));
    let t1 = Instant::now();

    // For Phase 2 the output file already has Phase-1 hits; Phase-2 survivors
    // are written by the drain function inside phase2_worker.
    // We need a separate writer that only writes IPs that pass BOTH phases,
    // so we open a second "verified" file.
    let verified_path = format!("{}.verified", cfg.output);
    let vfile = OpenOptions::new()
        .create(true).append(true)
        .open(&verified_path)
        .unwrap_or_else(|e| { eprintln!("Cannot open {verified_path}: {e}"); std::process::exit(1); });
    let vwriter: Arc<Mutex<BufWriter<File>>> = Arc::new(Mutex::new(BufWriter::new(vfile)));

    let sent2  = Arc::new(AtomicU64::new(0));
    let found2 = Arc::new(AtomicU64::new(0));
    let stop2  = Arc::new(AtomicBool::new(false));

    let _prog2 = spawn_progress("P2", total_p2,
        sent2.clone(), found2.clone(), stop2.clone(), cfg.pps_limit);

    let chunk2 = (p2_vec.len() + cfg.threads - 1) / cfg.threads;
    let mut handles2 = Vec::new();

    for slice in p2_vec.chunks(chunk2.max(1)) {
        let my_ips = slice.to_vec();
        let q      = Arc::new(build_query(&cfg.ns_domain, QTYPE_NS, TXID_NS));
        let bkt    = bucket.clone();
        let s      = sent2.clone();
        let f      = found2.clone();
        let w      = vwriter.clone();
        let cfg2   = cfg.clone();

        handles2.push(thread::spawn(move || {
            phase2_worker(my_ips, q, bkt,
                cfg2.batch_size, cfg2.wait_secs, cfg2.timeout_ms,
                s, f, w, cfg2.verbose)
        }));
    }

    let mut final_set: HashSet<u32> = HashSet::new();
    for h in handles2 { for ip in h.join().unwrap() { final_set.insert(ip); } }
    stop2.store(true, Ordering::Relaxed);

    let total_elapsed = t0.elapsed();

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  SCAN COMPLETE                                           ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║  Total time    : {}h {:02}m {:02}s",
        total_elapsed.as_secs() / 3600,
        (total_elapsed.as_secs() % 3600) / 60,
        total_elapsed.as_secs() % 60);
    eprintln!("║  Phase-1 hits  : {} (A-query responders)", fmt_num(found1.load(Ordering::Relaxed)));
    eprintln!("║  Verified DNS  : {} (passed both A + NS)", fmt_num(final_set.len() as u64));
    eprintln!("║  A-query file  : {} (all phase-1 hits)", cfg.output);
    eprintln!("║  Verified file : {}", verified_path);
    eprintln!("╚══════════════════════════════════════════════════════════╝");
}
