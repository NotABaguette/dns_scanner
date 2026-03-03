//! dns_scanner — High-speed full-IPv4 DNS server scanner
//!
//! Scans all ~3.7 billion public IPv4 addresses for working recursive DNS
//! servers in two phases:
//!
//!   Phase 1  →  A   query (example.com / any domain) sent to every public IP
//!   Phase 2  →  NS  query sent only to Phase-1 responders
//!
//! Servers that pass both phases are written to the output file.
//!
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Throughput maths on 1 Gbps                                        │
//! │  DNS query packet ≈ 48 bytes payload + 28 bytes UDP/IP = 76 B     │
//! │  1 Gbps ÷ 76 B  ≈ 1.64 M pps (theoretical NIC limit)             │
//! │  3.7 B IPs ÷ 1.3 M pps ≈ 2 850 s ≈ 47 min   (Phase 1 send)      │
//! │  Phase 2 is tiny (only real DNS servers respond to Phase 1)        │
//! │  Total well under 60 minutes.                                      │
//! └───────────────────────────────────────────────────────────────────┘
//!
//! BUILD
//!   cargo build --release
//!   # Binary: ./target/release/dns_scanner
//!
//! RECOMMENDED OS TUNING (run as root before scanning)
//!   sysctl -w net.core.rmem_max=134217728
//!   sysctl -w net.core.wmem_max=134217728
//!   sysctl -w net.core.rmem_default=33554432
//!   sysctl -w net.core.wmem_default=33554432
//!   sysctl -w net.core.netdev_max_backlog=500000
//!   sysctl -w net.ipv4.udp_mem="102400 873800 16777216"
//!   ulimit -n 65535
//!
//! USAGE
//!   dns_scanner [OPTIONS]
//!
//! OPTIONS
//!   --threads N        Worker threads (default: 2×logical-CPUs, min 32)
//!   --a-domain  D      Domain for A  query (default: example.com)
//!   --ns-domain D      Domain for NS query (default: com)
//!   --timeout-ms N     recv_from timeout in ms between send batches (default: 20)
//!   --wait-secs  N     Straggler collection window after last send (default: 8)
//!   --batch-size N     Sends per recv-drain cycle  (default: 1024)
//!   --output FILE      Output file  (default: working_dns.txt)
//!   --phase1-only      Skip Phase 2 NS validation (faster, less accurate)
//!   --verbose          Print each found server immediately
//!   --help             Show this message

#![allow(clippy::field_reassign_with_default)]

use std::{
    collections::HashSet,
    env,
    fs::File,
    io::{BufWriter, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ─────────────────────────────────────────────────────────────────────────────
//  Reserved / private IP ranges to skip
//  Each entry: (first_ip_inclusive, last_ip_inclusive) as big-endian u32
// ─────────────────────────────────────────────────────────────────────────────

const EXCLUDED: &[(u32, u32)] = &[
    (a(0,0,0,0),     a(0,255,255,255)),   // 0.0.0.0/8       — "This" network
    (a(10,0,0,0),    a(10,255,255,255)),   // 10.0.0.0/8      — RFC 1918
    (a(100,64,0,0),  a(100,127,255,255)),  // 100.64.0.0/10   — RFC 6598 shared
    (a(127,0,0,0),   a(127,255,255,255)),  // 127.0.0.0/8     — Loopback
    (a(169,254,0,0), a(169,254,255,255)),  // 169.254.0.0/16  — Link-local
    (a(172,16,0,0),  a(172,31,255,255)),   // 172.16.0.0/12   — RFC 1918
    (a(192,0,0,0),   a(192,0,0,255)),      // 192.0.0.0/24    — IETF protocol
    (a(192,0,2,0),   a(192,0,2,255)),      // 192.0.2.0/24    — TEST-NET-1
    (a(192,168,0,0), a(192,168,255,255)),  // 192.168.0.0/16  — RFC 1918
    (a(198,18,0,0),  a(198,19,255,255)),   // 198.18.0.0/15   — Benchmarking
    (a(198,51,100,0),a(198,51,100,255)),   // 198.51.100.0/24 — TEST-NET-2
    (a(203,0,113,0), a(203,0,113,255)),    // 203.0.113.0/24  — TEST-NET-3
    (a(224,0,0,0),   a(239,255,255,255)),  // 224.0.0.0/4     — Multicast
    (a(240,0,0,0),   a(255,255,255,255)),  // 240.0.0.0/4+    — Reserved + broadcast
];

/// Const helper: build a big-endian u32 from 4 octets (same as IPv4 network order).
#[inline(always)]
const fn a(o1: u8, o2: u8, o3: u8, o4: u8) -> u32 {
    ((o1 as u32) << 24) | ((o2 as u32) << 16) | ((o3 as u32) << 8) | (o4 as u32)
}

/// Returns true if `ip` (big-endian u32) is inside any excluded range.
#[inline(always)]
fn is_excluded(ip: u32) -> bool {
    // 14-element linear scan — branch predictor makes this negligible.
    for &(s, e) in EXCLUDED {
        if ip >= s && ip <= e {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  DNS packet helpers
// ─────────────────────────────────────────────────────────────────────────────

const QTYPE_A:  u16 = 1;
const QTYPE_NS: u16 = 2;

// Fixed transaction IDs — chosen so we can quickly filter our own responses.
// Phase 1 (A query):  0x4141 ("AA")
// Phase 2 (NS query): 0x4E53 ("NS")
const TXID_A:  u16 = 0x4141;
const TXID_NS: u16 = 0x4E53;

fn encode_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 2);
    for label in domain.split('.') {
        if label.is_empty() { continue; }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out
}

/// Build a minimal DNS query packet ready to send over UDP.
fn build_query(domain: &str, qtype: u16, tx_id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(48);
    p.extend_from_slice(&tx_id.to_be_bytes());       // ID
    p.extend_from_slice(&0x0100u16.to_be_bytes());   // Flags: RD=1
    p.extend_from_slice(&1u16.to_be_bytes());         // QDCOUNT=1
    p.extend_from_slice(&[0u8; 6]);                   // ANCOUNT, NSCOUNT, ARCOUNT=0
    p.extend_from_slice(&encode_name(domain));
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());         // QCLASS=IN
    p
}

/// Quick response check (no full parsing — we just need to know it's a valid answer).
/// Returns true if:
///   • packet length ≥ 12
///   • TX ID matches our expected value
///   • QR bit = 1  (it's a response, not a query)
///   • RCODE = 0   (NOERROR)
///   • ANCOUNT > 0 (at least one answer record)
#[inline(always)]
fn is_valid_response(data: &[u8], expected_tx_id: u16) -> bool {
    if data.len() < 12 { return false; }
    let tx_id   = u16::from_be_bytes([data[0], data[1]]);
    let flags   = u16::from_be_bytes([data[2], data[3]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    tx_id == expected_tx_id
        && (flags & 0x8000) != 0   // QR = 1
        && (flags & 0x000F) == 0   // RCODE = 0
        && ancount > 0
}

// ─────────────────────────────────────────────────────────────────────────────
//  Socket creation with generous kernel buffers
// ─────────────────────────────────────────────────────────────────────────────

fn make_socket() -> UdpSocket {
    let s = UdpSocket::bind("0.0.0.0:0").expect("UDP bind failed");

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = s.as_raw_fd();
        // 32 MB buffers — kernel may cap at rmem_max/wmem_max.
        // Run: sysctl -w net.core.rmem_max=134217728  to allow up to 128 MB.
        let buf: libc::c_int = 33_554_432;
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                &buf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&buf) as libc::socklen_t);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                &buf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&buf) as libc::socklen_t);
        }
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
//  Receive-drain helper
// ─────────────────────────────────────────────────────────────────────────────

/// Drain all currently available responses from `sock`.
/// Valid responses are appended to `out`; the global `found` counter is bumped.
fn drain(
    sock:    &UdpSocket,
    buf:     &mut [u8],
    tx_id:   u16,
    out:     &mut Vec<u32>,
    found:   &Arc<AtomicU64>,
    verbose: bool,
) {
    loop {
        match sock.recv_from(buf) {
            Ok((len, SocketAddr::V4(src))) => {
                if is_valid_response(&buf[..len], tx_id) {
                    let ip_int = u32::from(*src.ip());
                    out.push(ip_int);
                    found.fetch_add(1, Ordering::Relaxed);
                    if verbose {
                        eprintln!("  ✓ {}", src.ip());
                    }
                }
            }
            Ok(_) => {} // IPv6 source — ignore
            Err(ref e) if matches!(e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(_) => break,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase 1 — sweep the full public IPv4 space with A queries
// ─────────────────────────────────────────────────────────────────────────────

/// Scans IPs in the range `[ip_start, ip_end)` (u64, exclusive end to allow 2^32).
/// Returns every IP that sent a valid A-query response.
fn phase1_thread(
    ip_start:   u64,
    ip_end:     u64,
    query:      Arc<Vec<u8>>,
    batch_size: usize,
    wait_secs:  u64,
    timeout_ms: u64,
    sent:       Arc<AtomicU64>,
    found:      Arc<AtomicU64>,
    verbose:    bool,
) -> Vec<u32> {
    let sock = make_socket();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    let mut results  = Vec::new();
    let mut recv_buf = [0u8; 512];
    let mut batch    = 0usize;
    let mut ip       = ip_start;

    while ip < ip_end {
        let ip32 = ip as u32;
        if !is_excluded(ip32) {
            let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip32), 53));
            // Fire and forget — we don't care about individual send errors.
            let _ = sock.send_to(&query, dest);
            sent.fetch_add(1, Ordering::Relaxed);
            batch += 1;
        }
        ip += 1;

        // Interleave: send a batch, then drain anything waiting in the recv buffer.
        if batch >= batch_size {
            batch = 0;
            drain(&sock, &mut recv_buf, TXID_A, &mut results, &found, verbose);
        }
    }

    // ── Straggler collection window ──────────────────────────────────────────
    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        drain(&sock, &mut recv_buf, TXID_A, &mut results, &found, verbose);
        thread::sleep(Duration::from_millis(20));
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
//  Phase 2 — NS query validation on Phase-1 survivors
// ─────────────────────────────────────────────────────────────────────────────

/// Sends NS queries to `ips` and returns those that respond with a valid answer.
fn phase2_thread(
    ips:        Vec<u32>,
    query:      Arc<Vec<u8>>,
    batch_size: usize,
    wait_secs:  u64,
    timeout_ms: u64,
    sent:       Arc<AtomicU64>,
    found:      Arc<AtomicU64>,
    verbose:    bool,
) -> Vec<u32> {
    let sock = make_socket();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    let mut results  = Vec::new();
    let mut recv_buf = [0u8; 512];
    let mut batch    = 0usize;

    for &ip32 in &ips {
        let dest = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip32), 53));
        let _ = sock.send_to(&query, dest);
        sent.fetch_add(1, Ordering::Relaxed);
        batch += 1;

        if batch >= batch_size {
            batch = 0;
            drain(&sock, &mut recv_buf, TXID_NS, &mut results, &found, verbose);
        }
    }

    sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    while Instant::now() < deadline {
        drain(&sock, &mut recv_buf, TXID_NS, &mut results, &found, verbose);
        thread::sleep(Duration::from_millis(20));
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
//  Progress reporter thread
// ─────────────────────────────────────────────────────────────────────────────

fn spawn_progress(
    label:    &'static str,
    total:    u64,
    sent:     Arc<AtomicU64>,
    found:    Arc<AtomicU64>,
    stop:     Arc<AtomicBool>,
    interval: Duration,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let start = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(interval);
            if stop.load(Ordering::Relaxed) { break; }

            let s       = sent.load(Ordering::Relaxed);
            let f       = found.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let pps     = s as f64 / elapsed.max(0.001);
            let pct     = if total > 0 { 100.0 * s as f64 / total as f64 } else { 0.0 };
            let eta     = if pps > 0.0 && s < total {
                let secs = (total - s) as f64 / pps;
                format!("{}m{:02}s", secs as u64 / 60, secs as u64 % 60)
            } else {
                "—".into()
            };
            eprintln!(
                "[{}][{}] sent={} / {} ({:.1}%) | {:.0} pps | found={} | ETA {}",
                hhmm(), label, s, total, pct, pps, f, eta
            );
        }
    })
}

/// Current wall-clock time as HH:MM:SS (no chrono dependency).
fn hhmm() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:02}:{:02}:{:02}", (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60)
}

// ─────────────────────────────────────────────────────────────────────────────
//  CLI config
// ─────────────────────────────────────────────────────────────────────────────

struct Config {
    threads:     usize,
    a_domain:    String,
    ns_domain:   String,
    timeout_ms:  u64,
    wait_secs:   u64,
    batch_size:  usize,
    output:      String,
    phase1_only: bool,
    verbose:     bool,
}

impl Default for Config {
    fn default() -> Self {
        let cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8);
        Self {
            threads:     (cpus * 2).max(32),
            a_domain:    "example.com".into(),
            ns_domain:   "com".into(),
            timeout_ms:  20,
            wait_secs:   8,
            batch_size:  1024,
            output:      "working_dns.txt".into(),
            phase1_only: false,
            verbose:     false,
        }
    }
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--threads"     => { i += 1; cfg.threads     = args[i].parse().expect("--threads"); }
            "--a-domain"    => { i += 1; cfg.a_domain    = args[i].clone(); }
            "--ns-domain"   => { i += 1; cfg.ns_domain   = args[i].clone(); }
            "--timeout-ms"  => { i += 1; cfg.timeout_ms  = args[i].parse().expect("--timeout-ms"); }
            "--wait-secs"   => { i += 1; cfg.wait_secs   = args[i].parse().expect("--wait-secs"); }
            "--batch-size"  => { i += 1; cfg.batch_size  = args[i].parse().expect("--batch-size"); }
            "--output"      => { i += 1; cfg.output      = args[i].clone(); }
            "--phase1-only" =>           cfg.phase1_only = true,
            "--verbose"     =>           cfg.verbose     = true,
            "--help" | "-h" => { print_help(); std::process::exit(0); }
            other           => { eprintln!("Unknown arg: {other}"); }
        }
        i += 1;
    }
    cfg
}

fn print_help() {
    eprintln!(r#"
dns_scanner — Full-IPv4 DNS scanner (1 Gbps, ~45 min for full sweep)

OPTIONS
  --threads N        Worker threads     (default: 2×CPUs, min 32)
  --a-domain  D      A query domain     (default: example.com)
  --ns-domain D      NS query domain    (default: com)
  --timeout-ms N     Recv timeout (ms)  (default: 20)
  --wait-secs  N     Straggler wait (s) (default: 8)
  --batch-size N     Sends/recv-drain   (default: 1024)
  --output FILE      Output file        (default: working_dns.txt)
  --phase1-only      Skip NS validation (faster, less precise)
  --verbose          Print each found server live
  --help             This message

OS TUNING (run before scanning for best results):
  sysctl -w net.core.rmem_max=134217728
  sysctl -w net.core.wmem_max=134217728
  sysctl -w net.core.netdev_max_backlog=500000
"#);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    let cfg = parse_args();

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║           dns_scanner — Full IPv4 sweep                  ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("  Threads   : {}", cfg.threads);
    eprintln!("  A domain  : {}", cfg.a_domain);
    eprintln!("  NS domain : {} {}", cfg.ns_domain,
              if cfg.phase1_only { "(skipped — phase1-only mode)" } else { "" });
    eprintln!("  Batch sz  : {}", cfg.batch_size);
    eprintln!("  Wait      : {}s after last send", cfg.wait_secs);
    eprintln!("  Output    : {}", cfg.output);
    eprintln!();

    // Approximate public IPs: 4 294 967 296 − ~600 M excluded ≈ 3.702 B
    const TOTAL_PHASE1: u64 = 3_702_258_432;

    // Pre-build and Arc-wrap query packets (one allocation, shared across all threads).
    let a_query  = Arc::new(build_query(&cfg.a_domain,  QTYPE_A,  TXID_A));
    let ns_query = Arc::new(build_query(&cfg.ns_domain, QTYPE_NS, TXID_NS));

    let cfg = Arc::new(cfg);

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    eprintln!("[{}] Phase 1 — sending A queries to ~{:.2}B public IPs …",
              hhmm(), TOTAL_PHASE1 as f64 / 1e9);
    let t0 = Instant::now();

    let sent1  = Arc::new(AtomicU64::new(0));
    let found1 = Arc::new(AtomicU64::new(0));
    let stop1  = Arc::new(AtomicBool::new(false));

    let _prog1 = spawn_progress(
        "P1", TOTAL_PHASE1,
        sent1.clone(), found1.clone(), stop1.clone(),
        Duration::from_secs(5),
    );

    // Divide the entire 32-bit IP space (0..2^32) evenly among threads.
    let total_space: u64 = 1u64 << 32;
    let chunk: u64 = total_space / cfg.threads as u64;
    let mut handles1 = Vec::with_capacity(cfg.threads);

    for t in 0..cfg.threads {
        let ip_start = t as u64 * chunk;
        let ip_end   = if t == cfg.threads - 1 { total_space } else { ip_start + chunk };

        let q    = a_query.clone();
        let s    = sent1.clone();
        let f    = found1.clone();
        let cfg2 = cfg.clone();

        handles1.push(thread::spawn(move || {
            phase1_thread(
                ip_start, ip_end, q,
                cfg2.batch_size, cfg2.wait_secs, cfg2.timeout_ms,
                s, f, cfg2.verbose,
            )
        }));
    }

    // Collect all Phase-1 responders.
    let mut p1_set: HashSet<u32> = HashSet::new();
    for h in handles1 {
        for ip in h.join().expect("phase1 thread panicked") {
            p1_set.insert(ip);
        }
    }
    stop1.store(true, Ordering::Relaxed);

    let p1_elapsed = t0.elapsed();
    eprintln!("[{}] Phase 1 done in {:.1}s — {} IPs responded to A query",
              hhmm(), p1_elapsed.as_secs_f64(), p1_set.len());

    if cfg.phase1_only {
        write_results(&p1_set.into_iter().collect::<Vec<_>>(), &cfg.output);
        return;
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    let p1_vec: Vec<u32> = p1_set.into_iter().collect();
    let total_p2 = p1_vec.len() as u64;

    eprintln!("[{}] Phase 2 — sending NS queries to {} Phase-1 responders …",
              hhmm(), total_p2);
    let t1 = Instant::now();

    let sent2  = Arc::new(AtomicU64::new(0));
    let found2 = Arc::new(AtomicU64::new(0));
    let stop2  = Arc::new(AtomicBool::new(false));

    let _prog2 = spawn_progress(
        "P2", total_p2,
        sent2.clone(), found2.clone(), stop2.clone(),
        Duration::from_secs(3),
    );

    // Distribute Phase-1 IPs among threads (simple chunking).
    let chunk_sz = ((p1_vec.len() + cfg.threads - 1) / cfg.threads).max(1);
    let mut handles2 = Vec::with_capacity(cfg.threads);

    for chunk in p1_vec.chunks(chunk_sz) {
        let ips  = chunk.to_vec();
        let q    = ns_query.clone();
        let s    = sent2.clone();
        let f    = found2.clone();
        let cfg2 = cfg.clone();

        handles2.push(thread::spawn(move || {
            phase2_thread(
                ips, q,
                cfg2.batch_size, cfg2.wait_secs, cfg2.timeout_ms,
                s, f, cfg2.verbose,
            )
        }));
    }

    let mut final_set: HashSet<u32> = HashSet::new();
    for h in handles2 {
        for ip in h.join().expect("phase2 thread panicked") {
            final_set.insert(ip);
        }
    }
    stop2.store(true, Ordering::Relaxed);

    let p2_elapsed = t1.elapsed();
    eprintln!("[{}] Phase 2 done in {:.1}s — {} IPs passed NS check",
              hhmm(), p2_elapsed.as_secs_f64(), final_set.len());

    // ── Write output ─────────────────────────────────────────────────────────

    let mut sorted: Vec<u32> = final_set.into_iter().collect();
    sorted.sort_unstable();
    write_results(&sorted, &cfg.output);

    let total_elapsed = t0.elapsed();
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  SCAN COMPLETE                                           ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║  Total time  : {:.1}s  ({:.1} min)",
              total_elapsed.as_secs_f64(), total_elapsed.as_secs_f64() / 60.0);
    eprintln!("║  DNS servers : {}", sorted.len());
    eprintln!("║  Output file : {}", cfg.output);
    eprintln!("╚══════════════════════════════════════════════════════════╝");
}

fn write_results(ips: &[u32], path: &str) {
    let file = File::create(path).unwrap_or_else(|e| {
        eprintln!("Cannot create output file {path}: {e}");
        std::process::exit(1);
    });
    let mut w = BufWriter::new(file);
    for &ip in ips {
        writeln!(w, "{}", Ipv4Addr::from(ip)).expect("write failed");
    }
    w.flush().expect("flush failed");
    eprintln!("[{}] Results written to {}", hhmm(), path);
}
