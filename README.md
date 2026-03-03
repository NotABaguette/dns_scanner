# DNS Scanner & Tunnel Manager

A toolkit for finding working DNS servers on restricted or censored networks, and keeping your DNS tunnel clients (DNSTT, SLIPSTREAM) running with fresh servers automatically.

---

## What's in this repo

| File | What it does |
|---|---|
| `dns_scanner/` | Rust program — scans IP ranges for working DNS resolvers |
| `dns_manager.py` | Python script — manages DNSTT/SLIPSTREAM processes, rotates DNS servers hourly |
| `dns_scanner.py` | Python script — lighter scanner for targeted ranges (no Rust required) |

---

## How it works — the big picture

```
[ Scan the internet ]  →  [ Get list of working DNS servers ]  →  [ Feed them to your tunnel ]
   dns_scanner (Rust)          working_dns.txt                      dns_manager.py
```

1. `dns_scanner` sends a small UDP probe to every IP you point it at
2. IPs that reply correctly get saved to `working_dns.txt` in real time
3. `dns_manager.py` reads that file, starts your tunnel clients with fresh servers, and repeats every hour

---

## Part 1 — dns_scanner (Rust)

### Why Rust?

Scanning millions of IPs requires sending and receiving hundreds of thousands of UDP packets per second. Python can't do this efficiently. The Rust scanner runs at up to 300,000 packets/sec while staying stealthy enough that your ISP won't notice.

### Build it

You need Rust installed. If you don't have it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

Then build:

```bash
cd dns_scanner
cargo build --release
# The binary will be at: ./target/release/dns_scanner
```

### Before you scan — tune your OS

These commands let the kernel handle large amounts of network traffic without dropping packets. Run them once before scanning (requires root):

```bash
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.netdev_max_backlog=500000
sudo sysctl -w net.ipv4.udp_mem="102400 873800 16777216"
ulimit -n 65535
```

### Basic usage

```bash
# Scan a country file (safest starting point)
./target/release/dns_scanner --cidr-file ir.txt --output ir_dns.txt

# Scan specific ranges
./target/release/dns_scanner --ranges 5.0.0.0/8 31.0.0.0/8 --output found.txt

# Scan everything (full internet sweep)
./target/release/dns_scanner --output full_dns.txt
```

### How the scan works — two phases

The scanner runs in two phases to avoid false positives:

**Phase 1 — A query**
Sends a DNS question for `example.com` to every IP. Only IPs that reply with a real answer move on to Phase 2. Results are written to your output file immediately as they're found.

**Phase 2 — NS query**
Sends a DNS question for the `com` nameservers to Phase-1 survivors. Only IPs that pass *both* checks end up in the final verified file.

```
All IPs  →  [A query]  →  ~tens of thousands respond  →  [NS query]  →  verified DNS servers
```

Output files:
- `working_dns.txt` — every IP that answered Phase 1 (written live, use for resuming)
- `working_dns.txt.verified` — only IPs that passed both phases (use this for tunnels)

### ⚠️ Important: rate limiting & your ISP

**If you scan too fast, your ISP will detect it as a DDoS attack and block your connection.**

This happened during development — sending 1.3 million packets/second to the entire internet caused an ISP ban within minutes. The scanner has several protections built in, but you need to choose the right speed for your situation:

| `--pps-limit` | Bandwidth | Full sweep time | Risk level |
|---|---|---|---|
| `30,000` | ~18 Mbps | ~34 hours | Very safe |
| `50,000` | ~30 Mbps | ~20 hours | Safe |
| `100,000` | ~61 Mbps | ~10 hours | Moderate |
| `300,000` | ~180 Mbps | ~3.5 hours | Higher risk |
| `1,000,000` | ~610 Mbps | ~1 hour | Will likely trigger ISP |

**Recommendation:** Start with `--pps-limit 50000`. If your connection stays stable for an hour, you can try higher values.

### Anti-detection features

The scanner uses several techniques to avoid looking like a DDoS attack:

- **Shuffled scan order** — IPs are scanned in random order, not sequentially. Sequential scans are the #1 ISP trigger. Random order looks like normal distributed traffic.
- **Token-bucket rate limiter** — hard cap on packets/second, shared across all threads. Never exceeds what you set.
- **Random source ports** — each packet appears to come from a different UDP port, making the traffic look like many different connections.
- **Batch jitter** — optional random delays between send bursts break up patterns that hardware detectors look for.

### All options

```
--pps-limit N        Max packets per second (default: 100,000)
--threads N          CPU threads to use (default: 2× your CPU count, min 8)
--output FILE        Where to save results (default: working_dns.txt)

--ranges CIDR...     Only scan these IP ranges, e.g: 5.0.0.0/8 31.0.0.0/8
--cidr-file FILE     File with one CIDR per line (e.g. ir.txt, de.txt)
--include-private    Also scan private/LAN IP ranges (off by default)

--resume             Skip IPs already in your output file (continue interrupted scans)
--phase1-only        Only do the A query, skip NS verification (faster but less accurate)

--a-domain D         Domain to use for A query check (default: example.com)
--ns-domain D        Domain to use for NS query check (default: com)
--timeout-ms N       How long to wait for replies between sends, in milliseconds (default: 20)
--wait-secs N        How long to wait for straggler replies after the last send (default: 8)
--batch-size N       How many packets to send before draining replies (default: 512)
--jitter-us N        Max random microsecond delay between batches (default: 0)
                     Try 5000–20000 for extra stealth

--verbose            Print each found server as it's discovered
--help               Show this message
```

### Example scenarios

**Scan a country file at a safe speed:**
```bash
./target/release/dns_scanner \
  --cidr-file ir.txt \
  --pps-limit 50000 \
  --output ir_dns.txt
```

**Resume an interrupted scan:**
```bash
./target/release/dns_scanner \
  --cidr-file ir.txt \
  --resume \
  --output ir_dns.txt
```

**Scan multiple country files together:**
```bash
cat ir.txt de.txt nl.txt > combined.txt
./target/release/dns_scanner \
  --cidr-file combined.txt \
  --pps-limit 80000 \
  --output combined_dns.txt
```

**Full internet sweep — stealthy mode:**
```bash
./target/release/dns_scanner \
  --pps-limit 50000 \
  --jitter-us 10000 \
  --output full_dns.txt
```

**Full internet sweep — fast (1 Gbps machine, coordinate with ISP first):**
```bash
./target/release/dns_scanner \
  --pps-limit 800000 \
  --threads 32 \
  --output full_dns.txt
```

---

## Part 2 — dns_manager.py

This script keeps your tunnel clients running with fresh working DNS servers. Every hour (or however often you choose) it:

1. Reads your DNS server list
2. Picks a random selection of servers
3. Kills the old tunnel processes
4. Starts fresh ones with the new servers

### Requirements

Python 3.7 or newer. No third-party packages needed.

### Basic usage

```bash
python dns_manager.py \
  --dns-file working_dns.txt.verified \
  --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey YOUR_KEY tunnel.example.com 127.0.0.1:8080" \
  --slipstream-cmd "slipstream-client --dns {dns} --domain tunnel.example.com"
```

### Command placeholders

In your `--dnstt-cmd` and `--slipstream-cmd`, use these:

| Placeholder | What it becomes |
|---|---|
| `{dns}` | The primary DNS server IP for this process instance |
| `{dns_list}` | Comma-separated list of all assigned DNS IPs |

### Controlling how many DNS servers each process gets

```bash
python dns_manager.py \
  --dns-file working_dns.txt.verified \
  --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey KEY tun.example.com 127.0.0.1:8080" \
  --dnstt-count 2 \         # run 2 parallel dnstt processes
  --dnstt-servers 5 \       # assign 5 DNS servers per dnstt process
  --slipstream-cmd "slipstream-client --dns {dns}" \
  --slipstream-count 1 \
  --slipstream-servers 3    # assign 3 DNS servers to slipstream
```

With `--dnstt-count 2 --dnstt-servers 5`, the manager picks 10 random DNS servers and gives each of the 2 processes a different primary server from that pool.

### All options

```
--dns-file FILE              Working DNS servers file (required)
--interval N                 Seconds between refreshes (default: 3600 = 1 hour)

--dnstt-cmd CMD              DNSTT client command template
--dnstt-count N              Parallel DNSTT instances (default: 1)
--dnstt-servers N            DNS servers per DNSTT instance (default: 3)

--slipstream-cmd CMD         SLIPSTREAM client command template
--slipstream-count N         Parallel SLIPSTREAM instances (default: 1)
--slipstream-servers N       DNS servers per SLIPSTREAM instance (default: 3)

--config FILE                JSON config for additional/custom processes (see below)
--on-start-cmd CMD           Shell command to run after every refresh
--once                       Refresh once then exit (good for cron)
--status                     Show current process status and exit
--verbose                    Debug logging
```

### JSON config for custom processes

If you have other tunnel tools, or want finer control, create a `processes.json`:

```json
{
  "processes": [
    {
      "name": "dnstt-main",
      "cmd": "dnstt-client -udp {dns}:53 -pubkey YOUR_KEY tunnel.example.com 127.0.0.1:8080",
      "count": 2,
      "servers_per_instance": 4
    },
    {
      "name": "slipstream",
      "cmd": "slipstream-client --dns {dns} --domain tunnel.example.com --socks5 127.0.0.1:1080",
      "count": 1,
      "servers_per_instance": 3
    },
    {
      "name": "custom-tool",
      "cmd": "mytunnel --resolver {dns_list} --verbose",
      "count": 1,
      "servers_per_instance": 5,
      "env": {
        "MY_ENV_VAR": "value"
      }
    }
  ]
}
```

Then run:
```bash
python dns_manager.py --dns-file working_dns.txt.verified --config processes.json
```

### Run as a service (systemd)

Create `/etc/systemd/system/dns-manager.service`:

```ini
[Unit]
Description=DNS Tunnel Manager
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/your/scripts
ExecStart=/usr/bin/python3 /path/to/dns_manager.py \
    --dns-file /path/to/working_dns.txt.verified \
    --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey YOUR_KEY tun.example.com 127.0.0.1:8080" \
    --slipstream-cmd "slipstream-client --dns {dns}"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-manager
sudo systemctl start dns-manager
sudo journalctl -fu dns-manager   # watch logs
```

---

## Part 3 — dns_scanner.py (Python fallback)

If you can't build Rust, use the pure Python scanner. It's slower but works anywhere Python 3 runs, and is better suited for targeted scans of specific ranges.

### Usage

```bash
# Scan from a country file
python dns_scanner.py --files ir.txt

# Multiple country files
python dns_scanner.py --files ir.txt de.txt nl.txt --workers 256

# Specific ranges
python dns_scanner.py --ranges 5.0.0.0/8 31.0.0.0/16

# Mix both
python dns_scanner.py --files ir.txt --ranges 5.200.0.0/16 --workers 512
```

### Options

```
--files FILE...       CIDR text files (one CIDR per line)
--ranges CIDR...      Inline CIDR ranges

--workers N           Concurrent threads (default: 256)
--timeout N           Per-query timeout in seconds (default: 1.5)

--a-domain D          Domain for A record check (default: example.com)
--a-expected IP       Expected IP in A record (default: 93.184.216.34)
--ns-domain D         Domain for NS record check (default: com)
--ns-expected NAME    Expected NS hostname (default: any)

--output FILE         Output file (default: working_dns.txt)
--json-output FILE    Also save results as JSON
--include-private     Don't skip private/reserved ranges
--verbose             Print every IP as it's probed
```

---

## Full workflow example

Here's a complete end-to-end example for finding and using working DNS servers in Iran:

```bash
# Step 1 — Build the Rust scanner
cd dns_scanner && cargo build --release && cd ..

# Step 2 — Scan Iranian IPs at a safe rate
./dns_scanner/target/release/dns_scanner \
  --cidr-file ir.txt \
  --pps-limit 50000 \
  --output ir_dns.txt

# Step 3 — Wait for the scan to finish, then check results
wc -l ir_dns.txt.verified
# e.g. "847 ir_dns.txt.verified"

# Step 4 — Start the tunnel manager
python dns_manager.py \
  --dns-file ir_dns.txt.verified \
  --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey YOUR_PUBKEY tunnel.example.com 127.0.0.1:8080" \
  --dnstt-servers 5 \
  --interval 3600
```

The manager will now keep DNSTT running continuously, swapping in fresh DNS servers every hour automatically.

---

## CIDR file format

Country CIDR files (like `ir.txt`) should have one IP range per line:

```
# Iran - RIPE NCC
5.22.0.0/17
5.53.32.0/19
31.2.128.0/17
31.7.64.0/18
# Comments starting with # are ignored
; So are lines starting with ;

37.0.8.0/21
```

You can get these files from:
- [RIPE NCC](https://ftp.ripe.net/pub/stats/ripencc/) — Europe, Middle East, Central Asia
- [APNIC](https://ftp.apnic.net/stats/apnic/) — Asia Pacific
- [ARIN](https://ftp.arin.net/pub/stats/arin/) — North America
- [LACNIC](https://ftp.lacnic.net/pub/stats/lacnic/) — Latin America
- [AFRINIC](https://ftp.afrinic.net/stats/afrinic/) — Africa
- Tools like `ipdeny.com` provide pre-aggregated per-country CIDR files

---

## Troubleshooting

**My ISP blocked me**
Lower `--pps-limit`. Start at `30000` and work up slowly. Also add `--jitter-us 10000`.

**The scan is too slow**
For targeted ranges (a single country), even `--pps-limit 200000` usually completes in under an hour. For a full internet sweep you need to accept that scanning safely takes many hours.

**Found 0 DNS servers**
- Check that UDP port 53 outbound is not blocked (`nmap -sU -p 53 8.8.8.8`)
- Try `--a-expected ""` and `--ns-expected ""` to accept any valid response
- Try a known-good server first: `--ranges 8.8.8.8/32 1.1.1.1/32 --verbose`

**dns_manager isn't finding my binary**
Make sure the binary is in your `PATH` or use the full absolute path in your `--dnstt-cmd`.

**Rust won't compile**
Make sure you have the latest stable Rust: `rustup update stable`

---

## Legal notice

This tool sends DNS queries to public IP addresses. While DNS queries are a normal part of internet operation, scanning at high rates may violate your ISP's terms of service. Use responsibly, keep `--pps-limit` reasonable, and only scan IP ranges you have permission to probe.
