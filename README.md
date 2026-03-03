## dns_scanner (Rust)

**Build:**
```bash
sudo apt install cargo   # or: curl https://sh.rustup.rs | sh
cd dns_scanner_rs
cargo build --release
# binary: ./target/release/dns_scanner
```

**OS tuning first (major impact on throughput):**
```bash
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.core.netdev_max_backlog=500000
sudo sysctl -w net.ipv4.udp_mem="102400 873800 16777216"
ulimit -n 65535
```

**Run:**
```bash
./target/release/dns_scanner --threads 64 --output working_dns.txt
```

**How it works — two-phase fire-and-collect design:**
- **Phase 1**: All N threads divide the full 0.0.0.0/0 space, skip 14 excluded private ranges (~600M IPs), and fire A queries simultaneously to the remaining ~3.7B IPs. Each thread interleaves a `recv_from` drain every 1024 sends so no responses pile up in the kernel buffer.
- **Phase 2**: Only the Phase-1 responders (typically tens of thousands of real resolvers) get an NS query. Much faster than phase 1.
- At 1 Gbps with 70-byte packets → ~1.3M pps → Phase 1 finishes in ~47 minutes. Phase 2 takes a few minutes at most.

---

## dns_manager.py

Reads `working_dns.txt`, kills old DNSTT/SLIPSTREAM processes, starts fresh instances with randomly selected DNS servers, repeats every hour.

```bash
python dns_manager.py \
  --dns-file working_dns.txt \
  --dnstt-cmd      "dnstt-client -udp {dns}:53 -pubkey YOUR_KEY tunnel.example.com 127.0.0.1:8080" \
  --dnstt-count    2  \        # 2 parallel dnstt processes
  --dnstt-servers  5  \        # 5 DNS servers per dnstt instance
  --slipstream-cmd "slipstream-client --dns {dns} --domain tunnel.example.com" \
  --slipstream-count   1 \
  --slipstream-servers 3 \
  --interval 3600              # refresh every hour
```

**Key features:**
- `{dns}` → primary server IP for that specific process instance
- `{dns_list}` → comma-separated list of all assigned servers (if the tool accepts multiple)
- `--dnstt-count 2 --dnstt-servers 5` → 2 instances, each with a different primary from a pool of 10 randomly chosen servers
- Process groups (`setsid`) ensure child processes are fully killed on refresh
- SIGTERM → 5s grace → SIGKILL teardown
- Health check every 60 seconds, logs dead instances
- `--once` for scripted/cron use; `--status` to inspect live state

**Typical workflow:**
```bash
# 1. Scan (takes ~50 min)
./dns_scanner --output working_dns.txt

# 2. Start manager (runs forever, rotates hourly)
python dns_manager.py --dns-file working_dns.txt \
    --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey KEY ..."
```
