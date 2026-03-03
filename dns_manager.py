#!/usr/bin/env python3
"""
dns_manager.py — DNSTT & SLIPSTREAM process manager
=====================================================
Reads a list of working DNS servers, assigns fresh random selections to
each tunnel client process, and automatically rotates them every hour
(or any configurable interval).

On each refresh cycle:
  1. Re-reads the DNS server file (picks up new scan results automatically)
  2. Kills all currently managed processes
  3. Restarts them with freshly chosen DNS servers
  4. Logs the assigned servers and PIDs

COMMAND TEMPLATES
  Use these placeholders in your --dnstt-cmd / --slipstream-cmd strings:
    {dns}       — single DNS server IP (one per process instance)
    {dns_list}  — comma-separated list of all assigned DNS IPs for this tool

EXAMPLES
  # Minimal — let manager pick server counts automatically
  python dns_manager.py \\
      --dns-file working_dns.txt \\
      --dnstt-cmd  "dnstt-client -udp {dns}:53 -pubkey YOUR_PUBKEY tunnel.example.com 127.0.0.1:8080" \\
      --slipstream-cmd "slipstream-client --dns {dns} --domain tunnel.example.com --socks5 127.0.0.1:1080"

  # Fine-grained control
  python dns_manager.py \\
      --dns-file working_dns.txt \\
      --dnstt-cmd      "dnstt-client -udp {dns}:53 -pubkey KEY tun.example.com 127.0.0.1:8080" \\
      --dnstt-count    2          \\   # 2 parallel dnstt processes
      --dnstt-servers  5          \\   # 5 DNS servers per dnstt instance
      --slipstream-cmd "slipstream-client --resolver {dns}" \\
      --slipstream-count   1      \\
      --slipstream-servers 3      \\
      --interval 1800             \\   # refresh every 30 minutes instead of 1 hour
      --on-start-cmd "echo 'DNS refreshed' | notify-send -"

  # JSON config for multiple/custom processes
  python dns_manager.py --dns-file working_dns.txt --config processes.json

JSON CONFIG FORMAT (processes.json)
  {
    "processes": [
      {
        "name": "dnstt-main",
        "cmd":  "dnstt-client -udp {dns}:53 -pubkey KEY tun.example.com 127.0.0.1:8080",
        "count": 2,
        "servers_per_instance": 4
      },
      {
        "name": "slipstream",
        "cmd":  "slipstream-client --dns {dns}",
        "count": 1,
        "servers_per_instance": 3
      }
    ]
  }
"""

import argparse
import json
import logging
import os
import random
import re
import shlex
import signal
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("dns_manager")


# ─── DNS file reader ─────────────────────────────────────────────────────────

def load_dns_servers(path: str) -> List[str]:
    """Load and return all DNS server IPs from a one-IP-per-line file."""
    if not os.path.isfile(path):
        log.error("DNS server file not found: %s", path)
        return []
    servers: List[str] = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Basic IPv4 sanity check
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                servers.append(line)
            else:
                log.debug("Skipping non-IP line: %r", line)
    return servers


def pick_random(servers: List[str], count: int) -> List[str]:
    """Pick `count` random servers, or all of them if fewer are available."""
    if not servers:
        return []
    if count >= len(servers):
        result = list(servers)
        random.shuffle(result)
        return result
    return random.sample(servers, count)


# ─── Process descriptor ──────────────────────────────────────────────────────

class ProcessSpec:
    """Describes one family of managed processes (e.g. all dnstt instances)."""

    def __init__(
        self,
        name:                str,
        cmd_template:        str,
        count:               int = 1,
        servers_per_instance: int = 3,
        restart_on_death:    bool = True,
        env_extra:           Optional[Dict[str, str]] = None,
    ):
        self.name                  = name
        self.cmd_template          = cmd_template
        self.count                 = count
        self.servers_per_instance  = servers_per_instance
        self.restart_on_death      = restart_on_death
        self.env_extra             = env_extra or {}

        # Runtime state
        self._procs: List[Tuple[subprocess.Popen, str]] = []  # (proc, dns_ip)

    # ── Command formatting ───────────────────────────────────────────────────

    def _render(self, dns_ip: str, dns_list: str) -> str:
        return (
            self.cmd_template
            .replace("{dns}",      dns_ip)
            .replace("{dns_list}", dns_list)
        )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self, dns_pool: List[str]) -> None:
        """Stop any running instances, then launch `count` new ones."""
        self.stop()

        if not dns_pool:
            log.error("[%s] No DNS servers available — not starting", self.name)
            return

        # Each instance gets its own primary server; all share the full pool str.
        dns_list_str = ",".join(dns_pool)
        env = {**os.environ, **self.env_extra}

        for i in range(self.count):
            dns_ip = dns_pool[i % len(dns_pool)]
            cmd    = self._render(dns_ip, dns_list_str)
            log.info(
                "[%s] instance %d/%d  DNS=%s  cmd: %s",
                self.name, i + 1, self.count, dns_ip, cmd,
            )
            try:
                proc = subprocess.Popen(
                    shlex.split(cmd),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    # Create a new process group so we can kill the whole tree.
                    start_new_session=True,
                )
                self._procs.append((proc, dns_ip))
                log.info(
                    "[%s] started PID %d (instance %d, DNS %s)",
                    self.name, proc.pid, i + 1, dns_ip,
                )
            except FileNotFoundError:
                log.error(
                    "[%s] binary not found — check your command: %s", self.name, cmd
                )
            except Exception as exc:
                log.error("[%s] failed to start instance %d: %s", self.name, i + 1, exc)

    def stop(self) -> None:
        """Terminate all running instances (SIGTERM → wait 5 s → SIGKILL)."""
        if not self._procs:
            return
        log.info("[%s] stopping %d instance(s)…", self.name, len(self._procs))
        for proc, _ in self._procs:
            if proc.poll() is not None:
                continue
            try:
                # Kill the entire process group (handles sub-processes / shells).
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    proc.terminate()
                except Exception:
                    pass
        # Grace period
        deadline = time.monotonic() + 5.0
        for proc, _ in self._procs:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        proc.kill()
        self._procs.clear()

    def health_check(self) -> Tuple[int, int]:
        """Returns (alive_count, dead_count)."""
        alive = [(p, d) for p, d in self._procs if p.poll() is None]
        dead  = len(self._procs) - len(alive)
        self._procs = alive
        return len(alive), dead

    def summary(self) -> str:
        lines = []
        for proc, dns_ip in self._procs:
            status = "alive" if proc.poll() is None else f"dead (rc={proc.poll()})"
            lines.append(f"    PID {proc.pid:6d}  DNS={dns_ip}  [{status}]")
        return "\n".join(lines) if lines else "    (no instances)"


# ─── Manager ─────────────────────────────────────────────────────────────────

class Manager:
    def __init__(self, dns_file: str, specs: List[ProcessSpec], on_start_cmd: Optional[str]):
        self.dns_file     = dns_file
        self.specs        = specs
        self.on_start_cmd = on_start_cmd
        self._last_refresh: Optional[datetime] = None

    def refresh(self) -> None:
        """Reload DNS list, kill old processes, start fresh ones."""
        all_dns = load_dns_servers(self.dns_file)

        if not all_dns:
            log.error("DNS file empty or missing — skipping refresh")
            return

        log.info("─" * 60)
        log.info("Refresh — %d DNS servers available in %s", len(all_dns), self.dns_file)

        for spec in self.specs:
            needed    = spec.count * spec.servers_per_instance
            dns_pool  = pick_random(all_dns, needed)
            log.info(
                "[%s] selected %d servers for %d instance(s): %s",
                spec.name, len(dns_pool), spec.count,
                ", ".join(dns_pool) if len(dns_pool) <= 8
                else ", ".join(dns_pool[:8]) + f"… (+{len(dns_pool)-8})",
            )
            spec.start(dns_pool)

        self._last_refresh = datetime.now()
        log.info("All processes refreshed at %s", self._last_refresh.strftime("%H:%M:%S"))
        log.info("─" * 60)

        if self.on_start_cmd:
            try:
                subprocess.run(
                    shlex.split(self.on_start_cmd),
                    timeout=10,
                    check=False,
                )
            except Exception as e:
                log.warning("on_start_cmd error: %s", e)

    def health_report(self) -> None:
        log.info("── Health check ──")
        for spec in self.specs:
            alive, dead = spec.health_check()
            if dead:
                log.warning("[%s] %d/%d instances died since last check",
                            spec.name, dead, spec.count)
            log.info("[%s] %d/%d alive\n%s",
                     spec.name, alive, spec.count, spec.summary())

    def stop_all(self) -> None:
        for spec in self.specs:
            spec.stop()

    def run_forever(self, interval: int, health_check_secs: int = 60) -> None:
        """Main loop. Refresh immediately, then every `interval` seconds."""
        log.info("Starting DNS manager — refresh every %ds (%s)",
                 interval, str(timedelta(seconds=interval)))

        def _handle_signal(sig, _frame):
            log.info("Signal %s received — shutting down gracefully…", sig)
            self.stop_all()
            sys.exit(0)

        signal.signal(signal.SIGINT,  _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        next_refresh      = time.monotonic()
        next_health_check = time.monotonic() + health_check_secs

        while True:
            now = time.monotonic()

            if now >= next_refresh:
                self.refresh()
                next_refresh = now + interval

            if now >= next_health_check:
                self.health_report()
                next_health_check = now + health_check_secs

            # Time until next event
            sleep_for = min(next_refresh, next_health_check) - time.monotonic()
            if sleep_for > 0:
                time.sleep(min(sleep_for, 10))  # wake up at most every 10 s


# ─── Config helpers ───────────────────────────────────────────────────────────

def specs_from_json(path: str) -> List[ProcessSpec]:
    with open(path) as fh:
        data = json.load(fh)
    specs = []
    for entry in data.get("processes", []):
        specs.append(ProcessSpec(
            name=entry["name"],
            cmd_template=entry["cmd"],
            count=entry.get("count", 1),
            servers_per_instance=entry.get("servers_per_instance", 3),
            env_extra=entry.get("env", {}),
        ))
    return specs


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dns_manager.py",
        description="DNSTT & SLIPSTREAM manager with automatic hourly DNS rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        PLACEHOLDERS in command templates:
          {dns}        single DNS server IP assigned to this instance
          {dns_list}   comma-separated list of all assigned IPs for this tool

        EXAMPLE
          python dns_manager.py \\
            --dns-file working_dns.txt \\
            --dnstt-cmd "dnstt-client -udp {dns}:53 -pubkey KEY tun.ex.com 127.0.0.1:8080" \\
            --slipstream-cmd "slipstream-client --dns {dns}" \\
            --dnstt-count 2 --dnstt-servers 5 \\
            --slipstream-count 1 --slipstream-servers 3
        """),
    )

    # ── Required ──────────────────────────────────────────────────────────────
    p.add_argument(
        "--dns-file", "-d", required=True,
        metavar="FILE",
        help="Path to working DNS servers file (one IP per line, output of dns_scanner)",
    )

    # ── Timing ────────────────────────────────────────────────────────────────
    p.add_argument(
        "--interval", "-i", type=int, default=3600,
        metavar="SECS",
        help="DNS rotation interval in seconds (default: 3600 = 1 hour)",
    )

    # ── DNSTT ─────────────────────────────────────────────────────────────────
    g1 = p.add_argument_group("DNSTT client")
    g1.add_argument(
        "--dnstt-cmd",
        metavar="CMD",
        help='DNSTT command template, e.g.: "dnstt-client -udp {dns}:53 -pubkey KEY tun.example.com 127.0.0.1:8080"',
    )
    g1.add_argument(
        "--dnstt-count", type=int, default=1, metavar="N",
        help="Number of parallel DNSTT instances (default: 1)",
    )
    g1.add_argument(
        "--dnstt-servers", type=int, default=3, metavar="N",
        help="DNS servers to assign per DNSTT instance (default: 3)",
    )

    # ── SLIPSTREAM ────────────────────────────────────────────────────────────
    g2 = p.add_argument_group("SLIPSTREAM client")
    g2.add_argument(
        "--slipstream-cmd",
        metavar="CMD",
        help='SLIPSTREAM command template, e.g.: "slipstream-client --dns {dns} --domain tun.example.com"',
    )
    g2.add_argument(
        "--slipstream-count", type=int, default=1, metavar="N",
        help="Number of parallel SLIPSTREAM instances (default: 1)",
    )
    g2.add_argument(
        "--slipstream-servers", type=int, default=3, metavar="N",
        help="DNS servers to assign per SLIPSTREAM instance (default: 3)",
    )

    # ── Extra processes via JSON ───────────────────────────────────────────────
    g3 = p.add_argument_group("Extra processes")
    g3.add_argument(
        "--config", "-c",
        metavar="JSON",
        help="JSON file describing additional process families (see FORMAT below)",
    )

    # ── Misc ──────────────────────────────────────────────────────────────────
    p.add_argument(
        "--on-start-cmd",
        metavar="CMD",
        help="Shell command to run after every refresh (e.g. send a notification)",
    )
    p.add_argument(
        "--once", action="store_true",
        help="Perform a single refresh then exit (don't loop)",
    )
    p.add_argument(
        "--status", action="store_true",
        help="Print status of currently running managed processes and exit",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    return p


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Build list of ProcessSpec objects
    specs: List[ProcessSpec] = []

    if args.dnstt_cmd:
        specs.append(ProcessSpec(
            name="dnstt",
            cmd_template=args.dnstt_cmd,
            count=args.dnstt_count,
            servers_per_instance=args.dnstt_servers,
        ))

    if args.slipstream_cmd:
        specs.append(ProcessSpec(
            name="slipstream",
            cmd_template=args.slipstream_cmd,
            count=args.slipstream_count,
            servers_per_instance=args.slipstream_servers,
        ))

    if args.config:
        try:
            specs.extend(specs_from_json(args.config))
            log.info("Loaded %d process spec(s) from %s", len(specs), args.config)
        except Exception as e:
            log.error("Failed to load config file: %s", e)
            sys.exit(1)

    if not specs:
        parser.error(
            "Provide at least one of: --dnstt-cmd, --slipstream-cmd, or --config"
        )

    manager = Manager(
        dns_file=args.dns_file,
        specs=specs,
        on_start_cmd=args.on_start_cmd,
    )

    if args.status:
        manager.health_report()
        return

    if args.once:
        manager.refresh()
        log.info("One-shot refresh complete.")
    else:
        manager.run_forever(interval=args.interval)


if __name__ == "__main__":
    main()
