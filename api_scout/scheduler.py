"""Scheduled monitoring — watches log files and runs periodic scans."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .database import Database
from .inventory import APIInventory
from .parsers.base import BaseLogParser
from .scanner import scan_network

console = Console()


class LogWatcher:
    """Watches log files for new lines (tail -f style)."""

    def __init__(self, paths: list[Path]):
        self.paths = paths
        self._offsets: dict[Path, int] = {}

        # Initialize offsets to end of file
        for path in paths:
            if path.exists():
                self._offsets[path] = path.stat().st_size

    def get_new_lines(self) -> dict[Path, list[str]]:
        """Read new lines from all watched files since last check."""
        new_lines: dict[Path, list[str]] = {}

        for path in self.paths:
            if not path.exists():
                continue

            current_size = path.stat().st_size
            last_offset = self._offsets.get(path, 0)

            # File was truncated/rotated
            if current_size < last_offset:
                last_offset = 0

            if current_size == last_offset:
                continue

            lines = []
            with open(path, "r", errors="replace") as f:
                f.seek(last_offset)
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)

            self._offsets[path] = current_size
            if lines:
                new_lines[path] = lines

        return new_lines


class Scheduler:
    """Runs periodic log analysis and network scans."""

    def __init__(
        self,
        db: Database,
        log_files: list[Path] | None = None,
        parser: BaseLogParser | None = None,
        scan_targets: list[str] | None = None,
        scan_ports: list[int] | None = None,
        log_interval: int = 30,        # seconds between log checks
        scan_interval: int = 3600,     # seconds between network scans
        zombie_days: int = 30,
    ):
        self.db = db
        self.inventory = APIInventory(zombie_threshold_days=zombie_days)
        self.parser = parser
        self.scan_targets = scan_targets or []
        self.scan_ports = scan_ports
        self.log_interval = log_interval
        self.scan_interval = scan_interval
        self._running = False
        self._stats = {
            "started_at": None,
            "log_checks": 0,
            "network_scans": 0,
            "total_records": 0,
            "total_new_endpoints": 0,
            "total_alerts": 0,
            "last_log_check": None,
            "last_scan": None,
        }

        # Set up log watcher
        self.watcher = LogWatcher(log_files or [])

        # Load existing endpoints from DB
        existing = self.db.get_all_endpoints()
        for ep in existing:
            self.inventory._endpoints[ep.endpoint_id] = ep

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    def _process_new_log_lines(self) -> tuple[int, int]:
        """Process new lines from watched log files. Returns (records, new_endpoints)."""
        if not self.parser:
            return 0, 0

        new_lines = self.watcher.get_new_lines()
        if not new_lines:
            return 0, 0

        all_records = []
        for path, lines in new_lines.items():
            for line in lines:
                record = self.parser.parse_line(line)
                if record:
                    all_records.append(record)

        if not all_records:
            return 0, 0

        new_endpoints = self.inventory.ingest_traffic(all_records)

        # Persist to DB
        path_patterns = {
            r.path: self.inventory.normalize_path(r.path) for r in all_records
        }
        self.db.log_traffic(all_records, path_patterns)

        return len(all_records), new_endpoints

    async def _run_network_scan(self) -> tuple[int, int]:
        """Run a network scan. Returns (endpoints_found, new_endpoints)."""
        if not self.scan_targets:
            return 0, 0

        scan_id = self.db.start_scan("network", ",".join(self.scan_targets))

        try:
            results = await scan_network(self.scan_targets, self.scan_ports)
            new_endpoints = self.inventory.ingest_scan_results(results)
            total_found = sum(len(r.endpoints_found) for r in results)

            self.db.complete_scan(scan_id, total_found, new_endpoints, 0)
            return total_found, new_endpoints

        except Exception as e:
            self.db.fail_scan(scan_id, str(e))
            return 0, 0

    def _save_state(self):
        """Save current inventory state to DB."""
        self.inventory.classify()
        self.db.save_endpoints(self.inventory.endpoints)

        alerts = self.inventory.generate_alerts()
        if alerts:
            self.db.save_alerts(alerts)
            self._stats["total_alerts"] += len(alerts)

    async def run(self):
        """Main scheduler loop."""
        self._running = True
        self._stats["started_at"] = datetime.now().isoformat()

        console.print(Panel(
            f"[bold green]API Scout Scheduler Started[/]\n"
            f"  Log check interval: {self.log_interval}s\n"
            f"  Scan interval: {self.scan_interval}s\n"
            f"  Watching {len(self.watcher.paths)} log file(s)\n"
            f"  Scanning {len(self.scan_targets)} target(s)\n"
            f"  Loaded {len(self.inventory.endpoints)} existing endpoints from DB",
            border_style="green",
        ))

        last_scan_time = 0

        while self._running:
            now = time.time()

            # Check logs
            records, new_eps = self._process_new_log_lines()
            self._stats["log_checks"] += 1
            self._stats["total_records"] += records
            self._stats["total_new_endpoints"] += new_eps
            self._stats["last_log_check"] = datetime.now().isoformat()

            if records > 0:
                console.print(
                    f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                    f"Processed [green]{records}[/] records, "
                    f"[yellow]{new_eps}[/] new endpoints"
                )

            # Periodic network scan
            if self.scan_targets and (now - last_scan_time) >= self.scan_interval:
                console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] Running network scan...")
                found, new_scan = await self._run_network_scan()
                last_scan_time = now
                self._stats["network_scans"] += 1
                self._stats["last_scan"] = datetime.now().isoformat()

                if found > 0:
                    console.print(
                        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] "
                        f"Scan found [green]{found}[/] endpoints, "
                        f"[yellow]{new_scan}[/] new"
                    )

            # Save state periodically
            self._save_state()

            # Wait for next cycle
            try:
                await asyncio.sleep(self.log_interval)
            except asyncio.CancelledError:
                break

        self._save_state()
        console.print("[yellow]Scheduler stopped.[/]")

    def stop(self):
        self._running = False
