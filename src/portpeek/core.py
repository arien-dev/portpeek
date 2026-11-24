"""Parsing, scanning, export, and shared helpers (stdlib only)."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from .constants import (
    ANSI_DIM,
    ANSI_GREEN,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
    DEFAULT_HOST,
    PRESETS,
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_ports(raw_items: list[str] | None) -> list[int]:
    """Parse single ports, comma lists, and 'start-end' ranges into deduplicated ints."""
    if not raw_items:
        return []

    ports: list[int] = []
    seen: set[int] = set()
    tokens: list[str] = []
    for raw in raw_items:
        for part in str(raw).split(","):
            token = part.strip()
            if token:
                tokens.append(token)

    for item in tokens:
        if "-" in item and not item.startswith("-"):
            parts = item.split("-", 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f"Invalid port range: '{item}'")
            start, end = int(parts[0]), int(parts[1])
            if start > end or not (1 <= start <= 65535) or not (1 <= end <= 65535):
                raise ValueError(f"Port range out of bounds (1-65535): '{item}'")
            for p in range(start, end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            if not item.isdigit():
                raise ValueError(f"Invalid port number: '{item}'")
            p = int(item)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port must be between 1 and 65535: {p}")
            if p not in seen:
                seen.add(p)
                ports.append(p)
    return ports


def parse_host_port(token: str) -> tuple[str | None, int | None]:
    """Parse 'HOST:PORT', '[IPv6]:PORT', or bare PORT. Returns (host, port)."""
    token = token.strip()
    if not token:
        return None, None

    # [ipv6]:port
    if token.startswith("["):
        end = token.find("]")
        if end != -1 and end + 1 < len(token) and token[end + 1] == ":":
            host = token[1:end]
            port_s = token[end + 2 :]
            if port_s.isdigit():
                p = int(port_s)
                if 1 <= p <= 65535:
                    return host, p
            raise ValueError(f"Invalid HOST:PORT: '{token}'")
        return token, None

    # host:port (last colon) — avoid treating IPv6 as host:port without brackets
    if token.count(":") == 1:
        host, port_s = token.rsplit(":", 1)
        if port_s.isdigit() and host:
            p = int(port_s)
            if 1 <= p <= 65535:
                return host, p
            raise ValueError(f"Port must be between 1 and 65535: {p}")

    if token.isdigit():
        p = int(token)
        if 1 <= p <= 65535:
            return None, p
        raise ValueError(f"Port must be between 1 and 65535: {p}")

    return token, None


def parse_targets(raw_items: list[str]) -> tuple[list[str], list[int]]:
    """Parse mixed positionals into hosts and ports (HOST:PORT, ports, ranges)."""
    hosts: list[str] = []
    ports: list[int] = []
    seen_hosts: set[str] = set()
    seen_ports: set[int] = set()

    for raw in raw_items:
        for part in raw.split(","):
            token = part.strip()
            if not token:
                continue
            # Range like 3000-3010
            if "-" in token and token[0].isdigit() and ":" not in token:
                for p in parse_ports([token]):
                    if p not in seen_ports:
                        seen_ports.add(p)
                        ports.append(p)
                continue
            host, port = parse_host_port(token)
            if port is not None and host is None:
                if port not in seen_ports:
                    seen_ports.add(port)
                    ports.append(port)
            elif port is not None and host is not None:
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    hosts.append(host)
                if port not in seen_ports:
                    seen_ports.add(port)
                    ports.append(port)
            elif host is not None:
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    hosts.append(host)
    return hosts, ports


def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR notation into host address strings (IPv4/IPv6)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: '{cidr}'") from exc
    # Cap runaway scans
    if net.num_addresses > 4096:
        raise ValueError(f"CIDR too large ({net.num_addresses} hosts); max 4096")
    return [str(ip) for ip in net.hosts()] if net.num_addresses > 2 else [str(ip) for ip in net]


def load_hosts_file(path: str) -> list[str]:
    hosts: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                hosts.append(line)
    return hosts


def resolve_hosts_and_ports(
    positionals: list[str] | None,
    *,
    host_args: list[str] | None = None,
    host_file: str | None = None,
    cidr: str | None = None,
    preset: str | None = None,
) -> tuple[list[str], list[int]]:
    """Combine CLI sources into final host list and port list."""
    hosts: list[str] = []
    ports: list[int] = []

    if positionals:
        ph, pp = parse_targets(positionals)
        hosts.extend(ph)
        ports.extend(pp)

    if host_args:
        for h in host_args:
            if h not in hosts:
                hosts.append(h)

    if host_file:
        for h in load_hosts_file(host_file):
            if h not in hosts:
                hosts.append(h)

    if cidr:
        for h in expand_cidr(cidr):
            if h not in hosts:
                hosts.append(h)

    if preset:
        key = preset.lower()
        if key not in PRESETS:
            raise ValueError(f"Unknown preset '{preset}'. Choose from: {', '.join(PRESETS)}")
        for p in PRESETS[key]:
            if p not in ports:
                ports.append(p)

    if not hosts:
        hosts = [DEFAULT_HOST]
    return hosts, ports


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def _grab_banner(sock: socket.socket, port: int) -> str | None:
    try:
        sock.settimeout(0.35)
        if port in (80, 8080, 8000, 3000, 5173, 5000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        data = sock.recv(128)
        if not data:
            return None
        cleaned = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()
        return cleaned[:80] if cleaned else None
    except OSError:
        return None


def check_port(
    host: str,
    port: int,
    timeout: float = 0.25,
    measure_latency: bool = False,
    grab_banner: bool = False,
) -> dict[str, Any]:
    """Check a single TCP port using getaddrinfo (IPv4/IPv6)."""
    start_time = time.perf_counter()
    is_open = False
    banner: str | None = None
    error: str | None = None

    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, socktype, proto, _, sockaddr in addr_info:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex(sockaddr) == 0:
                    is_open = True
                    if grab_banner:
                        banner = _grab_banner(sock, port)
                    break
    except OSError as exc:
        is_open = False
        error = str(exc)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "status": "open" if is_open else "free",
        "service": service_name(port),
    }
    if measure_latency:
        result["latency_ms"] = elapsed_ms
    if grab_banner and is_open:
        result["banner"] = banner or "-"
    if error:
        result["error"] = error
    return result


def scan_target(
    host: str,
    ports: list[int],
    timeout: float = 0.25,
    workers: int = 64,
    measure_latency: bool = False,
    grab_banner: bool = False,
) -> list[dict[str, Any]]:
    if not ports:
        return []
    results_by_port: dict[int, dict[str, Any]] = {}
    max_workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(check_port, host, port, timeout, measure_latency, grab_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            res = future.result()
            results_by_port[res["port"]] = res
    return [results_by_port[p] for p in ports]


def scan_hosts(
    hosts: list[str],
    ports: list[int],
    timeout: float = 0.25,
    workers: int = 64,
    measure_latency: bool = False,
    grab_banner: bool = False,
) -> list[dict[str, Any]]:
    all_results: list[dict[str, Any]] = []
    for host in hosts:
        all_results.extend(
            scan_target(
                host=host,
                ports=ports,
                timeout=timeout,
                workers=workers,
                measure_latency=measure_latency,
                grab_banner=grab_banner,
            )
        )
    return all_results


def find_free_block(ports: list[int], results: list[dict[str, Any]], block_size: int) -> list[int] | None:
    status_map = {r["port"]: r["status"] for r in results}
    run: list[int] = []
    for p in ports:
        if status_map.get(p) == "free":
            run.append(p)
            if len(run) == block_size:
                return run
        else:
            run = []
    return None


def find_free_port_local(start: int, end: int, block: int = 1, host: str = DEFAULT_HOST) -> list[int] | None:
    """Find free port(s) by bind-test (faster for freeport than connect scan)."""
    if block < 1:
        block = 1
    run: list[int] = []
    for port in range(start, end + 1):
        if _can_bind(host, port):
            run.append(port)
            if len(run) == block:
                return run
        else:
            run = []
    return None


def _can_bind(host: str, port: int) -> bool:
    families = [socket.AF_INET]
    if host in ("::", "::1") or ":" in host:
        families = [socket.AF_INET6]
    elif host in ("0.0.0.0", "127.0.0.1", ""):
        families = [socket.AF_INET]
    for family in families:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                addr = host if host else ("0.0.0.0" if family == socket.AF_INET else "::")
                if family == socket.AF_INET6:
                    sock.bind((addr, port, 0, 0))
                else:
                    sock.bind((addr, port))
                return True
        except OSError:
            continue
    # Fallback: try connect to see if something listens
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.05)
            return sock.connect_ex(("127.0.0.1", port)) != 0
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Display / color
# ---------------------------------------------------------------------------


def use_color(no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def print_results(
    results: list[dict[str, Any]],
    show_services: bool = False,
    no_color: bool = False,
    show_proc: bool = False,
) -> None:
    color = use_color(no_color)
    for r in results:
        is_open = r["status"] == "open"
        if is_open:
            tag = f"{ANSI_RED}[IN USE]{ANSI_RESET}" if color else "[IN USE]"
        else:
            tag = f"{ANSI_GREEN}[FREE]  {ANSI_RESET}" if color else "[FREE]  "

        svc = f" ({r['service']})" if show_services else ""
        lat = f" [{r['latency_ms']} ms]" if "latency_ms" in r else ""
        banner = ""
        if r.get("banner") and r["banner"] != "-":
            banner = f" {ANSI_DIM}| {r['banner']}{ANSI_RESET}" if color else f" | {r['banner']}"
        proc = ""
        if show_proc and r.get("process"):
            proc = f"  pid={r['process'].get('pid')} {r['process'].get('name', '')}"
            if r["process"].get("docker"):
                proc += f" {r['process']['docker']}"
        warn = ""
        if r.get("public_warning"):
            w = r["public_warning"]
            warn = f" {ANSI_YELLOW}⚠ {w}{ANSI_RESET}" if color else f" [WARN] {w}"
        print(f"{tag} {r['host']}:{r['port']}{svc}{lat}{banner}{proc}{warn}")


def print_summary(results: list[dict[str, Any]], no_color: bool = False) -> None:
    open_n = sum(1 for r in results if r["status"] == "open")
    free_n = len(results) - open_n
    color = use_color(no_color)
    line = f"Summary: {open_n} open, {free_n} free, {len(results)} total"
    if color:
        print(f"\n{ANSI_DIM}{line}{ANSI_RESET}")
    else:
        print(f"\n{line}")


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def auto_output_path(ext: str = "json") -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"portpeek-{ts}.{ext.lstrip('.')}"


def normalize_output_path(path: str | None, default_ext: str = "json") -> str | None:
    """Handle `-o` / `--output` with optional bare flag / extension-only value."""
    if path is None:
        return None
    if path in ("", "-"):
        return auto_output_path(default_ext)
    # Bare extension like "json" or ".md"
    if path.lstrip(".").lower() in ("json", "jsonl", "csv", "md", "txt") and "/" not in path:
        return auto_output_path(path.lstrip("."))
    return path


def export_results(
    path: str,
    rows: list[dict[str, Any]],
    *,
    include_meta: bool = False,
    meta: dict[str, Any] | None = None,
) -> str:
    """Export to .json / .jsonl / .csv / .md / .txt. Returns path written."""
    ext = os.path.splitext(path)[1].lower()
    if not ext:
        path = path + ".json"
        ext = ".json"

    payload_meta = {
        "tool": "portpeek",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(rows),
        **(meta or {}),
    }

    if ext == ".csv":
        fieldnames = _csv_fields(rows)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(_flatten_row(row, fieldnames))
    elif ext == ".jsonl":
        with open(path, "w", encoding="utf-8") as f:
            if include_meta:
                f.write(json.dumps({"_meta": payload_meta}) + "\n")
            for row in rows:
                f.write(json.dumps(row, default=str) + "\n")
    elif ext == ".md":
        with open(path, "w", encoding="utf-8") as f:
            f.write("# portpeek results\n\n")
            if include_meta:
                f.write(f"_Generated: {payload_meta['generated_at']}_ · {payload_meta['count']} rows\n\n")
            cols = _csv_fields(rows)
            f.write("| " + " | ".join(cols) + " |\n")
            f.write("| " + " | ".join("---" for _ in cols) + " |\n")
            for row in rows:
                flat = _flatten_row(row, cols)
                f.write("| " + " | ".join(str(flat.get(c, "")) for c in cols) + " |\n")
    elif ext == ".txt":
        with open(path, "w", encoding="utf-8") as f:
            if include_meta:
                f.write(f"# portpeek {payload_meta['generated_at']} ({payload_meta['count']} rows)\n")
            for r in rows:
                status = r.get("status", "?")
                host = r.get("host", "")
                port = r.get("port", "")
                svc = r.get("service", "")
                extra = ""
                if r.get("process"):
                    extra = f" pid={r['process'].get('pid')} {r['process'].get('name', '')}"
                f.write(f"[{status.upper():7}] {host}:{port} {svc}{extra}\n")
    else:
        data: Any = {"meta": payload_meta, "results": rows} if include_meta else rows
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    return path


def _csv_fields(rows: list[dict[str, Any]]) -> list[str]:
    base = ["host", "port", "status", "service", "latency_ms", "banner", "proto", "bind", "pid", "process", "command"]
    present: list[str] = []
    keys_in_rows: set[str] = set()
    for r in rows:
        keys_in_rows.update(r.keys())
        if "process" in r and isinstance(r["process"], dict):
            keys_in_rows.update(f"process.{k}" for k in r["process"])
    for k in base:
        if k in keys_in_rows or k.split(".")[0] in keys_in_rows:
            present.append(k)
    for k in sorted(keys_in_rows):
        if k not in present and k != "process":
            present.append(k)
    return present or base[:4]


def _flatten_row(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    flat: dict[str, Any] = dict(row)
    proc = row.get("process")
    if isinstance(proc, dict):
        flat["pid"] = proc.get("pid", flat.get("pid", ""))
        flat["process"] = proc.get("name", "")
        flat["command"] = proc.get("cmdline", proc.get("command", ""))
        if proc.get("docker"):
            flat["process"] = f"{flat['process']} {proc['docker']}"
    return {k: flat.get(k, "") for k in fields}


# ---------------------------------------------------------------------------
# Clipboard
# ---------------------------------------------------------------------------


def copy_to_clipboard(text: str) -> bool:
    """Best-effort clipboard copy via wl-copy / xclip / xsel / pbcopy / clip."""
    candidates: list[list[str]] = []
    if shutil.which("wl-copy"):
        candidates.append(["wl-copy"])
    if shutil.which("xclip"):
        candidates.append(["xclip", "-selection", "clipboard"])
    if shutil.which("xsel"):
        candidates.append(["xsel", "--clipboard", "--input"])
    if shutil.which("pbcopy"):
        candidates.append(["pbcopy"])
    if shutil.which("clip"):
        candidates.append(["clip"])
    for cmd in candidates:
        try:
            subprocess.run(cmd, input=text.encode(), check=True, timeout=2)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def open_github(url: str) -> bool:
    import webbrowser

    return webbrowser.open(url)


def watch_loop(
    hosts: list[str],
    ports: list[int],
    interval: float,
    timeout: float,
    workers: int,
    show_services: bool,
    measure_latency: bool,
    no_color: bool,
) -> None:
    prev_states: dict[tuple[str, int], str] = {}
    try:
        while True:
            results = scan_hosts(
                hosts=hosts,
                ports=ports,
                timeout=timeout,
                workers=workers,
                measure_latency=measure_latency,
                grab_banner=False,
            )
            os.system("clear" if os.name != "nt" else "cls")
            ts = time.strftime("%H:%M:%S")
            print(f"portpeek watch @ {ts} (every {interval}s) — Ctrl+C to stop\n")
            for r in results:
                key = (r["host"], r["port"])
                curr = r["status"]
                prev = prev_states.get(key)
                change = ""
                if prev is not None and prev != curr:
                    change = f"  <-- CHANGED ({prev} -> {curr})"
                prev_states[key] = curr
                tag = "[IN USE]" if curr == "open" else "[FREE]  "
                svc = f" ({r['service']})" if show_services else ""
                lat = f" [{r['latency_ms']} ms]" if "latency_ms" in r else ""
                print(f"{tag} {r['host']}:{r['port']}{svc}{lat}{change}")
            time.sleep(max(0.2, interval))
    except KeyboardInterrupt:
        print("\nWatch stopped.")


def parse_freeport_spec(spec: str | None) -> tuple[int, int]:
    """Parse RANGE (3000-3999) or COUNT (starting at 3000 for N ports of search window)."""
    from .constants import DEFAULT_FREEPORT_RANGE

    raw = (spec or DEFAULT_FREEPORT_RANGE).strip()
    if "-" in raw:
        ports = parse_ports([raw])
        if not ports:
            raise ValueError(f"Invalid freeport range: '{raw}'")
        return ports[0], ports[-1]
    if raw.isdigit():
        # Interpret as count of ports to search starting at 3000
        count = int(raw)
        if count < 1:
            raise ValueError("COUNT must be >= 1")
        start = 3000
        end = min(65535, start + max(count, 1000) - 1)
        return start, end
    raise ValueError(f"Invalid freeport spec: '{raw}' (use RANGE like 3000-3999)")
