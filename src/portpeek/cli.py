import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
import os
import socket
import sys
import termios
import time
import tty
from typing import Any

ASCII_BANNER = r"""
 ____   ___  ____ _____ ____  _____ _____ _  __
|  _ \ / _ \|  _ \_   _|  _ \| ____| ____| |/ /
| |_) | | | | |_) || | | |_) |  _| |  _| | ' / 
|  __/| |_| |  _ < | | |  __/| |___| |___| . \ 
|_|    \___/|_| \_\|_| |_|   |_____|_____|_|\_\
"""

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_DIM = "\033[2m"


def parse_ports(raw_items: list[str]) -> list[int]:
    """Parse single ports, comma lists, and 'start-end' ranges into deduplicated ints."""
    ports: list[int] = []
    seen: set[int] = set()

    tokens: list[str] = []
    for raw in raw_items:
        for part in raw.split(","):
            token = part.strip()
            if token:
                tokens.append(token)

    for item in tokens:
        if "-" in item:
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


def service_name(port: int) -> str:
    """Return standard IANA service name for a TCP port if known."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def _grab_banner(sock: socket.socket, port: int) -> str | None:
    """Best-effort lightweight banner grab without hanging."""
    try:
        sock.settimeout(0.35)
        if port in (80, 8080, 8000, 3000, 5173):
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
    """Check a single TCP port using getaddrinfo (IPv4/IPv6) and return a result dict."""
    start_time = time.perf_counter()
    is_open = False
    banner: str | None = None

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
    except OSError:
        is_open = False

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
    return result


def scan_target(
    host: str,
    ports: list[int],
    timeout: float = 0.25,
    workers: int = 64,
    measure_latency: bool = False,
    grab_banner: bool = False,
) -> list[dict[str, Any]]:
    """Scan all given ports on a single host while preserving port order."""
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
    """Scan ports across one or more hosts."""
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
    """Find a contiguous sequence of `block_size` free ports in `ports` order."""
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


def export_results(path: str, rows: list[dict[str, Any]]) -> None:
    """Export scan rows to .json or .csv based on file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        fieldnames = ["host", "port", "status", "service", "latency_ms", "banner"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)


def _use_color(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def print_results(
    results: list[dict[str, Any]],
    show_services: bool = False,
    no_color: bool = False,
) -> None:
    color = _use_color(no_color)
    for r in results:
        is_open = r["status"] == "open"
        if is_open:
            tag = f"{ANSI_RED}[IN USE]{ANSI_RESET}" if color else "[IN USE]"
        else:
            tag = f"{ANSI_GREEN}[FREE]  {ANSI_RESET}" if color else "[FREE]  "

        svc = f" ({r['service']})" if show_services else ""
        lat = f" [{r['latency_ms']} ms]" if "latency_ms" in r else ""
        banner = f" {ANSI_DIM}| {r['banner']}{ANSI_RESET}" if r.get("banner") and r["banner"] != "-" else ""
        print(f"{tag} {r['host']}:{r['port']}{svc}{lat}{banner}")


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
    """Continuously monitor ports and highlight state transitions."""
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
            os.system("clear")
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


def _read_key() -> str:
    """Read a single keypress or escape sequence (up/down arrows)."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            seq = sys.stdin.read(2)
            if seq == "[A":
                return "UP"
            if seq == "[B":
                return "DOWN"
            return "ESC"
        if ch in ("\r", "\n"):
            return "ENTER"
        if ch in ("k", "K"):
            return "UP"
        if ch in ("j", "J"):
            return "DOWN"
        if ch in ("q", "Q", "\x03"):
            return "QUIT"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def select_option(title: str, subtitle: str, options: list[tuple[str, str]]) -> int | None:
    """Render ASCII header + interactive up/down selector. Returns selected index or None."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print(ASCII_BANNER)
        print(f"{title} — {subtitle}")
        for idx, (label, desc) in enumerate(options, start=1):
            print(f"  [{idx}] {label} ({desc})")
        choice = input("Select number (or q): ").strip().lower()
        if choice == "q" or not choice.isdigit():
            return None
        num = int(choice) - 1
        return num if 0 <= num < len(options) else None

    selected = 0
    while True:
        os.system("clear")
        print(ASCII_BANNER.strip("\n"))
        print(f"  {title}")
        print(f"  {subtitle}")
        print("  Use [↑/↓] or [j/k] to move, [Enter] to select, [q] to quit\n")

        for idx, (label, desc) in enumerate(options):
            cursor = "›" if idx == selected else " "
            line = f"  {cursor} {label:<28} {desc}"
            if idx == selected:
                print(f"\033[7m{line}\033[0m")
            else:
                print(line)

        key = _read_key()
        if key == "UP":
            selected = (selected - 1) % len(options)
        elif key == "DOWN":
            selected = (selected + 1) % len(options)
        elif key == "ENTER":
            return selected
        elif key in ("QUIT", "ESC"):
            return None


def run_menu() -> None:
    presets = [
        ("Common Web & Dev Ports", "80, 443, 3000, 5173, 8000, 8080", "127.0.0.1", "80,443,3000,5173,8000,8080"),
        ("Databases & Cache", "5432, 3306, 6379, 27017", "127.0.0.1", "5432,3306,6379,27017"),
        ("Find First Free Dev Port", "3000-3050", "127.0.0.1", "3000-3050"),
        ("Find Contiguous Free Block", "3 ports in 4000-4100", "127.0.0.1", "4000-4100"),
        ("Watch Ports Live", "Live status transitions", "127.0.0.1", "3000,8080"),
        ("Custom Host & Ports", "Interactive prompt", "", ""),
    ]

    while True:
        menu_items = [(p[0], p[1]) for p in presets] + [("Exit", "Quit portpeek menu")]
        idx = select_option("PORTPEEK INTERACTIVE MENU", "Quick TCP Port Inspector", menu_items)
        if idx is None or idx == len(presets):
            os.system("clear")
            return

        title, _, default_host, default_ports = presets[idx]
        os.system("clear")
        print(f"=== {title} ===\n")

        if idx == 5:
            host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
            raw_ports = input("Ports/Ranges (e.g. 80,443,8000-8010): ").strip()
            if not raw_ports:
                print("No ports entered.")
                input("\nPress Enter to continue...")
                continue
        else:
            host = input(f"Host [{default_host}]: ").strip() or default_host
            raw_ports = input(f"Ports [{default_ports}]: ").strip() or default_ports

        try:
            ports = parse_ports([raw_ports])
        except ValueError as exc:
            print(f"\nError: {exc}")
            input("\nPress Enter to continue...")
            continue

        if idx == 2:
            results = scan_target(host, ports)
            free_port = next((r["port"] for r in results if r["status"] == "free"), None)
            print(f"\nFirst free port on {host}: {free_port}" if free_port else "\nNo free port found.")
        elif idx == 3:
            raw_size = input("Block size [3]: ").strip() or "3"
            size = int(raw_size) if raw_size.isdigit() and int(raw_size) > 0 else 3
            results = scan_target(host, ports)
            block = find_free_block(ports, results, size)
            print(f"\nFree block ({size} ports): {block}" if block else f"\nNo {size}-port free block found.")
        elif idx == 4:
            raw_int = input("Interval in seconds [1.5]: ").strip() or "1.5"
            try:
                interval = float(raw_int)
            except ValueError:
                interval = 1.5
            watch_loop([host], ports, interval, 0.25, 64, True, True, False)
        else:
            print(f"\nScanning {host} ({len(ports)} port(s))...\n")
            results = scan_target(host, ports, measure_latency=True, grab_banner=True)
            print_results(results, show_services=True)

        input("\nPress Enter to return to menu...")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="Fast TCP port & range checker for local and remote hosts.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("menu", help="Launch interactive ASCII menu with arrow-key navigation")

    scan_parser = argparse.ArgumentParser(add_help=False)
    scan_parser.add_argument("ports", nargs="+", help="Port numbers or ranges (e.g. 80 443 3000-3010)")
    scan_parser.add_argument("--host", nargs="+", default=["127.0.0.1"], help="One or more target hosts")
    scan_parser.add_argument("--timeout", type=float, default=0.25, help="Connection timeout per port in seconds")
    scan_parser.add_argument("--workers", type=int, default=64, help="Number of concurrent worker threads")
    scan_parser.add_argument("--services", action="store_true", help="Show known TCP service names")
    scan_parser.add_argument("--latency", action="store_true", help="Measure connection time in ms")
    scan_parser.add_argument("--banner", action="store_true", help="Grab short response banner from open ports")
    scan_parser.add_argument("--find-free", action="store_true", help="Print first free port and exit")
    scan_parser.add_argument("--block", type=int, default=0, help="Find N contiguous free ports and exit")
    scan_parser.add_argument("--watch", nargs="?", const=1.5, type=float, metavar="SEC", help="Watch ports continuously")
    scan_parser.add_argument("-o", "--output", help="Export results to .json or .csv file")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress output and return exit status only")

    filter_group = scan_parser.add_mutually_exclusive_group()
    filter_group.add_argument("--only-open", action="store_true", help="Only include open (in-use) ports")
    filter_group.add_argument("--only-free", action="store_true", help="Only include free ports")

    for action in scan_parser._actions:
        if action.dest != "help":
            parser._add_action(action)

    return parser


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "menu":
        run_menu()
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        if args.block < 0:
            raise ValueError("--block must be greater than 0")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.watch is not None:
        watch_loop(
            hosts=args.host,
            ports=ports,
            interval=args.watch,
            timeout=args.timeout,
            workers=args.workers,
            show_services=args.services,
            measure_latency=args.latency,
            no_color=args.no_color,
        )
        sys.exit(0)

    results = scan_hosts(
        hosts=args.host,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        measure_latency=args.latency,
        grab_banner=args.banner,
    )

    if args.block > 0:
        for h in args.host:
            host_res = [r for r in results if r["host"] == h]
            block = find_free_block(ports, host_res, args.block)
            if block:
                if not args.quiet:
                    print(json.dumps({"host": h, "ports": block}) if args.json else " ".join(map(str, block)))
                sys.exit(0)
        if not args.quiet:
            print(f"No contiguous block of {args.block} free ports found.", file=sys.stderr)
        sys.exit(1)

    if args.find_free:
        for item in results:
            if item["status"] == "free":
                if not args.quiet:
                    print(json.dumps(item, indent=2) if args.json else item["port"])
                sys.exit(0)
        if not args.quiet:
            print("No free port found in selection.", file=sys.stderr)
        sys.exit(1)

    filtered = results
    if args.only_open:
        filtered = [r for r in results if r["status"] == "open"]
    elif args.only_free:
        filtered = [r for r in results if r["status"] == "free"]

    if args.output:
        export_results(args.output, filtered)

    any_open = any(r["status"] == "open" for r in results)

    if not args.quiet:
        if args.json:
            print(json.dumps(filtered, indent=2))
        else:
            print_results(filtered, show_services=args.services, no_color=args.no_color)

    sys.exit(1 if any_open else 0)


if __name__ == "__main__":
    main()
