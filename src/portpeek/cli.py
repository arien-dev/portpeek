__version__ = "0.2.0"

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import socket
import sys
from typing import Any


def parse_ports(raw_items: list[str]) -> list[int]:
    """Parse single ports and 'start-end' ranges into a deduplicated list of ints."""
    ports: list[int] = []
    seen: set[int] = set()

    for item in raw_items:
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


def check_port(host: str, port: int, timeout: float = 0.25) -> dict[str, Any]:
    """Check a single TCP port and return a structured result dictionary."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        is_open = sock.connect_ex((host, port)) == 0

    return {
        "host": host,
        "port": port,
        "status": "open" if is_open else "free",
        "service": service_name(port),
    }


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 0.25,
    workers: int = 32,
) -> list[dict[str, Any]]:
    """Scan ports concurrently while preserving original port order."""
    results_by_port: dict[int, dict[str, Any]] = {}
    max_workers = max(1, min(workers, len(ports)))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            res = future.result()
            results_by_port[res["port"]] = res

    return [results_by_port[p] for p in ports]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="Fast TCP port & range checker for local and remote hosts.",
    )
    parser.add_argument(
        "ports",
        nargs="+",
        help="Port numbers or ranges (e.g. 80 443 3000-3010)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.25,
        help="Connection timeout per port in seconds (default: 0.25)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Number of concurrent worker threads (default: 32)",
    )
    parser.add_argument(
        "--services",
        action="store_true",
        help="Show known TCP service names next to ports",
    )
    parser.add_argument(
        "--find-free",
        action="store_true",
        help="Print the first free port from the given list/range and exit",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress output and only return exit status (0=all free, 1=any open)",
    )

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "--only-open",
        action="store_true",
        help="Only include open (in-use) ports",
    )
    filter_group.add_argument(
        "--only-free",
        action="store_true",
        help="Only include free ports",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    results = scan_ports(args.host, ports, timeout=args.timeout, workers=args.workers)

    if args.find_free:
        for item in results:
            if item["status"] == "free":
                if not args.quiet:
                    if args.json:
                        print(json.dumps(item, indent=2))
                    else:
                        print(item["port"])
                sys.exit(0)
        if not args.quiet:
            print("No free port found in selection.", file=sys.stderr)
        sys.exit(1)

    filtered = results
    if args.only_open:
        filtered = [r for r in results if r["status"] == "open"]
    elif args.only_free:
        filtered = [r for r in results if r["status"] == "free"]

    any_open = any(r["status"] == "open" for r in results)

    if not args.quiet:
        if args.json:
            print(json.dumps(filtered, indent=2))
        else:
            for r in filtered:
                tag = "[IN USE]" if r["status"] == "open" else "[FREE]  "
                svc = f" ({r['service']})" if args.services else ""
                print(f"{tag} {r['host']}:{r['port']}{svc}")

    sys.exit(1 if any_open else 0)


if __name__ == "__main__":
    main()
