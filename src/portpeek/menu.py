"""Interactive ASCII menu with arrow-key navigation."""

from __future__ import annotations

import os
import sys
import termios
import tty
import webbrowser
from typing import Any, Callable

from . import __version__
from .constants import (
    ANSI_BOLD,
    ANSI_CYAN,
    ANSI_DIM,
    ANSI_GREEN,
    ANSI_RESET,
    ASCII_BANNER,
    AUTHOR_LINE,
    GITHUB_URL,
    PRESETS,
)
from .core import (
    export_results,
    find_free_port_local,
    normalize_output_path,
    parse_ports,
    print_results,
    scan_target,
    use_color,
    watch_loop,
)
from .doctor import diagnose, format_doctor, parse_endpoint
from .local import format_list_table, format_who, kill_pid, list_listening, who_port


def _read_key() -> str:
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
        if ch in ("g", "G"):
            return "GITHUB"
        if ch in ("q", "Q", "\x03"):
            return "QUIT"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def _paint(text: str, *codes: str, on: bool) -> str:
    if not on or not codes:
        return text
    return f"{''.join(codes)}{text}{ANSI_RESET}"


def _render_header(title: str, subtitle: str, *, color: bool) -> None:
    """ASCII logo, breathing room, then author / title block."""
    for line in ASCII_BANNER.strip("\n").splitlines():
        print(_paint(line, ANSI_BOLD, ANSI_CYAN, on=color))

    # Extra air between logo and copy
    print()
    print()

    print(f"  {_paint(AUTHOR_LINE, ANSI_DIM, on=color)}")
    print(f"  {_paint(f'v{__version__}', ANSI_DIM, on=color)}")
    print()
    print(f"  {_paint(title, ANSI_BOLD, on=color)}")
    print(f"  {_paint(subtitle, ANSI_DIM, on=color)}")
    print()
    hints = "[↑/↓] [j/k] move   [Enter] select   [g] GitHub   [q]/[Esc] quit"
    print(f"  {_paint(hints, ANSI_DIM, on=color)}")
    print()


def select_option(title: str, subtitle: str, options: list[tuple[str, str]]) -> int | None:
    """Render ASCII header + interactive selector. Returns index or None."""
    color = use_color(False)

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        _render_header(title, subtitle, color=False)
        for idx, (label, desc) in enumerate(options, start=1):
            print(f"  [{idx}] {label}  —  {desc}")
        choice = input("Select number (or q): ").strip().lower()
        if choice == "q" or not choice.isdigit():
            return None
        num = int(choice) - 1
        return num if 0 <= num < len(options) else None

    selected = 0
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        _render_header(title, subtitle, color=color)

        for idx, (label, desc) in enumerate(options):
            num = f"{idx + 1:>2}."
            if idx == selected:
                cursor = _paint("›", ANSI_BOLD, ANSI_GREEN, on=color)
                label_s = _paint(f"{label:<34}", ANSI_BOLD, ANSI_GREEN, on=color)
                desc_s = _paint(desc, ANSI_DIM, on=color)
                num_s = _paint(num, ANSI_GREEN, on=color)
                print(f"  {cursor} {num_s} {label_s}  {desc_s}")
            else:
                cursor = " "
                num_s = _paint(num, ANSI_DIM, on=color)
                desc_s = _paint(desc, ANSI_DIM, on=color)
                print(f"  {cursor} {num_s} {label:<34}  {desc_s}")

        print()
        key = _read_key()
        if key == "UP":
            selected = (selected - 1) % len(options)
        elif key == "DOWN":
            selected = (selected + 1) % len(options)
        elif key == "ENTER":
            return selected
        elif key == "GITHUB":
            webbrowser.open(GITHUB_URL)
            print(f"\n  {_paint(f'Opened {GITHUB_URL}', ANSI_CYAN, on=color)}")
            input("  Press Enter to continue...")
        elif key in ("QUIT", "ESC"):
            return None


def _offer_export(rows: list[dict[str, Any]]) -> None:
    if not rows:
        input("\nPress Enter to return to menu...")
        return
    ans = input("\nExport results? [json/csv/md/txt/n]: ").strip().lower()
    if ans in ("", "n", "no"):
        input("\nPress Enter to return to menu...")
        return
    ext = ans if ans in ("json", "csv", "md", "txt", "jsonl") else "json"
    path = normalize_output_path(ext) or f"portpeek-export.{ext}"
    written = export_results(path, rows, include_meta=True)
    print(f"Wrote {written}")
    input("\nPress Enter to return to menu...")


def run_menu() -> None:
    items = [
        ("Active Local Ports", "what's listening right now", _menu_list),
        ("Who is using Port X?", "process info · optional kill", _menu_who),
        ("Deep Port Doctor", "DNS · TCP · TLS · HTTP", _menu_doctor),
        ("Common Web & Dev Ports", "80, 443, 3000, 5173, 8000, 8080", _menu_web),
        ("Databases & Cache", "5432, 3306, 6379, 27017", _menu_db),
        ("Find Free Port / Block", "next free port or contiguous block", _menu_freeport),
        ("Live Watch Ports", "monitor status transitions", _menu_watch),
        ("Custom Host / Range Scan", "host, CIDR, or port range", _menu_custom),
        ("Open GitHub Repository", "arien-dev/portpeek", _menu_github),
        ("Exit", "quit menu", None),
    ]

    while True:
        menu_items = [(label, desc) for label, desc, _ in items]
        idx = select_option(
            "Interactive Menu",
            "port · process · TLS · network inspector",
            menu_items,
        )
        if idx is None or items[idx][2] is None:
            os.system("clear" if os.name != "nt" else "cls")
            return
        os.system("clear" if os.name != "nt" else "cls")
        print(f"=== {items[idx][0]} ===\n")
        handler: Callable[[], None] = items[idx][2]  # type: ignore[assignment]
        try:
            handler()
        except (ValueError, OSError, KeyboardInterrupt) as exc:
            if isinstance(exc, KeyboardInterrupt):
                print("\nCancelled.")
            else:
                print(f"\nError: {exc}")
            input("\nPress Enter to continue...")


def _menu_list() -> None:
    rows = list_listening()
    print(format_list_table(rows))
    _offer_export(rows)


def _menu_who() -> None:
    raw = input("Port number: ").strip()
    if not raw.isdigit():
        print("Invalid port.")
        input("\nPress Enter to continue...")
        return
    port = int(raw)
    rows = who_port(port)
    print(format_who(rows))
    if rows and rows[0].get("pid"):
        ans = input("\nKill process? [y/N]: ").strip().lower()
        if ans == "y":
            confirm = input("Type YES to send SIGTERM: ").strip()
            if confirm == "YES":
                ok, msg = kill_pid(int(rows[0]["pid"]), yes=True)
                print(msg if ok else f"Failed: {msg}")
    _offer_export(rows)


def _menu_doctor() -> None:
    raw = input("Target HOST:PORT (e. and example.com:443): ").strip()
    try:
        host, port = parse_endpoint(raw)
    except ValueError as exc:
        print(exc)
        input("\nPress Enter to continue...")
        return
    report = diagnose(host, port)
    print(format_doctor(report))
    _offer_export([report])


def _menu_web() -> None:
    host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
    ports = PRESETS["dev"][:3] + PRESETS["web"]
    # unique preserve order
    seen: set[int] = set()
    plist = []
    for p in [80, 443, 3000, 5173, 8000, 8080]:
        if p not in seen:
            seen.add(p)
            plist.append(p)
    results = scan_target(host, plist, measure_latency=True, grab_banner=True)
    print_results(results, show_services=True)
    _offer_export(results)


def _menu_db() -> None:
    host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
    results = scan_target(host, PRESETS["db"], measure_latency=True)
    print_results(results, show_services=True)
    _offer_export(results)


def _menu_freeport() -> None:
    raw = input("Range [3000-3999]: ").strip() or "3000-3999"
    block_s = input("Contiguous block size [1]: ").strip() or "1"
    ports = parse_ports([raw])
    block = int(block_s) if block_s.isdigit() and int(block_s) > 0 else 1
    found = find_free_port_local(ports[0], ports[-1], block=block)
    if found:
        print(" ".join(map(str, found)) if block > 1 else str(found[0]))
        _offer_export([{"ports": found, "block": block}])
    else:
        print(f"No free {'block of ' + str(block) if block > 1 else 'port'} in {raw}.")
        input("\nPress Enter to continue...")


def _menu_watch() -> None:
    host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
    raw = input("Ports [3000,8080]: ").strip() or "3000,8080"
    ports = parse_ports([raw])
    interval_s = input("Interval seconds [1.5]: ").strip() or "1.5"
    try:
        interval = float(interval_s)
    except ValueError:
        interval = 1.5
    watch_loop([host], ports, interval, 0.25, 64, True, True, False)
    input("\nPress Enter to return to menu...")


def _menu_custom() -> None:
    host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
    raw = input("Ports/Ranges (e.g. 80,443,8000-8010): ").strip()
    if not raw:
        print("No ports entered.")
        input("\nPress Enter to continue...")
        return
    ports = parse_ports([raw])
    print(f"\nScanning {host} ({len(ports)} port(s))...\n")
    results = scan_target(host, ports, measure_latency=True, grab_banner=True)
    print_results(results, show_services=True)
    _offer_export(results)


def _menu_github() -> None:
    print(f"portpeek v{__version__}")
    print(GITHUB_URL)
    webbrowser.open(GITHUB_URL)
    print("Opened in browser.")
    input("\nPress Enter to continue...")
