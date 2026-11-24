"""portpeek CLI entrypoint — ultra-fast port, process, TLS & network inspector."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from typing import Any, Sequence

from . import __version__
from .constants import (
    ANSI_BOLD,
    ANSI_CYAN,
    ANSI_DIM,
    ANSI_GREEN,
    ANSI_RESET,
    ANSI_YELLOW,
    ASCII_BANNER,
    AUTHOR_LINE_HELP,
    DEFAULT_FREEPORT_RANGE,
    GITHUB_URL,
    PRESETS,
)
from .core import (
    copy_to_clipboard,
    export_results,
    find_free_block,
    find_free_port_local,
    normalize_output_path,
    parse_freeport_spec,
    parse_ports,
    print_results,
    print_summary,
    resolve_hosts_and_ports,
    scan_hosts,
    use_color,
    watch_loop,
)
from .doctor import (
    diagnose,
    diff_hosts,
    format_diff,
    format_doctor,
    parse_endpoint,
    tcp_ping,
)
from .local import (
    enrich_scan_with_proc,
    format_list_table,
    format_who,
    kill_pid,
    list_listening,
    who_port,
)
from .menu import run_menu

SUBCOMMANDS = frozenset(
    {
        "menu",
        "freeport",
        "who",
        "pid",
        "list",
        "ls",
        "doctor",
        "check",
        "diff",
        "ping",
        "repo",
        "github",
        "help",
    }
)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------


def _c(text: str, *codes: str, on: bool) -> str:
    if not on or not codes:
        return text
    return f"{''.join(codes)}{text}{ANSI_RESET}"


def format_help_text(*, color: bool | None = None) -> str:
    """Build the main help screen; light accent colors when stdout is a TTY."""
    on = use_color(False) if color is None else color

    def banner() -> str:
        lines = ASCII_BANNER.strip("\n").splitlines()
        return "\n".join(_c(line, ANSI_BOLD, ANSI_CYAN, on=on) for line in lines)

    def head(title: str) -> str:
        return _c(title, ANSI_BOLD, ANSI_CYAN, on=on)

    def cmd(name: str, width: int = 26) -> str:
        return _c(name.ljust(width), ANSI_BOLD, ANSI_GREEN, on=on)

    def flag(name: str, width: int = 26) -> str:
        return _c(name.ljust(width), ANSI_YELLOW, on=on)

    def dim(text: str) -> str:
        return _c(text, ANSI_DIM, on=on)

    def comment(text: str) -> str:
        return _c(text, ANSI_DIM, on=on)

    subcommands = [
        ("freeport [RANGE|COUNT]", "Next free port (default 3000-3999); ideal for PORT=$(…)"),
        ("who|pid <PORT>", "Which process owns a local port (optional --kill)"),
        ("list|ls", "Table of local listening TCP/UDP ports"),
        ("doctor|check <HOST:PORT>", "DNS + TCP latency + TLS cert + HTTP headers"),
        ("diff <A> <B> [PORTS]", "Compare open/free ports across two hosts"),
        ("ping <HOST:PORT>", "Continuous TCP latency (ICMP-free)"),
        ("menu", "Interactive ASCII menu (↑/↓ · j/k · g=GitHub)"),
        ("repo|github", "Open GitHub repo in your browser"),
    ]

    target_opts = [
        ("ports", "Port numbers, lists, ranges  (80 443 3000-3010)"),
        ("HOST:PORT", "Direct target as positional  (127.0.0.1:3000)"),
        ("--host HOST [HOST…]", "One or more hosts            (default: 127.0.0.1)"),
        ("--host-file FILE", "Hosts file (one per line)"),
        ("--cidr CIDR", "Expand subnet (max 4096 hosts)"),
        ("--preset NAME", "common | web | db | dev"),
    ]
    inspect_opts = [
        ("--services", "Show IANA TCP service names"),
        ("--latency", "Measure connect time (ms)"),
        ("--banner", "Grab short banner from open ports"),
        ("--proc", "Attach local PID / process / Docker info"),
        ("--timeout SEC", "Per-port connect timeout     (default: 0.25)"),
        ("--workers N", "Concurrent worker threads    (default: 64)"),
        ("--summary", "Print open/free totals"),
        ("--tls", "Force TLS checks (doctor)"),
    ]
    free_opts = [
        ("--find-free", "Print first free port and exit"),
        ("--block N", "Find N contiguous free ports"),
        ("--watch [SEC]", "Live status monitor          (default interval: 1.5)"),
    ]
    filter_opts = [
        ("--only-open / --only-free", ""),
        ("--max-latency MS", "Keep results at or below latency"),
        ("--dev-only / --public / --search NAME", "(list)"),
        ("-o, --output [PATH|EXT]", "Export .json .jsonl .csv .md .txt"),
        ("--include-meta", "Add timestamp / tool meta to export"),
        ("--json", "Print JSON to stdout"),
        ("--quiet", "Exit status only"),
        ("--no-color", "Disable ANSI colors"),
        ("-V, --version", "Show version and exit"),
    ]

    examples = [
        ("# Is my dev server port free?", ["portpeek 3000"]),
        ("# Classic multi-port scan with service names", ["portpeek 80 443 --services"]),
        ("# HOST:PORT shorthand", ["portpeek example.com:443 --latency --banner"]),
        (
            "# Shell-friendly free port",
            ["PORT=$(portpeek freeport)", "PORT=$(portpeek freeport 4000-4100 --block 3 --copy)"],
        ),
        ("# Who is blocking me?", ["portpeek who 5432", "portpeek who 3000 --kill --yes"]),
        (
            "# What's listening locally (and dangerously public)?",
            ["portpeek list --public", "portpeek ls --dev-only --search node"],
        ),
        (
            "# One-shot deep diagnose instead of curl/openssl/wireshark",
            ["portpeek doctor example.com:443", "portpeek check 127.0.0.1:8080"],
        ),
        ("# Staging vs local", ["portpeek diff localhost staging.example.com web"]),
        ("# TCP ping when ICMP is blocked", ["portpeek ping db.internal:5432 -c 5"]),
        (
            "# Presets, watch, export",
            [
                "portpeek --preset db --proc --summary",
                "portpeek 3000,8080 --watch 1",
                "portpeek --preset web -o report.md --include-meta",
            ],
        ),
        ("# Interactive menu", ["portpeek menu"]),
    ]

    lines: list[str] = [
        banner(),
        f"  {_c('Fast port · process · TLS · network inspector for developers', ANSI_DIM, on=on)}",
        f"  {_c(AUTHOR_LINE_HELP, ANSI_DIM, on=on)}",
        f"  {_c(f'version {__version__}', ANSI_DIM, on=on)}",
        "",
        head("USAGE"),
        f"  {_c('portpeek', ANSI_GREEN, on=on)} <ports…> [options]",
        f"  {_c('portpeek', ANSI_GREEN, on=on)} <HOST:PORT> [options]",
        f"  {_c('portpeek', ANSI_GREEN, on=on)} <subcommand> [args] [options]",
        "",
        head("QUICK SUBCOMMANDS"),
    ]
    for name, desc in subcommands:
        lines.append(f"  {cmd(name)}{dim(desc)}")

    lines += ["", head("TARGETS & PRESETS")]
    for name, desc in target_opts:
        lines.append(f"  {flag(name)}{dim(desc)}" if desc else f"  {flag(name).rstrip()}")

    lines += ["", head("INSPECTION & DIAGNOSTICS")]
    for name, desc in inspect_opts:
        lines.append(f"  {flag(name)}{dim(desc)}")

    lines += ["", head("FREE PORT & WATCH")]
    for name, desc in free_opts:
        lines.append(f"  {flag(name)}{dim(desc)}")

    lines += ["", head("FILTERING & EXPORT")]
    for name, desc in filter_opts:
        if desc:
            lines.append(f"  {flag(name, 40)}{dim(desc)}")
        else:
            lines.append(f"  {flag(name, 40).rstrip()}")

    lines += ["", head("EXAMPLES")]
    for note, cmds in examples:
        lines.append(f"  {comment(note)}")
        for c_line in cmds:
            # Highlight leading portpeek / PORT=$(portpeek …) lightly
            if c_line.startswith("PORT=$("):
                lines.append(f"  {c_line}")
            elif c_line.startswith("portpeek "):
                rest = c_line[len("portpeek") :]
                lines.append(f"  {_c('portpeek', ANSI_GREEN, on=on)}{rest}")
            else:
                lines.append(f"  {c_line}")
        lines.append("")

    lines.append(
        dim("Run `portpeek <subcommand> --help` for subcommand-specific options.")
    )
    return "\n".join(lines)


# Back-compat alias for anything importing HELP_TEXT
HELP_TEXT = format_help_text(color=False)


class _HelpAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):  # noqa: ANN001
        print(format_help_text())
        parser.exit(0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="Fast port · process · TLS · network inspector for developers.",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action=_HelpAction, nargs=0, help=argparse.SUPPRESS)
    parser.add_argument("-V", "--version", action="version", version=f"portpeek {__version__}")

    # Shared scan / global options (also work with bare port syntax)
    parser.add_argument("targets", nargs="*", help=argparse.SUPPRESS)
    parser.add_argument("--host", nargs="+", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--host-file", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--cidr", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--preset", choices=sorted(PRESETS.keys()), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=0.25, help=argparse.SUPPRESS)
    parser.add_argument("--workers", type=int, default=64, help=argparse.SUPPRESS)
    parser.add_argument("--services", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--latency", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--banner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--proc", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--find-free", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--block", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--watch", nargs="?", const=1.5, type=float, metavar="SEC", help=argparse.SUPPRESS)
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--include-meta", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--summary", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--max-latency", type=float, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--tls", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--copy", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--kill", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--yes", "-y", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dev-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--public", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--search", default=None, help=argparse.SUPPRESS)
    parser.add_argument("-c", "--count", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--interval", type=float, default=1.0, help=argparse.SUPPRESS)

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("--only-open", action="store_true", help=argparse.SUPPRESS)
    filter_group.add_argument("--only-free", action="store_true", help=argparse.SUPPRESS)

    return parser


def _subcommand_help(name: str) -> str:
    helps = {
        "freeport": """usage: portpeek freeport [RANGE|COUNT] [--block N] [--copy] [--json] [--quiet]

Find the next free TCP port (default range 3000-3999).
Prints only the port number — perfect for PORT=$(portpeek freeport).

  --block N    Require N contiguous free ports (prints space-separated list)
  --copy       Copy result to clipboard (wl-copy / xclip / pbcopy / clip)
""",
        "who": """usage: portpeek who|pid <PORT> [--kill [--yes] [--force]] [--json]

Show which local process owns PORT (PID, user, cmdline, bind, uptime, Docker).

  --kill       Send SIGTERM (or SIGKILL with --force); requires --yes or prompt
  --yes / -y   Skip confirmation
  --force      Use SIGKILL instead of SIGTERM
""",
        "list": """usage: portpeek list|ls [--dev-only] [--public] [--search NAME] [--json] [-o FILE]

List local listening TCP & UDP ports as a table.

  --dev-only   Ports >= 1024 only
  --public     Only 0.0.0.0 / :: bindings (network-reachable!)
  --search S   Filter by process / command / user substring
""",
        "doctor": """usage: portpeek doctor|check <HOST:PORT|HOST PORT> [--tls] [--timeout SEC] [--json]

Deep one-shot diagnose: DNS, TCP latency (3 probes), TLS cert, HTTP headers,
plus a plain-English diagnosis line.
""",
        "diff": """usage: portpeek diff <HOST_A> <HOST_B> [PORTS|PRESET]

Compare two hosts side-by-side: ONLY ON A / ONLY ON B / BOTH OPEN / BOTH FREE.
PORTS may be ranges or a preset name (web, db, dev, common).
""",
        "ping": """usage: portpeek ping <HOST:PORT> [-c COUNT] [--interval SEC] [--timeout SEC]

TCP ping with live latency, min/avg/max/jitter. Exit 0 if any probe succeeded.
""",
        "menu": "usage: portpeek menu\n\nLaunch the interactive ASCII menu.\n",
        "repo": f"usage: portpeek repo|github\n\nOpen {GITHUB_URL} and print version.\n",
    }
    key = {
        "pid": "who",
        "ls": "list",
        "check": "doctor",
        "github": "repo",
    }.get(name, name)
    return helps.get(key, format_help_text())


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_freeport(args: argparse.Namespace) -> int:
    spec = args.targets[0] if args.targets else DEFAULT_FREEPORT_RANGE
    start, end = parse_freeport_spec(spec)
    block = args.block if args.block and args.block > 0 else 1
    found = find_free_port_local(start, end, block=block)
    if not found:
        # Fall back to connect-scan based finder
        ports = list(range(start, end + 1))
        results = scan_hosts(["127.0.0.1"], ports, timeout=min(args.timeout, 0.15), workers=args.workers)
        found = find_free_block(ports, results, block)
    if not found:
        if not args.quiet:
            print(f"No free {'block of ' + str(block) if block > 1 else 'port'} in {start}-{end}.", file=sys.stderr)
        return 1
    if args.json:
        if not args.quiet:
            print(json.dumps({"ports": found} if block > 1 else {"port": found[0]}))
    elif not args.quiet:
        text = " ".join(map(str, found)) if block > 1 else str(found[0])
        print(text)
        if args.copy:
            if copy_to_clipboard(text):
                print("copied to clipboard", file=sys.stderr)
            else:
                print("clipboard tool not found", file=sys.stderr)
    return 0


def cmd_who(args: argparse.Namespace) -> int:
    if not args.targets:
        print("Error: port required — portpeek who <PORT>", file=sys.stderr)
        return 2
    try:
        port = parse_ports([args.targets[0]])[0]
    except (ValueError, IndexError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    rows = who_port(port)
    if args.kill:
        if not rows or not rows[0].get("pid"):
            if not args.quiet:
                print(f"Nothing listening on port {port}.", file=sys.stderr)
            return 1
        pid = int(rows[0]["pid"])
        yes = args.yes
        if not yes and sys.stdin.isatty():
            confirm = input(f"Send {'SIGKILL' if args.force else 'SIGTERM'} to pid {pid}? [y/N]: ").strip().lower()
            yes = confirm in ("y", "yes")
        ok, msg = kill_pid(pid, force=args.force, yes=yes)
        if not args.quiet:
            print(msg if ok else f"Error: {msg}", file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1

    if args.json:
        if not args.quiet:
            print(json.dumps(rows, indent=2, default=str))
    elif not args.quiet:
        print(format_who(rows, no_color=args.no_color))
    _maybe_export(args, rows)
    return 0 if rows else 1


def cmd_list(args: argparse.Namespace) -> int:
    rows = list_listening(
        dev_only=args.dev_only,
        public_only=args.public,
        search=args.search,
    )
    if args.json:
        if not args.quiet:
            print(json.dumps(rows, indent=2, default=str))
    elif not args.quiet:
        print(format_list_table(rows, no_color=args.no_color))
        # Extra safety callout
        risky = [r for r in rows if r.get("public_warning")]
        if risky and not args.json:
            print(f"\n⚠ {len(risky)} sensitive port(s) bound publicly — review bind addresses.")
    _maybe_export(args, rows)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    try:
        if len(args.targets) >= 2 and str(args.targets[1]).isdigit():
            host, port = args.targets[0], int(args.targets[1])
        elif args.targets:
            host, port = parse_endpoint(args.targets[0])
        else:
            raise ValueError("Need HOST:PORT")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    report = diagnose(host, port, force_tls=args.tls, timeout=max(args.timeout, 1.0))
    if args.json:
        if not args.quiet:
            print(json.dumps(report, indent=2, default=str))
    elif not args.quiet:
        print(format_doctor(report, no_color=args.no_color))
    _maybe_export(args, [report])
    tcp_ok = report.get("tcp", {}).get("success", 0) > 0
    return 0 if tcp_ok else 1


def cmd_diff(args: argparse.Namespace) -> int:
    if len(args.targets) < 2:
        print("Error: portpeek diff <HOST_A> <HOST_B> [PORTS|PRESET]", file=sys.stderr)
        return 2
    host_a, host_b = args.targets[0], args.targets[1]
    rest = args.targets[2:]
    ports: list[int] = []
    if not rest:
        ports = PRESETS["common"]
    elif len(rest) == 1 and rest[0].lower() in PRESETS:
        ports = PRESETS[rest[0].lower()]
    else:
        try:
            ports = parse_ports(rest)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
    rows = diff_hosts(host_a, host_b, ports, timeout=args.timeout, workers=args.workers)
    if args.json:
        if not args.quiet:
            print(json.dumps(rows, indent=2))
    elif not args.quiet:
        print(format_diff(rows, no_color=args.no_color))
    _maybe_export(args, rows)
    # Exit 1 if there are differences in openness
    differs = any(r["diff"] in ("ONLY ON A", "ONLY ON B") for r in rows)
    return 1 if differs else 0


def cmd_ping(args: argparse.Namespace) -> int:
    if not args.targets:
        print("Error: portpeek ping <HOST:PORT>", file=sys.stderr)
        return 2
    try:
        if len(args.targets) >= 2 and args.targets[1].isdigit():
            host, port = args.targets[0], int(args.targets[1])
        else:
            host, port = parse_endpoint(args.targets[0])
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return tcp_ping(
        host,
        port,
        count=args.count,
        interval=args.interval,
        timeout=max(args.timeout, 1.0),
    )


def cmd_repo(args: argparse.Namespace) -> int:
    print(f"portpeek v{__version__}")
    print(GITHUB_URL)
    print(AUTHOR_LINE_HELP)
    if not args.quiet:
        webbrowser.open(GITHUB_URL)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        hosts, ports = resolve_hosts_and_ports(
            args.targets,
            host_args=args.host,
            host_file=args.host_file,
            cidr=args.cidr,
            preset=args.preset,
        )
        if args.block < 0:
            raise ValueError("--block must be >= 0")
        if not ports:
            raise ValueError("No ports specified. Pass ports, ranges, or --preset.")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.watch is not None:
        watch_loop(
            hosts=hosts,
            ports=ports,
            interval=args.watch,
            timeout=args.timeout,
            workers=args.workers,
            show_services=args.services,
            measure_latency=args.latency,
            no_color=args.no_color,
        )
        return 0

    results = scan_hosts(
        hosts=hosts,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        measure_latency=args.latency or args.max_latency is not None,
        grab_banner=args.banner,
    )

    if args.proc:
        results = enrich_scan_with_proc(results)

    if args.block > 0:
        for h in hosts:
            host_res = [r for r in results if r["host"] == h]
            block = find_free_block(ports, host_res, args.block)
            if block:
                if not args.quiet:
                    payload = {"host": h, "ports": block}
                    print(json.dumps(payload) if args.json else " ".join(map(str, block)))
                    if args.copy:
                        copy_to_clipboard(" ".join(map(str, block)))
                return 0
        if not args.quiet:
            print(f"No contiguous block of {args.block} free ports found.", file=sys.stderr)
        return 1

    if args.find_free:
        for item in results:
            if item["status"] == "free":
                if not args.quiet:
                    print(json.dumps(item, indent=2) if args.json else item["port"])
                    if args.copy:
                        copy_to_clipboard(str(item["port"]))
                return 0
        if not args.quiet:
            print("No free port found in selection.", file=sys.stderr)
        return 1

    filtered = results
    if args.only_open:
        filtered = [r for r in results if r["status"] == "open"]
    elif args.only_free:
        filtered = [r for r in results if r["status"] == "free"]
    if args.max_latency is not None:
        filtered = [
            r for r in filtered if r.get("latency_ms", 0) <= args.max_latency or r["status"] == "free"
        ]

    _maybe_export(args, filtered, meta={"hosts": hosts, "ports_count": len(ports)})

    any_open = any(r["status"] == "open" for r in results)

    if not args.quiet:
        if args.json:
            print(json.dumps(filtered, indent=2, default=str))
        else:
            print_results(
                filtered,
                show_services=args.services,
                no_color=args.no_color,
                show_proc=args.proc,
            )
            if args.summary:
                print_summary(results, no_color=args.no_color)

    return 1 if any_open else 0


def _maybe_export(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    meta: dict[str, Any] | None = None,
) -> None:
    if args.output is None:
        return
    path = normalize_output_path(args.output)
    if not path:
        return
    written = export_results(path, rows, include_meta=args.include_meta, meta=meta)
    if not args.quiet and not args.json:
        print(f"Wrote {written}", file=sys.stderr)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _split_argv(argv: Sequence[str]) -> tuple[str | None, list[str]]:
    """Detect leading subcommand; return (command|None, remaining argv for parser)."""
    if not argv:
        return None, []
    # help aliases
    if argv[0] in ("-h", "--help", "help"):
        return "help", list(argv[1:])
    if argv[0] in SUBCOMMANDS:
        return argv[0], list(argv[1:])
    return None, list(argv)


def main(argv: Sequence[str] | None = None) -> None:
    raw = list(argv) if argv is not None else sys.argv[1:]
    command, rest = _split_argv(raw)

    if command == "help":
        topic = rest[0] if rest else None
        print(_subcommand_help(topic) if topic else format_help_text())
        sys.exit(0)

    if command == "menu":
        # Allow `portpeek menu --help`
        if rest and rest[0] in ("-h", "--help"):
            print(_subcommand_help("menu"))
            sys.exit(0)
        run_menu()
        sys.exit(0)

    # Subcommand-specific help before argparse consumes -h
    if command and rest and rest[0] in ("-h", "--help"):
        print(_subcommand_help(command))
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args(rest if command else raw)

    dispatch = {
        "freeport": cmd_freeport,
        "who": cmd_who,
        "pid": cmd_who,
        "list": cmd_list,
        "ls": cmd_list,
        "doctor": cmd_doctor,
        "check": cmd_doctor,
        "diff": cmd_diff,
        "ping": cmd_ping,
        "repo": cmd_repo,
        "github": cmd_repo,
    }

    try:
        if command is None:
            if not args.targets and not args.preset and not args.host_file and not args.cidr:
                print(format_help_text(color=False if args.no_color else None))
                sys.exit(0)
            code = cmd_scan(args)
        else:
            handler = dispatch.get(command)
            if handler is None:
                print(f"Unknown command: {command}", file=sys.stderr)
                sys.exit(2)
            code = handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    sys.exit(code)


if __name__ == "__main__":
    main()
