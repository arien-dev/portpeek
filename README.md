[![Python Package](https://github.com/arien-dev/portpeek/actions/workflows/python-publish.yml/badge.svg)](https://github.com/arien-dev/portpeek/actions/workflows/python-publish.yml)

```
 ____   ___  ____ _____ ____  _____ _____ _  __
|  _ \ / _ \|  _ \_   _|  _ \| ____| ____| |/ /
| |_) | | | | |_) || | | |_) |  _| |  _| | ' /
|  __/| |_| |  _ < | | |  __/| |___| |___| . \
|_|    \___/|_| \_\|_| |_|   |_____|_____|_|\_\
```

# portpeek

**Ultra-fast all-in-one port · process · TLS · network inspector for developers.**

`made by arien-dev • https://github.com/arien-dev/portpeek`

Pure Python ≥ 3.10 standard library — **zero runtime dependencies**.

## Features

- **Quick subcommands** — `freeport`, `who`/`pid`, `list`/`ls`, `doctor`/`check`, `diff`, `ping`, `menu`, `repo`
- **Classic scanner** — `portpeek 3000`, ranges, `HOST:PORT`, presets (`web`/`db`/`dev`/`common`), `--cidr`, `--host-file`
- **Local process intel** — PID, user, full cmdline, bind address, uptime; Docker container/image when `docker-proxy` holds the port
- **Deep doctor** — DNS (A/AAAA + ms), TCP latency (min/avg/max/jitter/loss), TLS cert CN/SANs/expiry, HTTP status/headers, plain-English diagnosis
- **Safety** — warn when databases/caches bind on `0.0.0.0` / `::`
- **Export** — `-o` / `--output` for `.json`, `.jsonl`, `.csv`, `.md`, `.txt` (+ `--include-meta`, auto filename)
- **Interactive menu** — ASCII logo, ↑/↓ or j/k, `g` opens GitHub, export after each scan

## Installation

```bash
pip install "git+https://github.com/arien-dev/portpeek.git"
# or editable:
pip install -e /path/to/portpeek
```

## Quick Subcommands

```bash
# Next free port for scripts
PORT=$(portpeek freeport)
PORT=$(portpeek freeport 4000-4100 --block 3 --copy)

# Who owns this port?
portpeek who 3000
portpeek pid 5432 --kill --yes          # SIGTERM (add --force for SIGKILL)

# Everything listening locally
portpeek list
portpeek ls --public --dev-only --search postgres

# Deep diagnose (DNS + TCP + TLS + HTTP)
portpeek doctor example.com:443
portpeek check 127.0.0.1:8080

# Compare two environments
portpeek diff localhost staging.example.com web

# TCP ping (works when ICMP is blocked)
portpeek ping db.internal:5432 -c 5

# Open the repo
portpeek repo
```

## Classic Scanner (backwards compatible)

```bash
portpeek 3000
portpeek 80 443 --services
portpeek 127.0.0.1:3000
portpeek example.com:443 --latency --banner
portpeek 80,443 3000-3010 --host 127.0.0.1
portpeek --preset web --services --latency
portpeek --preset db --proc --summary
portpeek 80,443 --cidr 192.168.1.0/29 --only-open
portpeek 3000-3050 --find-free
portpeek 4000-4100 --block 3
portpeek 3000,8080 --watch 1 --services
portpeek --preset web -o report.md --include-meta
portpeek 3000-3020 -o events.jsonl
portpeek 80,443 --quiet
```

## Interactive Menu

```bash
portpeek menu
```

Arrow keys (`↑`/`↓`) or `j`/`k` to move, `Enter` to select, `g` for GitHub, `q`/`Esc` to quit.

1. Active Local Ports  
2. Who is using Port X?  
3. Deep Port Doctor  
4. Common Web & Dev Ports Scan  
5. Databases & Cache Scan  
6. Find Free Port / Contiguous Block  
7. Live Watch Ports  
8. Custom Host / CIDR / Range Scan  
9. Open GitHub Repository  
10. Exit  

## Help

```bash
portpeek --help
portpeek freeport --help
portpeek doctor --help
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success / all scanned ports free / TCP reachable (doctor/ping) |
| 1 | At least one port in use / not found / unreachable |
| 2 | Usage / parse error |
| 130 | Interrupted (`Ctrl+C`) |

## License

MIT — **arien-dev** · [github.com/arien-dev/portpeek](https://github.com/arien-dev/portpeek)
