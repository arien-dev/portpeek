[![Python Package](https://github.com/arien-dev/portpeek/actions/workflows/python-publish.yml/badge.svg)](https://github.com/arien-dev/portpeek/actions/workflows/python-publish.yml)

# portpeek

**Fast concurrent TCP port checker, free-port finder, live watcher, and interactive CLI inspector.**

## Features

- **Flexible Port & Target Parsing:** Single ports, comma-separated lists, `start-end` ranges, built-in presets (`common`, `web`, `db`, `dev`), multiple `--host` targets, `--host-file`, and `--cidr` subnets.
- **Interactive ASCII Menu (`portpeek menu`):** Arrow-key (`↑`/`↓` or `j`/`k`) navigation with quick presets, free-port search, live watch mode, and optional result export.
- **Inspection & Tuning:** Adjustable `--timeout` and `--workers`, IPv4/IPv6 (`getaddrinfo`) support, `--services` (IANA service names), `--latency` (connection time in ms), `--banner` grabbing, and `--proc` lookup for local listening processes (`ss`/`lsof`).
- **Free Port Search & Live Watch:** Find the first free port (`--find-free`), find contiguous free port blocks (`--block N`), or monitor live state transitions (`--watch`).
- **Filtering & Multi-Format Export:** Filter via `--only-open`, `--only-free`, or `--max-latency`, show `--summary`, and export to `.json`, `.jsonl`, `.csv`, `.md`, or `.txt` (with optional `--include-meta`).

---

## Installation

Install directly from GitHub:

```
pip install "git+https://github.com/arien-dev/portpeek.git"
```

## Usage

### Interactive Menu

Launch the interactive CLI menu:

```
portpeek menu
```

### Basic Port & Range Checks

```
portpeek 3000
portpeek 80,443 3000-3010 --host 127.0.0.1
portpeek --preset web --services --latency
```

### Multiple Hosts, Host Files & Subnets

```
portpeek 22 80 443 --host 127.0.0.1 192.168.1.10 --banner
portpeek 80,443 --cidr 192.168.1.0/29 --only-open
portpeek --preset db --host-file hosts.txt
```

### Finding Free Ports & Watching Live

```
portpeek 3000-3050 --find-free
portpeek 4000-4100 --block 3
portpeek 3000,8080 --watch 1 --services
```

### Filtering, Process Info & Export

```
portpeek --preset dev --proc --summary
portpeek 1-1024 --only-open -o open-ports.json --include-meta
portpeek --preset web -o report.md --include-meta
portpeek 3000-3020 -o events.jsonl
portpeek 80,443 --quiet
```

---

## ⚙️ CLI Options

For the complete list of available commands, arguments, and options, run:

```
portpeek --help
```


---

**GitHub:** [arien-dev/portpeek](https://github.com/arien-dev/portpeek)
