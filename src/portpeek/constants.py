"""Shared constants, presets, and styling for portpeek."""

from __future__ import annotations

ASCII_BANNER = r"""
 ____   ___  ____ _____ ____  _____ _____ _  __
|  _ \ / _ \|  _ \_   _|  _ \| ____| ____| |/ /
| |_) | | | | |_) || | | |_) |  _| |  _| | ' /
|  __/| |_| |  _ < | | |  __/| |___| |___| . \
|_|    \___/|_| \_\|_| |_|   |_____|_____|_|\_\
"""

GITHUB_URL = "https://github.com/arien-dev/portpeek"
AUTHOR_LINE = "made by arien-dev • github.com/arien-dev/portpeek"
AUTHOR_LINE_HELP = "made by arien-dev | https://github.com/arien-dev/portpeek"

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_REVERSE = "\033[7m"

# Ports that are risky when bound publicly (0.0.0.0 / ::).
SENSITIVE_PUBLIC_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "MSRPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

TLS_PORTS = frozenset({443, 8443, 9443, 4443, 7443, 6443})
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 5173, 4173})
HTTPS_PORTS = frozenset({443, 8443, 9443})

PRESETS: dict[str, list[int]] = {
    "common": [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 27017],
    "web": [80, 443, 8000, 8080, 8443, 8888],
    "db": [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
    "dev": [3000, 3001, 4200, 5000, 5173, 8000, 8080, 8888, 9000],
}

DEFAULT_FREEPORT_RANGE = "3000-3999"
DEFAULT_HOST = "127.0.0.1"
CERT_WARN_DAYS = 14
