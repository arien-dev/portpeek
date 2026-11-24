"""Local listening-port inspection: /proc, ss/lsof fallback, Docker, kill."""

from __future__ import annotations

import os
import pwd
import re
import shutil
import signal
import subprocess
from typing import Any

from .constants import SENSITIVE_PUBLIC_PORTS


def list_listening(
    *,
    proto: str = "all",
    dev_only: bool = False,
    public_only: bool = False,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """List local TCP/UDP listeners. Best-effort pure-/proc with ss/lsof fallback."""
    rows = _merge_listeners(_from_proc(), _from_ss(), _from_lsof())
    docker_map = _docker_port_map()
    out: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, ...]] = set()

    for row in rows:
        if proto != "all" and row.get("proto", "").lower() != proto.lower():
            continue
        port = int(row["port"])
        if dev_only and port < 1024:
            continue
        bind = row.get("bind", "")
        is_public = bind in ("0.0.0.0", "::", "*", "") or bind.startswith("::ffff:0.0.0.0")
        if public_only and not is_public:
            continue

        pid = row.get("pid")
        info = process_info(pid) if pid else {}
        name = info.get("name") or row.get("process") or "-"
        cmdline = info.get("cmdline") or row.get("command") or "-"
        user = info.get("user") or row.get("user") or "-"
        uptime = info.get("uptime")

        # Docker: match by process name OR published host port (works without root PID access)
        docker = docker_map.get(port)
        if not docker and pid and (name in ("docker-proxy", "docker") or "docker-proxy" in (cmdline or "")):
            docker = _docker_for_port(port)
        if docker:
            name = f"<docker: {docker['name']} ({docker['image']})>"
            if not pid:
                # Still annotate that docker-proxy likely holds it
                cmdline = cmdline if cmdline and cmdline != "-" else f"docker publish → {docker['name']}"

        warning = None
        if is_public and port in SENSITIVE_PUBLIC_PORTS:
            warning = f"public {SENSITIVE_PUBLIC_PORTS[port]} on {bind} — prefer 127.0.0.1"

        dedupe_key = (row.get("proto", "tcp").upper(), port, bind, pid or 0)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        entry = {
            "port": port,
            "proto": row.get("proto", "tcp").upper(),
            "bind": bind,
            "pid": pid,
            "process": name,
            "command": cmdline,
            "user": user,
            "uptime": uptime or "-",
            "public": is_public,
            "public_warning": warning,
            "docker": docker,
        }
        if search:
            hay = f"{name} {cmdline} {user} {bind} {port}".lower()
            if search.lower() not in hay:
                continue
        out.append(entry)

    out.sort(key=lambda r: (r["port"], r["proto"], r.get("bind") or ""))
    return out


def _merge_listeners(*sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge listener sources; prefer rows that already know the PID."""
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    for source in sources:
        for row in source:
            proto = str(row.get("proto", "tcp")).lower()[:3]
            port = int(row["port"])
            bind = str(row.get("bind") or "")
            key = (proto, port, bind)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = {**row, "proto": proto}
                continue
            # Fill missing pid / process from richer source
            if not existing.get("pid") and row.get("pid"):
                existing["pid"] = row["pid"]
            if (not existing.get("process") or existing.get("process") in ("-", None)) and row.get("process"):
                existing["process"] = row["process"]
            if (not existing.get("command") or existing.get("command") in ("-", None)) and row.get("command"):
                existing["command"] = row["command"]
            if (not existing.get("user") or existing.get("user") in ("-", None)) and row.get("user"):
                existing["user"] = row["user"]
    return list(by_key.values())


def who_port(port: int) -> list[dict[str, Any]]:
    """Detailed ownership info for a local port."""
    listeners = [r for r in list_listening() if r["port"] == port]
    if listeners:
        enriched = []
        for r in listeners:
            info = process_info(r.get("pid")) if r.get("pid") else {}
            enriched.append({**r, **{k: v for k, v in info.items() if k not in r or not r[k] or r[k] == "-"}})
        return enriched
    # Fallback connect-style: nothing listening according to tables
    return []


def process_info(pid: int | None) -> dict[str, Any]:
    if not pid:
        return {}
    info: dict[str, Any] = {"pid": pid}
    try:
        # name
        with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
            info["name"] = f.read().strip()
    except OSError:
        info["name"] = "-"
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b"\x00", b" ").strip()
            info["cmdline"] = raw.decode("utf-8", errors="replace") or "-"
    except OSError:
        info["cmdline"] = "-"
    try:
        st = os.stat(f"/proc/{pid}")
        try:
            info["user"] = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            info["user"] = str(st.st_uid)
    except OSError:
        info["user"] = "-"
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            # field 22 (1-indexed) = starttime in clock ticks
            parts = f.read().split()
            start_ticks = int(parts[21])
        hz = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) if hasattr(os, "sysconf") else 100
        with open("/proc/uptime", encoding="utf-8") as f:
            uptime_sec = float(f.read().split()[0])
        start_sec = uptime_sec - (start_ticks / float(hz))
        info["uptime_sec"] = max(0, int(start_sec))
        info["uptime"] = _format_uptime(info["uptime_sec"])
    except (OSError, IndexError, ValueError):
        info["uptime"] = "-"
        info["uptime_sec"] = None
    return info


def kill_pid(pid: int, *, force: bool = False, yes: bool = False) -> tuple[bool, str]:
    """Send SIGTERM (or SIGKILL if force). Returns (ok, message)."""
    if not yes:
        return False, "refused: pass --yes to confirm kill"
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
        return True, f"sent {sig.name} to pid {pid}"
    except ProcessLookupError:
        return False, f"pid {pid} not found"
    except PermissionError:
        return False, f"permission denied killing pid {pid}"
    except OSError as exc:
        return False, str(exc)


def _format_uptime(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    if m or h or d:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# /proc parsers
# ---------------------------------------------------------------------------


def _from_proc() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    inode_map = _inode_to_pid()
    for path, proto in (
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ):
        rows.extend(_parse_proc_net(path, proto, inode_map))
    return rows


def _parse_proc_net(path: str, proto: str, inode_map: dict[int, int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError:
        return []

    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        state = parts[3]
        inode = int(parts[9])
        # TCP LISTEN = 0A; UDP has no listen state — include all bound UDP
        if proto == "tcp" and state != "0A":
            continue
        try:
            ip_hex, port_hex = local.split(":")
            port = int(port_hex, 16)
            bind = _hex_ip(ip_hex)
        except ValueError:
            continue
        pid = inode_map.get(inode)
        rows.append({"proto": proto, "port": port, "bind": bind, "pid": pid, "inode": inode})
    return rows


def _hex_ip(ip_hex: str) -> str:
    if len(ip_hex) == 8:
        # little-endian IPv4
        b = bytes.fromhex(ip_hex)
        return ".".join(str(x) for x in b[::-1])
    if len(ip_hex) == 32:
        b = bytes.fromhex(ip_hex)
        # 4 little-endian 32-bit words
        words = []
        for i in range(0, 16, 4):
            words.extend(b[i : i + 4][::-1])
        hextets = [f"{words[i]:02x}{words[i+1]:02x}" for i in range(0, 16, 2)]
        # Compress via ipaddress
        try:
            import ipaddress

            return str(ipaddress.IPv6Address(":".join(hextets)))
        except Exception:
            return ":".join(hextets)
    return ip_hex


def _inode_to_pid() -> dict[int, int]:
    mapping: dict[int, int] = {}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return mapping
    for pid_s in pids:
        fd_dir = f"/proc/{pid_s}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:["):
                    try:
                        inode = int(target[8:-1])
                        mapping[inode] = int(pid_s)
                    except ValueError:
                        pass
        except OSError:
            continue
    return mapping


# ---------------------------------------------------------------------------
# ss / lsof fallbacks
# ---------------------------------------------------------------------------


def _from_ss() -> list[dict[str, Any]]:
    if not shutil.which("ss"):
        return []
    try:
        proc = subprocess.run(
            ["ss", "-tulnpH"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[dict[str, Any]] = []
    # Example: tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))
    pat = re.compile(
        r"^(?P<proto>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<local>\S+)\s+\S+(?:\s+users:\(\((?P<users>.*)\)\))?"
    )
    users_pat = re.compile(r'"([^"]+)",pid=(\d+)')
    for line in proc.stdout.splitlines():
        m = pat.match(line.strip())
        if not m:
            continue
        local = m.group("local")
        bind, port = _split_local(local)
        if port is None:
            continue
        name, pid = "-", None
        users = m.group("users") or ""
        um = users_pat.search(users)
        if um:
            name, pid = um.group(1), int(um.group(2))
        rows.append(
            {
                "proto": m.group("proto").lower().replace("tcp6", "tcp").replace("udp6", "udp")[:3],
                "port": port,
                "bind": bind,
                "pid": pid,
                "process": name,
            }
        )
    return rows


def _from_lsof() -> list[dict[str, Any]]:
    if not shutil.which("lsof"):
        return []
    try:
        proc = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-iUDP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name, pid, user = parts[0], parts[1], parts[2]
        proto = parts[7].lower() if len(parts) > 7 else "tcp"
        name_field = parts[-1]  # *:3000 (LISTEN) or *:53
        m = re.search(r"([^:]+):(\d+)", name_field)
        if not m:
            continue
        bind = m.group(1).replace("*", "0.0.0.0")
        port = int(m.group(2))
        rows.append(
            {
                "proto": "udp" if "UDP" in proto.upper() or "UDP" in line else "tcp",
                "port": port,
                "bind": bind,
                "pid": int(pid) if pid.isdigit() else None,
                "process": name,
                "user": user,
            }
        )
    return rows


def _split_local(local: str) -> tuple[str, int | None]:
    if local.startswith("["):
        end = local.rfind("]")
        if end != -1 and end + 1 < len(local) and local[end + 1] == ":":
            try:
                return local[1:end], int(local[end + 2 :])
            except ValueError:
                return local, None
    if ":" in local:
        bind, port_s = local.rsplit(":", 1)
        if port_s.isdigit():
            return bind, int(port_s)
    return local, None


# ---------------------------------------------------------------------------
# Docker (CLI best-effort)
# ---------------------------------------------------------------------------


def _docker_port_map() -> dict[int, dict[str, str]]:
    if not shutil.which("docker"):
        return {}
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    mapping: dict[int, dict[str, str]] = {}
    # 0.0.0.0:5432->5432/tcp
    port_re = re.compile(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|::):(\d+)->")
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        _cid, name, image, ports = parts[0], parts[1], parts[2], parts[3]
        for m in port_re.finditer(ports):
            mapping[int(m.group(1))] = {"name": name, "image": image}
    return mapping


def _docker_for_port(port: int) -> dict[str, str] | None:
    return _docker_port_map().get(port)


def enrich_scan_with_proc(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach local process info to open scan results on localhost-ish hosts."""
    listeners = {(r["port"], r.get("proto", "TCP").upper()): r for r in list_listening()}
    for row in results:
        if row.get("status") != "open":
            continue
        host = row.get("host", "")
        if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", ""):
            # still try matching by port for local scans
            if not _is_local_host(host):
                continue
        key = (row["port"], "TCP")
        info = listeners.get(key)
        if info:
            row["process"] = {
                "pid": info.get("pid"),
                "name": info.get("process"),
                "cmdline": info.get("command"),
                "user": info.get("user"),
                "bind": info.get("bind"),
                "docker": (
                    f"<docker: {info['docker']['name']} ({info['docker']['image']})>"
                    if info.get("docker")
                    else None
                ),
            }
            if info.get("public_warning"):
                row["public_warning"] = info["public_warning"]
            row["bind"] = info.get("bind")
    return results


def _is_local_host(host: str) -> bool:
    local_names = {"127.0.0.1", "localhost", "::1", "0.0.0.0", ""}
    if host in local_names:
        return True
    try:
        import socket

        return socket.gethostbyname(host) in ("127.0.0.1", "::1")
    except OSError:
        return False


def format_who(rows: list[dict[str, Any]], *, no_color: bool = False) -> str:
    from .constants import ANSI_BOLD, ANSI_CYAN, ANSI_RESET, ANSI_YELLOW
    from .core import use_color

    color = use_color(no_color)
    if not rows:
        return "No local process is listening on that port."
    lines: list[str] = []
    for r in rows:
        title = f"Port {r['port']}/{r.get('proto', 'TCP')}"
        if color:
            lines.append(f"{ANSI_BOLD}{ANSI_CYAN}{title}{ANSI_RESET}")
        else:
            lines.append(title)
        fields = [
            ("Bind", r.get("bind", "-")),
            ("PID", r.get("pid") or "-"),
            ("Process", r.get("process") or "-"),
            ("User", r.get("user") or "-"),
            ("Command", r.get("command") or r.get("cmdline") or "-"),
            ("Uptime", r.get("uptime") or "-"),
        ]
        if r.get("docker"):
            d = r["docker"]
            fields.append(("Docker", f"{d['name']} ({d['image']})"))
        for label, val in fields:
            lines.append(f"  {label:<10} {val}")
        if r.get("public_warning"):
            w = r["public_warning"]
            if color:
                lines.append(f"  {ANSI_YELLOW}Warning    {w}{ANSI_RESET}")
            else:
                lines.append(f"  Warning    {w}")
        lines.append("")
    return "\n".join(lines).rstrip()


def format_list_table(rows: list[dict[str, Any]], *, no_color: bool = False) -> str:
    from .constants import ANSI_RESET, ANSI_YELLOW
    from .core import use_color

    color = use_color(no_color)
    if not rows:
        return "No listening ports found."
    headers = ("PORT", "PROTO", "BIND", "PID", "PROCESS", "COMMAND")
    data = []
    for r in rows:
        cmd = (r.get("command") or "-")[:48]
        data.append(
            (
                str(r["port"]),
                str(r.get("proto", "TCP")),
                str(r.get("bind") or "-"),
                str(r.get("pid") or "-"),
                str(r.get("process") or "-")[:28],
                cmd,
            )
        )
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        "  ".join("-" * widths[i] for i in range(len(headers))),
    ]
    for idx, row in enumerate(data):
        line = "  ".join(row[i].ljust(widths[i]) for i in range(len(headers)))
        warn = rows[idx].get("public_warning")
        if warn:
            suffix = f"  ⚠ {warn}"
            if color:
                line = f"{line}{ANSI_YELLOW}{suffix}{ANSI_RESET}"
            else:
                line = f"{line}{suffix}"
        lines.append(line)
    return "\n".join(lines)
