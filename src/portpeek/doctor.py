"""Deep diagnostics: DNS, TCP latency, TLS certs, HTTP probes, TCP ping, host diff."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .constants import CERT_WARN_DAYS, HTTP_PORTS, HTTPS_PORTS, TLS_PORTS
from .core import scan_target, service_name


def parse_endpoint(spec: str, port: int | None = None) -> tuple[str, int]:
    """Parse 'HOST', 'HOST:PORT', 'http(s)://HOST:PORT/...' into (host, port)."""
    raw = spec.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        p = parsed.port
        if p is None:
            p = 443 if parsed.scheme == "https" else 80
        return host, p
    if raw.startswith("[") and "]" in raw:
        end = raw.find("]")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        if port is not None:
            return host, port
        raise ValueError("Port required")
    if port is not None:
        # host + separate port arg
        if ":" in raw and raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
            h, p = raw.rsplit(":", 1)
            return h, int(p)
        return raw, port
    if raw.count(":") == 1:
        h, p = raw.rsplit(":", 1)
        if p.isdigit():
            return h, int(p)
    raise ValueError(f"Need HOST:PORT (got '{spec}')")


def resolve_dns(host: str) -> dict[str, Any]:
    start = time.perf_counter()
    ipv4: list[str] = []
    ipv6: list[str] = []
    error = None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, *_rest, sockaddr in infos:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ipv4:
                ipv4.append(addr)
            elif family == socket.AF_INET6 and addr not in ipv6:
                ipv6.append(addr)
    except OSError as exc:
        error = str(exc)
    ms = round((time.perf_counter() - start) * 1000, 2)
    return {"host": host, "ipv4": ipv4, "ipv6": ipv6, "resolve_ms": ms, "error": error}


def tcp_latency_probes(host: str, port: int, probes: int = 3, timeout: float = 2.0) -> dict[str, Any]:
    samples: list[float] = []
    failures = 0
    last_error = None
    for _ in range(probes):
        t0 = time.perf_counter()
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            connected = False
            for family, socktype, proto, _, sockaddr in addr_info:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(timeout)
                    err = sock.connect_ex(sockaddr)
                    if err == 0:
                        connected = True
                        break
                    last_error = errno_hint(err)
            if connected:
                samples.append((time.perf_counter() - t0) * 1000)
            else:
                failures += 1
        except OSError as exc:
            failures += 1
            last_error = str(exc)
    result: dict[str, Any] = {
        "probes": probes,
        "success": len(samples),
        "failures": failures,
        "loss_pct": round(100.0 * failures / probes, 1) if probes else 0.0,
        "samples_ms": [round(s, 2) for s in samples],
        "error": last_error,
    }
    if samples:
        result["min_ms"] = round(min(samples), 2)
        result["max_ms"] = round(max(samples), 2)
        result["avg_ms"] = round(sum(samples) / len(samples), 2)
        if len(samples) > 1:
            mean = sum(samples) / len(samples)
            jitter = sum(abs(s - mean) for s in samples) / len(samples)
            result["jitter_ms"] = round(jitter, 2)
        else:
            result["jitter_ms"] = 0.0
    return result


def errno_hint(err: int) -> str:
    mapping = {
        111: "connection refused",
        110: "connection timed out",
        113: "no route to host",
        101: "network unreachable",
    }
    return mapping.get(err, f"errno {err}")


def tls_inspect(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    result: dict[str, Any] = {"enabled": True, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                result["version"] = ssock.version()
                result["cipher"] = ssock.cipher()
                cert = ssock.getpeercert()
                result.update(_parse_cert(cert))
    except ssl.SSLCertVerificationError as exc:
        # Still try without verify to extract cert details
        result["verify_error"] = str(exc)
        try:
            ctx = ssl._create_unverified_context()  # noqa: SLF001
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                    result["version"] = ssock.version()
                    result["cipher"] = ssock.cipher()
                    cert = ssock.getpeercert()
                    result.update(_parse_cert(cert))
        except OSError as exc2:
            result["error"] = str(exc2)
    except OSError as exc:
        result["error"] = str(exc)
        result["enabled"] = False
    return result


def _parse_cert(cert: dict[str, Any] | None) -> dict[str, Any]:
    if not cert:
        return {"cert": None}
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sans = []
    for typ, val in cert.get("subjectAltName", ()) or ():
        if typ == "DNS":
            sans.append(val)
    not_after = cert.get("notAfter")
    days_left = None
    warn = False
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
            warn = days_left < CERT_WARN_DAYS
        except ValueError:
            pass
    return {
        "cn": subject.get("commonName"),
        "sans": sans,
        "issuer": issuer.get("commonName") or issuer.get("organizationName"),
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_left": days_left,
        "expiring_soon": warn,
    }


def http_probe(host: str, port: int, *, use_tls: bool = False, timeout: float = 3.0) -> dict[str, Any]:
    result: dict[str, Any] = {"error": None}
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    t0 = time.perf_counter()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            try:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                conn.request("HEAD", "/", headers={"User-Agent": "portpeek/1.3", "Host": host})
                resp = conn.getresponse()
            except ssl.SSLError:
                ctx = ssl._create_unverified_context()  # noqa: SLF001
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                conn.request("HEAD", "/", headers={"User-Agent": "portpeek/1.3", "Host": host})
                resp = conn.getresponse()
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("HEAD", "/", headers={"User-Agent": "portpeek/1.3", "Host": host})
            resp = conn.getresponse()
        # Some servers dislike HEAD — retry GET
        if resp.status in (405, 501):
            conn.close()
            if use_tls:
                conn = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=ssl._create_unverified_context()  # noqa: SLF001
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", "/", headers={"User-Agent": "portpeek/1.3", "Host": host})
            resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        result.update(
            {
                "status": resp.status,
                "reason": resp.reason,
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "location": headers.get("location"),
                "content_type": headers.get("content-type"),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            }
        )
        conn.close()
    except OSError as exc:
        result["error"] = str(exc)
        result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return result


def diagnose(host: str, port: int, *, force_tls: bool = False, timeout: float = 2.0) -> dict[str, Any]:
    """Full doctor report for HOST:PORT."""
    report: dict[str, Any] = {
        "host": host,
        "port": port,
        "service": service_name(port),
        "dns": resolve_dns(host),
        "tcp": tcp_latency_probes(host, port, probes=3, timeout=timeout),
    }

    want_tls = force_tls or port in TLS_PORTS or port in HTTPS_PORTS
    want_http = port in HTTP_PORTS or port in HTTPS_PORTS or force_tls

    if report["tcp"]["success"] > 0:
        if want_tls:
            report["tls"] = tls_inspect(host, port, timeout=timeout)
        if want_http or want_tls:
            use_tls = want_tls and not (port in HTTP_PORTS and port not in HTTPS_PORTS and not force_tls)
            # For classic HTTPS ports always TLS; for 80 plain HTTP
            if port in HTTPS_PORTS or force_tls:
                use_tls = True
            elif port in HTTP_PORTS:
                use_tls = False
            report["http"] = http_probe(host, port, use_tls=use_tls, timeout=timeout)
            # If plain HTTP failed and TLS might work
            if report["http"].get("error") and not use_tls and (force_tls or port in TLS_PORTS):
                report["http"] = http_probe(host, port, use_tls=True, timeout=timeout)
                report["tls"] = report.get("tls") or tls_inspect(host, port, timeout=timeout)

    report["diagnosis"] = build_diagnosis(report)
    return report


def build_diagnosis(report: dict[str, Any]) -> list[str]:
    msgs: list[str] = []
    dns = report.get("dns", {})
    tcp = report.get("tcp", {})
    host = report.get("host")
    port = report.get("port")

    if dns.get("error") and not dns.get("ipv4") and not dns.get("ipv6"):
        msgs.append(f"DNS failed for '{host}': {dns['error']} — check hostname / resolver.")
        return msgs

    if tcp.get("success", 0) == 0:
        err = (tcp.get("error") or "").lower()
        if "refused" in err:
            msgs.append(
                f"Connection refused — host resolves and is reachable, but nothing listens on port {port}."
            )
        elif "timed out" in err or "timeout" in err:
            msgs.append(
                f"Timeout — firewall DROP, filtered port, or host offline (ICMP may still work)."
            )
        elif "route" in err or "unreachable" in err:
            msgs.append("Network unreachable — routing / VPN / interface problem.")
        else:
            msgs.append(f"TCP connect failed ({tcp.get('error') or 'unknown'}).")
        if tcp.get("loss_pct", 0) == 100:
            msgs.append("100% probe loss — treat as blocked or down.")
        return msgs

    msgs.append(
        f"TCP open — avg {tcp.get('avg_ms')} ms "
        f"(min {tcp.get('min_ms')} / max {tcp.get('max_ms')}, jitter {tcp.get('jitter_ms')} ms)."
    )
    if tcp.get("loss_pct", 0) > 0:
        msgs.append(f"Partial loss: {tcp['loss_pct']}% of probes failed — unstable path or overload.")

    tls = report.get("tls")
    if tls:
        if tls.get("error") and not tls.get("version"):
            msgs.append(f"TLS handshake failed: {tls['error']}")
        else:
            days = tls.get("days_left")
            cn = tls.get("cn")
            msgs.append(f"TLS {tls.get('version')} — CN={cn}, expires in {days} days.")
            if tls.get("expiring_soon"):
                msgs.append(f"⚠ Certificate expires in < {CERT_WARN_DAYS} days — renew soon.")
            if tls.get("verify_error"):
                msgs.append(f"Certificate verify warning: {tls['verify_error']}")

    http = report.get("http")
    if http and not http.get("error"):
        loc = f" → {http['location']}" if http.get("location") else ""
        msgs.append(f"HTTP {http.get('status')} {http.get('reason')}{loc} in {http.get('latency_ms')} ms.")
        if http.get("server"):
            msgs.append(f"Server header: {http['server']}")
    elif http and http.get("error"):
        msgs.append(f"HTTP probe failed: {http['error']}")

    return msgs


def format_doctor(report: dict[str, Any], *, no_color: bool = False) -> str:
    from .constants import ANSI_BOLD, ANSI_CYAN, ANSI_GREEN, ANSI_RED, ANSI_RESET, ANSI_YELLOW
    from .core import use_color

    color = use_color(no_color)
    lines: list[str] = []

    def head(text: str) -> None:
        if color:
            lines.append(f"\n{ANSI_BOLD}{ANSI_CYAN}== {text} =={ANSI_RESET}")
        else:
            lines.append(f"\n== {text} ==")

    host, port = report["host"], report["port"]
    title = f"portpeek doctor → {host}:{port} ({report.get('service', '-')})"
    lines.append(f"{ANSI_BOLD}{title}{ANSI_RESET}" if color else title)

    head("DNS")
    dns = report["dns"]
    if dns.get("error") and not dns.get("ipv4") and not dns.get("ipv6"):
        lines.append(f"  error: {dns['error']}")
    else:
        lines.append(f"  A     {', '.join(dns.get('ipv4') or ['-'])}")
        lines.append(f"  AAAA  {', '.join(dns.get('ipv6') or ['-'])}")
        lines.append(f"  time  {dns.get('resolve_ms')} ms")

    head("TCP")
    tcp = report["tcp"]
    if tcp.get("success"):
        lines.append(
            f"  probes {tcp['success']}/{tcp['probes']}  "
            f"min/avg/max {tcp.get('min_ms')}/{tcp.get('avg_ms')}/{tcp.get('max_ms')} ms  "
            f"jitter {tcp.get('jitter_ms')} ms  loss {tcp.get('loss_pct')}%"
        )
    else:
        lines.append(f"  failed ({tcp.get('error') or 'no connection'})  loss {tcp.get('loss_pct')}%")

    if "tls" in report:
        head("TLS")
        tls = report["tls"]
        if tls.get("version"):
            cipher = tls.get("cipher")
            cipher_s = cipher[0] if isinstance(cipher, tuple) else cipher
            lines.append(f"  version  {tls.get('version')}")
            lines.append(f"  cipher   {cipher_s}")
            lines.append(f"  CN       {tls.get('cn')}")
            lines.append(f"  SANs     {', '.join(tls.get('sans') or []) or '-'}")
            lines.append(f"  issuer   {tls.get('issuer')}")
            days = tls.get("days_left")
            exp = tls.get("not_after")
            day_s = f"{days} days left" if days is not None else "-"
            if tls.get("expiring_soon") and color:
                day_s = f"{ANSI_YELLOW}{day_s}{ANSI_RESET}"
            lines.append(f"  expires  {exp} ({day_s})")
            if tls.get("verify_error"):
                lines.append(f"  verify   {tls['verify_error']}")
        else:
            lines.append(f"  error: {tls.get('error')}")

    if "http" in report:
        head("HTTP")
        http = report["http"]
        if http.get("error"):
            lines.append(f"  error: {http['error']}")
        else:
            lines.append(f"  status   {http.get('status')} {http.get('reason')}")
            lines.append(f"  server   {http.get('server') or '-'}")
            lines.append(f"  powered  {http.get('x_powered_by') or '-'}")
            lines.append(f"  location {http.get('location') or '-'}")
            lines.append(f"  time     {http.get('latency_ms')} ms")

    head("Diagnosis")
    for msg in report.get("diagnosis") or []:
        if color and msg.startswith("⚠"):
            lines.append(f"  {ANSI_YELLOW}• {msg}{ANSI_RESET}")
        elif color and ("refused" in msg.lower() or "failed" in msg.lower() or "timeout" in msg.lower()):
            lines.append(f"  {ANSI_RED}• {msg}{ANSI_RESET}")
        elif color:
            lines.append(f"  {ANSI_GREEN}• {msg}{ANSI_RESET}")
        else:
            lines.append(f"  • {msg}")
    return "\n".join(lines).rstrip() + "\n"


def tcp_ping(
    host: str,
    port: int,
    *,
    count: int | None = None,
    interval: float = 1.0,
    timeout: float = 2.0,
) -> int:
    """Continuous TCP ping. Returns exit code 0 if any success, else 1."""
    print(f"TCP PING {host}:{port} (Ctrl+C to stop)")
    sent = 0
    ok = 0
    samples: list[float] = []
    try:
        while True:
            sent += 1
            t0 = time.perf_counter()
            err_msg = None
            success = False
            try:
                infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                for family, socktype, proto, _, sockaddr in infos:
                    with socket.socket(family, socktype, proto) as sock:
                        sock.settimeout(timeout)
                        if sock.connect_ex(sockaddr) == 0:
                            success = True
                            break
            except OSError as exc:
                err_msg = str(exc)
            ms = (time.perf_counter() - t0) * 1000
            if success:
                ok += 1
                samples.append(ms)
                print(f"connected to {host}:{port} seq={sent} time={ms:.2f} ms")
            else:
                print(f"no response from {host}:{port} seq={sent} ({err_msg or 'failed'}) time={ms:.2f} ms")
            if count is not None and sent >= count:
                break
            time.sleep(max(0.05, interval))
    except KeyboardInterrupt:
        print()
    loss = 100.0 * (sent - ok) / sent if sent else 100.0
    print(f"--- {host}:{port} tcp ping statistics ---")
    print(f"{sent} probes sent, {ok} successful, {loss:.1f}% loss")
    if samples:
        mean = sum(samples) / len(samples)
        jitter = sum(abs(s - mean) for s in samples) / len(samples) if len(samples) > 1 else 0.0
        print(
            f"rtt min/avg/max/jitter = {min(samples):.2f}/{mean:.2f}/{max(samples):.2f}/{jitter:.2f} ms"
        )
    return 0 if ok else 1


def diff_hosts(
    host_a: str,
    host_b: str,
    ports: list[int],
    *,
    timeout: float = 0.35,
    workers: int = 64,
) -> list[dict[str, Any]]:
    res_a = {r["port"]: r for r in scan_target(host_a, ports, timeout=timeout, workers=workers)}
    res_b = {r["port"]: r for r in scan_target(host_b, ports, timeout=timeout, workers=workers)}
    rows = []
    for p in ports:
        a_open = res_a[p]["status"] == "open"
        b_open = res_b[p]["status"] == "open"
        if a_open and b_open:
            tag = "BOTH OPEN"
        elif not a_open and not b_open:
            tag = "BOTH FREE"
        elif a_open:
            tag = "ONLY ON A"
        else:
            tag = "ONLY ON B"
        rows.append(
            {
                "port": p,
                "service": service_name(p),
                "host_a": host_a,
                "host_b": host_b,
                "status_a": res_a[p]["status"],
                "status_b": res_b[p]["status"],
                "diff": tag,
            }
        )
    return rows


def format_diff(rows: list[dict[str, Any]], *, no_color: bool = False) -> str:
    from .constants import ANSI_CYAN, ANSI_GREEN, ANSI_RED, ANSI_RESET, ANSI_YELLOW
    from .core import use_color

    color = use_color(no_color)
    if not rows:
        return "No ports to compare."
    host_a = rows[0]["host_a"]
    host_b = rows[0]["host_b"]
    lines = [f"diff {host_a}  vs  {host_b}", ""]
    palette = {
        "ONLY ON A": ANSI_RED,
        "ONLY ON B": ANSI_YELLOW,
        "BOTH OPEN": ANSI_GREEN,
        "BOTH FREE": ANSI_CYAN,
    }
    for r in rows:
        tag = r["diff"]
        if color:
            c = palette.get(tag, "")
            lines.append(f"  {c}{tag:<12}{ANSI_RESET}  {r['port']:>5}  {r['service']}")
        else:
            lines.append(f"  {tag:<12}  {r['port']:>5}  {r['service']}")
    # Summary
    from collections import Counter

    counts = Counter(r["diff"] for r in rows)
    lines.append("")
    lines.append(
        "summary: "
        + ", ".join(f"{k}={v}" for k, v in counts.items())
    )
    return "\n".join(lines)
