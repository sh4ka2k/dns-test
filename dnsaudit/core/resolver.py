"""DNS resolver wrapper with support for custom nameservers."""

import socket
import subprocess
from typing import Optional


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]

PUBLIC_RESOLVERS = {
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
}


def query_dns(domain: str, record_type: str, nameserver: Optional[str] = None) -> dict:
    """
    Query DNS records for a domain using the system's dig command.

    Returns a dict with keys: status, answers, raw_output, error
    """
    cmd = ["dig", "+noall", "+answer", "+authority", "+comments", record_type, domain]
    if nameserver:
        cmd.insert(1, f"@{nameserver}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        answers = _parse_dig_output(result.stdout)
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "answers": answers,
            "raw_output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "answers": [], "raw_output": "", "error": "Query timed out"}
    except FileNotFoundError:
        return _fallback_query(domain, record_type)


def _parse_dig_output(output: str) -> list[dict]:
    """Parse dig +answer output into structured records."""
    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            records.append({
                "name": parts[0],
                "ttl": parts[1],
                "class": parts[2],
                "type": parts[3],
                "value": " ".join(parts[4:]),
            })
    return records


def _fallback_query(domain: str, record_type: str) -> dict:
    """Fallback using socket for basic A/AAAA lookups when dig is unavailable."""
    if record_type not in ("A", "AAAA"):
        return {
            "status": "error",
            "answers": [],
            "raw_output": "",
            "error": "dig not found; only A/AAAA supported via fallback",
        }
    try:
        family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
        results = socket.getaddrinfo(domain, None, family)
        answers = [{"name": domain, "ttl": "N/A", "class": "IN", "type": record_type, "value": r[4][0]} for r in results]
        return {"status": "ok", "answers": answers, "raw_output": "", "error": None}
    except socket.gaierror as e:
        return {"status": "nxdomain", "answers": [], "raw_output": "", "error": str(e)}


def check_propagation(domain: str, record_type: str = "A") -> dict:
    """Check DNS propagation across multiple public resolvers."""
    results = {}
    for name, servers in PUBLIC_RESOLVERS.items():
        resolver_results = []
        for server in servers:
            r = query_dns(domain, record_type, nameserver=server)
            resolver_results.append({
                "nameserver": server,
                "answers": [a["value"] for a in r.get("answers", [])],
                "status": r["status"],
            })
        results[name] = resolver_results
    return results


def reverse_lookup(ip: str) -> str:
    """Perform a reverse DNS lookup (PTR) for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "No PTR record"
