"""
scanner.py
Network TLS certificate discovery.

For each candidate host/port, performs a real TLS handshake (the same
one any browser would do) and keeps the certificate presented by the
server, without validating it yet - validation is analyzer.py's
responsibility. Nothing is exploited here: reading a server's
certificate is exactly what happens during any normal HTTPS connection.
"""

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional

DEFAULT_PORTS = [443, 8443, 993, 995, 465, 636]
CONNECT_TIMEOUT = 3.0


def fetch_certificate_der(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> Optional[bytes]:
    """Connects via TLS to host:port and returns the certificate in DER format, or None if there's no TLS there."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to READ the certificate, not have the connection fail if it's invalid
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert(binary_form=True)
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
        return None


def expand_targets(cidr_or_host: str) -> Iterable[str]:
    """Accepts a single host/IP or a CIDR range (e.g. 192.168.1.0/28) and yields individual hosts."""
    try:
        network = ipaddress.ip_network(cidr_or_host, strict=False)
        for ip in network.hosts():
            yield str(ip)
    except ValueError:
        yield cidr_or_host  # not a CIDR: treated as a plain host/domain


def discover(targets: list[str], ports: Optional[list[int]] = None, max_workers: int = 50) -> list[dict]:
    """
    Scans a list of targets (hosts, IPs, or CIDR ranges) on the given
    ports and returns the DER certificates found, ready to be passed
    to analyzer.analyze_certificate().
    """
    ports = ports or DEFAULT_PORTS
    hosts: list[str] = []
    for t in targets:
        hosts.extend(expand_targets(t.strip()))

    jobs = [(h, p) for h in hosts for p in ports]
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(fetch_certificate_der, h, p): (h, p) for h, p in jobs}
        for future in as_completed(future_map):
            host, port = future_map[future]
            der = future.result()
            if der:
                results.append({"host": host, "port": port, "der": der})

    return results
