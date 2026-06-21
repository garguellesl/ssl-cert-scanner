"""
cli.py
Command-line entry point.

Examples:
    python -m ssl_cert_scanner --host example.com
    python -m ssl_cert_scanner --cidr 192.168.1.0/28 --ports 443,8443
    python -m ssl_cert_scanner --targets examples/targets.txt --json report.json --csv report.csv
"""

import argparse
import sys
from pathlib import Path

from . import alerts, analyzer, exporters, scanner


def _load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.targets:
        targets.extend(Path(args.targets).read_text().splitlines())
    if args.cidr:
        targets.append(args.cidr)
    if args.host:
        targets.append(args.host)
    return [t for t in targets if t.strip() and not t.strip().startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SSL/TLS certificate scanner")
    parser.add_argument("--targets", help="File with hosts/IPs/CIDRs, one per line")
    parser.add_argument("--cidr", help="CIDR range to scan, e.g. 192.168.1.0/28")
    parser.add_argument("--host", help="Single host to scan")
    parser.add_argument("--ports", default="443", help="Comma-separated ports, e.g. 443,8443")
    parser.add_argument("--json", help="Output path to export as JSON")
    parser.add_argument("--csv", help="Output path to export as CSV")
    parser.add_argument("--workers", type=int, default=50, help="Concurrent threads (default: 50)")
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with code 1 if there are critical/expired certificates (useful in CI/CD)",
    )
    args = parser.parse_args(argv)

    targets = _load_targets(args)
    if not targets:
        parser.error("Provide at least --targets, --cidr, or --host")

    ports = [int(p) for p in args.ports.split(",")]

    print(f"Scanning {len(targets)} target(s) on ports {ports}...")
    raw_certs = scanner.discover(targets, ports=ports, max_workers=args.workers)
    print(f"{len(raw_certs)} certificate(s) found. Analyzing...\n")

    results = [analyzer.analyze_certificate(c["der"], c["host"], c["port"]) for c in raw_certs]

    summary = alerts.print_report(results)

    if args.json:
        exporters.export_json(results, args.json)
        print(f"\nJSON exported to {args.json}")
    if args.csv:
        exporters.export_csv(results, args.csv)
        print(f"CSV exported to {args.csv}")

    if args.fail_on_critical and (summary["critical"] or summary["expired"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
