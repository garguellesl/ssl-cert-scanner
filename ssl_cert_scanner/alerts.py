"""
alerts.py
Classifies results by severity and prints them as a colored console
report, plus an aggregate summary suitable for a CI pipeline.
"""

COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"

_COLOR_BY_LEVEL = {
    "expired": COLOR_RED,
    "critical": COLOR_RED,
    "warning": COLOR_YELLOW,
    "ok": COLOR_GREEN,
}


def colorize(text: str, level: str) -> str:
    return f"{_COLOR_BY_LEVEL.get(level, '')}{text}{COLOR_RESET}"


def print_report(results: list[dict]) -> dict:
    """Prints the report and returns an aggregate summary (useful for CI/CD)."""
    print(f"{'HOST':30} {'PORT':7} {'DAYS':6} {'STATUS':10} FLAGS")
    print("-" * 95)

    for r in sorted(results, key=lambda x: x["days_until_expiry"]):
        level = r["status"]
        line = (
            f"{r['host']:30} {r['port']:<7} {r['days_until_expiry']:<6} "
            f"{level:10} {', '.join(r['flags']) or '-'}"
        )
        print(colorize(line, level))

    summary = {"total": len(results), "expired": 0, "critical": 0, "warning": 0, "ok": 0}
    for r in results:
        summary[r["status"]] += 1

    print("-" * 95)
    print(
        f"Total: {summary['total']} | "
        f"Expired: {summary['expired']} | "
        f"Critical: {summary['critical']} | "
        f"Warning: {summary['warning']} | "
        f"OK: {summary['ok']}"
    )
    return summary
