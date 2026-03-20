"""Human-readable output formatting for scan results."""

import json


# ANSI colour codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_DIM = "\033[2m"

STATUS_COLOURS = {
    "pass": _GREEN,
    "warning": _YELLOW,
    "fail": _RED,
    "error": _RED,
}

GRADE_COLOURS = {
    "A+": _GREEN, "A": _GREEN, "A-": _GREEN,
    "B+": _CYAN, "B": _CYAN, "B-": _CYAN,
    "C+": _YELLOW, "C": _YELLOW, "C-": _YELLOW,
    "D": _RED, "F": _RED,
}


def _colour(text: str, code: str, use_colour: bool = True) -> str:
    if not use_colour:
        return text
    return f"{code}{text}{_RESET}"


def print_scan_result(data: dict, use_colour: bool = True) -> None:
    """Print a formatted scan result to stdout."""
    domain = data.get("domain", "")
    score = data.get("securityScore", "?")
    grade = data.get("grade", "?")
    scan_date = data.get("scanDate", "")
    summary = data.get("summary", {})
    results = data.get("results", {})

    grade_col = GRADE_COLOURS.get(grade, "")

    print()
    print(_colour(f"  DNS Security Audit: {domain}", _BOLD, use_colour))
    print(_colour(f"  {scan_date}", _DIM, use_colour))
    print()
    print(
        f"  Score: {_colour(str(score), _BOLD, use_colour)}/100  "
        f"Grade: {_colour(grade, grade_col + _BOLD, use_colour)}"
    )
    print()

    critical = summary.get("criticalIssues", 0)
    warnings = summary.get("warnings", 0)
    passed = summary.get("passed", 0)

    print(
        f"  {_colour(str(passed), _GREEN, use_colour)} passed  "
        f"{_colour(str(warnings), _YELLOW, use_colour)} warnings  "
        f"{_colour(str(critical), _RED, use_colour)} critical"
    )
    print()

    if results:
        print(_colour("  Check Results", _BOLD, use_colour))
        print(_colour("  " + "-" * 40, _DIM, use_colour))
        for check, info in results.items():
            if not isinstance(info, dict):
                continue
            status = info.get("status", "").lower()
            col = STATUS_COLOURS.get(status, "")
            icon = {"pass": "✔", "warning": "⚠", "fail": "✘", "error": "✘"}.get(status, "·")
            details = info.get("details", "")
            record = info.get("record", "")
            label = check.upper().ljust(10)
            status_tag = _colour(f"[{status.upper()}]", col, use_colour).ljust(20 if use_colour else 8)
            print(f"  {_colour(icon, col, use_colour)} {label} {status_tag} {details}")
            if record:
                print(f"             {_colour(record, _DIM, use_colour)}")
    print()


def print_history(data: dict, use_colour: bool = True) -> None:
    """Print scan history table."""
    scans = data.get("scans", [])
    total = data.get("total", len(scans))

    print()
    print(_colour(f"  Scan History  ({total} total)", _BOLD, use_colour))
    print(_colour("  " + "-" * 55, _DIM, use_colour))

    header = f"  {'Domain':<35} {'Score':>6}  {'Grade':<5}  {'Date'}"
    print(_colour(header, _DIM, use_colour))
    print(_colour("  " + "-" * 55, _DIM, use_colour))

    for scan in scans:
        domain = scan.get("domain", "")
        score = scan.get("securityScore", "?")
        grade = scan.get("grade", "?")
        date = scan.get("scanDate", "")[:10]
        grade_col = GRADE_COLOURS.get(grade, "")
        print(
            f"  {domain:<35} {score:>6}  "
            f"{_colour(f'{grade:<5}', grade_col, use_colour)}  {date}"
        )
    print()


def print_json(data: dict) -> None:
    """Pretty-print raw JSON."""
    print(json.dumps(data, indent=2))
