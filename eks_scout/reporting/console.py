"""Console output for scan results."""
import sys

from eks_scout.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

# ANSI color codes — disabled automatically when output is not a TTY.
_USE_COLOR = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

_COLORS = {
    SEVERITY_CRITICAL: '\033[1;91m',  # Bold bright red
    SEVERITY_HIGH:     '\033[91m',    # Red
    SEVERITY_MEDIUM:   '\033[93m',    # Yellow
    SEVERITY_LOW:      '\033[96m',    # Cyan
    SEVERITY_INFO:     '\033[37m',    # Light gray
}
_BOLD = '\033[1m'
_DIM = '\033[2m'
_RESET = '\033[0m'


def _c(text, code):
    """Apply ANSI color code if color output is enabled."""
    if not _USE_COLOR:
        return str(text)
    return f"{code}{text}{_RESET}"


def _severity(sev):
    """Color a severity label."""
    return _c(sev, _COLORS.get(sev, ''))


def _bar(count, max_count, width=20):
    """Render a proportional bar chart segment."""
    if max_count == 0:
        return ''
    filled = max(1, round(count / max_count * width))
    return '\u2588' * filled


def print_summary(findings, suppressed_count=0, combos=None, duration=None):
    """Print a severity summary and combo highlights to the console.

    Args:
        findings: List of active finding dicts.
        suppressed_count: Number of suppressed findings.
        combos: List of combo result dicts from combo analysis.
        duration: Optional timedelta of scan duration.
    """
    severity_order = [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]

    if not findings:
        print(f"\n{_c('No findings to report.', _DIM)}")
        if suppressed_count:
            print(f"  {_c(f'({suppressed_count} findings suppressed by configuration)', _DIM)}")
        return

    severity_counts = {}
    for f in findings:
        sev = f['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    max_count = max(severity_counts.values()) if severity_counts else 0

    # Executive summary line
    crit = severity_counts.get(SEVERITY_CRITICAL, 0)
    high = severity_counts.get(SEVERITY_HIGH, 0)
    total = len(findings)

    print()
    print(_c('=' * 60, _DIM))
    print(_c('  SCAN RESULTS', _BOLD))
    print(_c('=' * 60, _DIM))

    # Headline stat
    if crit > 0:
        print(f"  {_c(f'{crit} CRITICAL', _COLORS[SEVERITY_CRITICAL])} and "
              f"{_c(f'{high} HIGH', _COLORS[SEVERITY_HIGH])} severity findings "
              f"out of {_c(total, _BOLD)} total")
    elif high > 0:
        print(f"  {_c(f'{high} HIGH', _COLORS[SEVERITY_HIGH])} severity findings "
              f"out of {_c(total, _BOLD)} total")
    else:
        print(f"  {_c(total, _BOLD)} findings (no Critical or High severity)")

    if duration:
        print(f"  Scan duration: {duration}")

    # Severity breakdown with bars
    print()
    for sev in severity_order:
        count = severity_counts.get(sev, 0)
        if count == 0:
            continue
        bar = _bar(count, max_count)
        color = _COLORS.get(sev, '')
        label = f"{sev:<15}"
        print(f"  {_severity(label)} {_c(bar, color)} {count}")

    if suppressed_count:
        print(f"  {_c(f'Suppressed', _DIM):<15} {_c('', _DIM)} {suppressed_count}")

    # Combo analysis summary
    if combos:
        workload_keys = {c['workload_key'] for c in combos}

        print()
        print(_c('-' * 60, _DIM))
        print(f"  {_c('HIGH-RISK COMBINATIONS', _BOLD)} "
              f"({len(combos)} across {len(workload_keys)} workloads)")
        print(_c('-' * 60, _DIM))

        # Show top combos
        for combo in combos[:5]:
            sev = combo['risk_level']
            print(f"  {_severity(f'[{sev}]')} {combo['title']}")
            print(f"         {_c(combo['workload_key'], _DIM)}")
        if len(combos) > 5:
            print(f"  {_c(f'... and {len(combos) - 5} more', _DIM)}")

    print(_c('=' * 60, _DIM))
    print()
