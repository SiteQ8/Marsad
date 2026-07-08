"""
CVSS v3.1 Base Score engine.

Faithful implementation of the FIRST.org CVSS v3.1 specification base-metric
equations. Parses a vector string and returns the base score plus severity band.
No external dependencies so it is trivially unit-testable and auditable.
"""
from __future__ import annotations
import math
from typing import Dict

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CVSSError(ValueError):
    """Raised when a vector string is malformed or missing base metrics."""


def parse_vector(vector: str) -> Dict[str, str]:
    """Turn 'CVSS:3.1/AV:N/AC:L/...' into a metric dict. Prefix optional."""
    metrics: Dict[str, str] = {}
    for part in vector.strip().split("/"):
        if not part or part.upper().startswith("CVSS:"):
            continue
        if ":" not in part:
            raise CVSSError(f"Malformed metric segment: {part!r}")
        k, v = part.split(":", 1)
        metrics[k.upper()] = v.upper()
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise CVSSError(f"Vector missing base metrics: {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS 3.1 roundup: nearest 0.1, correcting binary float noise."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score (0.0–10.0) from a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    try:
        iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
        )
    except KeyError as exc:
        raise CVSSError(f"Invalid metric value: {exc}") from exc

    if impact <= 0:
        return 0.0
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_band(score: float) -> str:
    """Map a base score to the qualitative severity rating (CVSS 3.1 §5)."""
    if score == 0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_and_band(vector: str) -> tuple[float, str]:
    s = base_score(vector)
    return s, severity_band(s)
