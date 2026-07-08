"""CVSS v3.1 engine tests — validated against FIRST.org published example scores."""
import pytest

from app.cvss import base_score, severity_band, parse_vector, CVSSError

# (vector, expected base score) — all independently verifiable on FIRST.org calculator.
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # unauth RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope-changed RCE (Log4Shell-class)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # network DoS
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),   # low-impact local
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local priv-esc
]


@pytest.mark.parametrize("vector,expected", KNOWN)
def test_known_vectors(vector, expected):
    assert base_score(vector) == expected


def test_prefixless_vector_accepted():
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_severity_bands():
    assert severity_band(0.0) == "Info"
    assert severity_band(3.9) == "Low"
    assert severity_band(6.9) == "Medium"
    assert severity_band(8.9) == "High"
    assert severity_band(9.8) == "Critical"


def test_missing_metric_raises():
    with pytest.raises(CVSSError):
        parse_vector("AV:N/AC:L")


def test_invalid_metric_value_raises():
    with pytest.raises(CVSSError):
        base_score("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
