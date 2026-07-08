"""Contextual risk scoring + SLA tests."""
import datetime as dt

from app.scoring import contextual_risk, sla_due_date, is_overdue


def test_criticality_raises_risk():
    low = contextual_risk(7.5, criticality=1, internet_facing=False)
    high = contextual_risk(7.5, criticality=4, internet_facing=False)
    assert high > low


def test_internet_facing_multiplier():
    internal = contextual_risk(6.0, 2, internet_facing=False)
    external = contextual_risk(6.0, 2, internet_facing=True)
    assert external == round(internal * 1.25, 1)


def test_risk_capped_at_100():
    assert contextual_risk(10.0, 4, True) == 100.0


def test_sla_due_dates():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert (sla_due_date("Critical", now) - now).days == 7
    assert (sla_due_date("High", now) - now).days == 30
    assert (sla_due_date("Low", now) - now).days == 180


def test_overdue_logic():
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5)
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)
    assert is_overdue("open", past) is True
    assert is_overdue("open", future) is False
    # resolved states are never overdue
    assert is_overdue("remediated", past) is False
    assert is_overdue("accepted", past) is False
