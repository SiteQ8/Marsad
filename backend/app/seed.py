"""
Seed Marsad with a realistic demo dataset.

Run:  python -m app.seed
Creates three role users and a mid-size company's vulnerability landscape so the
dashboard, prioritisation and remediation workflow are populated on first launch.

Default logins (change in production!):
  admin@marsad.local   / MarsadAdmin1
  analyst@marsad.local / MarsadAnalyst1
  viewer@marsad.local  / MarsadViewer1
"""
from __future__ import annotations
import datetime as dt
import random

from .database import SessionLocal, init_db
from . import models
from .auth import hash_password
from .cvss import base_score, severity_band
from .scoring import contextual_risk, sla_due_date

USERS = [
    ("admin@marsad.local", "Ali AlEnezi", "MarsadAdmin1", models.Role.admin),
    ("analyst@marsad.local", "SOC Analyst", "MarsadAnalyst1", models.Role.analyst),
    ("viewer@marsad.local", "Audit / Exec", "MarsadViewer1", models.Role.viewer),
]

ASSETS = [
    # name, ip, type, env, bu, criticality, internet_facing
    ("web-prod-01", "203.0.113.10", "Server", "production", "Digital", 4, True),
    ("web-prod-02", "203.0.113.11", "Server", "production", "Digital", 4, True),
    ("api-gateway", "203.0.113.20", "Application", "production", "Platform", 4, True),
    ("db-core-01", "10.0.5.10", "Database", "production", "Platform", 4, False),
    ("erp-sap", "10.0.5.30", "Application", "production", "Finance", 4, False),
    ("mail-relay", "10.0.6.5", "Server", "production", "IT", 3, True),
    ("vpn-concentrator", "203.0.113.40", "Network device", "production", "IT", 3, True),
    ("build-ci", "10.0.9.12", "Server", "staging", "Engineering", 2, False),
    ("dev-sandbox", "10.0.9.50", "Server", "dev", "Engineering", 1, False),
    ("fileshare-01", "10.0.7.20", "Server", "production", "Corporate", 3, False),
    ("k8s-worker-03", "10.0.8.33", "Server", "production", "Platform", 3, False),
    ("hr-portal", "203.0.113.60", "Application", "production", "HR", 3, True),
]

# title, cve, vector, remediation
VULNS = [
    ("OpenSSL 3.0 X.509 buffer overflow", "CVE-2022-3602",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", "Upgrade OpenSSL to 3.0.7+"),
    ("Apache Log4j2 RCE (Log4Shell)", "CVE-2021-44228",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Upgrade Log4j to 2.17.1+; set formatMsgNoLookups"),
    ("PAN-OS GlobalProtect command injection", "CVE-2024-3400",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Apply PAN-OS hotfix; rotate credentials"),
    ("Exposed database with no authentication", None,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Enable auth, restrict to internal network"),
    ("TLS 1.0/1.1 enabled", None,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "Disable legacy TLS; enforce TLS 1.2+"),
    ("SMBv1 protocol enabled", "CVE-2017-0144",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Disable SMBv1; apply MS17-010"),
    ("Outdated jQuery with known XSS", "CVE-2020-11022",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Upgrade jQuery to 3.5.0+"),
    ("SSH weak ciphers permitted", None,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "Restrict to strong ciphers/MACs"),
    ("Missing OS security patches (multiple)", None,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "Apply vendor patch baseline"),
    ("Default admin credentials on appliance", None,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Change default credentials; enforce MFA"),
    ("Publicly accessible .git directory", None,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Block access to .git; rotate any leaked secrets"),
    ("Verbose error messages leak stack traces", None,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Disable debug mode in production"),
]


def run():
    init_db()
    db = SessionLocal()
    if db.query(models.User).first():
        print("Database already seeded — skipping. (Wipe marsad.db to reseed.)")
        db.close()
        return

    for email, name, pw, role in USERS:
        db.add(models.User(email=email, full_name=name, role=role, hashed_password=hash_password(pw)))

    assets = []
    for name, ip, typ, env, bu, crit, inet in ASSETS:
        a = models.Asset(name=name, ip_address=ip, hostname=name, asset_type=typ,
                         environment=env, business_unit=bu, criticality=crit,
                         internet_facing=inet, owner="IT Ops")
        db.add(a); assets.append(a)

    vulns = []
    for title, cve, vector, remediation in VULNS:
        score = base_score(vector)
        v = models.Vulnerability(title=title, cve_id=cve, cvss_vector=vector,
                                cvss_score=score, severity=severity_band(score),
                                remediation=remediation)
        db.add(v); vulns.append(v)
    db.flush()

    # Distribute findings across assets with some realism + a spread of statuses/ages.
    random.seed(7)
    statuses = ([models.FindingStatus.open] * 6 + [models.FindingStatus.triaged] * 2 +
                [models.FindingStatus.in_progress] * 2 + [models.FindingStatus.remediated] * 2 +
                [models.FindingStatus.accepted])
    now = dt.datetime.now(dt.timezone.utc)
    count = 0
    for asset in assets:
        for vuln in random.sample(vulns, random.randint(3, 7)):
            age = random.randint(1, 200)
            first_seen = now - dt.timedelta(days=age)
            status = random.choice(statuses)
            resolved = None
            if status in (models.FindingStatus.remediated, models.FindingStatus.accepted):
                resolved = first_seen + dt.timedelta(days=random.randint(2, 40))
            f = models.Finding(
                asset_id=asset.id, vulnerability_id=vuln.id,
                status=status, port=str(random.choice([22, 80, 443, 445, 3389, 8080])),
                risk_score=contextual_risk(vuln.cvss_score, asset.criticality, asset.internet_facing),
                first_seen=first_seen, last_seen=now,
                due_date=sla_due_date(vuln.severity, first_seen), resolved_at=resolved,
                assigned_to=random.choice(["", "IT Ops", "AppSec", "Platform"]),
            )
            db.add(f); count += 1

    db.commit()
    print(f"Seeded {len(assets)} assets, {len(vulns)} vulnerabilities, {count} findings, {len(USERS)} users.")
    print("Login: admin@marsad.local / MarsadAdmin1")
    db.close()


if __name__ == "__main__":
    run()
