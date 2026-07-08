# Marsad — Architecture

## Overview

Marsad is a three-tier web application:

```
┌──────────────┐     HTTPS      ┌──────────────────┐    SQL     ┌────────────┐
│   Browser    │ ─────────────▶ │   FastAPI (API)  │ ─────────▶ │ PostgreSQL │
│  SPA (nginx) │ ◀───── JSON ── │  uvicorn workers │ ◀───────── │  (or SQLite)│
└──────────────┘                └──────────────────┘            └────────────┘
      static assets                 JWT auth · RBAC                 findings,
      served by nginx               CVSS engine                     assets,
      /api proxied to API           scanner importers                users …
```

- **Frontend** — a dependency-free vanilla-JS single-page app. In production it is served by nginx, which also reverse-proxies `/api/*` to the API container. It has a built-in demo mode so it can run entirely offline (e.g. on GitHub Pages) against a bundled dataset.
- **API** — FastAPI + SQLAlchemy 2.0, stateless, horizontally scalable behind a load balancer. Auth is JWT bearer tokens; authorization is role-based (admin / analyst / viewer).
- **Database** — SQLite for zero-config local dev, PostgreSQL for production (swap via the `DATABASE_URL` env var; no code change).

## Backend layout

```
backend/app/
├── main.py          FastAPI app, router wiring, CORS, lifespan
├── config.py        env-driven settings (DB URL, secret, token TTL, SLA table)
├── database.py      SQLAlchemy engine + session dependency
├── models.py        ORM: User, Asset, Vulnerability, Finding, Comment, ScanImport
├── schemas.py       Pydantic v2 request/response contracts
├── auth.py          bcrypt hashing, JWT issue/verify, require_role() RBAC guard
├── cvss.py          CVSS v3.1 base-score engine (spec-faithful, dependency-free)
├── scoring.py       contextual risk (CVSS × asset criticality × exposure) + SLA
├── services.py      Nessus/CSV importers + shared finding-upsert (de-dup) logic
├── seed.py          demo dataset generator
└── routers/
    ├── auth.py      /api/auth/*  + /api/users/* (admin)
    ├── catalog.py   /api/assets/*  /api/vulnerabilities/*
    ├── findings.py  /api/findings/*  (workflow, comments, scan import)
    └── dashboard.py /api/dashboard   (aggregations)
```

## Key design decisions

**Finding = (Vulnerability × Asset).** A `Vulnerability` is a catalog entry scored once with CVSS. A `Finding` is that vulnerability observed on a specific asset — the atomic unit of remediation work, carrying status, SLA due date, and contextual risk. This separation means a re-scan updates existing findings (via de-duplication on asset+vuln+port) rather than creating duplicates, and lets one CVE be tracked across the whole estate.

**Contextual risk over raw CVSS.** CVSS says how bad a vulnerability is in the abstract. Enterprises need to know how bad it is *here*. Marsad multiplies the normalised CVSS by asset criticality (1–4) and a 1.25× exposure factor for internet-facing assets, yielding a 0–100 score used for prioritisation. A 9.8 on an isolated dev box ranks below a 7.5 on an internet-facing crown jewel.

**SLA-driven due dates.** Each finding's due date is derived from its severity via a configurable SLA table (Critical 7d, High 30d, Medium 90d, …). Overdue state is computed, never stored, so it's always correct.

**Stateless API.** No server-side sessions; JWTs carry identity and role. This keeps the API horizontally scalable — run N uvicorn workers behind a load balancer.

## Security notes

- Passwords are bcrypt-hashed; only hashes are stored.
- Every mutating endpoint is guarded by `require_role(...)`; viewers are strictly read-only.
- The default `MARSAD_SECRET_KEY` and seeded demo passwords are for local use only and **must** be overridden in any real deployment.
- CORS origins are configurable via `MARSAD_CORS`.

## Scaling path

The current design supports a straightforward path to larger scale: move the API behind an ALB with multiple uvicorn workers, use managed PostgreSQL with read replicas for dashboard queries, add a Redis cache for the dashboard aggregation, and push scanner ingestion to a background worker (Celery/RQ) for very large scan files.
