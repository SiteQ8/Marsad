# Marsad — API Reference

Base URL: `/api`. All responses are JSON. Interactive docs (Swagger UI) are served
at `/docs` and the OpenAPI schema at `/openapi.json` when the API is running.

## Authentication

Marsad uses JWT bearer tokens. Obtain one from `/api/auth/login`, then send it as
`Authorization: Bearer <token>` on every subsequent request.

### `POST /api/auth/login`
Form-encoded (`application/x-www-form-urlencoded`): `username`, `password`.
```json
{ "access_token": "eyJ…", "token_type": "bearer", "role": "analyst", "full_name": "SOC Analyst" }
```

### `GET /api/auth/me`
Returns the current user.

## Roles

| Role | Capabilities |
|---|---|
| `viewer` | Read everything (dashboards, findings, assets). No writes. |
| `analyst` | Everything a viewer can, plus create/import/triage findings, change status, manage assets & vulnerabilities. |
| `admin` | Everything, plus user management and asset deletion. |

A `403` is returned when a role is insufficient.

## Users (admin only)

- `GET /api/users` — list users
- `POST /api/users` — create `{ email, full_name, password, role }`

## Assets

- `GET /api/assets?q=` — list/search
- `POST /api/assets` *(analyst+)* — create
- `PUT /api/assets/{id}` *(analyst+)* — update
- `DELETE /api/assets/{id}` *(admin)* — delete

Asset body:
```json
{ "name": "web-prod-01", "ip_address": "203.0.113.10", "asset_type": "Server",
  "environment": "production", "business_unit": "Digital", "criticality": 4,
  "internet_facing": true }
```
`criticality` is 1 (low) – 4 (critical) and feeds the contextual risk score.

## Vulnerabilities

- `GET /api/vulnerabilities?q=` — list/search (sorted by CVSS desc)
- `POST /api/vulnerabilities` *(analyst+)* — create

On create, if `cvss_vector` is supplied it is validated and scored server-side;
an invalid vector returns `422`.
```json
{ "title": "Log4Shell", "cve_id": "CVE-2021-44228",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }
```

## Findings

- `GET /api/findings` — filters: `status`, `severity`, `asset_id`, `overdue`, `sort` (`risk|due|first_seen`)
- `GET /api/findings/{id}` — full detail with asset, vulnerability, comments, and computed `overdue`
- `POST /api/findings` *(analyst+)* — `{ asset_id, vulnerability_id, port?, detail?, assigned_to? }`
- `PATCH /api/findings/{id}/status` *(analyst+)* — `{ status, assigned_to? }`; auto-logs a comment and sets `resolved_at`
- `POST /api/findings/{id}/comments` *(analyst+)* — `{ body }`

Statuses: `open`, `triaged`, `in_progress`, `remediated`, `accepted`, `false_positive`.

## Scan import

### `POST /api/findings/import` *(analyst+)*
`multipart/form-data` with a `file` field. Auto-detects Nessus XML vs CSV.
```json
{ "source": "nessus", "findings_created": 42, "findings_updated": 8 }
```
Re-importing a later scan updates `last_seen` on existing findings and reopens any
that had been marked remediated but reappeared — it does not create duplicates.

**CSV columns** (case-insensitive, flexible): `host`/`hostname`/`name`, `ip`,
`cve`, `name`/`title`, `cvss_vector`, `port`, `severity`, `description`, `remediation`.

## Dashboard

### `GET /api/dashboard`
```json
{
  "totals": { "assets": 12, "vulnerabilities": 12, "open_findings": 45,
              "overdue": 36, "mttr_days": 21.7 },
  "by_severity": { "Critical": 21, "High": 13, "Medium": 11, "Low": 0, "Info": 0 },
  "by_status": { "open": 30, "triaged": 6, "remediated": 12, "accepted": 8 },
  "top_risks": [ { "id": 3, "risk_score": 100.0, "title": "PAN-OS …",
                   "cve": "CVE-2024-3400", "severity": "Critical",
                   "asset": "web-prod-01", "status": "open", "overdue": true } ]
}
```

## Health

`GET /api/health` → `{ "status": "ok", "app": "Marsad", "version": "1.0.0" }` (no auth).
