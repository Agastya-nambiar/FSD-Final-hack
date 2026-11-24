# API Reference

Base URL locally: `http://localhost:3000`. All request and response bodies are JSON except evidence upload routes, which use `multipart/form-data`. Protected routes require `Authorization: Bearer <JWT>`. Tokens expire after 12 hours.

## Authentication

| Method | Route | Access | Body / response |
|---|---|---|---|
| `POST` | `/api/auth/register` | Public, rate limited | `{name,email,password,department?}`; always creates an `employee`. |
| `POST` | `/api/auth/login` | Public, rate limited | `{email,password}`; returns `{token,user}`. |
| `GET` | `/api/auth/me` | Signed in | Returns current safe user profile. |
| `GET` | `/api/health` | Public | App/database/integration configuration status. |

## Incident routes

| Method | Route | Access | Purpose |
|---|---|---|---|
| `POST` | `/api/incidents` | Employee | Multipart report. Fields: `title`, `description`, `systemId?`, `occurredAt?`, repeatable `evidence` (max 6). Groq/local triage and duplicate hint run during intake. Groq receives the text, affected system name, and attachment names/types, not file contents. |
| `GET` | `/api/incidents` | Employee, analyst, security admin | Employee sees own reports; analyst/security admin sees queue. Optional `status` and `severity` query filters. |
| `GET` | `/api/incidents/:id` | Employee, analyst, security admin | Read details; employees can only see reports they filed. |
| `PATCH` | `/api/incidents/:id` | Analyst, security admin | Set `status`, `severity`, `category`; security admin can also set `assignedAnalystId` (ID or `null`). Changes append audit entries. |
| `POST` | `/api/incidents/:id/tasks` | Analyst, security admin | JSON `{title,details?,assignedTo?}`; analysts assign work to themselves, security admins can target an analyst. |
| `PATCH` | `/api/incidents/:id/tasks/:taskId` | Analyst, security admin | JSON `{status:"Open"|"In Progress"|"Done"}`. |
| `POST` | `/api/incidents/:id/investigation` | Analyst, security admin | Multipart `note` and/or repeatable `evidence` files. |
| `GET` | `/api/audit/:incidentId` | Employee, analyst, security admin | Chronological incident audit events; employee access is owner-scoped. |
| `GET` | `/api/files/:storageName` | Employee, analyst, security admin | Download evidence after incident authorization check. |

Severity values: `Low`, `Medium`, `High`, `Critical`. Status values: `Reported`, `Triaged`, `Investigating`, `Contained`, `Resolved`, `Closed`. Category values: `Phishing`, `Malware`, `Unauthorized Access`, `Data Breach`, `Suspicious Network Activity`, `Other`.

## Users, systems, and analytics

| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/api/users` | System admin | List safe user profiles; password hashes are excluded. |
| `GET` | `/api/users?role=analyst` | Security admin | List active analysts for incident assignment only. |
| `PATCH` | `/api/users/:id` | System admin | Set `{active:boolean,department?,role?}`. Role may be one of the four supported roles. You cannot change your own role. |
| `GET` | `/api/systems` | Signed in | List monitored system inventory. |
| `POST` | `/api/systems` | System admin | Register a system with `{name,hostname,type,environment,owner,criticality}`. |
| `PATCH` | `/api/systems/:id` | System admin | Update system inventory/status fields. |
| `GET` | `/api/analytics` | Security admin | Aggregate category, severity, status, system, analyst workload, 14-day trend, mean first response, and mean resolution. |
| `GET` | `/api/similarweb-report` | Security admin | Qualitative Similarweb research brief and source links; no live Similarweb data. |

## Notifications, push, and Groq assistant

| Method | Route | Access | Purpose |
|---|---|---|---|
| `GET` | `/api/notifications` | Signed in | Current user's newest notifications. |
| `PATCH` | `/api/notifications/:id/read` | Signed in | Mark own notification read. |
| `GET` | `/api/push/public-key` | Signed in | Return configured VAPID public key, or `null`. |
| `POST` | `/api/push/subscribe` | Signed in | JSON `{subscription}` to save browser push endpoint. |
| `POST` | `/api/chat` | Signed in | JSON `{messages:[{role:"user"|"assistant",content}]}`; returns `{answer,databaseContextUsed}`. Incident-related questions receive a limited, role-scoped MongoDB context before the backend calls Groq. |

Socket.IO emits authenticated `notification` and `incident:updated` events. Email and push delivery are enabled only when SMTP/VAPID environment variables are configured.

## Common responses

- `200` success
- `201` resource created
- `400` invalid body, query, or evidence
- `401` missing, expired, or invalid token
- `403` insufficient role
- `404` missing or inaccessible resource
- `409` duplicate email / duplicate resource conflict
- `429` authentication or API rate limit
- `502` Groq service failure
- `500` unexpected server failure

Errors use `{ "message": "..." }`. The client must not treat AI output as an authorization decision or a replacement for analyst judgment.
