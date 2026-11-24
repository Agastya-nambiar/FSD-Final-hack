# Database Design

MongoDB database name is configured by `DB_NAME` (default `sentinel_ir`). The application creates the following collections and indexes at startup.

## Collections

### `users`

`{ _id, name, email, salt, passwordHash, role, department, active, createdAt, lastLoginAt }`

Roles: `employee`, `analyst`, `system_admin`, `security_admin`. Email has a unique index. Password material uses per-user salt and Node.js scrypt; API responses never include `salt` or `passwordHash`.

### `systems`

`{ _id, name, hostname, type, environment, owner, criticality, status, lastHeartbeatAt, createdAt, updatedAt, createdBy }`

Hostname has a unique index. This prototype stores a system inventory and heartbeat timestamp. It does not install endpoint agents or collect operating system telemetry.

### `incidents`

`{ _id, incidentCode, title, description, category, severity, severitySource, confidence, recommendations, duplicateOf, duplicateScore, status, systemId, systemSnapshot, reporterId, reporterName, occurredAt, reportedAt, firstResponseAt, resolvedAt, assignedAnalystId, assignedAnalystName, tasks[], investigationNotes[], attachments[], audit[], createdAt, updatedAt }`

An incident stores a snapshot of the system label so historic incidents remain readable if an asset is renamed. `tasks`, `investigationNotes`, evidence metadata, and a concise `audit` timeline are embedded for direct incident-detail rendering. A separate `audit_logs` collection provides chronological query and retention support.

### `audit_logs`

`{ _id, incidentId, actorId, actorName, actorRole, action, details, createdAt }`

This is append-only through the application routes. Index: `{ incidentId: 1, createdAt: 1 }`.

### `notifications`

`{ _id, userId, incidentId, title, message, kind, read, createdAt }`

Index: `{ userId: 1, read: 1, createdAt: -1 }`.

### `push_subscriptions`

`{ _id, userId, subscription, updatedAt }`

Stores browser Push API subscriptions. Index: `{ userId: 1, subscription.endpoint: 1 }` unique.

### Evidence files

Files are stored outside MongoDB under `data/uploads/` using random UUID-based filenames. MongoDB stores `storageName`, display filename, verified MIME type, size, and upload time. Files are downloaded through an authenticated incident-scoped route, not served as public static files. The Render Blueprint mounts a persistent disk at this directory.

## Relationships

```text
users 1 ── * incidents (reporterId)
users 1 ── * incidents (assignedAnalystId)
systems 1 ── * incidents (systemId)
incidents 1 ── * audit_logs
incidents 1 ── * notifications
users 1 ── * notifications
users 1 ── * push_subscriptions
incidents 1 ── * tasks / investigationNotes / evidence metadata (embedded)
```

## Indexes

- `users.email` unique
- `systems.hostname` unique
- `incidents.incidentCode` unique
- `incidents.status, severity, updatedAt` for queue views
- `incidents.systemId, reportedAt` for system analytics
- `audit_logs.incidentId, createdAt` for audit history
- `notifications.userId, read, createdAt` for notification inboxes
- `push_subscriptions.userId, subscription.endpoint` unique
