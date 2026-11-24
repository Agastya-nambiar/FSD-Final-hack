# Security and Testing Guide

## Security controls implemented

- Passwords are salted and hashed with Node.js `scrypt`; the server returns no password hash or salt.
- Signed JWT bearer tokens expire after 12 hours. Protected endpoints enforce role checks server-side.
- Employee incident access is scoped to incidents they reported; evidence downloads use the same access check.
- Authentication routes have a tighter rate limit; API requests have a general rate limit.
- Helmet sets browser security headers. The service disables the Express fingerprint header and limits JSON request size.
- Uploads use random server-side names, a format allow-list, per-file size/count limits, MIME/extension checks, basic file-signature checks, and non-public storage. Downloads are authenticated and sent with safe response headers.
- Database queries use MongoDB driver filters and ObjectId validation. User-supplied text is HTML-escaped in the client renderer.
- Critical incidents generate security-admin escalation alerts. Investigation actions are recorded with actor, role, action, details, and timestamp.
- Secrets are read from environment variables and `.env` is ignored by Git. The Render deployment uses a managed Node.js runtime and a persistent evidence disk.
- Socket.IO requires a signed token and joins user/role rooms. Push subscriptions are associated with a user.

## Manual verification checklist

Run these checks in a non-production database and with test accounts.

### Authentication and roles

1. Register an employee with a valid email and long password; confirm role is always `employee`.
2. Try short password, invalid email, duplicate email, and wrong-password sign-in; expect validation/conflict/auth errors.
3. Call a protected route without a token, with an invalid token, and after token expiry; expect `401`.
4. Call analyst-only/admin-only routes as an employee; expect `403`.
5. Verify system admin can manage roles/access and edit system inventory; verify security admin can view only the active analyst directory for assignment and cannot change roles or edit systems.
6. Verify only security admin can open the security posture dashboard; analysts and security admins can open the incident queue, while system admins cannot access incident records, audit trails, or evidence downloads.

### Incident flow and authorization

1. Create a report as an employee with a known system, occurrence timestamp, description, and a PNG or TXT attachment.
2. Confirm category/severity, response recommendations, duplicate hint, and report timestamp populate.
3. Attempt an unsupported extension, MIME mismatch, oversized file, and more than six files; expect rejection and no public file URL.
4. Sign in as a different employee and try to open the first employee's incident and evidence; expect `404`.
5. As an analyst, add a task, mark it in progress/done, add a note/evidence, change severity/status, and verify the ordered audit trail.
7. As security admin, assign an analyst and create/escalate a critical incident; verify assigned analyst and security-admin notifications.
8. Verify resolving an incident records `resolvedAt` and updates analytics.

### Alerts and integrations

1. Keep an analyst and security-admin browser session open. Submit a report in the employee session and verify real-time in-app notification.
2. With SMTP configured, verify email delivery. Without SMTP, verify app still works and logs no false success.
3. With VAPID configured on HTTPS/localhost, enable push and verify a critical alert reaches the browser.
4. With Groq configured, ask the assistant a defensive response question and submit a sample phishing report. Without Groq, verify the local classification fallback.
5. Confirm API key does not appear in browser source, local storage, or API response payloads.

### Analytics and API

1. Check category/severity/system/workload and 14-day trend counts against known test incidents.
2. Confirm mean first-response time is populated after triage and mean resolution after resolution.
3. Import routes from `API.md` into Postman and test status codes, multipart upload, token access, and error cases.
4. Check `GET /api/health` before and after Groq/SMTP/VAPID configuration.

## Test coverage status

This deliverable provides a manual acceptance checklist rather than an automated test suite. Integration verification requires a disposable MongoDB instance and configured Groq/SMTP/VAPID test credentials. Do not run test scenarios against real incident or production data.

## Operational limitations and next controls

- This project is a demonstration/reference implementation, not a certified SOC/SIEM platform. The system inventory does not collect host telemetry or replace endpoint monitoring.
- The evidence type checks reduce accidental uploads but do not scan files for malware. A real deployment should add an antivirus/sandbox scanning pipeline, quarantine, and retention/deletion policies.
- Keep the Groq key server-side. Incident descriptions and attachment names/types are sent to Groq for classification; relevant role-scoped incident descriptions/metadata are sent for incident-related chat questions. Uploaded file contents are not sent. Use only data your organization permits for model processing. Local classification rules work without a key.
- Use HTTPS, secret rotation, database least-privilege users, backups, audit retention controls, and provider monitoring in production.
- Access tokens are stored in browser local storage for this demo. A production deployment may prefer short-lived access tokens and secure, HttpOnly session cookies with CSRF protection.
- Email/push are optional integrations and require secrets, provider setup, and live delivery testing.
