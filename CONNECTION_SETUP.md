# Connection Setup

This guide connects the browser, API, MongoDB, Groq chat and incident classification, alerts, and optional email/push services.

## 1. Requirements

- Node.js 22 or later and npm
- MongoDB Community Server or MongoDB Atlas
- Groq API key for chatbot and AI incident classification
- Optional SMTP account for email alerts
- Optional VAPID key pair for browser push alerts

## 2. Configure MongoDB and application settings

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

For a local MongoDB service, the example `MONGODB_URI` is:

```env
MONGODB_URI=mongodb://127.0.0.1:27017
DB_NAME=sentinel_ir
```

For Atlas, create a database user, allow access from the app host in Network Access, and set `MONGODB_URI` to the Atlas connection string. Use the database user's credentials; URL-encode special characters in a password when required. Keep `.env` private; it is ignored by Git.

For the Render deployment, configure the external Atlas URI in the service's `MONGODB_URI` secret. For a self-managed host, set `MONGODB_URI` to its reachable MongoDB connection string.

## 3. Configure the role accounts

Set strong unique values for:

```env
JWT_SECRET=<long-random-secret>
SUPERADMIN_EMAIL=<security-admin-email>
SUPERADMIN_PASSWORD=<strong-password>
SYSTEM_ADMIN_EMAIL=<systems-admin-email>
SYSTEM_ADMIN_PASSWORD=<strong-password>
ANALYST_EMAIL=<analyst-email>
ANALYST_PASSWORD=<strong-password>
EMPLOYEE_EMAIL=<employee-email>
EMPLOYEE_PASSWORD=<strong-password>
```

On startup, the server creates these users if their email does not already exist. Their role is assigned from the corresponding environment variable. New signups are employees. A new empty database also receives four demo systems and six sample incidents for queue/analytics views. Avoid using the classroom demo passwords on an internet-facing deployment.

## 4. Configure Groq chat and classification

Create a Groq API key in the Groq console and keep it only in the backend environment. The chatbot uses Groq; the server-side SDK is installed with the project dependencies (`groq-sdk`).

```env
GROQ_API_KEY=<your-groq-key>
GROQ_MODEL=openai/gpt-oss-120b
```

The browser sends chat messages to `/api/chat`; the backend loads a limited role-scoped incident context from MongoDB for incident-related questions, calls Groq, and returns the answer. Employees can only provide their own incidents to the chatbot; staff roles receive the incidents visible to their role. Incident submission also calls Groq to classify the report and recommend defensive response actions. The API key is never sent to the browser. Both features use `GROQ_MODEL`; check Groq's [current supported models](https://console.groq.com/docs/models) for available IDs. If Groq is not configured or returns invalid output, incident classification falls back to local keyword rules. Classification receives the incident description, affected system name, and attachment names/types; uploaded file contents are stored securely but are not sent to Groq. Chat context includes relevant incident descriptions and limited metadata, but not attachments, audit records, or user credentials.

## 5. Configure email notifications (optional)

To enable email, set SMTP values in `.env`:

```env
SMTP_HOST=<smtp-host>
SMTP_PORT=587
SMTP_USER=<smtp-user>
SMTP_PASS=<smtp-password>
SMTP_FROM=Sentinel IR <alerts@example.com>
```

If `SMTP_HOST` or credentials are missing, in-app and real-time notifications still work; email delivery is skipped. Your provider may require an app password or an approved sender.

## 6. Configure browser push (optional)

Generate a VAPID key pair with the `web-push` package:

```powershell
npx web-push generate-vapid-keys
```

Put the public/private pair and a contact address in `.env`:

```env
VAPID_PUBLIC_KEY=<public-key>
VAPID_PRIVATE_KEY=<private-key>
VAPID_SUBJECT=mailto:security@example.com
```

Restart the server, sign in from `http://localhost` or an HTTPS site, then choose **Enable push alerts**. Browsers require a secure context for push subscriptions; localhost is allowed for development. Private keys stay on the server.

## 7. Start the app

```powershell
npm install
npm start
```

Open `http://localhost:3000`. Check `GET http://localhost:3000/api/health`; it reports service status and whether Groq/email/push are configured.

The browser and Express app share an origin. The frontend uses relative `/api/...` URLs, and Socket.IO uses the same host. No separate CORS allow-list is needed for the included deployment.

## 8. Connection map

```text
Browser HTML/CSS/JS
  ├─ REST JSON + Bearer token ──────► Express API
  ├─ Socket.IO authenticated link ──► real-time incident alerts
  └─ service worker push ◄─────────── Web Push service

Express API
  ├─ MongoDB driver ────────────────► MongoDB (users, incidents, systems, audit, notifications)
  ├─ Groq SDK ──────────────────────► Groq API (chat + incident classification)
  ├─ Nodemailer ────────────────────► SMTP provider (optional)
  └─ web-push ──────────────────────► browser push endpoints (optional)
```

## 9. Postman examples

Set `baseUrl` to `http://localhost:3000`.

### Register an employee

`POST {{baseUrl}}/api/auth/register`, Body → raw → JSON:

```json
{
  "name": "Alex Employee",
  "email": "alex@example.com",
  "password": "StrongerDemoPass123!",
  "department": "Finance"
}
```

Copy the response `token`; set `Authorization: Bearer <token>` for protected routes.

### Sign in as a seeded role

`POST {{baseUrl}}/api/auth/login`:

```json
{
  "email": "<role-email-from-.env>",
  "password": "<role-password-from-.env>"
}
```

### Register an incident

Use an employee token. `POST {{baseUrl}}/api/incidents` as **form-data** with fields `title`, `description`, optional `systemId`, optional ISO `occurredAt`, and `evidence` file field (repeat for multiple files). Get valid system IDs from `GET {{baseUrl}}/api/systems`.

### Analyst/security admin operations

- `GET {{baseUrl}}/api/incidents`
- `PATCH {{baseUrl}}/api/incidents/<id>` with JSON such as `{"status":"Investigating","severity":"High"}`
- `POST {{baseUrl}}/api/incidents/<id>/tasks` with `{"title":"Review sign-in logs"}`
- `POST {{baseUrl}}/api/incidents/<id>/investigation` as form-data with `note` and optional `evidence` files
- `GET {{baseUrl}}/api/audit/<incidentId>`
- `GET {{baseUrl}}/api/analytics` (security admin)

System administrators own user access/role changes and system inventory writes. Security administrators can read the active analyst directory for assignment, update incident assignment/severity/status, and view the security posture dashboard. They cannot change user roles or edit system inventory. See [API.md](./API.md) for full request/role details.

## Troubleshooting

- **MongoDB refused connection:** start the local service or check the Atlas URI and network allow-list.
- **Atlas timeout:** verify cluster state, IP access, credentials, and encoded URI password.
- **Groq chat is unavailable:** check the backend `GROQ_API_KEY`, `GROQ_MODEL`, and outbound network access.
- **Incident classification falls back to local rules:** check the backend `GROQ_API_KEY`, `GROQ_MODEL`, and outbound network access. Local incident classification remains available without Groq.
- **Evidence upload rejected:** use an allowed format (PNG, JPG, PDF, TXT, LOG, CSV, DOCX), check the size limit, and ensure file bytes match the extension/type.
- **Email does not arrive:** inspect the server log; confirm SMTP host, port, auth, sender, and provider restrictions.
- **Push permission missing:** use localhost/HTTPS, allow notifications in the browser, and configure both VAPID keys.
- **No seeded role accounts:** check that each email/password is set in `.env` and that the app connects to the intended database.
