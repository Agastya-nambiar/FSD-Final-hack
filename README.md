# Sentinel IR — Cybersecurity Incident Response

Sentinel IR is a full-stack security incident reporting and response application. It uses HTML, CSS, and vanilla JavaScript in the browser, with Node.js/Express APIs and MongoDB storage. Groq powers both the cybersecurity chat assistant and AI incident classification (`GROQ_API_KEY`).

## What is included

- Employee registration and role-specific sign-in for employees, analysts, system administrators, and security administrators.
- Distinct admin scopes: system admins manage user roles/access and system inventory; security admins manage incident assignments/escalation and the security posture dashboard.
- Incident reporting with affected system, occurrence time, description, screenshot/evidence attachments, and automatic category/severity recommendations.
- Similarity-based duplicate hints, analyst assignment, investigation tasks, evidence and notes, status changes, critical incident escalation, and a chronological audit timeline.
- Role-based access checks in API middleware, password hashing, signed API tokens, request rate limits, secure headers, upload limits/type checks, and private evidence downloads.
- Live in-app alerts over Socket.IO, optional email through SMTP, and optional browser push through VAPID.
- Security posture analytics for categories, severity, affected systems, workload, historical trend, and response/resolution times.
- Groq chat assistant with role-scoped MongoDB incident context, plus incident classification with a local rules fallback when no Groq key is set or AI classification fails.
- Similarweb market research report, database/API/security documentation, and native Node.js deployment configuration.

## Run locally

Requirements: Node.js 22+, npm, and MongoDB local/Atlas.

```powershell
Copy-Item .env.example .env
npm install
npm start
```

Open `http://localhost:3000`. Configure `MONGODB_URI`, role passwords, and `GROQ_API_KEY` in `.env`. More complete setup, optional mail/push, Postman examples, and troubleshooting are in [CONNECTION_SETUP.md](./CONNECTION_SETUP.md).

## Demo accounts

On a new database, the server seeds demo employee, analyst, system admin, and security admin accounts from `.env`, along with four example systems and six demo incidents. The example file contains classroom demo passwords. Change them before deployment. Employees can also register through the app; the registration endpoint always assigns the employee role.

## Deploy as a native Node.js service

See [DEPLOYMENT.md](./DEPLOYMENT.md). The project includes a Render Blueprint for a native Node.js web service, with MongoDB Atlas and persistent evidence storage configured separately.

## Documentation

- [Connection setup](./CONNECTION_SETUP.md)
- [API reference](./API.md)
- [Database design](./DATABASE_DESIGN.md)
- [Security and testing guide](./SECURITY_TESTING.md)
- [Deployment guide](./DEPLOYMENT.md)
- [Similarweb analysis report](./SIMILARWEB_ANALYSIS.md)

## Prototype boundaries

Endpoint monitoring is represented by system inventory and heartbeat fields; it does not install agents or collect telemetry from real computers. Incident classification uses Groq when configured and a transparent keyword-based fallback otherwise. Classification considers report text and attachment names/types; it does not inspect uploaded file contents. Similarweb research is a qualitative report with cited product sources; it does not claim live Similarweb API data or traffic analytics for this private app.
