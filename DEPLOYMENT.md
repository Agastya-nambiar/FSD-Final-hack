# Native Node.js Deployment Guide

This project is prepared for a native Node.js web service on Render. It uses MongoDB Atlas for the database and a persistent service disk for uploaded evidence. It is not configured for a container-based deployment.

## 1. Prepare the source repository

Render Blueprints deploy from a connected Git repository. Commit this project folder to a private GitHub/GitLab repository and connect that repository in Render. The included `render.yaml` creates one Node.js web service and prompts for required secrets.

Required external setup:

- A Render account and a connected Git provider
- A MongoDB Atlas cluster with a database user and network access for Render
- A Groq API key for the chat assistant and AI incident classification
- SMTP/VAPID settings if email or browser push should be enabled

## 2. Configure MongoDB Atlas

1. Create an Atlas cluster and a database user with access limited to the `sentinel_ir` database.
2. In Atlas Network Access, allow connections from the Render service. Use the narrowest safe access policy supported by your Atlas setup.
3. Copy the Node.js connection string and URL-encode reserved characters in the username/password.
4. Set `MONGODB_URI` as a secret environment variable for the Render service. Example shape only:

   ```text
   mongodb+srv://<db-user>:<encoded-password>@<cluster-host>/sentinel_ir?retryWrites=true&w=majority
   ```

Do not commit database credentials.

## 3. Create the Render service

1. Push the project to your connected Git provider.
2. In Render, choose **New → Blueprint** and select the repository.
3. Review `render.yaml`. It uses the native Node runtime, `npm install`, and `npm start`.
4. Provide all prompted secret environment variables: `MONGODB_URI`, `JWT_SECRET`, and the seeded employee/analyst/system-admin/security-admin emails and passwords.
5. Add `GROQ_API_KEY` for chatbot responses and AI incident classification. Add SMTP and VAPID secrets only if those channels are configured.
6. Create/apply the Blueprint. After the first deploy, use the Render URL to test sign-in and `/api/health`.

Render's default service filesystem is ephemeral. The Blueprint attaches a persistent disk at `/opt/render/project/src/data/uploads`, the app's evidence directory. Persistent disks require a paid web service and have deployment/scaling limitations; check the current Render plan and disk terms before creating the service. If the project must run on a free or horizontally scaled service, change evidence storage to a private object store such as an S3-compatible bucket instead of local disk.

## 4. Configure environment variables

The Blueprint has placeholders for secrets. Use long, unique values for:

- `JWT_SECRET`
- `SUPERADMIN_PASSWORD`
- `SYSTEM_ADMIN_PASSWORD`
- `ANALYST_PASSWORD`
- `EMPLOYEE_EMAIL`
- `EMPLOYEE_PASSWORD`
- `MONGODB_URI`
- `GROQ_API_KEY` (chat assistant)
- `GROQ_MODEL` (optional; defaults to `openai/gpt-oss-120b`)
- `SMTP_PASS` (optional)
- `VAPID_PRIVATE_KEY` (optional)

Change the demo addresses to organization-controlled test accounts. Keep the Groq key server-side; the browser never receives it. Incident descriptions and attachment names/types are sent to Groq for classification. Relevant incident descriptions and limited metadata are also sent for incident-related chatbot questions, scoped to the signed-in user's role. Uploaded file contents are not sent to the model. Use only data your organization permits for model processing.

## 5. Validate deployment

1. Open `https://<render-service-url>/api/health`; confirm `status` is `ok` and `database` is `connected`.
2. Register a regular employee account and confirm it receives the employee role.
3. Sign in to each seeded staff account and verify role-specific pages/API actions.
4. Submit a report with a safe test attachment, then check the file still opens after a service restart/redeploy.
5. Test analyst assignment, critical escalation, audit entries, dashboard analytics, and Similarweb research links.
6. If configured, test Groq chat and classification, email, push, and Socket.IO using separate browser sessions.

## 6. Ongoing operations

- Back up MongoDB Atlas and evidence files together; a DB restore without evidence leaves broken references.
- Review Render logs and health checks after updates.
- Rotate keys if exposed. Keep staff role accounts non-public.
- Review file retention, account deactivation, audit retention, and deletion policies before using real incidents.
- For stronger production hardening, add malware scanning/quarantine, object storage, secure HttpOnly sessions, and identity provider integration.

## 7. If using another native Node host

Use Node.js 22+, install packages with `npm install`, and start the app with `npm start`. Configure the environment variables from `.env.example`, set the service's port through `PORT`, provide an external MongoDB URI, allow WebSocket upgrades for Socket.IO, and mount persistent storage at the `data/uploads` directory. Use HTTPS for browser push and production sessions.
