# CDLSHS FeedTrack — SBFP Monitoring

School-based feeding program monitoring app with login, QR scanner, attendance, BMI charts, and Excel export.

## Files
- `code2.html` — single-file frontend (login, dashboard, QR, charts, Excel export)
- `feedtrack-server.ps1` — PowerShell backend (auth + static file server)
- `feedtrack-server.json` — config (users, SMTP) — **created locally, never committed**
- `feedtrack-auth-state.json` — sessions & password hashes — **created locally, never committed**

## Local run
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File feedtrack-server.ps1
# Open: http://localhost:8765/code2.html
```

## Deploy to Render (Docker Web Service)
1. Push this repo to GitHub.
2. In Render, create a **Web Service** from this repo, select Docker.
3. Add Environment Variables (from `feedtrack-server.json`):
   - `SMTP_HOST`, `SMTP_PORT`, `SSL`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
   - `USERS_JSON` (optional, if overriding seeded users)
4. Add a **Persistent Disk** mounted at `/app` so `feedtrack-auth-state.json` survives redeploys.
5. Deploy. Open the Render URL.

> ⚠️ Note: Attendance records live in **browser localStorage**, not on the server. Each device has its own copy. Records do not sync across devices.

## Login (default seeded accounts)
- bernabejace21@gmail.com / CDLSHS2026
- headadvisor@cdlshs.edu.ph / CDLSHS2026
- rizza.enriquez@cdlshs.edu.ph / CDLSHS2026