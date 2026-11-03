# SAMS — School Attendance Management System

SAMS is a Flask and SQLite application for school attendance operations. It includes a public system homepage, a student check-in kiosk, separate administrator and security workspaces, controlled gate sessions and handovers, and an individual student portal.

## Run on Windows

Open PowerShell in this folder:

```powershell
cd C:\Users\HP\OneDrive\Desktop\SAMS\analyze-attendance
```

Install dependencies if needed:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Set a local secret key for this PowerShell session, then create the first administrator. The command prompts for the administrator name, username, and password; SAMS does not ship with a default password.

```powershell
$env:SAMS_SECRET_KEY = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
.\.venv\Scripts\python.exe -m flask --app run.py create-admin
```

Start SAMS:

```powershell
.\.venv\Scripts\python.exe run.py
```

The browser opens the public homepage at `http://127.0.0.1:5000/`. The main entry points are:

- `/` — system homepage
- `/gate` — student check-in kiosk; check-in requires an active gate session
- `/admin/login` — administrator sign-in
- `/security/login` — individual security staff sign-in
- `/student/login` — student attendance portal
- `/student/activate` — activate student access with an administrator-issued code

To hand a student an activation code, sign in as an administrator, open that student's record, and select **Generate one-time code**. Give the code directly to the student. It expires after 14 days and works once. Students choose their own password during activation.

## Database and backups

The SQLite database is stored at `instance/sams.db`. Schema migrations are additive and create a timestamped SQLite backup before changing the schema. Existing attendance remains available; historical rows keep a null gate-session reference.

Do not delete `instance/sams.db` to resolve a startup or migration error. Keep backups in a protected location because they contain student data.

## Verification

Run the workflow suite from PowerShell:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
```

## Deployment configuration

For production, set a persistent, random `SAMS_SECRET_KEY` outside the source code, set `SAMS_ENV=production`, and serve SAMS behind HTTPS. Production mode requires a configured secret and enables secure session cookies. Use a production WSGI server and back up the database using an approved protected storage process.

The teacher workspace remains planned and is not exposed as a working feature.
