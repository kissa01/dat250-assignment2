# DAT250 SecureApp - Assignment 2

Our fixed version of the DAT250 student app (FastAPI, PostgreSQL, Nginx, MailHog, phpPgAdmin). Five vulnerabilities from Assignment 1 are fixed. The report is in [docs/RAPPORT.pdf](docs/RAPPORT.pdf). The original app is commit `c089832` of https://github.com/ocatak/UiS-Vulnerable-Student-App.

Run it locally only. All ports are bound to `127.0.0.1`.

## Run

Needs Docker Desktop.

```bash
git clone https://github.com/kissa01/dat250-assignment2.git
cd dat250-assignment2
docker compose up --build -d --wait
docker compose down
```

`docker compose down -v` also resets the database.

| Service | URL |
| --- | --- |
| App | http://localhost:18181 |
| MailHog | http://localhost:8025 |
| phpPgAdmin (host `db`, user/password `dat250`) | http://localhost:8081 |

## Test accounts

| Role | Email | Password |
| --- | --- | --- |
| admin | admin@dat250.local | Admin123 |
| teacher | teacher@dat250.local | Teacher123 |
| TA | ta@dat250.local | TA123 |
| student | alice@student.uis.no | Alice123 |
| student | bob@student.uis.no | Bob123 |
| student | charlie@student.uis.no | Charlie123 |

## Fixed

| ID | Vulnerability | Where |
| --- | --- | --- |
| F01 | Account enumeration | `auth_routes.py` |
| F02 | Role escalation | `profile_routes.py`, `admin_routes.py` |
| F04 | Unauthorized grade read and write | `grade_routes.py`, `admin_routes.py` |
| F05 | SQL injection in admin search | `admin_routes.py` |
| F07 | Stored XSS in messages | `dashboard.html`, `messages.html`, `message_detail.html` |

Other vulnerabilities (for example SSRF and cookie flags) are not fixed.

## Testing

The `curl` commands and results are in section 5 of the report. Check stored values with:

```bash
docker compose exec db psql -U dat250 -d dat250 -c "SELECT id, email, role FROM users"
```

Group: Kristian Bruvik Leine (290625), Kyrre Elias Bjørkli (283466)
