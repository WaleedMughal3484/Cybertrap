
# CyberTrap 🛡️

### SSH Honeypot & Threat Intelligence Platform

CyberTrap is a full-stack cybersecurity project designed to capture,
analyze, and visualize suspicious SSH activity using a simulated
Linux server.

The project integrates the Cowrie SSH honeypot with Python,
FastAPI, SQLite, and React to demonstrate security monitoring,
rule-based threat detection, and incident investigation.

## Features

- SSH honeypot powered by Cowrie
- Collection of authentication and command events
- Automatic JSON log ingestion
- Duplicate-event prevention using SHA-256
- SQLite database for security event storage
- REST API built with FastAPI
- React security monitoring dashboard
- Interactive charts and event filtering
- Brute-force login detection
- Suspicious command identification
- Login-after-failure detection
- Potential file-transfer detection
- Automated unit and API tests

## Technology Stack

| Component | Technology |
|---|---|
| Honeypot | Cowrie |
| Containerization | Docker |
| Backend | Python, FastAPI |
| Database | SQLite |
| Frontend | React, Vite |
| Visualization | Recharts |
| Testing | pytest, FastAPI TestClient |

## Architecture

```text
SSH Test Connection
        |
        v
Cowrie Honeypot (Docker)
        |
        v
Cowrie JSON Logs
        |
        v
Python Automatic Log Collector
        |
        v
SQLite Database
        |
        v
FastAPI REST API
        |
        +----> Threat Detection Engine
        |
        v
React Security Dashboard
```

## Detection Rules

| Rule | Description | Severity |
|---|---|---|
| SSH_BRUTE_FORCE | Five failed logins in five minutes | High |
| LOGIN_AFTER_FAILURE | Successful login after recent failures | High |
| SUSPICIOUS_COMMAND | Detects selected suspicious shell commands | Medium |
| POTENTIAL_DOWNLOAD | Detects file-transfer-capable commands | High |

Detection rules identify indicators of potentially suspicious behavior.
They are not definitive proof of malicious activity.

## Local Installation

### Prerequisites

- Python 3.11 or compatible version
- Node.js compatible with the installed Vite version
- Docker Desktop
- Git

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/CyberTrap.git
cd CyberTrap
```

Replace YOUR_USERNAME with your GitHub username.

### 2. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Start the Cowrie honeypot

```bash
docker run -d \
  --name cybertrap-cowrie \
  -p 127.0.0.1:2222:2222 \
  cowrie/cowrie:latest
```

The honeypot is deliberately bound to localhost.

### 4. Start automatic ingestion

```bash
python3 backend/ingestion.py
```

The collector initializes the SQLite database and imports
Cowrie events every ten seconds while running.

### 5. Start the FastAPI backend

Open another terminal:

```bash
source .venv/bin/activate
python -m uvicorn backend.main:app \
  --reload \
  --host 127.0.0.1 \
  --port 8000
```

API documentation:

http://127.0.0.1:8000/docs

### 6. Start the React frontend

Open another terminal:

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Dashboard:

http://127.0.0.1:5173/

## Testing

Run the automated test suite:

```bash
python -m pytest tests/ -v
```

Initial development milestone:

**17 tests passed**

Tests cover threat detection, database ingestion,
duplicate prevention, malformed JSON handling,
and API endpoint responses.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | / | API welcome message |
| GET | /api/health | Server health |
| GET | /api/stats | Security statistics |
| GET | /api/attacks | Recorded SSH events |
| GET | /api/commands | Command statistics |
| GET | /api/alerts | Rule-based security alerts |

## Security Considerations

CyberTrap is intended for controlled cybersecurity
learning and authorized testing.

- The honeypot runs on localhost by default.
- Do not expose the development API publicly.
- Do not use real credentials for testing.
- Do not upload captured credentials or raw security logs.
- Local database and log files are excluded from Git.
- Use network isolation and appropriate controls before
  deploying any honeypot on a public network.

## Current Limitations

- Dashboard refresh is manual.
- Automatic ingestion runs as a separate local process.
- Detection rules are signature-based.
- Historical alerts are generated from stored events.
- Authentication and role-based access controls are
  not implemented for public deployment.
- The collector processes the current Cowrie JSON log
  rather than incrementally streaming log entries.

## Future Improvements

- Automatic dashboard refresh
- Persistent alert management
- IP reputation enrichment
- Geographic threat visualization
- Expanded detection rules
- Cloud deployment with network isolation
- SIEM integration

## Project Status

CyberTrap v1.0 — Final testing and documentation.

## License

A project license has not yet been selected.
