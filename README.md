# Tickets 🎫

A terminal UI (TUI) for managing ServiceNow vulnerability remediation tickets, backed by PostgreSQL for local tracking.

## Features

- **Create Tickets** — aggregate vulnerability findings from your DB and batch-create ServiceNow tickets
- **Create Tickets by CVE** — target specific CVEs for ticket creation
- **View Open Tickets** — query and display all open tickets from ServiceNow
- **Update Attachments** — replace ticket CSV attachments with current finding data
- **Append Comments** — add newly discovered vulnerabilities as comments to existing tickets
- **Close Tickets** — batch-close tickets that have been remediated
- **Ticket Sync** — sync ticket status from ServiceNow back to your local DB
- **Handle Exceptions** — review and approve/deny exception requests

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### 3. Database

Requires a PostgreSQL database with the expected schema (views: `new_ticket_data`, `append_ticket_data`, `update_ticket_attachment`, `tickets_to_close`; tables: `tickets`, `exceptions`; functions: `insert_ticket_tracking`, `fn_cve_ticket_data`).

### 4. Run

```bash
python tickets.py
```

Use `--debug` for verbose logging and full JSON payload previews:

```bash
python tickets.py --debug
```

## Environment Variables

| Variable | Description |
|---|---|
| `DB_NAME` | PostgreSQL database name |
| `DB_USER` | Database username |
| `DB_PASSWORD` | Database password |
| `DB_HOST` | Database host |
| `DB_PORT` | Database port (default: 5432) |
| `SNOW_INSTANCE_URL` | ServiceNow instance base URL |
| `SNOW_API_ENDPOINT` | Full API endpoint for your ticket table |
| `SNOW_USER` | ServiceNow username |
| `SNOW_PASS` | ServiceNow password |
