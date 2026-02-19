import psycopg2
import requests
import json
import os
import io
import csv
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
import datetime
import logging
import argparse
from collections import defaultdict


# Load environment variables from .env file
load_dotenv()
date = datetime.datetime.now().strftime("%Y-%m-%d")
# Initialize parser/logging
parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="Enable debug logging")
args = parser.parse_args()
DEBUG_MODE = args.debug

logging.basicConfig(
    level=logging.DEBUG if args.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Console
console = Console()

# Database connection parameters
DB_PARAMS = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT', '5432')
}

# ServiceNOW API details
SNOW_API_ENDPOINT = os.getenv('SNOW_API_ENDPOINT')
SNOW_INSTANCE_URL = os.getenv('SNOW_INSTANCE_URL') 
# derive table name from endpoint
TABLE_NAME = SNOW_API_ENDPOINT.rsplit('/', 1)[-1]
SNOW_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}
SNOW_AUTH = (os.getenv('SNOW_USER'), os.getenv('SNOW_PASS'))

# PostgreSQL connection helper
def get_db_connection():
    return psycopg2.connect(**DB_PARAMS)

# Fetch aggregated ticket data from DB
def fetch_ticket_data():
    query = """
        SELECT remediation_summary, assignment_group,
               MIN(severity_priority) as severity_priority,
               COUNT(DISTINCT u_asset_id) as asset_count,
               COUNT(u_finding_id) as vulnerability_count,
               json_agg(json_build_object(
                   'u_finding_id', u_finding_id,
                   'host', host,
                   'port', NULLIF(port, -1),
                   'proof', proof,
                   'last_scan_date', last_scan_date
               )) as details
        FROM new_ticket_data
        GROUP BY remediation_summary, assignment_group
    """
    logger.debug("Executing SQL query for ticket data: %s", query)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            logger.debug("Fetched %d rows from ticket data", len(rows))
    return rows

def fetch_ticket_data_by_cve(cve_list):
    placeholders = ','.join(['%s'] * len(cve_list))
    query = f"""
        SELECT remediation_summary, assignment_group,
               MIN(severity_priority) as severity_priority,
               COUNT(DISTINCT u_asset_id) as asset_count,
               COUNT(u_finding_id) as vulnerability_count,
               json_agg(json_build_object(
                   'u_finding_id', u_finding_id,
                   'host', host,
                   'port', port,
                   'proof', proof,
                   'last_scan_date', last_scan_date,
                   'cve', cve
               )) as details
        FROM fn_cve_ticket_data(ARRAY[{placeholders}])
        GROUP BY remediation_summary, assignment_group
    """

    logger.debug("Executing SQL query for ticket data by CVE: %s", query)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, cve_list)
            rows = cur.fetchall()
            logger.debug("Fetched %d aggregated rows for CVE-based ticket creation", len(rows))
    return rows


def query_open_tickets():
    params = {
        "sysparm_query": "state!=closed",
        "sysparm_limit": "200",
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }
    response = requests.get(SNOW_API_ENDPOINT, auth=SNOW_AUTH, headers=SNOW_HEADERS, params=params)
    response.raise_for_status()

    tickets = response.json()['result']

    # Sort tickets by Ticket ID
    tickets.sort(key=lambda x: x['number'], reverse=True)

    table = Table(title="Open Tickets (sorted by Ticket ID)", show_lines=True)
    table.add_column("Ticket ID", style="cyan")
    table.add_column("Short Description", style="magenta")
    table.add_column("Assignment Group", style="blue")
    table.add_column("Status", style="white")
    table.add_column("Severity", style="red")
    table.add_column("Created On", style="green")
    table.add_column("Due Date", style="yellow")

    for ticket in tickets:
        assignment_group = ticket.get('assignment_group', '')
        if isinstance(assignment_group, dict):
            assignment_group = assignment_group.get('display_value', '')

        state = ticket.get('state', '')
        if isinstance(state, dict):
            state = state.get('display_value', '')

        table.add_row(
            ticket['number'],
            ticket['short_description'],
            assignment_group,
            state,
            ticket['severity'],
            ticket['sys_created_on'],
            ticket['due_date']
        )
    console.print(table)
    #with console.pager():
    #    console.print(table)

    Prompt.ask("Press Enter to return to menu")



# Caching group mappings
def fetch_assignment_groups():
    group_mapping = {}
    url = f"{os.getenv('SNOW_INSTANCE_URL')}/api/now/table/sys_user_group"
    params = {"sysparm_fields": "sys_id,name", "sysparm_limit": 500, "sysparm_display_value": "true"}
    response = requests.get(url, auth=SNOW_AUTH, headers=SNOW_HEADERS, params=params)
    response.raise_for_status()
    data = response.json()['result']
    for group in data:
        group_mapping[group['name']] = group['sys_id']
    return group_mapping

# Post ticket to ServiceNOW
def post_ticket_to_snow(summary, description, severity, due_date, assignment_group_sys_id):
    payload = {
        "short_description": summary,
        "description": description,
        "severity": severity,
        "state": "1",  # Open state
        "due_date": due_date,
        "assignment_group": assignment_group_sys_id
    }
    logger.debug("Posting ticket to ServiceNOW: %s", payload)
    response = requests.post(SNOW_API_ENDPOINT, auth=SNOW_AUTH, headers=SNOW_HEADERS, json=payload)
    response.raise_for_status()
    result = response.json()['result']
    logger.debug("Received response from ServiceNOW: %s", result)
    return result


# Insert ticket tracking info back into DB
def insert_ticket_tracking(sn_ticket_id, sn_sys_id, summary, assignment_group, findings, severity_label):
    logger.debug("Inserting tracking data for ticket %s with sys_id %s", sn_ticket_id, sn_sys_id)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT insert_ticket_tracking(%s, %s, %s, %s, %s, %s)",
                        (sn_ticket_id, sn_sys_id, summary, assignment_group, findings, severity_label))
            conn.commit()
    logger.debug("Inserted tracking data successfully.")

# Map severity_priority to ServiceNOW severity
def map_severity(sev_priority):
    return {1: ('Critical', 30), 2: ('High', 60), 3: ('Medium', 90)}.get(sev_priority, ('Low', 120))

# Main TUI function for creating tickets
def create_tickets():
    data = fetch_ticket_data()

    if DEBUG_MODE:
        # Detailed JSON output in debug mode
        console.print("[bold red]DEBUG MODE:[/] Showing full ticket payloads in JSON format")
        for row in data:
            ticket_payload = {
                "summary": row[0],
                "assignment_group": row[1],
                "severity_priority": row[2],
                "asset_count": row[3],
                "vulnerability_count": row[4],
                "details": row[5]
            }
            console.print_json(json.dumps(ticket_payload, indent=2))

        proceed = Prompt.ask("Proceed with ticket creation? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("[yellow]Ticket creation aborted by user.[/yellow]")
            return

    assignment_groups_cache = fetch_assignment_groups()

    summary_table = Table(title="Ticket Creation Summary")
    summary_table.add_column("Assignment Group", style="cyan")
    summary_table.add_column("Tickets to Create", justify="right", style="magenta")

    assignment_group_summary = {}
    for row in data:
        assignment_group_summary[row[1]] = assignment_group_summary.get(row[1], 0) + 1

    for group, count in assignment_group_summary.items():
        summary_table.add_row(group, str(count))

    if not DEBUG_MODE:
        console.print(summary_table)
        proceed = Prompt.ask("Proceed with ticket creation? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("Ticket creation cancelled by user.", style="yellow")
            return

    assignment_groups_cache = fetch_assignment_groups()

    for row in data:
        sev_label, due_days = map_severity(row[2])
        summary = row[0]
        description = (
            f"{row[0]} on {row[3]} hosts. "
            f"This would remediate {row[4]} vulnerabilities.\n\nDetails:\n"
        )
        description += "\n".join(
            f"{d['host']} | {d['port']} | {d['proof']} | {d['last_scan_date']}" for d in row[5]
        )

        due_date = (datetime.date.today() + datetime.timedelta(days=due_days)).isoformat()

        assignment_group_sys_id = assignment_groups_cache.get(row[1])
        if not assignment_group_sys_id:
            console.print(f"[red]No sys_id found for {row[1]}, skipping ticket creation.[/red]")
            continue

        result = post_ticket_to_snow(summary, description, sev_label, due_date, assignment_group_sys_id)

        insert_ticket_tracking(
            result['number'], result['sys_id'], summary, row[1],
            [int(d['u_finding_id']) for d in row[5]], sev_label
        )

        console.print(f"[green]Created Ticket:[/] {result['number']}")

    Prompt.ask("Press Enter to return to menu")

def create_tickets_by_cve():
    cve_input = Prompt.ask("Enter CVE(s) separated by commas (e.g., CVE-2023-1234,CVE-2024-5678)")
    cve_list = [cve.strip() for cve in cve_input.split(',') if cve.strip()]

    data = fetch_ticket_data_by_cve(cve_list)

    if not data:
        console.print("[yellow]No findings found for the provided CVE(s).[/yellow]")
        Prompt.ask("Press Enter to return to menu")
        return

    if DEBUG_MODE:
        console.print("[bold red]DEBUG MODE:[/] Showing full ticket payloads in JSON format")
        for row in data:
            ticket_payload = {
                "summary": row[0],
                "assignment_group": row[1],
                "severity_priority": row[2],
                "asset_count": row[3],
                "vulnerability_count": row[4],
                "details": row[5]
            }
            console.print_json(json.dumps(ticket_payload, indent=2))

        proceed = Prompt.ask("Proceed with ticket creation? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("[yellow]Ticket creation cancelled by user.[/yellow]")
            return

    else:
        summary_table = Table(title="CVE-Based Ticket Creation Summary")
        summary_table.add_column("Assignment Group", style="cyan")
        summary_table.add_column("Tickets to Create", justify="right", style="magenta")

        assignment_group_summary = {}
        for row in data:
            assignment_group_summary[row[1]] = assignment_group_summary.get(row[1], 0) + 1

        for group, count in assignment_group_summary.items():
            summary_table.add_row(group, str(count))

        console.print(summary_table)

        proceed = Prompt.ask("Proceed with ticket creation? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("[yellow]Ticket creation cancelled by user.[/yellow]")
            return

    assignment_groups_cache = fetch_assignment_groups()

    for row in data:
        sev_label, due_days = map_severity(row[2])
        summary = row[0]
        description = (
            f"{row[0]} on {row[3]} hosts. "
            f"This would remediate {row[4]} vulnerabilities.\n\nDetails:\n"
        )
        description += "\n".join(
            f"{d['host']} | Port: {d['port']} | Proof: {d['proof']} | CVE: {d['cve']} | Last Scanned: {d['last_scan_date']}"
            for d in row[5]
        )

        due_date = (datetime.date.today() + datetime.timedelta(days=due_days)).isoformat()

        assignment_group_sys_id = assignment_groups_cache.get(row[1])
        if not assignment_group_sys_id:
            console.print(f"[red]No sys_id found for {row[1]}, skipping ticket creation.[/red]")
            continue

        result = post_ticket_to_snow(summary, description, sev_label, due_date, assignment_group_sys_id)

        insert_ticket_tracking(
            result['number'], result['sys_id'], summary, row[1],
            [int(d['u_finding_id']) for d in row[5]], sev_label
        )

        console.print(f"[green]Created Ticket:[/] {result['number']}")

    Prompt.ask("Press Enter to return to menu")


def fetch_snow_ticket(sn_sys_id):
    url = f"{SNOW_API_ENDPOINT}/{sn_sys_id}"
    params = {"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true"}
    response = requests.get(url, auth=SNOW_AUTH, headers=SNOW_HEADERS, params=params)
    response.raise_for_status()
    return response.json()['result']


def update_ticket_tracking(sn_sys_id, short_description, status, assignment_group, management_comments):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tickets
                SET short_description = %s,
                    ticket_status = %s,
                    assignment_group = %s,
                    management_comments = %s
                WHERE sn_sys_id = %s
            """, (short_description, status, assignment_group, management_comments, sn_sys_id))
            conn.commit()


def ticket_sync():
    logger.info("Starting ticket sync...")
    console.print("Starting ticket sync with ServiceNOW...", style="cyan")

    # Fetch open tickets from ticket_tracking
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT sn_sys_id
                FROM tickets
                WHERE ticket_status != 'closed'
            """)
            sn_sys_ids = [row[0] for row in cur.fetchall()]
            logger.debug("Fetched %d tickets to sync", len(sn_sys_ids))

    #updated_count = 0
    for sn_sys_id in sn_sys_ids:
        snow_ticket = fetch_snow_ticket(sn_sys_id)

        short_description = snow_ticket.get('short_description', '')
        
        status = snow_ticket.get('state', '')
        if isinstance(status, dict):
            status = status.get('display_value', '')

        assignment_group = snow_ticket.get('assignment_group', '')
        if isinstance(assignment_group, dict):
            assignment_group = assignment_group.get('display_value', '')
        
        management_comments = snow_ticket.get('management_comments', None)

        logger.debug("Updating local DB for ticket sys_id %s", sn_sys_id)
        update_ticket_tracking(sn_sys_id, short_description, status, assignment_group, management_comments)

        console.print(f"Ticket [green]{sn_sys_id}[/green] updated.")

    console.print("[green]Ticket sync completed![/green]")
    logger.info("Ticket sync completed.")
    Prompt.ask("Press Enter to return to menu")

def fetch_tickets_to_close():
    query = "SELECT sn_ticket_id, sn_sys_id FROM tickets_to_close"
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
    return rows

def close_snow_ticket(sn_sys_id):
    payload = {"state": "7"}  # Typically, '7' is "Closed" state in ServiceNOW
    url = f"{SNOW_API_ENDPOINT}/{sn_sys_id}"
    response = requests.patch(url, auth=SNOW_AUTH, headers=SNOW_HEADERS, json=payload)
    response.raise_for_status()
    return response.json()['result']

def close_local_ticket(sn_sys_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE ticket_tracking
                SET status = 'closed'
                WHERE sn_sys_id = %s
            """, (sn_sys_id,))
            conn.commit()

def fetch_append_ticket_data():
    query = """
        SELECT
            u_finding_id,
            u_asset_id,
            cve,
            remediation_summary,
            dlx_severity,
            severity_priority,
            host,
            proof,
            port,
            last_scan_date,
            assignment_group,
            sn_sys_id,
            sn_ticket_id
        FROM append_ticket_data
        ORDER BY severity_priority, last_scan_date DESC
    """
    logger.debug("Fetching append_ticket_data VIEW")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            logger.debug("Fetched %d rows for append comments", len(rows))
    return rows

def append_snow_ticket_comment(sn_sys_id, comment):
    url = f"{SNOW_API_ENDPOINT}/{sn_sys_id}"
    payload = {"comments": comment}
    response = requests.patch(url, auth=SNOW_AUTH, headers=SNOW_HEADERS, json=payload)
    response.raise_for_status()
    return response.json()['result']

def append_tickets():
    data = fetch_append_ticket_data()

    tickets_dict = defaultdict(list)

    # Aggregate findings per ticket_id
    for row in data:
        finding = {
            'u_finding_id': row[0],
            'u_asset_id': row[1],
            'cve': row[2],
            'remediation_summary': row[3],
            'dlx_severity': row[4],
            'severity_priority': row[5],
            'host': row[6],
            'proof': row[7],
            'port': row[8] if row[8] else 'N/A',
            'last_scan_date': row[9],
            'assignment_group': row[10],
            'sn_sys_id': row[11],
        }
        sn_ticket_id = row[12]
        tickets_dict[sn_ticket_id].append(finding)

    if DEBUG_MODE:
        console.print("[bold yellow]DEBUG MODE:[/] Displaying detailed comments for each ticket\n")
        for sn_ticket_id, findings in tickets_dict.items():
            comment = f"Additional vulnerabilities were discovered associated with ticket {sn_ticket_id}:\n\n"
            for f in findings:
                comment += (
                    f"- Ticket ID: {f['sn_ticket_id']} | Host: {f['host']} | Port: {f['port']} | Severity: {f['dlx_severity']} | "
                    f"Proof: {f['proof']} | CVE: {f['cve']} | Last Scanned: {f['last_scan_date']}\n"
                )

            payload = {
                "sn_ticket_id": sn_ticket_id,
                "comment": comment
            }
            console.print_json(json.dumps(payload, indent=2))

        proceed = Prompt.ask("Proceed with appending comments? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("[yellow]Comment append cancelled by user.[/yellow]")
            return
    else:
        summary_table = Table(title="Ticket Append Summary")
        summary_table.add_column("Ticket ID", style="cyan")
        summary_table.add_column("Assignment Group", style="magenta")
        summary_table.add_column("Findings Count", justify="right", style="green")

        for sn_ticket_id, findings in tickets_dict.items():
            assignment_group = findings[0]['assignment_group']
            summary_table.add_row(sn_ticket_id, assignment_group, str(len(findings)))

        console.print(summary_table)

        proceed = Prompt.ask("Proceed with appending comments? (y/n)", choices=["y", "n"], default="n")
        if proceed != "y":
            console.print("[yellow]Comment append cancelled by user.[/yellow]")
            return

    # Append comments to tickets
    for sn_ticket_id, findings in tickets_dict.items():
        sn_sys_id = findings[0]['sn_sys_id']
        comment = "Additional vulnerabilities were discovered:\n\n"
        for f in findings:
            comment += (
                f"- Host: {f['host']} | Port: {f['port']} | Severity: {f['dlx_severity']} | "
                f"Proof: {f['proof']} | CVE: {f['cve']} | Last Scanned: {f['last_scan_date']}\n"
            )

        append_snow_ticket_comment(sn_sys_id, comment)
        console.print(f"[green]Appended comment to Ticket:[/] {sn_ticket_id}")

    Prompt.ask("Press Enter to return to menu")

def close_tickets():
    tickets_to_close = []

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT sn_ticket_id, sn_sys_id FROM tickets_to_close") 
            tickets_to_close = cur.fetchall()

    if not tickets_to_close:
        console.print("[green]No tickets to close at this time.[/green]")
        Prompt.ask("Press Enter to return to menu")
        return

    summary_table = Table(title="Tickets to be Closed")
    summary_table.add_column("Ticket ID", style="cyan")
    summary_table.add_column("Sys ID", style="magenta")

    for sn_ticket_id, sn_sys_id in tickets_to_close:
        summary_table.add_row(sn_ticket_id, sn_sys_id)

    console.print(summary_table)

    if Prompt.ask("Proceed with closing these tickets? (y/n)", choices=["y", "n"]) == "y":
        for sn_ticket_id, sn_sys_id in tickets_to_close:
            close_snow_ticket(sn_sys_id)
            close_local_ticket(sn_sys_id)
            console.print(f"Closed Ticket: [cyan]{sn_ticket_id}[/cyan]")

        console.print("[green]All tickets successfully closed.[/green]")

    Prompt.ask("Press Enter to return to menu")


# Fetch data from update_ticket_attachment view
def fetch_attachment_data():
    query = "SELECT sn_ticket_id, sn_sys_id, asset_name, ip_address, operating_system, environment, managed_by, proof, assignment_group, pci_scope, dlx_category, dlx_severity, title, port, first_found_date, last_scan_date, remediation_summary, remediation, status FROM update_ticket_attachment ORDER BY sn_ticket_id"
    logger.debug("Executing fetch_attachment_data SQL: %s", query)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchall()

# Delete existing attachments on a ticket
def delete_ticket_attachments(sys_id):
    url = f"{SNOW_INSTANCE_URL}/api/now/attachment"
    params = {
        'sysparm_query': f"table_sys_id={sys_id}^table_name={TABLE_NAME}",
        'sysparm_fields': 'sys_id,file_name',
        'sysparm_limit': '100'
    }
    resp = requests.get(url, auth=SNOW_AUTH, headers=SNOW_HEADERS, params=params)
    resp.raise_for_status()
    for att in resp.json().get('result', []):
        del_url = f"{SNOW_INSTANCE_URL}/api/now/attachment/{att['sys_id']}"
        del_resp = requests.delete(del_url, auth=SNOW_AUTH, headers=SNOW_HEADERS)
        del_resp.raise_for_status()
        logger.info("Deleted attachment %s", att['file_name'])

# Add CSV attachment to a ticket
def add_csv_attachment(sys_id, csv_content, filename):
    url = f"{SNOW_INSTANCE_URL}/api/now/attachment/file"
    # ServiceNow expects table parameters as query params
    params = {
        'table_name': TABLE_NAME,
        'table_sys_id': sys_id,
        'file_name': filename
    }
    files = {
        'file': (filename, csv_content, 'text/csv')
    }
    resp = requests.post(url,
                         auth=SNOW_AUTH,
                         headers=SNOW_HEADERS,
                         params=params,
                         files=files)
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        logger.error(
            "Failed to upload attachment %s to ticket %s: %s %s",
            filename, sys_id, resp.status_code, resp.text
        )
        raise
    logger.info("Uploaded attachment %s to ticket %s", filename, sys_id)

# Main update attachments logic
def update_ticket_attachments():
    rows = fetch_attachment_data()
    tickets = defaultdict(list)
    for r in rows:
        tickets[r[0]].append(r[1:])  # key = sn_ticket_id

    for ticket_id, entries in tickets.items():
        sys_id = entries[0][0]
        console.print(f"Processing Ticket {ticket_id} (sys_id={sys_id})")
        delete_ticket_attachments(sys_id)

        output = io.StringIO()
        writer = csv.writer(output)
        headers = ['sn_sys_id','asset_name','ip_address','operating_system','environment','managed_by',
                   'proof','assignment_group','pci_scope','dlx_category','dlx_severity','title','port',
                   'first_found_date','last_scan_date','remediation_summary','remediation','status']
        writer.writerow(headers)
        for entry in entries:
            writer.writerow(entry)

        csv_data = output.getvalue().encode('utf-8')
        filename = f"{ticket_id}_{date}.csv"
        add_csv_attachment(sys_id, csv_data, filename)

    console.print("[green]Update attachments completed for all tickets.[/green]")
    Prompt.ask("Press Enter to return to menu")

def handle_exceptions():
    query = """
        SELECT sn_ticket_id, management_comments, COUNT(*) as count
        FROM exceptions
        WHERE reviewed = false
        GROUP BY sn_ticket_id, management_comments ORDER BY count DESC;
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()

    if not rows:
        console.print("[green]No unreviewed exception requests.[/green]")
        Prompt.ask("Press Enter to return to menu")
        return

    table = Table(title="Unreviewed Exception Requests")
    table.add_column("Ticket ID", style="cyan")
    table.add_column("Management Comments", style="magenta")
    table.add_column("Count", justify="right", style="green")

    ticket_ids = [row[0] for row in rows]
    for row in rows:
        table.add_row(row[0], row[1] or '', str(row[2]))

    console.print(table)

    while True:
        ticket_id = Prompt.ask("Enter Ticket ID to review (or 'q' to quit)")
        if ticket_id.lower() == 'q':
            break
        if ticket_id not in ticket_ids:
            console.print("[red]Invalid Ticket ID.[/red]")
            continue

        review_notes = Prompt.ask("Enter review notes")
        approved_input = Prompt.ask("Approve? (y/n)", choices=["y", "n"], default="n")
        approved_bool = approved_input == 'y'
        username = os.getenv('SNOW_USER')

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE exceptions
                    SET
                        reviewed = TRUE,
                        review_date = NOW(),
                        review_notes = %s,
                        approved = %s,
                        approved_by = %s,
                        approved_date = NOW()
                    WHERE sn_ticket_id = %s
                """, (review_notes, approved_bool, username, ticket_id))
                conn.commit()

        console.print(f"[green]Reviewed Ticket {ticket_id}. Approved: {'Yes' if approved_bool else 'No'}[/green]")

# Application menu
def main():
    while True:
        console.print("\n[bold underline]Ticket Management[/]\n")
        console.print("1. Create Tickets")
        console.print("2. Create Tickets (CVE)")
        console.print("3. View Open Tickets")
        console.print("4. Update Ticket Attachments")
        console.print("5. Close Tickets")
        console.print("6. Ticket Sync")
        console.print("7. Handle Exceptions")
        console.print("8. Exit")

        choice = Prompt.ask("Choose an option", choices=[str(i) for i in range(1,9)])

        if choice == '1':
            create_tickets()
        elif choice == '2':
            create_tickets_by_cve()
        elif choice == '3':
            query_open_tickets()
        elif choice == '4':
            update_ticket_attachments()
        elif choice == '5':
            close_tickets()
        elif choice == '6':
            ticket_sync()
        elif choice == '7':
            handle_exceptions()
        elif choice == '8':
            break
        else:
            console.print("[yellow]Feature pending implementation.[/yellow]")

if __name__ == '__main__':
    main()
