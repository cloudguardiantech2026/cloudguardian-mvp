import sqlite3
import uuid
import os

DB_PATH = "backend/state/cloudguardian.db"


def _get_connection():
    """
    Returns a connection to the CloudGuardian SQLite database.
    Creates the database file and customers table if they do not exist.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            external_id   TEXT    NOT NULL UNIQUE,
            role_arn      TEXT,
            region        TEXT    DEFAULT 'eu-west-2',
            created_at    TEXT    DEFAULT (datetime('now')),
            last_scan_at  TEXT
        )
    """)
    conn.commit()
    return conn


def generate_external_id() -> str:
    """
    Generates a new unique External ID for a customer onboarding session.
    Format: cg-<uuid4>  e.g. cg-a1b2c3d4-e5f6-7890-abcd-ef1234567890

    The 'cg-' prefix makes the origin clear when it appears in AWS CloudTrail
    logs and IAM trust policy conditions.
    """
    return f"cg-{uuid.uuid4()}"


def create_customer(external_id: str, region: str = "eu-west-2") -> int:
    """
    Inserts a new customer row with the given External ID.
    Returns the new row's primary key.
    """
    with _get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO customers (external_id, region) VALUES (?, ?)",
            (external_id, region),
        )
        conn.commit()
        return cursor.lastrowid


def get_customer_by_external_id(external_id: str) -> dict | None:
    """
    Returns the customer row matching the given External ID, or None if not found.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM customers WHERE external_id = ?",
            (external_id,),
        ).fetchone()
        return dict(row) if row else None


def save_role_arn(external_id: str, role_arn: str) -> None:
    """
    Updates the role_arn for an existing customer after they complete
    Terraform deployment and paste their Role ARN into the dashboard.
    """
    with _get_connection() as conn:
        conn.execute(
            "UPDATE customers SET role_arn = ? WHERE external_id = ?",
            (role_arn, external_id),
        )
        conn.commit()


def record_scan(external_id: str) -> None:
    """
    Updates last_scan_at timestamp for the customer. Called after each
    successful scan to maintain an audit trail.
    """
    with _get_connection() as conn:
        conn.execute(
            "UPDATE customers SET last_scan_at = datetime('now') WHERE external_id = ?",
            (external_id,),
        )
        conn.commit()

# ── Add these functions to backend/db/customer_db.py ──────────────────────────
# These store Azure OAuth tokens server-side instead of in the browser cookie,
# fixing the "session cookie too large" bug that silently breaks the OAuth flow.

def save_azure_session(session_id: str, tenant_id: str, access_token: str,
                       refresh_token: str, subscription_id: str = "",
                       subscriptions_json: str = "") -> None:
    """
    Stores Azure OAuth tokens server-side, keyed by a short session_id
    that IS safe to store in the browser cookie.
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS azure_sessions (
                session_id         TEXT PRIMARY KEY,
                tenant_id           TEXT,
                access_token        TEXT,
                refresh_token       TEXT,
                subscription_id     TEXT,
                subscriptions_json  TEXT,
                created_at          TEXT DEFAULT (datetime('now')),
                updated_at          TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            INSERT INTO azure_sessions
                (session_id, tenant_id, access_token, refresh_token,
                 subscription_id, subscriptions_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(session_id) DO UPDATE SET
                tenant_id          = excluded.tenant_id,
                access_token       = excluded.access_token,
                refresh_token      = excluded.refresh_token,
                subscription_id    = excluded.subscription_id,
                subscriptions_json = excluded.subscriptions_json,
                updated_at         = datetime('now')
        """, (session_id, tenant_id, access_token, refresh_token,
              subscription_id, subscriptions_json))
        conn.commit()


def get_azure_session(session_id: str) -> dict | None:
    """
    Retrieves Azure OAuth session data by session_id.
    Returns None if not found.
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS azure_sessions (
                session_id         TEXT PRIMARY KEY,
                tenant_id           TEXT,
                access_token        TEXT,
                refresh_token       TEXT,
                subscription_id     TEXT,
                subscriptions_json  TEXT,
                created_at          TEXT DEFAULT (datetime('now')),
                updated_at          TEXT DEFAULT (datetime('now'))
            )
        """)
        row = conn.execute(
            "SELECT * FROM azure_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None


def update_azure_subscription(session_id: str, subscription_id: str) -> None:
    """Updates just the active subscription ID for a session (multi-sub switch)."""
    with _get_connection() as conn:
        conn.execute(
            "UPDATE azure_sessions SET subscription_id = ?, updated_at = datetime('now') WHERE session_id = ?",
            (subscription_id, session_id),
        )
        conn.commit()


def delete_azure_session(session_id: str) -> None:
    """Removes Azure OAuth session data — called on disconnect."""
    with _get_connection() as conn:
        conn.execute("DELETE FROM azure_sessions WHERE session_id = ?", (session_id,))
        conn.commit()