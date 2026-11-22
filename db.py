import os
import psycopg2
from psycopg2.extras import DictCursor
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def get_db():
    conn = psycopg2.connect(
        dbname=os.environ.get("DB_NAME", "helpdesk"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD"),
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432")
    )
    conn.cursor_factory = DictCursor
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    # Check if tables exist. If not, build them.
    cur.execute("SELECT to_regclass('public.users');")
    if cur.fetchone()[0] is None:
        with open(SCHEMA_PATH, "r") as f:
            sql = f.read()
            cur.execute(sql)
        conn.commit()
    
    conn.close()