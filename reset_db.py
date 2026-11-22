import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from db import get_db

load_dotenv()

print("Connecting to database...")
conn = get_db()
cur = conn.cursor()

print("Dropping old tables...")
cur.execute("DROP TABLE IF EXISTS ticket_log, tickets, assets, users CASCADE;")
conn.commit()

print("Rebuilding tables from schema.sql...")
with open("schema.sql", "r") as f:
    cur.execute(f.read())
conn.commit()

print("Creating fresh admin account...")
admin_pw = generate_password_hash("admin123")
cur.execute(
    "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)",
    ("System Admin", "admin@itdepot.co.za", admin_pw, "admin")
)
conn.commit()
conn.close()

print("✅ Database completely reset! You can now run 'python app.py'")