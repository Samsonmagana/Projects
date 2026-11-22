import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from db import get_db

load_dotenv()

email = "admin@itdepot.co.za"
pw = "admin123"

print(f"Checking database for: {email}")

conn = get_db()
cur = conn.cursor()

cur.execute("SELECT * FROM users WHERE email = %s", (email,))
row = cur.fetchone()

if not row:
    print("❌ USER NOT FOUND in the database!")
    print("Here are the users that ARE in the database:")
    cur.execute("SELECT email FROM users")
    for u in cur.fetchall():
        print(f" - {u['email']}")
else:
    print("✅ User found in database.")
    print(f"Stored password hash: {row['password_hash'][:20]}...")
    if check_password_hash(row["password_hash"], pw):
        print("✅ Password MATCHES perfectly!")
    else:
        print("❌ Password DOES NOT match the hash.")

conn.close()