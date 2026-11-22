import os
from dotenv import load_dotenv
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect
from db import get_db, init_db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise ValueError("No SECRET_KEY set. Check your .env file.")

csrf = CSRFProtect(app)

def db():
    if "db" not in g:
        g.db = get_db()
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn:
        conn.close()

with app.app_context():
    init_db()

@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        cur = db().cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
        g.user = cur.fetchone()

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapper

def role_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not g.user or g.user["role"] not in roles:
                abort(403)
            return f(*a, **kw)
        return wrapper
    return deco

def log_action(action, details=""):
    """Silently record user activity in the audit log."""
    if not g.user:
        return
    try:
        cur = db().cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (%s, %s, %s, %s)",
            (g.user["id"], action, details, request.remote_addr)
        )
        db().commit()
    except Exception:
        db().rollback()

@app.context_processor
def inject_globals():
    return {"current_user": g.get("user")}

# -- Auth -------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        cur = db().cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        
        if row and check_password_hash(row["password_hash"], pw):
            session.clear()
            session["uid"] = row["id"]
            cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (row["id"],))
            db().commit()
            return redirect(request.args.get("next") or url_for("dashboard"))
            
        flash("Incorrect email or password.", "error")
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        
        if not name or not email or not pw:
            flash("All fields are required.", "error")
        else:
            try:
                cur = db().cursor()
                # Check if this is the very first user
                cur.execute("SELECT COUNT(*) FROM users")
                is_first_user = cur.fetchone()[0] == 0
                
                # First user becomes admin, everyone else becomes staff
                assigned_role = "admin" if is_first_user else "staff"
                
                cur.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                    (name, email, generate_password_hash(pw), assigned_role)
                )
                db().commit()
                
                if is_first_user:
                    flash("Super Admin account created. You can now log in.", "ok")
                else:
                    flash("Account created. Please sign in.", "ok")
                    
                return redirect(url_for("login"))
            except Exception:
                db().rollback()
                flash("Email already exists.", "error")
    return render_template("signup.html")

@app.get("/logout")
def logout():
    log_action("Logout", "User signed out")
    session.clear()
    return redirect(url_for("login"))

# -- Dashboard --------------------------------------------------------
@app.get("/")
@login_required
def dashboard():
    cur = db().cursor()
    cur.execute("SELECT COUNT(*) FROM assets")
    assets_total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM tickets WHERE status IN ('open','in_progress')")
    tickets_open = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM tickets WHERE assigned_to=%s AND status IN ('open','in_progress')", (g.user["id"],))
    tickets_mine = cur.fetchone()[0]
    
    counts = {"assets_total": assets_total, "tickets_open": tickets_open, "tickets_mine": tickets_mine}
    return render_template("dashboard.html", counts=counts)

# -- Audit Log (Admin Only) -------------------------------------------
@app.get("/audit")
@login_required
@role_required("admin")
def audit_log():
    cur = db().cursor()
    cur.execute("""
        SELECT a.*, u.name AS user_name 
        FROM audit_log a 
        LEFT JOIN users u ON u.id = a.user_id 
        ORDER BY a.created_at DESC
    """)
    logs = cur.fetchall()
    
    cur.execute("SELECT id, name, email, role, last_login, created_at FROM users ORDER BY created_at")
    users = cur.fetchall()
    
    return render_template("audit.html", logs=logs, users=users)

# -- Assets -----------------------------------------------------------
@app.route("/assets", methods=["GET", "POST"])
@login_required
def assets():
    cur = db().cursor()
    if request.method == "POST":
        if g.user["role"] not in ("admin", "technician"):
            abort(403)
        tag = request.form.get("tag")
        type_ = request.form.get("type")
        make = request.form.get("make")
        model = request.form.get("model")
        serial = request.form.get("serial")
        location = request.form.get("location")
        status = request.form.get("status", "in_storage")
        
        try:
            cur.execute(
                """INSERT INTO assets (tag, type, make, model, serial, location, status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (tag, type_, make, model, serial, location, status)
            )
            db().commit()
            log_action("Asset Added", f"Added asset {tag}")
            flash(f"Asset {tag} added.", "ok")
        except Exception as e:
            db().rollback()
            flash(f"Could not save: {e}", "error")
        return redirect(url_for("assets"))

    cur.execute("""SELECT a.*, u.name AS assigned_name FROM assets a 
                   LEFT JOIN users u ON u.id = a.assigned_to ORDER BY a.tag""")
    rows = cur.fetchall()
    return render_template("assets.html", assets=rows)

# -- Tickets ----------------------------------------------------------
@app.route("/tickets", methods=["GET", "POST"])
@login_required
def tickets():
    cur = db().cursor()
    if request.method == "POST":
        title = request.form.get("title")
        desc = request.form.get("description")
        priority = request.form.get("priority", "medium")
        asset_id = request.form.get("asset_id") or None
        
        cur.execute(
            "INSERT INTO tickets (title, description, priority, asset_id, created_by) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (title, desc, priority, asset_id, g.user["id"])
        )
        ticket_id = cur.fetchone()["id"]
        db().commit()
        
        log_action("Ticket Created", f"Created ticket #{ticket_id}: {title}")
        flash("Ticket created.", "ok")
        return redirect(url_for("tickets"))

    cur.execute("""SELECT t.*, u1.name AS created_by_name, u2.name AS assigned_name, a.tag AS asset_tag
                   FROM tickets t JOIN users u1 ON u1.id = t.created_by
                   LEFT JOIN users u2 ON u2.id = t.assigned_to
                   LEFT JOIN assets a ON a.id = t.asset_id
                   ORDER BY t.created_at DESC""")
    rows = cur.fetchall()
    
    cur.execute("SELECT id, tag, model FROM assets")
    assets_list = cur.fetchall()
    return render_template("tickets.html", tickets=rows, assets=assets_list)

@app.route("/tickets/<int:id>", methods=["GET", "POST"])
@login_required
def ticket_detail(id):
    cur = db().cursor()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "update_status" and g.user["role"] in ("admin", "technician"):
            new_status = request.form.get("status")
            assignee = request.form.get("assigned_to") or None
            cur.execute("UPDATE tickets SET status=%s, assigned_to=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s", (new_status, assignee, id))
            db().commit()
            log_action("Ticket Updated", f"Ticket #{id} status changed to {new_status}")
            
        elif action == "add_note":
            note = request.form.get("note")
            if note:
                cur.execute("INSERT INTO ticket_log (ticket_id, user_id, note) VALUES (%s, %s, %s)", (id, g.user["id"], note))
                db().commit()
                log_action("Note Added", f"Added note to ticket #{id}")
        return redirect(url_for("ticket_detail", id=id))

    cur.execute("""SELECT t.*, u1.name AS created_by_name, a.tag AS asset_tag, u2.name AS assigned_name
                   FROM tickets t JOIN users u1 ON u1.id = t.created_by
                   LEFT JOIN users u2 ON u2.id = t.assigned_to
                   LEFT JOIN assets a ON a.id = t.asset_id WHERE t.id=%s""", (id,))
    ticket = cur.fetchone()
    if not ticket: abort(404)

    cur.execute("SELECT l.*, u.name AS author_name FROM ticket_log l JOIN users u ON u.id = l.user_id WHERE l.ticket_id=%s ORDER BY l.created_at DESC", (id,))
    logs = cur.fetchall()
    
    cur.execute("SELECT id, name FROM users WHERE role IN ('admin', 'technician')")
    techs = cur.fetchall()
    return render_template("ticket_detail.html", ticket=ticket, logs=logs, techs=techs)

@app.route("/tickets/<int:id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(id):
    cur = db().cursor()
    cur.execute("SELECT * FROM tickets WHERE id=%s", (id,))
    ticket = cur.fetchone()
    if not ticket: abort(404)
    if g.user["role"] != "admin" and g.user["id"] != ticket["created_by"]: abort(403)

    if request.method == "POST":
        cur.execute("UPDATE tickets SET title=%s, description=%s, priority=%s, updated_at=CURRENT_TIMESTAMP WHERE id=%s",
                    (request.form.get("title"), request.form.get("description"), request.form.get("priority"), id))
        db().commit()
        log_action("Ticket Edited", f"Edited details of ticket #{id}")
        flash("Ticket updated.", "ok")
        return redirect(url_for("ticket_detail", id=id))
    return render_template("ticket_edit.html", ticket=ticket)

@app.route("/tickets/<int:id>/delete", methods=["POST"])
@login_required
def delete_ticket(id):
    cur = db().cursor()
    cur.execute("SELECT * FROM tickets WHERE id=%s", (id,))
    ticket = cur.fetchone()
    if not ticket: abort(404)
    if g.user["role"] != "admin" and g.user["id"] != ticket["created_by"]: abort(403)
    
    cur.execute("DELETE FROM tickets WHERE id=%s", (id,))
    db().commit()
    log_action("Ticket Deleted", f"Deleted ticket #{id}")
    flash(f"Ticket #{id} deleted.", "ok")
    return redirect(url_for("tickets"))

if __name__ == "__main__":
    app.run(debug=True)