from flask import (
    Flask, request, jsonify, session, redirect, url_for, Response,
    g, render_template_string, send_from_directory
)
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import datetime
import os
import re
import logging
from functools import wraps

# ------------------ Config & App Setup ------------------
DB_FILE = os.environ.get("SHOP_DB", "shop.db")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    # For production set FLASK_SECRET_KEY in the environment
    logging.warning("Using fallback secret key. Set FLASK_SECRET_KEY in env for production.")
    SECRET_KEY = os.urandom(24).hex()

UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update({
    "SECRET_KEY": SECRET_KEY,
    "SESSION_TYPE": "filesystem",
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SECURE": False,  # set to True if you serve over HTTPS
    "PERMANENT_SESSION_LIFETIME": 7 * 24 * 3600,
})
Session(app)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------ Utilities ------------------
bnumber_re = re.compile(r"^[bB]\d+$")

def normalize_bnumber(bnumber: str) -> str:
    if not bnumber or not bnumber_re.match(bnumber):
        raise ValueError("Invalid bnumber format. Must start with 'B' or 'b' followed by numbers.")
    return "B" + bnumber[1:]

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------ Database helpers ------------------
def get_db():
    """
    Reuse a DB connection per request via flask.g
    Use row_factory to return dict-like rows.
    """
    if "db" not in g:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        # Improve concurrency for writes; enable WAL. Useful for multi-request apps.
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def with_cursor(func):
    """
    Decorator to supply a cursor and ensure commit/close on success/failure as appropriate.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        conn = get_db()
        cur = conn.cursor()
        try:
            result = func(cur, *args, **kwargs)
            return result
        except Exception:
            # Let caller handle response; ensure DB state not left partially committed
            conn.rollback()
            raise
        finally:
            cur.close()
    return wrapper

# ------------------ DB Initialization / Idempotent migrations ------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bnumber TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            background_image TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            stock INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS order_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bnumber TEXT NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            fulfilled INTEGER DEFAULT 0
        )
    """)
    # Useful indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_bnumber ON users(bnumber);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_bnumber ON order_history(bnumber);")
    conn.commit()
    cur.close()
    conn.close()

# run migrations at import
try:
    init_db()
except Exception as e:
    logging.exception("DB init failed: %s", e)

# ------------------ Common helpers ------------------
def meru_exists():
    meru_path = os.path.join(app.root_path, "static", "meru.jpg")
    return os.path.isfile(meru_path)

def iso_z_from_sql(ts):
    """
    Convert typical sqlite string timestamps to ISO 8601 Z-form (UTC).
    Accepts "%Y-%m-%d %H:%M:%S.%f" or "%Y-%m-%d %H:%M:%S".
    If already datetime, format appropriately.
    If None/empty, return None.
    """
    if not ts:
        return None
    if isinstance(ts, datetime.datetime):
        return ts.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    # fallback: return original string
    return ts

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "bnumber" not in session:
            return jsonify({"success": False, "msg": "Not logged in"}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "bnumber" not in session or not session.get("is_admin"):
            return jsonify({"success": False, "msg": "Not authorized"}), 403
        return f(*args, **kwargs)
    return wrapper

# ------------------ Middleware ------------------
@app.before_request
def block_if_meru_missing():
    # Allow static files & uploaded resources to be served even if meru missing
    path = request.path or ""
    if path.startswith("/static/") or path.startswith("/upload_background"):
        return None
    if not meru_exists():
        html = """
        <!doctype html><html><head><title>Service Unavailable</title></head>
        <body style="font-family: Arial, sans-serif; text-align:center; padding:40px;">
            <h1>503 — Service Unavailable</h1>
            <p>The application is temporarily unavailable. Please try again later.</p>
        </body></html>
        """
        return Response(html, status=503, mimetype="text/html")

# ------------------ HTML injection for accessibility (kept as helper) ------------------
ACCESSIBILITY_INJECTION = """
<link href="https://fonts.googleapis.com/css2?family=Lexend:wght@400;700&family=Atkinson+Hyperlegible:wght@400;700&display=swap" rel="stylesheet">
<style>
  body {{
    background-image: url('/{bg_path}');
    background-size: cover;
    background-repeat: no-repeat;
    background-attachment: fixed;
  }}
  body, body * {{ transition: font-family 0.3s ease; }}
  .lexend, .lexend * {{ font-family: 'Lexend', Arial, sans-serif !important; }}
  .hyperlegible, .hyperlegible * {{ font-family: 'Atkinson Hyperlegible', Arial, sans-serif !important; }}
  #toggleFont {{
    position: fixed; bottom: 20px; right: 20px;
    width: 45px; height: 45px; border: none; border-radius: 50%;
    background: #333; color: #fff; font-size: 20px; line-height: 1;
    display: flex; align-items: center; justify-content: center; cursor: pointer;
    box-shadow: 0 2px 6px rgba(0,0,0,0.2); z-index: 1000;
  }}
  #toggleFont:hover {{ background: #555; }}
  #toggleFont:focus {{ outline: 2px solid #007bff; }}
</style>
<button id="toggleFont" title="Toggle Dyslexia-Friendly Font" aria-label="Toggle dyslexia-friendly font" tabindex="0">🅰️</button>
<script>
document.addEventListener("DOMContentLoaded", () => {{
    const toggleBtn = document.getElementById("toggleFont");
    const body = document.body;
    const modes = ["default", "lexend", "hyperlegible"];
    let current = localStorage.getItem("fontMode") || "default";
    function applyMode(mode) {{
        body.classList.remove("lexend", "hyperlegible");
        if (mode === "lexend") body.classList.add("lexend");
        if (mode === "hyperlegible") body.classList.add("hyperlegible");
        localStorage.setItem("fontMode", mode);
        toggleBtn.textContent = mode === "default" ? "🅰️" : (mode === "lexend" ? "🔤" : "📖");
    }}
    applyMode(current);
    toggleBtn.addEventListener("click", () => {{
        let idx = modes.indexOf(current);
        current = modes[(idx + 1) % modes.length];
        applyMode(current);
    }});
    toggleBtn.addEventListener("keypress", (e) => {{
        if (e.key === "Enter" || e.key === " ") {{
            e.preventDefault();
            toggleBtn.click();
        }}
    }});
}});
</script>
"""

def serve_html(filename):
    """
    Serve raw HTML files from templates/ with the accessibility injection inserted
    before </body>. Falls back to simple 404 if missing.
    """
    path = os.path.join(app.template_folder, filename)
    if not os.path.isfile(path):
        return Response(f"<h1>404</h1><p>File not found: {path}</p>", status=404, mimetype="text/html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    bg_path = "static/mimidefault.jpg"
    if "bnumber" in session:
        try:
            bg_row = None
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT background_image FROM users WHERE bnumber=?", (session["bnumber"],))
            bg_row = cur.fetchone()
            cur.close()
            if bg_row and bg_row["background_image"]:
                bg_path = bg_row["background_image"]
        except Exception:
            # ignore and use default
            pass
    injected = ACCESSIBILITY_INJECTION.format(bg_path=bg_path)
    if "</body>" in html:
        html = html.replace("</body>", injected + "</body>")
    else:
        html = html + injected
    return Response(html, mimetype="text/html")

# ------------------ Auth endpoints ------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    bnumber = data.get("bnumber")
    password = data.get("password")
    if not bnumber or not password:
        return jsonify({"success": False, "msg": "Missing bnumber or password"}), 400
    try:
        bnumber = normalize_bnumber(bnumber)
    except ValueError as e:
        return jsonify({"success": False, "msg": str(e)}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT bnumber, password_hash, is_admin FROM users WHERE bnumber=?", (bnumber,))
    user = cur.fetchone()
    cur.close()
    if not user:
        return jsonify({"success": False, "msg": "User not found"}), 404
    if not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "msg": "Incorrect password"}), 403
    session.clear()
    session["bnumber"] = bnumber
    session["is_admin"] = bool(user["is_admin"])
    redirect_to = "/admin" if user["is_admin"] else "/shop"
    return jsonify({"success": True, "redirect": redirect_to})

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    bnumber = data.get("bnumber")
    password = data.get("password")
    if not bnumber or not password:
        return jsonify({"success": False, "msg": "Missing bnumber or password"}), 400
    try:
        bnumber = normalize_bnumber(bnumber)
    except ValueError as e:
        return jsonify({"success": False, "msg": str(e)}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE bnumber=?", (bnumber,))
    if cur.fetchone():
        cur.close()
        return jsonify({"success": False, "msg": "User already exists"}), 409
    password_hash = generate_password_hash(password)
    cur.execute("INSERT INTO users (bnumber, password_hash, is_admin) VALUES (?, ?, ?)", (bnumber, password_hash, 0))
    conn.commit()
    cur.close()
    return jsonify({"success": True}), 201

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ------------------ Pages ------------------
@app.route("/")
def index():
    return serve_html("index.html")

@app.route("/shop")
def shop_page():
    if "bnumber" not in session:
        return redirect("/a6ag2")
    return serve_html("shop.html")

@app.route("/checkout")
def checkout_page():
    if "bnumber" not in session:
        return redirect("/a6ag2")
    return serve_html("checkout.html")

@app.route("/admin")
def admin_page():
    if "bnumber" not in session:
        return redirect("/a6ag2")
    if not session.get("is_admin"):
        return redirect("/a6ag2/wompwomp")
    return serve_html("admin.html")

@app.route("/history")
def history_page():
    if "bnumber" not in session:
        return redirect("/a6ag2")
    return serve_html("history.html")

@app.route("/admin/orders")
def admin_orders_page():
    if "bnumber" not in session:
        return redirect("/a6ag2")
    if not session.get("is_admin"):
        return redirect("/a6ag2/wompwomp")
    return serve_html("admin_orders.html")

@app.route("/wompwomp")
def womp_womp():
    return serve_html("wompwomp.html")

# ------------------ API ------------------
@app.route("/api/history")
@login_required
def history_api():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT product_name, quantity, timestamp, fulfilled
        FROM order_history
        WHERE bnumber=?
        ORDER BY timestamp DESC
    """, (session["bnumber"],))
    rows = cur.fetchall()
    cur.close()
    orders = []
    for r in rows:
        row = dict(r)
        row["timestamp"] = iso_z_from_sql(row.get("timestamp"))
        orders.append(row)
    return jsonify(orders)

@app.route("/products")
@login_required
def products():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, stock FROM products")
    items = [dict(row) for row in cur.fetchall()]
    cur.close()
    return jsonify(items)

@app.route("/check_stock", methods=["POST"])
@login_required
def check_stock():
    """
    Atomically check and decrement stock for all items in the cart,
    and insert order_history rows. If any item lacks stock, rollback.
    """
    payload = request.get_json(silent=True) or {}
    cart = payload.get("cart", [])
    if not isinstance(cart, list) or not cart:
        return jsonify({"success": False, "msg": "Cart must be a non-empty array"}), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        # Begin immediate transaction to reduce race windows
        conn.execute("BEGIN IMMEDIATE")
        # Check availability
        for item in cart:
            # Expect item to have id and quantity and name
            try:
                item_id = int(item["id"])
                qty = int(item["quantity"])
            except Exception:
                conn.rollback()
                return jsonify({"success": False, "msg": "Invalid cart item format"}), 400
            cur.execute("SELECT stock, name FROM products WHERE id=?", (item_id,))
            row = cur.fetchone()
            if not row or row["stock"] < qty:
                conn.rollback()
                return jsonify({"success": False, "msg": f"Not enough stock for {item.get('name', row['name'] if row else 'item')}" }), 409
        # All good -> update and record
        for item in cart:
            item_id = int(item["id"])
            qty = int(item["quantity"])
            cur.execute("UPDATE products SET stock = stock - ? WHERE id=? AND stock >= ?", (qty, item_id, qty))
            if cur.rowcount == 0:
                conn.rollback()
                return jsonify({"success": False, "msg": "Failed to update stock due to concurrent modification"}), 409
            # Save order, use product name from DB for canonical name
            cur.execute("SELECT name FROM products WHERE id=?", (item_id,))
            prod = cur.fetchone()
            product_name = prod["name"] if prod else item.get("name", "Unknown")
            cur.execute("INSERT INTO order_history (bnumber, product_name, quantity) VALUES (?, ?, ?)",
                        (session["bnumber"], product_name, qty))
        conn.commit()
        return jsonify({"success": True})
    except sqlite3.DatabaseError as e:
        conn.rollback()
        logging.exception("DB error during check_stock: %s", e)
        return jsonify({"success": False, "msg": "Database error"}), 500
    finally:
        cur.close()

# ------------------ Admin APIs ------------------
@app.route("/admin/products")
@admin_required
def admin_products():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, stock FROM products")
    items = [dict(row) for row in cur.fetchall()]
    cur.close()
    return jsonify(items)

@app.route("/admin/products/update", methods=["POST"])
@admin_required
def admin_update_product():
    data = request.get_json(silent=True) or {}
    try:
        pid = int(data["id"])
        name = data["name"]
        stock = int(data["stock"])
    except Exception:
        return jsonify({"success": False, "msg": "Invalid payload"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE products SET name=?, stock=? WHERE id=?", (name, stock, pid))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/admin/products/add", methods=["POST"])
@admin_required
def admin_add_product():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    stock = data.get("stock", 0)
    try:
        stock = int(stock)
    except Exception:
        return jsonify({"success": False, "msg": "Invalid stock"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO products (name, stock) VALUES (?, ?)", (name, stock))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/admin/products/delete", methods=["POST"])
@admin_required
def admin_delete_product():
    data = request.get_json(silent=True) or {}
    try:
        pid = int(data["id"])
    except Exception:
        return jsonify({"success": False, "msg": "Invalid payload"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM products WHERE id=?", (pid,))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, bnumber, is_admin FROM users")
    users = [dict(row) for row in cur.fetchall()]
    cur.close()
    return jsonify(users)

@app.route("/admin/users/update", methods=["POST"])
@admin_required
def admin_update_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get("id")
    new_bnumber = data.get("bnumber")
    new_password = data.get("password")
    is_admin = int(bool(data.get("is_admin", 0)))
    if new_bnumber:
        try:
            new_bnumber = normalize_bnumber(new_bnumber)
        except ValueError as e:
            return jsonify({"success": False, "msg": str(e)}), 400
    conn = get_db()
    cur = conn.cursor()
    if new_password:
        password_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET bnumber=?, password_hash=?, is_admin=? WHERE id=?",
                    (new_bnumber, password_hash, is_admin, user_id))
    else:
        cur.execute("UPDATE users SET bnumber=?, is_admin=? WHERE id=?",
                    (new_bnumber, is_admin, user_id))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get("id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

@app.route("/admin/users/search")
@admin_required
def admin_search_users():
    query = (request.args.get("query") or "").strip().lower()
    conn = get_db()
    cur = conn.cursor()
    if query:
        cur.execute("""
            SELECT id, bnumber, is_admin
            FROM users
            WHERE LOWER(bnumber) LIKE ?
            ORDER BY bnumber ASC
        """, (f"%{query}%",))
    else:
        cur.execute("SELECT id, bnumber, is_admin FROM users ORDER BY bnumber ASC")
    users = [dict(row) for row in cur.fetchall()]
    cur.close()
    return jsonify(users)

@app.route("/admin/orders/data")
@admin_required
def admin_orders_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, bnumber, product_name, quantity, timestamp, fulfilled
        FROM order_history
        ORDER BY timestamp DESC
    """)
    rows = cur.fetchall()
    cur.close()
    orders = []
    for r in rows:
        row = dict(r)
        row["timestamp"] = iso_z_from_sql(row.get("timestamp"))
        orders.append(row)
    return jsonify(orders)

@app.route("/admin/orders/search")
@admin_required
def admin_orders_search():
    query = (request.args.get("query") or "").strip().lower()
    conn = get_db()
    cur = conn.cursor()
    if query:
        cur.execute("""
            SELECT id, bnumber, product_name, quantity, timestamp, fulfilled
            FROM order_history
            WHERE LOWER(bnumber) LIKE ?
            ORDER BY timestamp DESC
        """, (f"%{query}%",))
    else:
        cur.execute("""
            SELECT id, bnumber, product_name, quantity, timestamp, fulfilled
            FROM order_history
            ORDER BY timestamp DESC
        """)
    rows = cur.fetchall()
    cur.close()
    orders = []
    for r in rows:
        row = dict(r)
        row["timestamp"] = iso_z_from_sql(row.get("timestamp"))
        orders.append(row)
    return jsonify(orders)

@app.route("/admin/orders/fulfill", methods=["POST"])
@admin_required
def fulfill_order():
    data = request.get_json(silent=True) or {}
    order_id = data.get("id")
    if order_id is None:
        return jsonify({"success": False, "msg": "Missing order ID"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE order_history SET fulfilled=1 WHERE id=?", (order_id,))
    conn.commit()
    cur.close()
    return jsonify({"success": True})

# ------------------ Background / Uploads ------------------
@app.route("/upload_background", methods=["POST"])
@login_required
def upload_background():
    if "background" not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files["background"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    if file.content_length is not None and file.content_length > MAX_UPLOAD_SIZE:
        return jsonify({"error": "File too large"}), 413
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    filename = secure_filename(f"{session['bnumber']}_{file.filename}")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    # Save safely
    file.save(filepath)
    rel_path = f"static/uploads/{filename}"
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET background_image=? WHERE bnumber=?", (rel_path, session["bnumber"]))
    conn.commit()
    cur.close()
    return jsonify({"url": f"/{rel_path}"}), 200

@app.route("/reset_background", methods=["POST"])
@login_required
def reset_background():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET background_image=NULL WHERE bnumber=?", (session["bnumber"],))
    conn.commit()
    cur.close()
    return jsonify({"url": url_for('static', filename='mimidefault.jpg')}), 200

@app.route("/api/background")
@login_required
def get_background():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT background_image FROM users WHERE bnumber=?", (session["bnumber"],))
    row = cur.fetchone()
    cur.close()
    if not row or not row["background_image"]:
        return jsonify({"success": True, "path": "static/mimidefault.jpg"})
    return jsonify({"success": True, "path": row["background_image"]})

# static serving (uploads)
@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ------------------ Run App ------------------
if __name__ == "__main__":
    # For development only: enable debug via env var
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug)
