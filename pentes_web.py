import os
import sqlite3
import random
from datetime import datetime, timedelta

# Import modul Flask dan ekstensi yang diperlukan
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    g,
    flash,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash

# --- Konfigurasi Aplikasi ---
# Menggunakan secret key yang aman untuk lingkungan produksi (meskipun ini latihan)
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "secret_key_yang_sangat_sulit_ditebak_untuk_latihan_pentest")
    # Menggunakan SQLite in-memory untuk kemudahan reproducibility
    DATABASE = ":memory:"  
    # Atau ganti dengan 'database.db' jika ingin data tetap setelah restart:
    # DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db') 

app = Flask(__name__)
app.config.from_object(Config)

# --- Konfigurasi Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Harap masuk untuk mengakses halaman ini."


# --- Model Pengguna (untuk Flask-Login) ---
class User(UserMixin):
    def __init__(self, user_id, username, password_hash, role):
        self.id = str(user_id)
        self.username = username
        self.password_hash = password_hash
        self.role = role  # 'Admin' atau 'User'

    def is_admin(self):
        return self.role == "Admin"


# --- Fungsi Database ---

def get_db():
    # Mendapatkan koneksi DB, atau membuat koneksi baru
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    # Menutup koneksi DB saat request selesai
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()

    # Tabel Pengguna
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL 
        )
    """
    )

    # Tabel Log Aktivitas (untuk diakses oleh Admin)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            route TEXT NOT NULL,
            method TEXT NOT NULL
        )
    """
    )
    db.commit()

def populate_db():
    db = get_db()
    cursor = db.cursor()

    # Hapus data lama (jika in-memory)
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM logs")

    # Tambahkan Pengguna untuk Latihan
    users_to_add = [
        # Pengguna Admin (Akses Penuh - Seharusnya)
        (1, "admin", generate_password_hash("password123"), "Admin"), 
        # Pengguna Standar (Akses Terbatas - LOKASI CELAH)
        (2, "user", generate_password_hash("password"), "User"),     
    ]
    cursor.executemany(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)", users_to_add
    )

    # Tambahkan Log Dummy
    log_entries = []
    current_time = datetime.now()
    routes = ["/", "/login", "/dashboard", "/admin/panel"]
    for i in range(10):
        timestamp = (current_time - timedelta(minutes=i*10)).strftime("%Y-%m-%d %H:%M:%S")
        user_id = random.choice([1, 2, 0]) # 0 untuk unauthenticated
        route = random.choice(routes)
        log_entries.append((timestamp, user_id, route, "GET"))
    
    cursor.executemany(
        "INSERT INTO logs (timestamp, user_id, route, method) VALUES (?, ?, ?, ?)", log_entries
    )
    db.commit()


# Inisialisasi DB saat startup
with app.app_context():
    init_db()
    populate_db()

# --- Fungsi Utility/Keamanan ---

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute("SELECT id, username, password_hash, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_data:
        return User(*user_data)
    return None

def log_activity(user_id, route, method):
    # Mencatat setiap aktivitas penting ke tabel logs
    db = get_db()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO logs (timestamp, user_id, route, method) VALUES (?, ?, ?, ?)",
        (timestamp, user_id, route, method),
    )
    db.commit()

# Decorator untuk mengecek peran Admin
def admin_required(f):
    def wrap(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Akses ditolak: Anda harus menjadi Admin.", "danger")
            # Log akses gagal
            log_activity(current_user.id if current_user.is_authenticated else 0, request.path, request.method)
            return redirect(url_for("dashboard")) # Redirect ke dashboard atau 403
        
        # Log akses berhasil
        log_activity(current_user.id, request.path, request.method)
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- Routes Aplikasi ---

@app.route("/")
def index():
    user_id = current_user.id if current_user.is_authenticated else 0
    log_activity(user_id, "/", request.method)
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user_data = db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user_data:
            user = User(*user_data)
            if check_password_hash(user.password_hash, password):
                login_user(user)
                flash(f"Berhasil masuk sebagai {user.username} ({user.role})!", "success")
                log_activity(user.id, "/login (Success)", request.method)
                return redirect(url_for("dashboard"))
        
        flash("Login gagal. Nama pengguna atau sandi salah.", "danger")
        log_activity(0, "/login (Failed)", request.method) # Log percobaan login gagal
        return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.id, "/logout", request.method)
    logout_user()
    flash("Anda telah keluar.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    log_activity(current_user.id, "/dashboard", request.method)
    return render_template("dashboard.html")

@app.route("/admin/panel")
@admin_required # Halaman ini memiliki kontrol akses yang BENAR (Hanya Admin)
def admin_panel():
    # log_activity sudah dilakukan di admin_required
    return render_template("admin_panel.html")

# ====================================================================
# LOKASI CELAH KEAMANAN BERISIKO RENDAH (UNTUK LATIHAN)
# ====================================================================

@app.route("/admin/logs")
@login_required # <--- CELAH: HANYA MEMERIKSA AUTENTIKASI, BUKAN PERAN (ROLE)
def admin_logs():
    # Log aktivitas di sini karena dekorator @login_required tidak menyediakan logging
    user_id = current_user.id if current_user.is_authenticated else 0
    log_activity(user_id, request.path, request.method) 
    
    # Kueri log
    db = get_db()
    logs = db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100").fetchall()
    
    # Catatan: Halaman ini seharusnya hanya diakses oleh Admin.
    # Namun, karena hanya menggunakan @login_required, Standar User bisa melihatnya.
    return render_template("logs.html", logs=logs)

# ====================================================================
# Akhir Lokasi Celah
# ====================================================================


# --- Template HTML Sederhana ---

# Karena instruksi melarang file terpisah, saya akan menyertakan konten template 
# dalam format string untuk menjalankan aplikasi dengan satu file, 
# tetapi dalam implementasi nyata, file-file ini berada di folder 'templates/'.

TEMPLATES = {
    "base.html": """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}kentang.net - Lingkungan Latihan Pentest{% endblock %}</title>
    <style>
        body { font-family: sans-serif; margin: 0; padding: 0; background-color: #f4f4f9; color: #333; }
        .container { width: 90%; max-width: 960px; margin: 20px auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background-color: #5d4037; color: white; padding: 10px 20px; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }
        .header a { color: white; text-decoration: none; margin: 0 15px; }
        .flash { padding: 10px; margin-bottom: 15px; border-radius: 4px; }
        .flash.success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .flash.danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .flash.info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        h1 { color: #5d4037; }
        form { background-color: #f9f9f9; padding: 20px; border-radius: 6px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"], .button { background-color: #795548; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block;}
        input[type="submit"]:hover, .button:hover { background-color: #4e342e; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #efebe9; }
        .admin-link { margin-left: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <a href="{{ url_for('index') }}">kentang.net</a>
        <nav>
            {% if current_user.is_authenticated %}
                {% if current_user.is_admin() %}
                    <a href="{{ url_for('admin_panel') }}" class="admin-link">Admin Panel</a>
                {% endif %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('logout') }}">Logout ({{ current_user.username }})</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
            {% endif %}
        </nav>
    </div>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=True) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
    """,
    "index.html": """
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
    <h1>Selamat Datang di kentang.net</h1>
    <p>Ini adalah lingkungan latihan pengujian penetrasi etis, dibangun dengan Flask.</p>
    <p>Tujuan Anda adalah menemukan kerentanan tunggal berisiko rendah yang disengaja. Ingat, fokuslah pada otorisasi dan akses.</p>
    {% if not current_user.is_authenticated %}
        <p>Gunakan kredensial berikut untuk login:</p>
        <ul>
            <li>**Admin:** `admin`/`password123`</li>
            <li>**User Standar:** `user`/`password`</li>
        </ul>
        <p><a href="{{ url_for('login') }}" class="button">Masuk Sekarang</a></p>
    {% else %}
        <p>Anda sudah login sebagai **{{ current_user.username }}** (Role: **{{ current_user.role }}**).</p>
        <p><a href="{{ url_for('dashboard') }}" class="button">Ke Dashboard</a></p>
    {% endif %}
{% endblock %}
    """,
    "login.html": """
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
    <h1>Login</h1>
    <form method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <input type="submit" value="Login">
    </form>
{% endblock %}
    """,
    "dashboard.html": """
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
    <h1>Dashboard Pengguna</h1>
    <h2>Halo, {{ current_user.username }}!</h2>
    <p>Selamat datang di dashboard Anda. Role Anda adalah: <strong>{{ current_user.role }}</strong>.</p>
    <p>Ini adalah halaman pribadi Anda. Jika Anda adalah Admin, coba temukan link menuju panel admin.</p>
    {% if current_user.is_admin() %}
        <p class="flash info">Sebagai Admin, Anda memiliki akses ke <a href="{{ url_for('admin_panel') }}">Panel Admin</a>.</p>
    {% else %}
        <p class="flash info">Sebagai User Standar, Anda **seharusnya** hanya memiliki akses ke halaman ini. Coba uji batasan akses Anda!</p>
    {% endif %}
{% endblock %}
    """,
    "admin_panel.html": """
{% extends "base.html" %}
{% block title %}Admin Panel{% endblock %}
{% block content %}
    <h1>Admin Panel</h1>
    <p class="flash danger">PERINGATAN: Halaman ini memiliki kontrol akses yang KETAT dan HANYA dapat diakses oleh Admin.</p>
    <p>Ini adalah pusat kendali Administrasi. Hanya Admin yang sah yang bisa berada di sini.</p>
    <ul>
        <li><a href="{{ url_for('admin_logs') }}">Lihat Log Aktivitas Sistem (Petunjuk: Ini adalah target utama Anda)</a></li>
        <li>Kelola Pengguna (Fitur fiktif)</li>
    </ul>
{% endblock %}
    """,
    "logs.html": """
{% extends "base.html" %}
{% block title %}Log Aktivitas Sistem{% endblock %}
{% block content %}
    <h1>Log Aktivitas Sistem (Halaman Admin)</h1>
    <p class="flash danger">PERHATIAN: Halaman ini seharusnya hanya diakses oleh pengguna Admin. <span style="font-weight: bold;">Periksa apakah Anda benar-benar Admin!</span></p>

    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>User ID</th>
                <th>Route</th>
                <th>Method</th>
            </tr>
        </thead>
        <tbody>
            {% for log in logs %}
            <tr>
                <td>{{ log.timestamp }}</td>
                <td>{{ log.user_id }}</td>
                <td>{{ log.route }}</td>
                <td>{{ log.method }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
{% endblock %}
    """
}

# --- Fungsi Render Kustom (untuk Single-File Deployment) ---
# Menggantikan fungsi render_template standar untuk menggunakan string di atas
@app.before_request
def before_request():
    # Ini diperlukan agar Flask bisa menemukan templates dalam string
    pass

def render_template(template_name_or_list, **context):
    if template_name_or_list in TEMPLATES:
        # Menggunakan Jinja2 untuk merender template dari string
        from jinja2 import Template
        template = Template(TEMPLATES[template_name_or_list])
        return template.render(**context, current_user=current_user, get_flashed_messages=lambda with_categories: session.pop('_flashes') if '_flashes' in session else [])
    
    # Fallback jika template tidak ditemukan (tidak akan terjadi dalam kasus ini)
    raise FileNotFoundError(f"Template not found: {template_name_or_list}")

def flash(message, category='message'):
    # Fungsi flash kustom karena kita menimpa render_template
    if '_flashes' not in session:
        session['_flashes'] = []
    session['_flashes'].append((category, message))

# Fungsi untuk url_for di dalam template (diperlukan saat menimpa render_template)
app.jinja_env.globals.update(url_for=url_for)
app.jinja_env.globals.update(get_flashed_messages=lambda with_categories: session.pop('_flashes') if '_flashes' in session else [])


if __name__ == "__main__":
    print("===================================================================")
    print(" LINGKUNGAN LATIHAN PENTEST kentang.net SIAP")
    print(" JANGAN PERNAH MENJALANKAN INI DI LINGKUNGAN PRODUKSI/PUBLIK!")
    print("===================================================================")
    print("Akses: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)")
    print("Kredensial Admin: admin / password123")
    print("Kredensial User Standar: user / password")
    print("\nInstruksi Celah:")
    print("Uji otorisasi dengan akun Standar User ke halaman Admin Logs.")
    app.run(debug=True, host="127.0.0.1")