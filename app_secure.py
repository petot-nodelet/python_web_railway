# app_secure.py
# Hardened version with parameterized queries, simple token auth for /secret,
# naive rate limiting and safer rendering.
from flask import Flask, request, render_template_string, abort, jsonify
import sqlite3
import time
from functools import wraps

app = Flask(__name__)

DB = 'users.db'
SECRET_FILE = 'secret_top_secret.txt'
# simple in-memory rate limiter {ip: [timestamps]}
RATE = {}
RATE_LIMIT = 10  # max requests
RATE_WINDOW = 60  # seconds
# simple token for /secret access (lab-only). Set via env or here:
ACCESS_TOKEN = "LAB_ONLY_TOKEN_ChangeMe"

def rate_limiter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or 'anon'
        now = time.time()
        RATE.setdefault(ip, [])
        # remove old
        RATE[ip] = [t for t in RATE[ip] if now - t < RATE_WINDOW]
        if len(RATE[ip]) >= RATE_LIMIT:
            return ("Too many requests", 429)
        RATE[ip].append(now)
        return func(*args, **kwargs)
    return wrapper

def query_user_param(user):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (user,))
    r = cur.fetchone()
    conn.close()
    return r[0] if r else None

@app.route('/')
def index():
    return "Lab Hardened App — for testing mitigations."

@app.route('/search')
@rate_limiter
def search():
    # escape user input via render_template_string with safe variable
    q = request.args.get('q', '')
    safe = render_template_string("{{ q }}", q=q)
    return "<h3>You searched:</h3><div>%s</div>" % safe

@app.route('/login', methods=['GET','POST'])
@rate_limiter
def login():
    if request.method == 'POST':
        user = request.form.get('username','')
        pw = request.form.get('password','')
        real = query_user_param(user)
        if real and pw == real:
            # real app: set secure cookie + session; here simple response
            return jsonify({"msg":"ok","user":user})
        return ("Bad creds", 401)
    return '''
      <form method="post">
       <input name="username" placeholder="username">
       <input name="password" placeholder="password" type="password">
       <button>Login</button>
      </form>
    '''

@app.route('/secret')
def secret():
    # Require a token in header for lab protection (simple)
    token = request.headers.get('X-ACCESS-TOKEN','')
    if token != ACCESS_TOKEN:
        abort(403)
    try:
        with open(SECRET_FILE,'r') as f:
            return f.read()
    except Exception as e:
        return "No secret found: %s" % e

if __name__ == '__main__':
    # debug off in hardened
    app.run(host='0.0.0.0', port=8000, debug=False)