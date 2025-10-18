# app_vuln.py
# Minimal vulnerable Flask app — intentionally insecure for learning.
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

DB = 'users.db'
SECRET_FILE = 'secret_top_secret.txt'

def query_user_raw(user):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # INTENTIONALLY VULNERABLE: string concat -> SQLi possible
    cur.execute("SELECT password FROM users WHERE username = '%s'" % user)
    r = cur.fetchone()
    conn.close()
    return r[0] if r else None

@app.route('/')
def index():
    return "Lab Vulnerable App — do not expose to internet."

@app.route('/search')
def search():
    # reflected XSS by design
    q = request.args.get('q', '')
    return render_template_string("<h3>You searched:</h3><div>" + q + "</div>")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username','')
        pw = request.form.get('password','')
        real = query_user_raw(user)
        if real and pw == real:
            return "Welcome, %s" % user
        return "Bad creds"
    return '''
      <form method="post">
       <input name="username" placeholder="username">
       <input name="password" placeholder="password" type="password">
       <button>Login</button>
      </form>
    '''

@app.route('/secret')
def secret():
    # naive secret read — no auth
    try:
        with open(SECRET_FILE,'r') as f:
            return f.read()
    except Exception as e:
        return "No secret found: %s" % e

if __name__ == '__main__':
    # debug=True purposeful for learning (shows stack traces)
    app.run(host='0.0.0.0', port=8000, debug=True)