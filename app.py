from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'database.db'


# -------------------------
# DATABASE INIT
# -------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Users
    c.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            email_verified INTEGER DEFAULT 0,
            verify_token TEXT
        )
    ''')

    # Analytics
    c.execute('''
        CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT
        )
    ''')

    # Fraud reports
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reported_username TEXT,
            message TEXT,
            status TEXT DEFAULT 'open',
            timestamp TEXT
        )
    ''')

    # Admin
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Default admin
    c.execute("SELECT * FROM admin WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO admin (username, password) VALUES (?, ?)",
                  ('admin', generate_password_hash('admin123')))

    conn.commit()
    conn.close()

init_db()


# -------------------------
# REGISTER (EMAIL VERIFY TOKEN GENERATED)
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        email = request.form['email']
        token = str(uuid.uuid4())

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        try:
            c.execute('''
                INSERT INTO profiles (username, password, email, verify_token)
                VALUES (?, ?, ?, ?)
            ''', (username, password, email, token))

            conn.commit()
            conn.close()

            # For now we display verification link (local testing)
            return f"""
            Registration successful.<br><br>
            VERIFY YOUR EMAIL:<br>
            <a href='/verify/{token}'>Click here to verify</a>
            """

        except:
            conn.close()
            return "Username already exists"

    return render_template('register.html')


# -------------------------
# VERIFY EMAIL
# -------------------------
@app.route('/verify/<token>')
def verify_email(token):

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("SELECT username FROM profiles WHERE verify_token=?", (token,))
    user = c.fetchone()

    if user:
        c.execute("UPDATE profiles SET email_verified=1 WHERE verify_token=?", (token,))
        conn.commit()
        conn.close()
        return "Email successfully verified!"
    else:
        conn.close()
        return "Invalid verification link."


# -------------------------
# FRAUD REPORT
# -------------------------
@app.route('/report/<username>', methods=['GET', 'POST'])
def report(username):

    if request.method == 'POST':

        message = request.form['message']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute('''
            INSERT INTO reports (reported_username, message, timestamp)
            VALUES (?, ?, ?)
        ''', (username, message, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        conn.close()

        return "Report submitted successfully."

    return render_template('report.html', username=username)


# -------------------------
# ADMIN DASHBOARD
# -------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM admin WHERE username=?", (username,))
        admin = c.fetchone()
        conn.close()

        if admin and check_password_hash(admin[0], password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid admin credentials"

    return render_template('admin_login.html')


@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("SELECT * FROM reports WHERE status='open'")
    open_reports = c.fetchall()

    conn.close()

    return render_template(
        'admin_dashboard.html',
        open_reports=open_reports
    )


@app.route('/resolve-report/<int:report_id>')
def resolve_report(report_id):

    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("UPDATE reports SET status='resolved' WHERE id=?", (report_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run()


