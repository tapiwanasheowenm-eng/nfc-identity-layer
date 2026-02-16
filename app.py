from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'database.db'


# -------------------------
# DATABASE INIT
# -------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Users table
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

    # Admin table
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Default admin creation
    c.execute("SELECT * FROM admin WHERE username='admin'")
    if not c.fetchone():
        c.execute(
            "INSERT INTO admin (username, password) VALUES (?, ?)",
            ('admin', generate_password_hash('admin123'))
        )

    conn.commit()
    conn.close()


init_db()
def alter_profiles_table():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    columns = [
        "full_name TEXT",
        "phone TEXT",
        "bio TEXT",
        "whatsapp TEXT",
        "instagram TEXT",
        "website TEXT"
    ]

    for column in columns:
        try:
            c.execute(f"ALTER TABLE profiles ADD COLUMN {column}")
        except:
            pass

    conn.commit()
    conn.close()

alter_profiles_table()



# -------------------------
# HOME (ONLY ONE)
# -------------------------
@app.route('/')
def home():
    return """
    <html>
    <body style="font-family: Arial; text-align:center; padding:60px;">
        <h1>NFC Identity Layer 🚀</h1>
        <p>Create your smart digital identity.</p>

        <br><br>

        <a href='/register' style="padding:12px 25px; background:black; color:white; text-decoration:none;">
            Register
        </a>

        <br><br>

        <a href='/login' style="padding:12px 25px; background:gray; color:white; text-decoration:none;">
            Login
        </a>

    </body>
    </html>
    """


# -------------------------
# REGISTER
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

            return f"""
            <html>
            <body style="font-family: Arial; text-align:center; padding:50px;">
                <h2>Registration Successful ✅</h2>
                <p>Please verify your email.</p>
                <a href='/verify/{token}' style="padding:10px 20px; background:black; color:white; text-decoration:none;">
                    Verify Email
                </a>
            </body>
            </html>
            """

        except:
            conn.close()
            return "<h3>Username already exists</h3>"

    return render_template('register.html')


# -------------------------
# EMAIL VERIFICATION
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

        return """
        <html>
        <body style="font-family: Arial; text-align:center; padding:50px;">
            <h2>Email Verified Successfully ✅</h2>
            <p>You can now login.</p>
            <a href='/login' style="padding:12px 25px; background:black; color:white; text-decoration:none;">
                Go to Login
            </a>
        </body>
        </html>
        """
    else:
        conn.close()
        return "<h3>Invalid verification link</h3>"


# -------------------------
# USER LOGIN
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        c.execute("SELECT password, email_verified FROM profiles WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[0], password):

            if user[1] == 0:
                return "<h3>Please verify your email before logging in.</h3>"

            session['user'] = username
            return redirect(url_for('dashboard'))

        return "<h3>Invalid username or password</h3>"

    return """
    <html>
    <body style="font-family: Arial; text-align:center; padding:50px;">
        <h2>User Login</h2>
        <form method="POST">
            <input name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


# -------------------------
# USER DASHBOARD
# -------------------------
@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM analytics WHERE username=?", (session['user'],))
    views = c.fetchone()[0]

    conn.close()

    profile_url = f"/u/{session['user']}"

    return f"""
    <html>
    <body style="font-family: Arial; text-align:center; padding:50px;">
        <h2>Welcome, {session['user']} 🎉</h2>

        <p>Total Profile Views: {views}</p>

        <br>

        <a href="{profile_url}">View Public Profile</a><br><br>
        <a href="/edit-profile">Edit Profile</a><br><br>
        <a href="/logout">Logout</a>
    </body>
    </html>
    """


@app.route('/u/<username>')
def public_profile(username):

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Get profile
    c.execute("""
        SELECT full_name, phone, bio, whatsapp, instagram, website
        FROM profiles
        WHERE username=?
    """, (username,))

    user = c.fetchone()

    if not user:
        conn.close()
        return "<h3>Profile not found</h3>"

    # Track visit
    c.execute("""
        INSERT INTO analytics (username, timestamp)
        VALUES (?, ?)
    """, (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

    full_name, phone, bio, whatsapp, instagram, website = user

    return f"""
    <html>
    <body style="font-family:Arial; text-align:center; padding:50px;">
        <h1>{full_name or username}</h1>
        <p>{bio or ''}</p>

        <br>

        <p>📞 {phone or ''}</p>

        <br>

        {"<a href='"+whatsapp+"'>WhatsApp</a><br>" if whatsapp else ""}
        {"<a href='"+instagram+"'>Instagram</a><br>" if instagram else ""}
        {"<a href='"+website+"'>Website</a><br>" if website else ""}

        <br><br>

        <a href="/report/{username}">Report Profile</a>
    </body>
    </html>
    """



# -------------------------
# LOGOUT
# -------------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


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
        ''', (
            username,
            message,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

        return "<h3>Report submitted successfully.</h3>"

    return render_template('report.html', username=username)

@app.route('/check')
def check():
    return "Routes are loading"

# -------------------------
# ADMIN LOGIN (NOT LINKED PUBLICLY)
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

        return "<h3>Invalid admin credentials</h3>"

    return render_template('admin_login.html')


# -------------------------
# ADMIN DASHBOARD
# -------------------------
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute("SELECT * FROM reports WHERE status='open'")
    open_reports = c.fetchall()

    conn.close()

    return render_template('admin_dashboard.html', open_reports=open_reports)


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
@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():

    if 'user' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    if request.method == 'POST':

        c.execute("""
            UPDATE profiles
            SET full_name=?, phone=?, bio=?, whatsapp=?, instagram=?, website=?
            WHERE username=?
        """, (
            request.form['full_name'],
            request.form['phone'],
            request.form['bio'],
            request.form['whatsapp'],
            request.form['instagram'],
            request.form['website'],
            session['user']
        ))

        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    c.execute("""
        SELECT full_name, phone, bio, whatsapp, instagram, website
        FROM profiles
        WHERE username=?
    """, (session['user'],))

    user = c.fetchone()
    conn.close()

    full_name, phone, bio, whatsapp, instagram, website = user

    return f"""
    <html>
    <body style="padding:40px; font-family:Arial;">
        <h2>Edit Profile</h2>
        <form method="POST">
            <input name="full_name" placeholder="Full Name" value="{full_name or ''}"><br><br>
            <input name="phone" placeholder="Phone" value="{phone or ''}"><br><br>
            <textarea name="bio" placeholder="Bio">{bio or ''}</textarea><br><br>
            <input name="whatsapp" placeholder="WhatsApp Link" value="{whatsapp or ''}"><br><br>
            <input name="instagram" placeholder="Instagram Link" value="{instagram or ''}"><br><br>
            <input name="website" placeholder="Website Link" value="{website or ''}"><br><br>
            <button type="submit">Save</button>
        </form>
    </body>
    </html>
    """


# -------------------------
# RUN LOCAL
# -------------------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

