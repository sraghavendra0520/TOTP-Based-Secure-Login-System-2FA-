# Secure Login System with TOTP-Based 2FA and Password Hashing in MySQL
from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "mysecretkey123"

# MySQL connection setup
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='mysql@Raghu@2005',
    database='website_db'
)
cursor = conn.cursor(dictionary=True)


@app.route('/')
def home():
    return redirect(url_for('login'))


# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            # If user has TOTP enabled, go to OTP verification
            if user.get('totp_enabled'):
                # keep username in session temporarily pending 2FA verification
                session['pre_2fa_user'] = user['username']
                return redirect(url_for('verify_2fa'))
            # no TOTP -> full login
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')


# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                           (username, hashed_password))
            conn.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username already exists. Try another one.", "danger")

    return render_template('register.html')


# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT username, totp_enabled FROM users WHERE username=%s", (session['username'],))
    user = cursor.fetchone()
    return render_template('dashboard.html', username=session['username'], totp_enabled=user.get('totp_enabled'))


# ---------- ENABLE 2FA (show QR & secret) ----------
@app.route('/enable-2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    # If POST: verify the code the user scanned and then enable
    if request.method == 'POST':
        token = request.form.get('token')
        # fetch secret from DB (should exist from GET)
        cursor.execute("SELECT totp_secret FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        if not user or not user.get('totp_secret'):
            flash("TOTP secret not found. Try again.", "danger")
            return redirect(url_for('enable_2fa'))

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(token, valid_window=1):
            cursor.execute("UPDATE users SET totp_enabled=1 WHERE username=%s", (username,))
            conn.commit()
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid token. Please try again.", "danger")
            # fall through to re-show the QR

    # GET: generate a secret and QR (only if not already set)
    cursor.execute("SELECT totp_secret, totp_enabled FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if user.get('totp_enabled'):
        flash("2FA is already enabled for your account.", "info")
        return redirect(url_for('dashboard'))

    if not user.get('totp_secret'):
        # generate new base32 secret and save it *temporarily* (persist so the verify page can check)
        secret = pyotp.random_base32()
        cursor.execute("UPDATE users SET totp_secret=%s WHERE username=%s", (secret, username))
        conn.commit()
    else:
        secret = user['totp_secret']

    # Create otpauth URI for Google Authenticator
    # Adjust issuer to your app name
    issuer_name = "MyFlaskApp"
    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

    # Create QR image and embed as base64
    qr_img = qrcode.make(otpauth_url)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('ascii')
    img_data = f"data:image/png;base64,{img_b64}"

    return render_template('enable_2fa.html', qr_data=img_data, secret=secret, otpauth_url=otpauth_url)


# ---------- VERIFY 2FA DURING LOGIN ----------
@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # pre_2fa_user was set after password success but before enabling session
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    username = session['pre_2fa_user']

    if request.method == 'POST':
        token = request.form.get('token')
        cursor.execute("SELECT totp_secret FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        if not user or not user.get('totp_secret'):
            flash("2FA not configured for this account.", "danger")
            return redirect(url_for('login'))

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(token, valid_window=1):
            # 2FA success -> complete login
            session.pop('pre_2fa_user', None)
            session['username'] = username
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid 2FA token. Try again.", "danger")

    return render_template('verify_2fa.html')


# ---------- DISABLE 2FA ----------
@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    # Optionally require current password or TOTP token to disable - here we require current TOTP token
    token = request.form.get('token')
    cursor.execute("SELECT totp_secret FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    if not user or not user.get('totp_secret'):
        flash("2FA not configured.", "danger")
        return redirect(url_for('dashboard'))

    totp = pyotp.TOTP(user['totp_secret'])
    if totp.verify(token, valid_window=1):
        cursor.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE username=%s", (username,))
        conn.commit()
        flash("Two-factor authentication disabled.", "success")
    else:
        flash("Invalid token. 2FA not disabled.", "danger")

    return redirect(url_for('dashboard'))


# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('pre_2fa_user', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
