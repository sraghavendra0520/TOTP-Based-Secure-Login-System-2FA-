from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, qrcode, io, base64

app = Flask(__name__)
app.secret_key = "super_secret_key"

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="mysql@Raghu@2005",
    database="website_db"
)
cursor = conn.cursor(dictionary=True)


@app.route('/')
def home():
    return redirect(url_for('login'))


# ---------- LOGIN ----------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username=%s", (u,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], p):
            if user['totp_enabled']:
                session['pre_2fa_user'] = u
                return redirect(url_for('verify_2fa'))
            session['username'] = u
            return redirect(url_for('dashboard'))
        flash("Invalid login credentials", "danger")

    return render_template('login.html')


# ---------- REGISTER ----------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        c = request.form['confirm_password']

        if p != c:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))

        try:
            cursor.execute(
                "INSERT INTO users(username,password) VALUES(%s,%s)",
                (u, generate_password_hash(p))
            )
            conn.commit()
            flash("Registration successful", "success")
            return redirect(url_for('login'))
        except:
            flash("Username already exists", "danger")

    return render_template('register.html')


# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    cursor.execute(
        "SELECT totp_enabled FROM users WHERE username=%s",
        (session['username'],)
    )
    user = cursor.fetchone()
    return render_template('dashboard.html', username=session['username'], totp_enabled=user['totp_enabled'])


# ---------- PROFILE ----------
@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    cursor.execute(
        "SELECT username, totp_enabled FROM users WHERE username=%s",
        (session['username'],)
    )
    user = cursor.fetchone()
    return render_template('profile.html', user=user)


# ---------- CHANGE PASSWORD ----------
@app.route('/change-password', methods=['GET','POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if new != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('change_password'))

        cursor.execute(
            "SELECT password FROM users WHERE username=%s",
            (session['username'],)
        )
        user = cursor.fetchone()

        if not check_password_hash(user['password'], old):
            flash("Old password incorrect", "danger")
            return redirect(url_for('change_password'))

        cursor.execute(
            "UPDATE users SET password=%s WHERE username=%s",
            (generate_password_hash(new), session['username'])
        )
        conn.commit()

        flash("Password updated successfully", "success")
        return redirect(url_for('profile'))

    return render_template('change_password.html')


# ---------- ENABLE 2FA ----------
@app.route('/enable-2fa', methods=['GET','POST'])
def enable_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    cursor.execute(
        "SELECT totp_secret, totp_enabled FROM users WHERE username=%s",
        (session['username'],)
    )
    user = cursor.fetchone()

    if user['totp_enabled']:
        flash("2FA already enabled", "info")
        return redirect(url_for('dashboard'))

    if not user['totp_secret']:
        secret = pyotp.random_base32()
        cursor.execute(
            "UPDATE users SET totp_secret=%s WHERE username=%s",
            (secret, session['username'])
        )
        conn.commit()
    else:
        secret = user['totp_secret']

    if request.method == 'POST':
        token = request.form['token']
        if pyotp.TOTP(secret).verify(token):
            cursor.execute(
                "UPDATE users SET totp_enabled=1 WHERE username=%s",
                (session['username'],)
            )
            conn.commit()
            flash("2FA enabled", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid code", "danger")

    uri = pyotp.totp.TOTP(secret).provisioning_uri(session['username'], issuer_name="SecureApp")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    qr = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    return render_template('enable_2fa.html', qr_data=qr, secret=secret)


# ---------- VERIFY 2FA ----------
@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    if 'pre_2fa_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        cursor.execute(
            "SELECT totp_secret FROM users WHERE username=%s",
            (session['pre_2fa_user'],)
        )
        user = cursor.fetchone()

        if pyotp.TOTP(user['totp_secret']).verify(token):
            session['username'] = session.pop('pre_2fa_user')
            return redirect(url_for('dashboard'))
        flash("Invalid code", "danger")

    return render_template('verify_2fa.html')


# ---------- DISABLE 2FA ----------
@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    password = request.form['password']
    token = request.form['token']

    cursor.execute(
        "SELECT password, totp_secret FROM users WHERE username=%s",
        (session['username'],)
    )
    user = cursor.fetchone()

    if not check_password_hash(user['password'], password):
        flash("Wrong password", "danger")
        return redirect(url_for('dashboard'))

    if not pyotp.TOTP(user['totp_secret']).verify(token):
        flash("Invalid OTP", "danger")
        return redirect(url_for('dashboard'))

    cursor.execute(
        "UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE username=%s",
        (session['username'],)
    )
    conn.commit()

    flash("2FA disabled", "success")
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
