from flask import Flask, render_template, request, jsonify, session
import hashlib
import random
import time
import os
import json
 
app = Flask(__name__)
app.secret_key = "cybersec_secret_key_2024_secureauth"
 
# ─────────────────────────────────────────
#  CONFIG  (same as original Python script)
# ─────────────────────────────────────────
FILE_NAME       = "users.json"   # stores user data (replaces users.txt)
MAX_ATTEMPTS    = 3
OTP_VALIDITY    = 30             # seconds
ADMIN_USERNAME  = "admin"
ADMIN_PASSWORD  = "admin123"
 
# In-memory stores (same as original script's global dicts)
reset_requests     = {}   # {username: "PENDING" | "APPROVED"}
pin_reset_requests = {}   # {username: "PENDING" | "APPROVED"}
otp_store          = {}   # {username: {otp, expires_at, type}}
login_attempts     = {}   # {username: attempt_count}
 
 
# ─────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────
def hash_value(value):
    """SHA-256 hash — same as original script"""
    return hashlib.sha256(value.encode()).hexdigest()
 
 
def load_users():
    """Load users from JSON file (replaces users.txt)"""
    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, "w") as f:
            json.dump({}, f)
    with open(FILE_NAME, "r") as f:
        return json.load(f)
 
 
def save_users(users):
    """Save users to JSON file"""
    with open(FILE_NAME, "w") as f:
        json.dump(users, f, indent=2)
 
 
def generate_otp():
    """Generate 6-digit OTP — same as original script"""
    return str(random.randint(100000, 999999))
 
 
# ─────────────────────────────────────────
#  ROUTES — PAGES
# ─────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")
 
 
# ─────────────────────────────────────────
#  ROUTES — CAPTCHA
# ─────────────────────────────────────────
@app.route("/api/captcha", methods=["GET"])
def new_captcha():
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    session["captcha_answer"] = a + b
    return jsonify({"question": f"{a} + {b} = ?"})
 
 
@app.route("/api/captcha/verify", methods=["POST"])
def verify_captcha():
    data = request.json
    correct = session.get("captcha_answer")
    try:
        ans = int(data.get("answer", -1))
    except (ValueError, TypeError):
        return jsonify({"ok": False})
    return jsonify({"ok": ans == correct})
 
 
# ─────────────────────────────────────────
#  ROUTES — REGISTER
# ─────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    pin      = data.get("pin", "")
 
    if not username or not password or not pin:
        return jsonify({"ok": False, "msg": "All fields are required"})
 
    if not pin.isdigit() or len(pin) != 6:
        return jsonify({"ok": False, "msg": "PIN must be exactly 6 digits"})
 
    users = load_users()
 
    if username in users:
        return jsonify({"ok": False, "msg": "Username already exists"})
 
    users[username] = {
        "password": hash_value(password),
        "pin":      hash_value(pin),
        "locked":   False
    }
    save_users(users)
    return jsonify({"ok": True, "msg": "Account created successfully!"})
 
 
# ─────────────────────────────────────────
#  ROUTES — LOGIN
# ─────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")
    pin      = data.get("pin", "")
 
    users = load_users()
 
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
 
    if users[username]["locked"]:
        return jsonify({"ok": False, "msg": "Account is LOCKED. Contact admin to unlock.", "locked": True})
 
    # Check credentials
    if (hash_value(password) == users[username]["password"] and
            hash_value(pin) == users[username]["pin"]):
        login_attempts[username] = 0
        session["logged_in_user"] = username
        return jsonify({"ok": True, "msg": "Login successful!", "username": username})
 
    # Wrong credentials
    attempts = login_attempts.get(username, 0) + 1
    login_attempts[username] = attempts
    remaining = MAX_ATTEMPTS - attempts
 
    if attempts >= MAX_ATTEMPTS:
        users[username]["locked"] = True
        save_users(users)
        login_attempts[username] = 0
        return jsonify({"ok": False, "msg": "Too many failed attempts. Account is now LOCKED.", "locked": True, "attempts": attempts})
 
    return jsonify({"ok": False, "msg": f"Wrong credentials. {remaining} attempt(s) left.", "attempts": attempts})
 
 
# ─────────────────────────────────────────
#  ROUTES — FORGOT PASSWORD
# ─────────────────────────────────────────
@app.route("/api/forgot-password/otp", methods=["POST"])
def forgot_password_otp():
    """Step 1: Verify user + PIN, send OTP"""
    data     = request.json
    username = data.get("username", "").strip()
    pin      = data.get("pin", "")
 
    users = load_users()
 
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
 
    if hash_value(pin) != users[username]["pin"]:
        return jsonify({"ok": False, "msg": "Incorrect PIN"})
 
    otp = generate_otp()
    otp_store[username] = {
        "otp":        otp,
        "expires_at": time.time() + OTP_VALIDITY,
        "type":       "password"
    }
    return jsonify({"ok": True, "otp": otp, "expires_in": OTP_VALIDITY,
                    "msg": "OTP generated (shown here for demo — in production sent via SMS/email)"})
 
 
@app.route("/api/forgot-password/verify", methods=["POST"])
def forgot_password_verify():
    """Step 2: Verify OTP, create admin reset request"""
    data        = request.json
    username    = data.get("username", "").strip()
    otp_entered = data.get("otp", "")
 
    record = otp_store.get(username)
    if not record or record["type"] != "password":
        return jsonify({"ok": False, "msg": "No OTP found. Please start over."})
    if time.time() > record["expires_at"]:
        return jsonify({"ok": False, "msg": "OTP has expired. Please start over."})
    if otp_entered != record["otp"]:
        return jsonify({"ok": False, "msg": "Wrong OTP entered"})
 
    reset_requests[username] = "PENDING"
    del otp_store[username]
    return jsonify({"ok": True, "msg": "Reset request sent to admin. Come back here after admin approves it."})
 
 
# ─────────────────────────────────────────
#  ROUTES — FORGOT PIN
# ─────────────────────────────────────────
@app.route("/api/forgot-pin/otp", methods=["POST"])
def forgot_pin_otp():
    """Step 1: Verify user exists, send OTP"""
    data     = request.json
    username = data.get("username", "").strip()
 
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
 
    otp = generate_otp()
    otp_store[username] = {
        "otp":        otp,
        "expires_at": time.time() + OTP_VALIDITY,
        "type":       "pin"
    }
    return jsonify({"ok": True, "otp": otp, "expires_in": OTP_VALIDITY,
                    "msg": "OTP generated"})
 
 
@app.route("/api/forgot-pin/verify", methods=["POST"])
def forgot_pin_verify():
    """Step 2: Verify OTP, create admin PIN reset request"""
    data        = request.json
    username    = data.get("username", "").strip()
    otp_entered = data.get("otp", "")
 
    record = otp_store.get(username)
    if not record or record["type"] != "pin":
        return jsonify({"ok": False, "msg": "No OTP found. Please start over."})
    if time.time() > record["expires_at"]:
        return jsonify({"ok": False, "msg": "OTP has expired. Please start over."})
    if otp_entered != record["otp"]:
        return jsonify({"ok": False, "msg": "Wrong OTP entered"})
 
    pin_reset_requests[username] = "PENDING"
    del otp_store[username]
    return jsonify({"ok": True, "msg": "PIN reset request sent to admin."})
 
 
# ─────────────────────────────────────────
#  ROUTES — RESET PASSWORD
# ─────────────────────────────────────────
@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data         = request.json
    username     = data.get("username", "").strip()
    pin          = data.get("pin", "")
    new_password = data.get("new_password", "")
    new_pin      = data.get("new_pin", "")
 
    users = load_users()
 
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
    if reset_requests.get(username) != "APPROVED":
        return jsonify({"ok": False, "msg": "No approved reset request found. Ask admin to approve first."})
    if hash_value(pin) != users[username]["pin"]:
        return jsonify({"ok": False, "msg": "Incorrect current PIN"})
    if not new_password:
        return jsonify({"ok": False, "msg": "New password cannot be empty"})
    if not new_pin.isdigit() or len(new_pin) != 6:
        return jsonify({"ok": False, "msg": "New PIN must be exactly 6 digits"})
 
    users[username]["password"] = hash_value(new_password)
    users[username]["pin"]      = hash_value(new_pin)
    save_users(users)
    del reset_requests[username]
 
    return jsonify({"ok": True, "msg": "Password updated successfully!"})
 
 
# ─────────────────────────────────────────
#  ROUTES — RESET PIN
# ─────────────────────────────────────────
@app.route("/api/reset-pin", methods=["POST"])
def reset_pin():
    data     = request.json
    username = data.get("username", "").strip()
    new_pin  = data.get("new_pin", "")
 
    users = load_users()
 
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
    if pin_reset_requests.get(username) != "APPROVED":
        return jsonify({"ok": False, "msg": "No approved PIN reset request. Ask admin to approve first."})
    if not new_pin.isdigit() or len(new_pin) != 6:
        return jsonify({"ok": False, "msg": "New PIN must be exactly 6 digits"})
 
    users[username]["pin"] = hash_value(new_pin)
    save_users(users)
    del pin_reset_requests[username]
 
    return jsonify({"ok": True, "msg": "PIN updated successfully!"})
 
 
# ─────────────────────────────────────────
#  ROUTES — ADMIN
# ─────────────────────────────────────────
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        session["admin"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Invalid admin credentials"})
 
 
@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin", None)
    return jsonify({"ok": True})
 
 
@app.route("/api/admin/data", methods=["GET"])
def admin_data():
    if not session.get("admin"):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
 
    users     = load_users()
    user_list = [{"username": u, "locked": d["locked"]} for u, d in users.items()]
 
    return jsonify({
        "ok":             True,
        "users":          user_list,
        "reset_requests": reset_requests,
        "pin_requests":   pin_reset_requests
    })
 
 
@app.route("/api/admin/unlock", methods=["POST"])
def admin_unlock():
    if not session.get("admin"):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
 
    data     = request.json
    username = data.get("username")
    users    = load_users()
 
    if username not in users:
        return jsonify({"ok": False, "msg": "User not found"})
 
    users[username]["locked"] = False
    save_users(users)
    return jsonify({"ok": True, "msg": f"'{username}' has been unlocked"})
 
 
@app.route("/api/admin/password-reset", methods=["POST"])
def admin_password_reset():
    if not session.get("admin"):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
 
    data     = request.json
    username = data.get("username")
    action   = data.get("action")  # "approve" or "reject"
 
    if username not in reset_requests:
        return jsonify({"ok": False, "msg": "No request found for this user"})
 
    if action == "approve":
        reset_requests[username] = "APPROVED"
        return jsonify({"ok": True, "msg": f"Password reset approved for '{username}'"})
    elif action == "reject":
        del reset_requests[username]
        return jsonify({"ok": True, "msg": f"Password reset rejected for '{username}'"})
 
    return jsonify({"ok": False, "msg": "Invalid action"})
 
 
@app.route("/api/admin/pin-reset", methods=["POST"])
def admin_pin_reset():
    if not session.get("admin"):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
 
    data     = request.json
    username = data.get("username")
    action   = data.get("action")
 
    if username not in pin_reset_requests:
        return jsonify({"ok": False, "msg": "No request found for this user"})
 
    if action == "approve":
        pin_reset_requests[username] = "APPROVED"
        return jsonify({"ok": True, "msg": f"PIN reset approved for '{username}'"})
    elif action == "reject":
        del pin_reset_requests[username]
        return jsonify({"ok": True, "msg": f"PIN reset rejected for '{username}'"})
 
    return jsonify({"ok": False, "msg": "Invalid action"})
 
 
# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*50)
    print("  SecureAuth — Secure Login System")
    print("="*50)
    print("  Open browser → http://localhost:5000")
    print("  Admin login  → admin / admin123")
    print("  Press CTRL+C to stop the server")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)