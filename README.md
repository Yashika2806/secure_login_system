# 🔐 SecureAuth — Secure Login System

A Flask-based secure authentication system with a fully working web UI.

---

## 🚀 Features
- ✅ User Registration with CAPTCHA
- ✅ Login with CAPTCHA + lockout after 3 failed attempts
- ✅ Forgot Password (CAPTCHA → OTP with 30s timer → Admin approval flow)
- ✅ Forgot PIN (CAPTCHA → OTP with 30s timer → Admin approval flow)
- ✅ Reset Password (once admin approves)
- ✅ Reset PIN (once admin approves)
- ✅ Full Admin Panel: view users, unlock accounts, approve/reject reset requests
- ✅ SHA-256 password & PIN hashing
- ✅ JSON-based user storage

---

## 📁 Project Structure
```
secureauth/
├── app.py                  ← Flask backend (all API routes)
├── templates/
│   └── index.html          ← Full web UI (single page)
├── users.json              ← User database (auto-created)
├── requirements.txt
├── run_windows.bat         ← Double-click to run on Windows
└── run_mac_linux.sh        ← Run on Mac/Linux
```

---

## ▶️ How to Run

### Windows
Double-click `run_windows.bat`

### Mac / Linux
```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```

### Manual
```bash
pip install -r requirements.txt
python app.py
```

Then open your browser → **http://localhost:5000**

---

## 🔑 Default Admin Credentials
| Field    | Value      |
|----------|------------|
| Username | `admin`    |
| Password | `admin123` |

---

## 🔄 Reset Flow (How It Works)
1. User goes to **Forgot Password** or **Forgot PIN**
2. Passes CAPTCHA → gets OTP (shown on screen for demo; in production sent via email/SMS)
3. OTP valid for **30 seconds**
4. After OTP verified → request sent to admin as **PENDING**
5. Admin logs in → approves the request → status becomes **APPROVED**
6. User goes to **Reset Password** / **Reset PIN** → enters new credentials
