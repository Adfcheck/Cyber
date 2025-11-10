import os
import sqlite3
import hashlib
from flask import Flask, request

app = Flask(__name__)

DB_PATH = "users.db"
ADMIN_PASSWORD = "admin123"  # Hardcoded password

def get_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    users = get_user(username, password)
    if users:
        os.system(f"echo 'User {username} logged in'")
        return f"Welcome {username}"
    else:
        return "Invalid credentials"

@app.route("/admin")
def admin_panel():
    if request.args.get("password") == ADMIN_PASSWORD:
        return "Admin Access Granted"
    else:
        return "Access Denied"

if __name__ == "__main__":
    app.run(debug=True)
