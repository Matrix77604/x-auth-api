import os
import sqlite3
import requests
from flask import Flask, request, redirect, session, jsonify, render_template, url_for
from requests_oauthlib import OAuth1Session

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = "accounts.db"
CALLBACK_URI = os.environ.get("CALLBACK_URI", "http://localhost:8080/callback")

# --- Banco SQLite ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                oauth_token TEXT NOT NULL,
                oauth_token_secret TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def insert_account(username, token, token_secret):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO accounts (username, oauth_token, oauth_token_secret)
            VALUES (?, ?, ?)
        """, (username, token, token_secret))
        conn.commit()
        return c.lastrowid

def get_account(account_id):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, oauth_token, oauth_token_secret FROM accounts WHERE id = ?", (account_id,))
        row = c.fetchone()
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "oauth_token": row[2],
                "oauth_token_secret": row[3]
            }
        return None

def list_accounts():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT id, username FROM accounts")
        return c.fetchall()

# --- Rotas ---
@app.route("/")
def index():
    accounts = list_accounts()
    return render_template("index.html", accounts=accounts)

@app.route("/auth", methods=["POST"])
def auth():
    consumer_key = request.form.get("consumer_key")
    consumer_secret = request.form.get("consumer_secret")
    session["consumer_key"] = consumer_key
    session["consumer_secret"] = consumer_secret

    oauth = OAuth1Session(consumer_key, client_secret=consumer_secret, callback_uri=CALLBACK_URI)
    fetch_response = oauth.fetch_request_token("https://api.twitter.com/oauth/request_token")
    session["resource_owner_key"] = fetch_response.get("oauth_token")
    session["resource_owner_secret"] = fetch_response.get("oauth_token_secret")

    authorization_url = oauth.authorization_url("https://api.twitter.com/oauth/authorize")
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    consumer_key = session.get("consumer_key")
    consumer_secret = session.get("consumer_secret")
    resource_owner_key = session.get("resource_owner_key")
    resource_owner_secret = session.get("resource_owner_secret")
    oauth_response = request.args

    oauth = OAuth1Session(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret,
        verifier=oauth_response.get("oauth_verifier")
    )

    tokens = oauth.fetch_access_token("https://api.twitter.com/oauth/access_token")
    access_token = tokens.get("oauth_token")
    access_token_secret = tokens.get("oauth_token_secret")
    username = tokens.get("screen_name")

    account_id = insert_account(username, access_token, access_token_secret)
    return redirect(url_for("index"))

@app.route("/api/tokens/<int:account_id>")
def api_tokens(account_id):
    account = get_account(account_id)
    if not account:
        return jsonify({"error": "Conta não encontrada"}), 404
    return jsonify(account)

if __name__ == "__main__":
    init_db()
    app.run(port=8080)