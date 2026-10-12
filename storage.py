"""Stockage local des comptes et des fichiers chiffrés partagés."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone


def now():
    return datetime.now(timezone.utc)


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return db


def initialize(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            display_name TEXT,
            bio TEXT,
            avatar_name TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contacts (
            user_a INTEGER NOT NULL REFERENCES users(id),
            user_b INTEGER NOT NULL REFERENCES users(id),
            requested_by INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL CHECK(status IN ('pending', 'accepted', 'rejected', 'blocked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_a, user_b)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            encrypted_payload BLOB NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT
        );
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            recipient_id INTEGER NOT NULL REFERENCES users(id),
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            size INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            downloaded_at TEXT,
            expires_on_download INTEGER NOT NULL DEFAULT 0,
            expired_at TEXT
        );
        """)
        columns = {column[1] for column in db.execute("PRAGMA table_info(users)")}
        for name, declaration in (("display_name", "TEXT"), ("bio", "TEXT"), ("avatar_name", "TEXT")):
            if name not in columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
        transfer_columns = {column[1] for column in db.execute("PRAGMA table_info(transfers)")}
        for name, declaration in (("expires_on_download", "INTEGER NOT NULL DEFAULT 0"), ("expired_at", "TEXT")):
            if name not in transfer_columns:
                db.execute(f"ALTER TABLE transfers ADD COLUMN {name} {declaration}")


def expiration(days=0, hours=0):
    return (now() + timedelta(days=days, hours=hours)).isoformat()


def cleanup_expired(db, upload_folder):
    expired = db.execute(
        "SELECT id, stored_name FROM transfers WHERE expires_at <= ? AND expired_at IS NULL", (now().isoformat(),)
    ).fetchall()
    for item in expired:
        path = os.path.join(upload_folder, item["stored_name"])
        if os.path.exists(path):
            os.remove(path)
    if expired:
        db.execute("UPDATE transfers SET expired_at = ? WHERE expires_at <= ? AND expired_at IS NULL", (now().isoformat(), now().isoformat()))
        db.commit()


def contact_pair(first_id, second_id):
    """Retourne une paire normalisée afin qu'une relation soit unique dans les deux sens."""
    return tuple(sorted((first_id, second_id)))
