import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_FILE = os.path.join(os.path.dirname(__file__), "research_vault.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS exports")
    cursor.execute("DROP TABLE IF EXISTS datasets")
    cursor.execute("DROP TABLE IF EXISTS users")

    cursor.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        export_quota INTEGER DEFAULT 5)""")

    cursor.execute("""CREATE TABLE datasets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        metrics TEXT NOT NULL,
        classification TEXT DEFAULT 'CONFIDENTIAL',
        FOREIGN KEY (owner_id) REFERENCES users (id))""")

    # Completed export jobs, saved by the Processing Service and later
    # retrieved by the requesting user through the Application API
    # (assignment Figure 1: the pipeline saves the artifact rather than
    # returning it inline).
    cursor.execute("""CREATE TABLE exports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dataset_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        summary TEXT NOT NULL,
        csv_data TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (dataset_id) REFERENCES datasets (id),
        FOREIGN KEY (owner_id) REFERENCES users (id))""")

    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM datasets")
    cursor.execute("DELETE FROM exports")

    # Seed users with salted password hashes (Secure Design: passwords never stored in plaintext)
    users = [
        ('admin', generate_password_hash('AdminSecret!2026'), 'admin', 100),
        ('alice', generate_password_hash('AlicePass!123'), 'researcher', 1),   # Quota = 1 for race condition test
        ('bob', generate_password_hash('BobPass!456'), 'researcher', 5)
    ]
    cursor.executemany("INSERT INTO users (username, password_hash, role, export_quota) VALUES (?, ?, ?, ?)", users)

    # Seed datasets: Alice owns ID 1, Bob owns ID 2
    datasets = [
        ('Genomic Sequencing Alpha', 2, '14.2,18.5,12.1,20.4', 'RESTRICTED'),
        ('Atmospheric Carbon Analysis', 3, '415.2,417.8,419.1', 'CONFIDENTIAL')
    ]
    cursor.executemany("INSERT INTO datasets (title, owner_id, metrics, classification) VALUES (?, ?, ?, ?)", datasets)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("[*] Database initialized and seeded with hashed credentials.")