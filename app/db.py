"""Accès SQLite : schéma, requêtes et export .sql."""
import os, sqlite3

DB_PATH = os.getenv("DB_PATH", "/data/scans.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sha256 TEXT, size INTEGER,
  verdict TEXT, score INTEGER, engine TEXT, details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS wireless_scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, batch TEXT, kind TEXT, name TEXT,
  address TEXT, rssi INTEGER, extra TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cves(
  id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE, description TEXT, cvss REAL,
  severity TEXT, published TEXT, refs TEXT, solution TEXT, keyword TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""

def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init():
    with conn() as c:
        c.executescript(SCHEMA)

def query(sql, args=()):
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]

def execute(sql, args=()):
    with conn() as c:
        return c.execute(sql, args).lastrowid

def dump_sql():
    c = conn()
    try:
        return "\n".join(c.iterdump()) + "\n"
    finally:
        c.close()
