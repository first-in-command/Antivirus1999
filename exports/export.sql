BEGIN TRANSACTION;
CREATE TABLE cves(
  id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE, description TEXT, cvss REAL,
  severity TEXT, published TEXT, refs TEXT, solution TEXT, keyword TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, sha256 TEXT, size INTEGER,
  verdict TEXT, score INTEGER, engine TEXT, details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE wireless_scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, batch TEXT, kind TEXT, name TEXT,
  address TEXT, rssi INTEGER, extra TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
DELETE FROM "sqlite_sequence";
COMMIT;
