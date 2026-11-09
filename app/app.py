"""Application web Flask."""
import json, os, time
from flask import Flask, render_template, request, redirect, url_for, Response
from . import db, scanner, cve, esp32

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
TITLE = os.getenv("APP_TITLE", "TP IA NOM PRENOM")
db.init()

@app.context_processor
def inject():
    return {"title": TITLE}

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/scan")
def scan():
    f = request.files.get("file")
    if not f or not f.filename:
        return redirect(url_for("index"))
    r = scanner.scan_file(f.filename, f.read())
    r["id"] = db.execute(
        "INSERT INTO scans(filename,sha256,size,verdict,score,engine,details) VALUES(?,?,?,?,?,?,?)",
        (r["filename"], r["sha256"], r["size"], r["verdict"], r["score"], r["engine"], json.dumps(r["details"])))
    return render_template("index.html", result=r)

@app.route("/cves")
def cves():
    kw = request.args.get("q", "").strip()
    err = cve.fetch(kw) if kw and request.args.get("online") else None
    return render_template("cves.html", cves=cve.search(kw), q=kw, error=err)

@app.route("/wireless", methods=["GET", "POST"])
def wireless():
    results, error, kind = [], None, None
    if request.method == "POST":
        kind = request.form["kind"]
        results, error = esp32.scan(kind)
        batch = time.strftime("%Y%m%d-%H%M%S")
        for d in results:
            extra = {k: v for k, v in d.items() if k not in ("name", "ssid", "address", "bssid", "rssi")}
            db.execute("INSERT INTO wireless_scans(batch,kind,name,address,rssi,extra) VALUES(?,?,?,?,?,?)",
                       (batch, kind, d.get("name") or d.get("ssid", ""), d.get("address") or d.get("bssid", ""),
                        d.get("rssi"), json.dumps(extra)))
    return render_template("wireless.html", results=results, error=error, kind=kind)

@app.route("/history")
def history():
    return render_template("history.html",
        scans=db.query("SELECT * FROM scans ORDER BY id DESC"),
        wireless=db.query("SELECT * FROM wireless_scans ORDER BY id DESC LIMIT 300"))

@app.route("/export.sql")
def export():
    sql = db.dump_sql()
    os.makedirs("/data/exports", exist_ok=True)
    open("/data/exports/export.sql", "w", encoding="utf-8").write(sql)
    return Response(sql, mimetype="application/sql",
                    headers={"Content-Disposition": "attachment; filename=export.sql"})
