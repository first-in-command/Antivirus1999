"""Récupération des CVE depuis l'API NVD (avec cache en base) + solutions."""
import json, os, requests
from . import db

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def solution_for(refs, severity):
    links = [r["url"] for r in refs
             if {"Patch", "Vendor Advisory", "Mitigation"} & set(r.get("tags", []))][:3]
    txt = "1) Mettre à jour le logiciel concerné vers une version corrigée. "
    txt += "2) Si impossible : désactiver le service/fonction vulnérable ou filtrer l'accès (pare-feu, segmentation). "
    if severity in ("HIGH", "CRITICAL"):
        txt += "3) Priorité haute : appliquer le correctif sous 72 h et surveiller les journaux. "
    if links:
        txt += "Sources : " + " ; ".join(links)
    return txt.strip()

def fetch(keyword, limit=20):
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    try:
        r = requests.get(NVD, params={"keywordSearch": keyword, "resultsPerPage": limit},
                         headers=headers, timeout=30)
        r.raise_for_status()
        for v in r.json().get("vulnerabilities", []):
            c = v["cve"]
            desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
            met = c.get("metrics", {})
            m = (met.get("cvssMetricV31") or met.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
            sev = m.get("baseSeverity", "N/A")
            refs = c.get("references", [])
            db.execute("""INSERT INTO cves(cve_id,description,cvss,severity,published,refs,solution,keyword)
                          VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET
                          description=excluded.description, cvss=excluded.cvss, severity=excluded.severity,
                          solution=excluded.solution, keyword=excluded.keyword""",
                       (c["id"], desc, m.get("baseScore"), sev, c.get("published", "")[:10],
                        json.dumps([x["url"] for x in refs[:10]]), solution_for(refs, sev), keyword))
        return None
    except requests.RequestException as e:
        return f"NVD injoignable ({e}) – affichage du cache local."

def search(keyword=""):
    like = f"%{keyword}%"
    return db.query("""SELECT * FROM cves WHERE cve_id LIKE ? OR description LIKE ? OR keyword LIKE ?
                       ORDER BY cvss DESC LIMIT 100""", (like, like, like))
