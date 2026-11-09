# Documentation technique

## 1. Objectif
Application web (Flask) qui : analyse un fichier (virus ou non), liste les CVE avec solutions,
scanne WiFi/Bluetooth via un ESP32 USB, historise tout dans SQLite. Déployée avec Docker Compose.

## 2. Structure du dépôt
```
Antivirus1999/
├── app/
│   ├── app.py        # routes Flask (/, /scan, /cves, /wireless, /history, /export.sql)
│   ├── scanner.py    # moteur d'analyse : SHA-256, signatures, heuristiques, ClamAV
│   ├── cve.py        # client API NVD, génération de solutions, cache en base
│   ├── esp32.py      # dialogue série avec l'ESP32 (direct ou via pont HTTP)
│   ├── db.py         # schéma SQLite, requêtes, export .sql
│   └── templates/    # base, index, cves, wireless, history (Jinja2)
├── esp32_firmware/esp32_scanner.ino   # firmware Arduino (commandes WIFI / BLE)
├── tools/esp32_bridge.py              # pont série→HTTP côté hôte
├── exports/export.sql                 # export de la base
├── prompts/PROMPTS.md                 # prompts IA
├── Dockerfile  docker-compose.yml  requirements.txt
```

## 3. Fonctionnement
**Scan de fichier** : le fichier est lu en mémoire, puis (1) SHA-256 comparé à une liste de hashs
connus + signature EICAR, (2) motifs suspects (PowerShell encodé, injection, reverse shell,
ransomware…), (3) type PE/ELF et entropie (>7,2 = packer), (4) envoi à ClamAV (`clamd`, protocole
INSTREAM sur TCP 3310). Un score 0-100 donne le verdict : SAIN (<30), SUSPECT (30-69),
MALVEILLANT (≥70 ou détection ClamAV). Le fichier n'est jamais exécuté ni écrit sur disque.

**CVE** : recherche par mot-clé sur l'API NVD 2.0 (clé optionnelle `NVD_API_KEY`). Chaque CVE est
enregistrée (UPSERT) avec CVSS, sévérité, références et une solution : mise à jour, contournement,
priorité selon la sévérité, liens « Patch / Vendor Advisory ». Hors-ligne : le cache SQLite est utilisé.

**ESP32** : le firmware répond à `WIFI` ou `BLE` par une ligne JSON `{"type":..,"results":[..]}`.
`esp32.py` ouvre le port série (115200 bauds), envoie la commande et lit la réponse.

## 4. Base de données (SQLite, volume Docker `db_data`)
| Table | Contenu |
|---|---|
| `scans` | fichier, sha256, taille, verdict, score, moteurs, détails JSON, date |
| `wireless_scans` | lot, type (wifi/ble), nom, adresse, RSSI, extra JSON, date |
| `cves` | cve_id (unique), description, cvss, sévérité, références, solution, mot-clé |

Export : route `/export.sql` (`sqlite3.iterdump`) → fichier `.sql` rejouable avec `sqlite3 scans.db < export.sql`.

## 5. Conteneurs Docker
| Service | Image | Rôle |
|---|---|---|
| `web` | build `Dockerfile` (python:3.12-slim + gunicorn) | application, port 5000 |
| `clamav` | `clamav/clamav:stable` | moteur antivirus (clamd:3310), signatures dans `clamav_db` |

Volumes : `db_data` (base SQLite persistante), `clamav_db` (signatures). Le premier démarrage de
ClamAV télécharge les signatures (quelques minutes) ; sans lui, l'analyse locale reste active.

**USB et Docker Desktop** : Docker Desktop exécute les conteneurs dans une VM Linux, qui ne voit pas
les ports USB de l'hôte. Deux solutions : pont `tools/esp32_bridge.py` sur l'hôte (recommandé, simple),
ou passthrough USB avec usbipd-win + `devices:` (WSL2).

## 6. Git
`git init`, commits par fonctionnalité, prompts IA dans `prompts/PROMPTS.md` (à compléter à chaque prompt).

## 7. Limites et améliorations
Signatures locales limitées (compléter via ClamAV/VirusTotal), pas d'authentification, SQLite mono-utilisateur
(PostgreSQL possible), sandbox dynamique absente.
