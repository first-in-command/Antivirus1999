# Antivirus1999
# TP IA MARQUET THEOTIM : scanner antivirus, CVE et WiFi/Bluetooth (ESP32)

Application web Python (Flask) qui :
- analyse un fichier pour savoir s'il est malveillant (signatures, heuristiques, ClamAV) ;
- liste les CVE (API NVD) avec des solutions proposées ;
- scanne le WiFi et le Bluetooth avec un ESP32 branché en USB ;
- enregistre tous les scans et CVE dans une base SQLite, avec historique et export `.sql`.

Le projet tourne dans des conteneurs Docker (Docker Desktop, Docker Compose).

## Démarrage rapide

```bash
git clone https://github.com/first-in-command/Antivirus1999.git
cd Antivirus1999
docker compose up --build
```

Ouvrir ensuite http://localhost:5000

Commandes utiles :

```bash
docker compose up -d        # démarrer en arrière-plan
docker compose logs -f web  # voir les journaux
docker compose stop         # arrêter sans rien supprimer
docker compose down         # supprimer les conteneurs (la base est conservée)
```

Attention : `docker compose down -v` supprime aussi les volumes, donc la base de données.

## Titre de la page

Défini par la variable `APP_TITLE` dans `docker-compose.yml`.

## Tester le scanner

Créer un fichier texte contenant uniquement la chaîne de test EICAR (inoffensive, reconnue par tous les antivirus), sur une seule ligne :

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Le verdict attendu est MALVEILLANT. Windows Defender peut supprimer ce fichier à l'enregistrement : utiliser un dossier exclu de l'analyse le temps du test.

## ESP32

1. Flasher `esp32_firmware/esp32_scanner.ino` (Arduino IDE, carte ESP32).
2. **Docker Desktop (Windows/Mac)** : les conteneurs ne voient pas les ports USB. Lancer un pont sur la machine hôte :
   ```bash
   pip install pyserial requests
   python tools/esp32_bridge.py COM3
   ```
   puis démarrer l'application avec `ESP32_BRIDGE_URL=http://host.docker.internal:8765` (variable d'environnement avant `docker compose up`).
3. **Linux / WSL2 avec usbipd** : décommenter la ligne `devices:` dans `docker-compose.yml`.

## CVE

La page `/cves` interroge l'API NVD par mot-clé. Une clé d'API NVD (variable `NVD_API_KEY`) est optionnelle et augmente la limite de requêtes. Hors ligne, les CVE déjà enregistrées sont affichées.

## Base de données et export

La base SQLite est dans le volume Docker `db_data` (`/data/scans.db`).

- Historique : page `/history`.
- Export : bouton « Export .sql » (route `/export.sql`). L'export de la base vide est aussi dans `exports/export.sql`.
- Restaurer : `sqlite3 scans.db < export.sql`.

## Structure

```
app/               code Flask : app, scanner, cve, esp32, db
app/templates/     pages HTML
esp32_firmware/    programme de l'ESP32 (.ino)
tools/             pont série vers HTTP pour l'ESP32
exports/           export de la base (.sql)
docs/              documentation technique
prompts/           prompts IA utilisés
Dockerfile, docker-compose.yml, requirements.txt
```

Documentation détaillée : [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md)
Prompts IA : [`prompts/PROMPTS.md`](prompts/PROMPTS.md)