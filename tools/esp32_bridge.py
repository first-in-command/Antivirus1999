"""Pont série->HTTP à lancer SUR L'HÔTE (Docker Desktop ne voit pas les ports USB).
Usage : python tools/esp32_bridge.py COM3     (ou /dev/cu.usbserial-xxx)
Puis : ESP32_BRIDGE_URL=http://host.docker.internal:8765 docker compose up"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
os.environ["ESP32_PORT"] = sys.argv[1]
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
from esp32 import serial_scan  # noqa

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        kind = self.path.strip("/")
        try:
            body, code = json.dumps({"results": serial_scan(kind)}), 200
        except Exception as e:
            body, code = json.dumps({"error": str(e)}), 500
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(body.encode())

HTTPServer(("0.0.0.0", 8765), H).serve_forever()
