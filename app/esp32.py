"""Communication avec l'ESP32 : port série direct OU pont HTTP lancé sur l'hôte."""
import json, os, time
import requests

def serial_scan(cmd: str, timeout: int = 20):
    import serial
    with serial.Serial(os.getenv("ESP32_PORT", "/dev/ttyUSB0"), 115200, timeout=1) as s:
        time.sleep(0.5); s.reset_input_buffer()
        s.write((cmd.upper() + "\n").encode())
        end = time.time() + timeout
        while time.time() < end:
            line = s.readline().decode(errors="ignore").strip()
            if line.startswith("{"):
                return json.loads(line)["results"]
    raise TimeoutError("Pas de réponse de l'ESP32")

def scan(kind: str):
    """kind = 'wifi' ou 'ble'. Retourne (liste, erreur)."""
    try:
        url = os.getenv("ESP32_BRIDGE_URL")
        if url:
            r = requests.get(f"{url}/{kind}", timeout=30); r.raise_for_status()
            return r.json()["results"], None
        return serial_scan(kind), None
    except Exception as e:
        return [], f"ESP32 inaccessible : {e}"
