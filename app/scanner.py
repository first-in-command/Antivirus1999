"""Analyse d'un fichier : hash, signatures, heuristiques, ClamAV (clamd)."""
import hashlib, math, os, re, socket

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
KNOWN_BAD = {  # SHA-256 -> nom (à compléter)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}
PATTERNS = [
    (rb"(?i)powershell\S*\s+-e(nc|ncodedcommand)", "PowerShell encodé", 30),
    (rb"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory", "Injection de processus", 30),
    (rb"WScript\.Shell|Shell\.Application", "Exécution via WScript", 20),
    (rb"/bin/(ba)?sh\s+-i|nc\s+-e\s", "Reverse shell", 35),
    (rb"(?i)mimikatz|keylog", "Outil de vol d'identifiants", 35),
    (rb"(?i)vssadmin\s+delete\s+shadows", "Suppression des clichés (ransomware)", 40),
    (rb"(?i)your files (have been|are) encrypted", "Note de rançon", 40),
]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return -sum(f / n * math.log2(f / n) for f in freq if f)

def clamav_scan(data: bytes):
    """Retourne le nom du virus, '' si propre, None si clamd injoignable."""
    try:
        with socket.create_connection((os.getenv("CLAMD_HOST", "clamav"),
                                       int(os.getenv("CLAMD_PORT", "3310"))), timeout=5) as s:
            s.settimeout(120)
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 65536):
                chunk = data[i:i + 65536]
                s.sendall(len(chunk).to_bytes(4, "big") + chunk)
            s.sendall(b"\0\0\0\0")
            resp = s.recv(4096).decode(errors="ignore")
        return resp.split(":", 1)[1].replace("FOUND", "").strip("\0 \n") if "FOUND" in resp else ""
    except OSError:
        return None

def scan_file(filename: str, data: bytes) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    findings, score, engines = [], 0, ["signatures", "heuristique"]

    if sha in KNOWN_BAD or EICAR in data:
        findings.append(f"Signature connue : {KNOWN_BAD.get(sha, 'EICAR-Test-File')}")
        score = 100
    for rx, label, pts in PATTERNS:
        if re.search(rx, data):
            findings.append(label); score += pts
    if data[:2] == b"MZ":
        findings.append("Exécutable Windows (PE)"); score += 5
        if entropy(data) > 7.2:
            findings.append("Entropie très élevée (packer/chiffrement probable)"); score += 25
    elif data[:4] == b"\x7fELF":
        findings.append("Exécutable Linux (ELF)"); score += 5

    clam = clamav_scan(data)
    if clam is None:
        findings.append("ClamAV indisponible (analyse locale uniquement)")
    else:
        engines.append("clamav")
        if clam:
            findings.append(f"ClamAV : {clam}"); score = 100

    score = min(score, 100)
    verdict = "MALVEILLANT" if score >= 70 else "SUSPECT" if score >= 30 else "SAIN"
    return {"filename": filename, "sha256": sha, "size": len(data), "verdict": verdict,
            "score": score, "engine": "+".join(engines), "details": findings}
