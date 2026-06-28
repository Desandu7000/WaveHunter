import re
from typing import List, Dict, Any

PATTERNS = {
    "Specific Flag (ANIMUS)": (rb'(?i)animus\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]+\}', 1.0),
    "Specific Flag (CTF/HTB/picoCTF)": (rb'(?i)(?:ctf|htb|picoctf|flag)\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]+\}', 1.0),
    "Generic Flag Pattern": (rb'\b[a-zA-Z0-9_\-]{3,15}\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]{4,60}\}\b', 0.85),
    "JWT Token": (rb'\beyJhbGciOi[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b', 0.95),
    "RSA/SSH Private Key Block": (rb'-----BEGIN [A-Z ]+ PRIVATE KEY-----', 1.0),
    "PEM Certificate Block": (rb'-----BEGIN CERTIFICATE-----', 1.0),
    "API Key Candidate": (rb'\b(?:api_key|apikey|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9\-_]{16,64}["\']?\b', 0.8),
    "URL": (rb'https?://[a-zA-Z0-9./\-_?=&%#@+]+', 0.9),
    "Email Address": (rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 0.95),
    "IPv4 Address": (rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 0.9),
    "IPv6 Address": (rb'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', 0.9),
    "Hex Hash (MD5)": (rb'\b[a-fA-F0-9]{32}\b', 0.65),
    "Hex Hash (SHA256)": (rb'\b[a-fA-F0-9]{64}\b', 0.75)
}

def scan_intelligence_patterns(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans a byte stream for intelligence indicators (flags, credentials, networks, crypto).
    Returns findings with calculated weights and confidence ratings.
    """
    findings = []
    
    for name, (pattern, base_confidence) in PATTERNS.items():
        compiled = re.compile(pattern)
        for m in compiled.finditer(data):
            try:
                val = m.group().decode("utf-8", errors="ignore").strip()
                if not val:
                    continue
                    
                # Dynamically adjust confidence based on size/content characteristics
                confidence = base_confidence
                
                # Penalize generic keys or hashes that are just repetitive chars
                if name in ["Hex Hash (MD5)", "Hex Hash (SHA256)"]:
                    if len(set(val)) < 5:  # e.g., "00000000000000000000000000000000"
                        confidence *= 0.1
                        
                findings.append({
                    "offset": m.start(),
                    "type": name,
                    "value": val,
                    "length": len(val),
                    "confidence": float(confidence)
                })
            except Exception:
                continue
                
    # Sort findings by offset, then by confidence descending
    findings.sort(key=lambda x: (x["offset"], -x["confidence"]))
    return findings
