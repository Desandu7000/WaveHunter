import re
from typing import List, Dict, Any

PATTERNS = {
    "Flag": rb'(?i)(?:(?:flag|ctf|key|secret|hunt|wavehunter|animus|[a-zA-Z0-9_\-]{3,15})\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]+\}|(?:flag|ctf|key|secret|hunt|wavehunter|animus)\s*[\=:\-]\s*[a-zA-Z0-9_\-\!\?\#\@\$]+)',
    "URL": rb'https?://[a-zA-Z0-9./\-_?=&%#@+]+',
    "Email": rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "IPv4 Address": rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "Base64 String": rb'\b[A-Za-z0-9+/]{16,}={0,2}\b',
    "Hex Hash (MD5)": rb'\b[a-fA-F0-9]{32}\b',
    "Hex Hash (SHA256)": rb'\b[a-fA-F0-9]{64}\b'
}

def scan_regex(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans binary data using regex patterns for flags, URLs, emails, etc.
    """
    matches = []
    
    for name, pattern in PATTERNS.items():
        compiled = re.compile(pattern)
        for m in compiled.finditer(data):
            try:
                val = m.group().decode("utf-8", errors="ignore").strip()
                if val:
                    matches.append({
                        "offset": m.start(),
                        "type": name,
                        "value": val,
                        "length": len(val)
                    })
            except Exception:
                continue
                
    # Sort by offset
    matches.sort(key=lambda x: x["offset"])
    return matches
