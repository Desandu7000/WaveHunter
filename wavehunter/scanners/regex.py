import re
from typing import List, Dict, Any

PATTERNS = {
    "Flag": rb'(?i)(?:(?:flag|ctf|key|secret|hunt|wavehunter|[a-zA-Z0-9_\-]{3,15})\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]+\}|(?:flag|ctf|key|secret|hunt|wavehunter)\s*[\=:\-]\s*[a-zA-Z0-9_\-\!\?\#\@\$]+)',
    "URL": rb'https?://[a-zA-Z0-9./\-_?=&%#@+]+',
    "Email": rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "IPv4 Address": rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "Base64 String": rb'\b[A-Za-z0-9+/]{16,}={0,2}\b',
    "Hex Hash (MD5)": rb'\b[a-fA-F0-9]{32}\b',
    "Hex Hash (SHA256)": rb'\b[a-fA-F0-9]{64}\b'
}

def scan_regex(data: bytes, flag_format: str | None = None) -> List[Dict[str, Any]]:
    """
    Scans binary data using regex patterns for flags, URLs, emails, etc.
    """
    matches = []
    
    local_patterns = dict(PATTERNS)
    if flag_format:
        flag_fmt_b = flag_format.encode("utf-8", errors="ignore")
        flag_fmt_esc = re.escape(flag_fmt_b)
        local_patterns["Custom Flag"] = rb'(?i)' + flag_fmt_esc + rb'\s*\{[a-zA-Z0-9_\-\.\!\?\#\(\)\@\$\%\^\&\*\s]+\}'
        
    for name, pattern in local_patterns.items():
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
