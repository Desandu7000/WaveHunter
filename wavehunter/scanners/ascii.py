import re
from typing import List, Dict, Any

def scan_ascii(data: bytes, min_len: int = 4) -> List[Dict[str, Any]]:
    """
    Searches for contiguous blocks of printable ASCII characters in a byte array.
    Returns a list of dicts with offset, text, and length.
    """
    # Regex matching printable ASCII characters (hex 20 to 7e) plus common whitespace
    pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
    
    matches = []
    for m in pattern.finditer(data):
        try:
            text = m.group().decode("ascii").strip()
            if text:
                matches.append({
                    "offset": m.start(),
                    "text": text,
                    "length": len(text)
                })
        except Exception:
            continue
            
    return matches
