from typing import List, Dict, Any
from wavehunter.core.signatures import find_signatures

def scan_magic(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans binary data for magic file signatures (e.g. ZIP, PNG).
    """
    return find_signatures(data)
