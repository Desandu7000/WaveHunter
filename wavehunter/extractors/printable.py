import numpy as np
from typing import List, Dict, Any
from wavehunter.scanners.ascii import scan_ascii
from wavehunter.extractors.interleave import pack_to_bytes

def extract_printable_text(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts sequences of contiguous printable ASCII characters from raw audio samples
    and returns them as consolidated text candidates.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        raw_bytes = pack_to_bytes(samples, bits_per_sample)
        
        # Scan for printable strings
        ascii_matches = scan_ascii(raw_bytes, min_len=4)
        if ascii_matches:
            # Join all text blocks with newlines
            joined_text = "\n".join(m["text"] for m in ascii_matches)
            candidates.append({
                "name": f"Channel {ch} Printable ASCII Strings",
                "source": f"ascii_strings_ch{ch}",
                "data": joined_text.encode("utf-8")
            })
            
    return candidates
