import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def extract_reversed(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts samples or LSB bits in reverse order.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        # 1. Reverse sample sequence
        rev_samples = samples[::-1]
        candidates.append({
            "name": f"Channel {ch} Reversed Samples",
            "source": f"reverse_samples_ch{ch}",
            "data": pack_to_bytes(rev_samples, bits_per_sample)
        })
        
        # 2. Reversed LSB bits
        mask = (1 << bits_per_sample) - 1
        unsigned_samples = samples & mask
        bits = unsigned_samples & 1
        
        # Reverse the bit array
        rev_bits = bits[::-1]
        
        for msb in [True, False]:
            bits_data = bits_to_bytes(rev_bits, pack_msb=msb)
            if len(bits_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Reversed LSB ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"reverse_lsb_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": bits_data
                })
                
    return candidates
