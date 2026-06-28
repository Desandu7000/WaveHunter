import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def gray_to_binary(arr: np.ndarray, bits_per_sample: int) -> np.ndarray:
    """
    Decodes Gray-coded integers in a NumPy array to binary integers.
    """
    mask = (1 << bits_per_sample) - 1
    unsigned = arr & mask
    
    decoded = unsigned.copy()
    shift = 1
    while shift < bits_per_sample:
        decoded ^= (decoded >> shift)
        shift <<= 1
        
    return decoded

def extract_graycode(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Decodes the Gray-coded audio samples and extracts:
    - Raw Gray-decoded sample streams.
    - LSB bitplanes of Gray-decoded samples.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        # 1. Decode Gray code
        decoded_samples = gray_to_binary(samples, bits_per_sample)
        candidates.append({
            "name": f"Channel {ch} Gray-Decoded Samples",
            "source": f"gray_samples_ch{ch}",
            "data": pack_to_bytes(decoded_samples, bits_per_sample)
        })
        
        # 2. Extract LSBs of Gray-decoded samples
        bits = decoded_samples & 1
        for msb in [True, False]:
            bits_data = bits_to_bytes(bits, pack_msb=msb)
            if len(bits_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Gray LSB ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"gray_lsb_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": bits_data
                })
                
    return candidates
