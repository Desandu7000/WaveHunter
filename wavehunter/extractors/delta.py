import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def delta_decode(arr: np.ndarray, bits_per_sample: int) -> np.ndarray:
    """
    Decodes delta-encoded integers using cumulative sums wrapped to the bits_per_sample.
    """
    mask = (1 << bits_per_sample) - 1
    unsigned = arr & mask
    # Perform cumulative sum with int64 to avoid overflow before masking
    decoded = np.cumsum(unsigned.astype(np.int64)) & mask
    return decoded.astype(np.int32)

def extract_delta(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Delta-decodes audio samples and extracts:
    - Raw delta-decoded sample streams.
    - LSB bitplanes of delta-decoded samples.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        # 1. Delta-decode samples
        decoded_samples = delta_decode(samples, bits_per_sample)
        candidates.append({
            "name": f"Channel {ch} Delta-Decoded Samples",
            "source": f"delta_samples_ch{ch}",
            "data": pack_to_bytes(decoded_samples, bits_per_sample)
        })
        
        # 2. Extract LSB of delta-decoded samples
        bits = decoded_samples & 1
        for msb in [True, False]:
            bits_data = bits_to_bytes(bits, pack_msb=msb)
            if len(bits_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Delta LSB ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"delta_lsb_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": bits_data
                })
                
    return candidates
