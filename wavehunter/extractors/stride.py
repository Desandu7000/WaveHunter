import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def extract_strided(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts samples or LSB bits at specific stride intervals (e.g. every 2nd, 3rd, 4th, 8th, etc. sample).
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    # Common stride sizes in CTFs/stego
    strides = [2, 3, 4, 5, 8, 16]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        for stride in strides:
            # 1. Raw strided samples
            strided_samples = samples[::stride]
            candidates.append({
                "name": f"Channel {ch} Stride {stride} Samples",
                "source": f"stride_samples_ch{ch}_s{stride}",
                "data": pack_to_bytes(strided_samples, bits_per_sample)
            })
            
            # 2. LSB bits from strided samples
            mask = (1 << bits_per_sample) - 1
            unsigned_samples = samples & mask
            bits = (unsigned_samples[::stride]) & 1
            
            for msb in [True, False]:
                bits_data = bits_to_bytes(bits, pack_msb=msb)
                if len(bits_data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} Stride {stride} LSB ({'MSB' if msb else 'LSB'} packed)",
                        "source": f"stride_lsb_ch{ch}_s{stride}_{'msb' if msb else 'lsb'}",
                        "data": bits_data
                    })
                    
    return candidates
