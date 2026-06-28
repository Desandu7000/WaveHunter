import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def extract_relationships(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts candidate byte streams by analyzing sample relationships:
    - Left/Right algebra (XOR, Diff, Sum)
    - Consecutive sample differences (high-pass filter)
    - Parity of consecutive samples
    - Sign-bit transitions (zero-crossings)
    """
    candidates = []
    n_samples, n_channels = raw_samples.shape
    
    # Analyze Left / Right relationships if stereo
    if n_channels >= 2:
        ch0 = raw_samples[:, 0]
        ch1 = raw_samples[:, 1]
        
        # XOR
        candidates.append({
            "name": "Left XOR Right Stream",
            "source": "rel_ch_xor",
            "data": pack_to_bytes(ch0 ^ ch1, bits_per_sample)
        })
        
        # Diff
        candidates.append({
            "name": "Left - Right (Diff) Stream",
            "source": "rel_ch_diff",
            "data": pack_to_bytes(ch0 - ch1, bits_per_sample)
        })
        
    # Analyze consecutive sample dynamics per channel
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        # 1. Consecutive sample differences
        diffs = np.diff(samples)
        candidates.append({
            "name": f"Channel {ch} Consecutive Diff Stream",
            "source": f"rel_consec_diff_ch{ch}",
            "data": pack_to_bytes(diffs, bits_per_sample)
        })
        
        # 2. Consecutive sample parity transitions (bits showing if parity changed)
        parity = (samples & 1).astype(np.int8)
        parity_trans = parity[1:] ^ parity[:-1]
        
        for msb in [True, False]:
            p_data = bits_to_bytes(parity_trans, pack_msb=msb)
            if len(p_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Parity Transitions ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"rel_parity_trans_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": p_data
                })
                
        # 3. Sign-bit transitions (zero-crossings)
        # 1 if zero crossing occurred between sample i and i+1, 0 otherwise
        sign_crossings = ((samples[1:] >= 0) != (samples[:-1] >= 0)).astype(np.int8)
        
        for msb in [True, False]:
            sc_data = bits_to_bytes(sign_crossings, pack_msb=msb)
            if len(sc_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Zero-Crossings ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"rel_zero_crossings_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": sc_data
                })
                
    return candidates
