import numpy as np
from typing import Dict, Any, List
from wavehunter.core.utils import bits_to_bytes

def extract_sample_parity(samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts the true parity bit of each sample (popcount % 2).
    In parity coding steganography, the parity of the entire sample represents the message bit.
    """
    candidates = []
    
    if len(samples) == 0:
        return candidates
        
    for ch in range(samples.shape[1] if len(samples.shape) > 1 else 1):
        ch_samples = samples[:, ch] if len(samples.shape) > 1 else samples
        
        # We process unsigned values to correctly handle bit operations
        mask = (1 << bits_per_sample) - 1
        unsigned = ch_samples.astype(np.int64) & mask
        
        # Calculate parity bit for each sample
        # XOR folding to get the parity
        x = unsigned.astype(np.uint64)
        x ^= x >> 32
        x ^= x >> 16
        x ^= x >> 8
        x ^= x >> 4
        x ^= x >> 2
        x ^= x >> 1
        
        parity_bits = (x & 1).astype(np.uint8)
        
        for pack_msb in (True, False):
            b_data = bits_to_bytes(parity_bits, pack_msb=pack_msb)
            if len(b_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Sample Parity ({'MSB' if pack_msb else 'LSB'} packed)",
                    "source": f"parity_ch{ch}_{'msb' if pack_msb else 'lsb'}",
                    "data": b_data
                })
                
    return candidates
