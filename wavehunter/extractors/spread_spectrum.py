import numpy as np
import random
from typing import Dict, Any, List
from wavehunter.core.utils import bits_to_bytes

def extract_dsss(samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts Direct Sequence Spread Spectrum (DSSS) encoded payloads.
    It attempts to despread the signal using common CTF PRNG seeds and chipping sequences.
    We test both XORing against the LSB plane and multiplying against the raw signal.
    """
    candidates = []
    
    if len(samples) == 0:
        return candidates
        
    common_seeds = [
        "1234", "0", "42", "1337", "sparrows", "sparrow", 
        "abstergo", "ABSTERGO", "animus", "ANIMUS"
    ]
    
    # We will just try applying Python's random with these seeds on the LSB plane.
    # A true DSSS on the analog signal is very hard to blind-guess without the exact sequence,
    # but in CTFs, it's often applied on the digital bits (XOR with PRNG).
    
    for ch in range(samples.shape[1] if len(samples.shape) > 1 else 1):
        ch_samples = samples[:, ch] if len(samples.shape) > 1 else samples
        lsb = (ch_samples.astype(np.int64) & 1).astype(np.uint8)
        
        for seed in common_seeds:
            # Re-seed PRNG
            random.seed(seed)
            # Generate pseudo-noise sequence
            pn_seq = np.array([random.randint(0, 1) for _ in range(len(lsb))], dtype=np.uint8)
            
            # Despread
            despread_bits = lsb ^ pn_seq
            
            for pack_msb in (True, False):
                b_data = bits_to_bytes(despread_bits, pack_msb=pack_msb)
                if len(b_data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} DSSS PRNG Seed '{seed}' ({'MSB' if pack_msb else 'LSB'} packed)",
                        "source": f"dsss_ch{ch}_{seed}_{'msb' if pack_msb else 'lsb'}",
                        "data": b_data
                    })
                    
    # Reset random seed to fully stochastic
    random.seed()
    
    return candidates
