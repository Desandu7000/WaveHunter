import numpy as np
import pywt
from typing import Dict, Any, List
from wavehunter.core.utils import bits_to_bytes

def extract_dwt_lsb(samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts LSBs from the Discrete Wavelet Transform (DWT) coefficients.
    This simulates 'Layered' drops by pulling from specific frequency subbands.
    """
    candidates = []
    
    # We only care about up to 16 bits for LSB extraction.
    
    for ch in range(samples.shape[1] if len(samples.shape) > 1 else 1):
        ch_samples = samples[:, ch] if len(samples.shape) > 1 else samples
        
        # Decompose using Haar wavelets (db1), up to 3 levels
        coeffs = pywt.wavedec(ch_samples, 'db1', level=3)
        
        # coeffs = [cA3, cD3, cD2, cD1]
        labels = ["cA3", "cD3", "cD2", "cD1"]
        
        for i, layer in enumerate(coeffs):
            # DWT coefficients are floats. 
            # In steganography, they are usually rounded to integers, modified, and inverse transformed.
            int_layer = np.round(layer).astype(np.int32)
            
            # Extract LSB of the coefficient
            bits = int_layer & 1
            
            for pack_msb in (True, False):
                b_data = bits_to_bytes(bits, pack_msb=pack_msb)
                if len(b_data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} DWT Layer {labels[i]} LSB ({'MSB' if pack_msb else 'LSB'} packed)",
                        "source": f"dwt_ch{ch}_{labels[i]}_{'msb' if pack_msb else 'lsb'}",
                        "data": b_data
                    })
                    
    return candidates
