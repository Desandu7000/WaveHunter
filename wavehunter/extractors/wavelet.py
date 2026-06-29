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
        
        # Decompose using Haar wavelets (db1), up to 8 levels
        # This yields [cA8, cD8, cD7, cD6, cD5, cD4, cD3, cD2, cD1]
        coeffs = pywt.wavedec(ch_samples, 'db1', level=8)
        
        labels = ["cA8", "cD8", "cD7", "cD6", "cD5", "cD4", "cD3", "cD2", "cD1"]
        
        for i, layer in enumerate(coeffs):
            # DWT coefficients are floats. 
            int_layer = np.round(layer).astype(np.int32)
            
            # Extract bits for all bitplanes (0 to 15)
            for bp in range(16):
                bits = (int_layer >> bp) & 1
                
                for pack_msb in (True, False):
                    b_data = bits_to_bytes(bits, pack_msb=pack_msb)
                    if len(b_data) >= 8:
                        candidates.append({
                            "name": f"Channel {ch} DWT Layer {labels[i]} Bit {bp} ({'MSB' if pack_msb else 'LSB'} packed)",
                            "source": f"dwt_ch{ch}_{labels[i]}_b{bp}_{'msb' if pack_msb else 'lsb'}",
                            "data": b_data
                        })

                    
    return candidates
