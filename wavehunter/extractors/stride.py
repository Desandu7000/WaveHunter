import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

def extract_strided(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts samples or LSB bits at specific stride intervals (1, 2, 4, 8, 16, 32, 64, 128)
    testing EVERY possible starting offset.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    # Phase 2 Stride Sizes
    strides = [1, 2, 4, 8, 16, 32, 64, 128, 256]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        mask = (1 << bits_per_sample) - 1
        unsigned_samples = samples & mask
        
        for stride in strides:
            # Test every possible starting offset from 0 to (stride - 1)
            for offset in range(stride):
                # Only check if we have enough samples left
                if len(samples) <= offset:
                    continue
                    
                # 1. Raw samples at stride & offset
                strided_samples = samples[offset::stride]
                if len(strided_samples) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} Stride {stride} Offset {offset} Samples",
                        "source": f"stride_samples_ch{ch}_s{stride}_o{offset}",
                        "data": pack_to_bytes(strided_samples, bits_per_sample)
                    })
                
                # 2. Bits from strided samples at stride & offset (all bitplanes)
                for bp in range(min(bits_per_sample, 16)):
                    bits = (unsigned_samples[offset::stride] >> bp) & 1
                    if len(bits) >= 64:  # Minimum 8 bytes
                        for msb in [True, False]:
                            bits_data = bits_to_bytes(bits, pack_msb=msb)
                            if len(bits_data) >= 8:
                                candidates.append({
                                    "name": f"Channel {ch} Stride {stride} Offset {offset} Bit {bp} ({'MSB' if msb else 'LSB'} packed)",
                                    "source": f"stride_bit_ch{ch}_s{stride}_o{offset}_b{bp}_{'msb' if msb else 'lsb'}",
                                    "data": bits_data
                                })
                            
    return candidates

