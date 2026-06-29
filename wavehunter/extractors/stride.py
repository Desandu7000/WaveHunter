import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

# In fast mode (default), cap offsets for large strides to avoid combinatorial explosion.
# Larger strides space samples far apart; offset 0 is sufficient in the vast majority of cases.
_FULL_OFFSET_STRIDE_LIMIT = 16  # strides <= this get all offsets tested; larger strides get offset 0 only


def extract_strided(raw_samples: np.ndarray, bits_per_sample: int, thorough: bool = False) -> List[Dict[str, Any]]:
    """
    Extracts samples or LSB bits at specific stride intervals (1, 2, 4, 8, 16, 32, 64, 128, 256)
    testing EVERY possible starting offset for small strides.

    In default (fast) mode, large strides (>16) only test offset 0 to avoid a combinatorial
    explosion that would generate tens of thousands of candidates for a long audio file.
    Pass thorough=True to test every offset for every stride (exhaustive — much slower).
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
            # In fast/default mode, only test all offsets for small strides.
            # For large strides, offset 0 covers the overwhelmingly common steganography patterns.
            if thorough or stride <= _FULL_OFFSET_STRIDE_LIMIT:
                offsets = range(stride)
            else:
                offsets = [0]

            for offset in offsets:
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
