import numpy as np
from typing import List, Dict, Any

def extract_channels(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts individual channel raw byte arrays, and logical combinations like XOR,
    Difference, and Sum for multi-channel audio.
    """
    candidates = []
    n_samples, n_channels = raw_samples.shape
    
    # Map bits_per_sample to numpy dtype for byte representation
    if bits_per_sample == 8:
        dtype = np.uint8
    elif bits_per_sample == 16:
        dtype = np.int16
    elif bits_per_sample == 24:
        # Since 24-bit is stored in int32, we pack it back to 3 bytes
        dtype = None
    else:  # 32-bit
        dtype = np.int32

    def pack_samples(arr: np.ndarray) -> bytes:
        if dtype is not None:
            return arr.astype(dtype).tobytes()
        else:
            # 24-bit packing: extract 3 bytes from int32
            arr_clipped = np.clip(arr, -8388608, 8388607).astype(np.int32)
            # Mask to 24 bits
            unsigned = arr_clipped & 0xFFFFFF
            # Extract bytes
            b0 = (unsigned & 0xFF).astype(np.uint8)
            b1 = ((unsigned >> 8) & 0xFF).astype(np.uint8)
            b2 = ((unsigned >> 16) & 0xFF).astype(np.uint8)
            
            packed = np.zeros(len(arr) * 3, dtype=np.uint8)
            packed[0::3] = b0
            packed[1::3] = b1
            packed[2::3] = b2
            return packed.tobytes()

    # Individual channels
    for ch in range(n_channels):
        ch_data = raw_samples[:, ch]
        candidates.append({
            "name": f"Channel {ch} Raw Stream",
            "source": f"channel_{ch}_raw",
            "data": pack_samples(ch_data)
        })

    # Channel arithmetic if stereo or multi-channel
    if n_channels >= 2:
        ch0 = raw_samples[:, 0]
        ch1 = raw_samples[:, 1]
        
        # XOR
        xor_result = ch0 ^ ch1
        candidates.append({
            "name": "Channel 0 XOR Channel 1",
            "source": "channel_xor_0_1",
            "data": pack_samples(xor_result)
        })
        
        # Difference (L - R)
        diff_result = ch0 - ch1
        candidates.append({
            "name": "Channel 0 - Channel 1 (Diff)",
            "source": "channel_diff_0_1",
            "data": pack_samples(diff_result)
        })
        
        # Sum (L + R)
        sum_result = ch0 + ch1
        candidates.append({
            "name": "Channel 0 + Channel 1 (Sum)",
            "source": "channel_sum_0_1",
            "data": pack_samples(sum_result)
        })
        
    return candidates
