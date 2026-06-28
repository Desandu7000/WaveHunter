import numpy as np
from typing import List, Dict, Any

def pack_to_bytes(arr: np.ndarray, bits_per_sample: int) -> bytes:
    """Helper to pack a sample array back into raw bytes."""
    if bits_per_sample == 8:
        return arr.astype(np.uint8).tobytes()
    elif bits_per_sample == 16:
        return arr.astype(np.int16).tobytes()
    elif bits_per_sample == 32:
        return arr.astype(np.int32).tobytes()
    elif bits_per_sample == 24:
        arr_clipped = np.clip(arr, -8388608, 8388607).astype(np.int32)
        unsigned = arr_clipped & 0xFFFFFF
        b0 = (unsigned & 0xFF).astype(np.uint8)
        b1 = ((unsigned >> 8) & 0xFF).astype(np.uint8)
        b2 = ((unsigned >> 16) & 0xFF).astype(np.uint8)
        packed = np.zeros(len(arr) * 3, dtype=np.uint8)
        packed[0::3] = b0
        packed[1::3] = b1
        packed[2::3] = b2
        return packed.tobytes()
    return arr.tobytes()

def extract_interleaved(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Analyzes interleaved channels, swaps Left/Right channels, and separates odd/even samples.
    """
    candidates = []
    n_samples, n_channels = raw_samples.shape
    
    if n_channels >= 2:
        # Swap Left and Right
        swapped = np.zeros_like(raw_samples)
        swapped[:, 0] = raw_samples[:, 1]
        swapped[:, 1] = raw_samples[:, 0]
        # Rest of channels copy if any
        if n_channels > 2:
            swapped[:, 2:] = raw_samples[:, 2:]
            
        candidates.append({
            "name": "Swapped Channels (L <-> R)",
            "source": "channels_swapped",
            "data": pack_to_bytes(swapped.flatten(), bits_per_sample)
        })
        
        # Even-indexed frames (samples)
        even_frames = raw_samples[0::2, :]
        candidates.append({
            "name": "Interleaved Even Frames",
            "source": "interleaved_even_frames",
            "data": pack_to_bytes(even_frames.flatten(), bits_per_sample)
        })
        
        # Odd-indexed frames (samples)
        odd_frames = raw_samples[1::2, :]
        candidates.append({
            "name": "Interleaved Odd Frames",
            "source": "interleaved_odd_frames",
            "data": pack_to_bytes(odd_frames.flatten(), bits_per_sample)
        })
    else:
        # Mono even/odd samples
        flat = raw_samples.flatten()
        candidates.append({
            "name": "Even Samples (Mono)",
            "source": "mono_even_samples",
            "data": pack_to_bytes(flat[0::2], bits_per_sample)
        })
        candidates.append({
            "name": "Odd Samples (Mono)",
            "source": "mono_odd_samples",
            "data": pack_to_bytes(flat[1::2], bits_per_sample)
        })

    return candidates
