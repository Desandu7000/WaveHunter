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
    Reconstructs and extracts sample layouts systematically:
    - LLLL: Mono Left
    - RRRR: Mono Right
    - LRLR: Standard stereo interleaving
    - RLRL: Swapped stereo interleaving
    - LLRR: Two left samples, two right samples
    - RRLL: Two right samples, two left samples
    """
    candidates = []
    n_samples, n_channels = raw_samples.shape
    
    if n_channels >= 2:
        left = raw_samples[:, 0]
        right = raw_samples[:, 1]
        
        # 1. LLLL (Mono Left)
        candidates.append({
            "name": "Layout LLLL (Mono Left)",
            "source": "layout_llll",
            "data": pack_to_bytes(left, bits_per_sample)
        })
        
        # 2. RRRR (Mono Right)
        candidates.append({
            "name": "Layout RRRR (Mono Right)",
            "source": "layout_rrrr",
            "data": pack_to_bytes(right, bits_per_sample)
        })
        
        # 3. LRLR (Standard Interleaved Stereo)
        candidates.append({
            "name": "Layout LRLR (Standard Stereo)",
            "source": "layout_lrlr",
            "data": pack_to_bytes(raw_samples.flatten(), bits_per_sample)
        })
        
        # 4. RLRL (Swapped Interleaved Stereo)
        swapped = raw_samples[:, [1, 0]].flatten()
        candidates.append({
            "name": "Layout RLRL (Swapped Stereo)",
            "source": "layout_rlrl",
            "data": pack_to_bytes(swapped, bits_per_sample)
        })
        
        # 5. LLRR (Two left samples, two right samples)
        n_frames = n_samples // 2
        if n_frames > 0:
            l_grouped = left[:n_frames * 2].reshape(-1, 2)
            r_grouped = right[:n_frames * 2].reshape(-1, 2)
            llrr = np.stack([l_grouped, r_grouped], axis=1).flatten()
            candidates.append({
                "name": "Layout LLRR (Pair interleaved)",
                "source": "layout_llrr",
                "data": pack_to_bytes(llrr, bits_per_sample)
            })
            
            # 6. RRLL (Two right samples, two left samples)
            rrll = np.stack([r_grouped, l_grouped], axis=1).flatten()
            candidates.append({
                "name": "Layout RRLL (Pair interleaved swapped)",
                "source": "layout_rrll",
                "data": pack_to_bytes(rrll, bits_per_sample)
            })
    else:
        # Mono defaults
        flat = raw_samples.flatten()
        candidates.append({
            "name": "Layout Mono Raw",
            "source": "layout_mono_raw",
            "data": pack_to_bytes(flat, bits_per_sample)
        })
        
    return candidates
