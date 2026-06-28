import numpy as np
from typing import Dict, Tuple

def reconstruct_signal_variations(
    samples: np.ndarray, 
    sample_rate: int
) -> Dict[str, Tuple[np.ndarray, int]]:
    """
    Generates alternative signal representations of the original audio.
    Returns: Dict[variation_name, (samples_array, sample_rate)]
    """
    variations = {}
    
    if len(samples) == 0:
        return variations
        
    is_stereo = len(samples.shape) > 1 and samples.shape[1] >= 2
    
    # Base mono signal (Left channel if stereo)
    mono = samples[:, 0] if is_stereo else samples
    variations["mono_base"] = (mono, sample_rate)
    
    # 1. Reverse playback
    variations["reverse_time"] = (np.flip(mono), sample_rate)
    
    if is_stereo:
        left = samples[:, 0]
        right = samples[:, 1]
        
        variations["left"] = (left, sample_rate)
        variations["right"] = (right, sample_rate)
        
        # Mid: (L + R) / sqrt(2)
        mid = (left.astype(np.float64) + right.astype(np.float64)) / np.sqrt(2)
        variations["mid"] = (mid.astype(np.float32), sample_rate)
        
        # Side: (L - R) / sqrt(2)
        side = (left.astype(np.float64) - right.astype(np.float64)) / np.sqrt(2)
        variations["side"] = (side.astype(np.float32), sample_rate)
        
        # Diff: L - R
        diff = left.astype(np.float64) - right.astype(np.float64)
        variations["diff"] = (diff.astype(np.float32), sample_rate)
        
        # Average: (L + R) / 2
        avg = (left.astype(np.float64) + right.astype(np.float64)) / 2.0
        variations["average"] = (avg.astype(np.float32), sample_rate)
        
    # 2. Interleaving and Strides
    # Even samples
    variations["even_samples"] = (mono[0::2], sample_rate // 2)
    # Odd samples
    variations["odd_samples"] = (mono[1::2], sample_rate // 2)
    
    # Strides
    for stride in [3, 4]:
        for offset in range(stride):
            variations[f"stride_s{stride}_o{offset}"] = (mono[offset::stride], sample_rate // stride)
            
    # 3. Simple decimation (downsampling)
    # Downsample by 2
    variations["decimate_by_2"] = (mono[0::2], sample_rate // 2)
    # Downsample by 4
    variations["decimate_by_4"] = (mono[0::4], sample_rate // 4)
    
    return variations
