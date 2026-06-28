import numpy as np
from typing import Tuple, List

def estimate_symbol_rate(samples: np.ndarray, sample_rate: int) -> float:
    """
    Estimates the symbol (baud) rate of a digital signal.
    Uses the envelope-derivative spectral method:
    1. Compute the absolute derivative of the signal envelope (to highlight transitions).
    2. Compute the FFT of the transitions.
    3. The dominant frequency peak in the FFT corresponds to the symbol rate.
    """
    if len(samples) < 100:
        return 1.0
        
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    
    # 1. Get transitions
    diff = np.abs(np.diff(sig))
    
    # 2. FFT of transitions
    n = len(diff)
    fft_out = np.fft.rfft(diff - np.mean(diff))
    freqs = np.fft.rfftfreq(n, d=1.0/sample_rate)
    mags = np.abs(fft_out)
    
    # Ignore DC and very low frequencies
    mask = (freqs > 5) & (freqs < 5000)
    if not np.any(mask):
        return 100.0  # Default fallback
        
    peak_idx = np.argmax(mags[mask])
    peak_freq = freqs[mask][peak_idx]
    
    # Check if there is a clear symbol rate, otherwise fallback to transition-crossing estimate
    if mags[mask][peak_idx] > np.median(mags) * 3.0:
        return float(peak_freq)
        
    # Fallback to transition crossing interval statistics
    zero_crossings = np.where(np.diff(np.sign(sig) >= 0))[0]
    if len(zero_crossings) >= 5:
        intervals = np.diff(zero_crossings)
        min_int = np.percentile(intervals, 10)
        if min_int > 0:
            return float(sample_rate / min_int)
            
    return 300.0  # Typical default baud rate

def synchronize_symbols(
    samples: np.ndarray, 
    sample_rate: int, 
    symbol_rate: float
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Synchronizes symbol timing and samples the signal at the optimal decision points (middle of symbols).
    Returns: (sampled_values, sample_indices)
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    symbol_period = sample_rate / symbol_rate
    
    if symbol_period <= 1:
        return sig, np.arange(len(sig))
        
    # Simple clock recovery using Gardner-like / Early-Late sliding window
    # We slice the signal into symbol-sized blocks, adjust offset to minimize transition energy at symbol edges
    n_symbols = int(len(sig) / symbol_period)
    sampled_values = []
    sample_indices = []
    
    # Initialize offset
    offset = 0.0
    
    for i in range(n_symbols - 1):
        center = offset + i * symbol_period + (symbol_period / 2.0)
        center_idx = int(round(center))
        
        if center_idx >= len(sig):
            break
            
        sampled_values.append(sig[center_idx])
        sample_indices.append(center_idx)
        
        # Simple phase tracking: look at the difference between samples around the center
        # to adjust the phase drift dynamically
        early_idx = int(round(center - symbol_period * 0.15))
        late_idx = int(round(center + symbol_period * 0.15))
        
        if early_idx >= 0 and late_idx < len(sig):
            early_val = abs(sig[early_idx])
            late_val = abs(sig[late_idx])
            # Adjust offset slightly based on drift direction
            drift = (early_val - late_val) * 0.05
            offset += np.clip(drift, -0.2 * symbol_period, 0.2 * symbol_period)
            
    return np.array(sampled_values), np.array(sample_indices, dtype=np.int32)
