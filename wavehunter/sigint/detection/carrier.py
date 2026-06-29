import numpy as np
from typing import List, Dict, Any, Tuple
from wavehunter.sigint.fingerprint.spectral import compute_stft

def detect_carrier_candidates(
    samples: np.ndarray, 
    sample_rate: int, 
    threshold_factor: float = 4.0
) -> List[Dict[str, Any]]:
    """
    Finds stable carrier frequency peaks in the signal.
    """
    freqs, times, stft = compute_stft(samples, sample_rate)
    if len(freqs) == 0 or stft.size == 0:
        return []
        
    mean_spectrum = np.mean(stft, axis=0)
    median_power = np.median(mean_spectrum)
    
    # Threshold for a peak to be considered a carrier candidate
    threshold = median_power * threshold_factor
    
    # Find local maxima in the mean spectrum
    candidates = []
    for i in range(1, len(mean_spectrum) - 1):
        if (mean_spectrum[i] > mean_spectrum[i - 1] and 
            mean_spectrum[i] > mean_spectrum[i + 1] and 
            mean_spectrum[i] > threshold):
            
            freq_hz = float(freqs[i])
            power = float(mean_spectrum[i])
            
            # Analyze stability of this frequency across frames
            # A stable carrier should have energy in this bin consistently
            bin_energies = stft[:, i]
            active_frames = np.sum(bin_energies > np.median(stft) * 2.0)
            stability = float(active_frames / len(times)) if len(times) > 0 else 0.0
            
            candidates.append({
                "frequency_hz": freq_hz,
                "power": power,
                "stability": stability,
                "bin_index": i
            })
            
    # Sort candidates by power descending
    candidates.sort(key=lambda x: -x["power"])
    return candidates

def group_harmonics(candidates: List[Dict[str, Any]], tolerance_percent: float = 0.02) -> List[Dict[str, Any]]:
    """
    Groups carriers that have harmonic relations (integer multiples).
    """
    if not candidates:
        return []
        
    grouped = []
    used_indices = set()
    
    # Sort candidates by frequency ascending
    sorted_cands = sorted(candidates, key=lambda x: x["frequency_hz"])
    
    for i, cand in enumerate(sorted_cands):
        if i in used_indices:
            continue
            
        fundamental = cand["frequency_hz"]
        harmonics = [cand]
        used_indices.add(i)
        
        for j in range(i + 1, len(sorted_cands)):
            if j in used_indices:
                continue
                
            other_freq = sorted_cands[j]["frequency_hz"]
            # Check if other_freq is an integer multiple of fundamental
            ratio = other_freq / fundamental
            nearest_int = round(ratio)
            
            if nearest_int > 1:
                diff = abs(ratio - nearest_int) / nearest_int
                if diff <= tolerance_percent:
                    harmonics.append(sorted_cands[j])
                    used_indices.add(j)
                    
        grouped.append({
            "fundamental_hz": fundamental,
            "carriers": harmonics,
            "harmonic_count": len(harmonics)
        })
        
    return grouped

def detect_sweeps(
    samples: np.ndarray, 
    sample_rate: int,
    min_slope_hz_s: float = 50.0
) -> List[Dict[str, Any]]:
    """
    Detects if there are frequency sweeps (chirps or sweeps) in the signal.
    """
    freqs, times, stft = compute_stft(samples, sample_rate)
    if len(times) < 5 or len(freqs) == 0:
        return []
        
    # Track the peak frequency index per frame
    peak_indices = np.argmax(stft, axis=1)
    peak_freqs = freqs[peak_indices]
    
    # Segment peak_freqs to identify sweep trends
    # We look for monotonic increases or decreases over windows
    window_len = min(20, len(times) // 2)
    if window_len < 3:
        return []
        
    sweeps = []
    
    for start_idx in range(0, len(times) - window_len, window_len // 2):
        end_idx = start_idx + window_len
        window_times = times[start_idx:end_idx]
        window_freqs = peak_freqs[start_idx:end_idx]
        
        # Fit a linear regression
        slope, intercept = np.polyfit(window_times, window_freqs, 1)
        
        with np.errstate(divide='ignore', invalid='ignore'):
            corr = np.corrcoef(window_times, window_freqs)[0, 1]
        
        if not np.isnan(corr) and abs(corr) > 0.85 and abs(slope) >= min_slope_hz_s:
            start_freq = float(window_freqs[0])
            end_freq = float(window_freqs[-1])
            
            sweeps.append({
                "start_time_s": float(window_times[0]),
                "end_time_s": float(window_times[-1]),
                "start_frequency_hz": start_freq,
                "end_frequency_hz": end_freq,
                "slope_hz_s": float(slope),
                "linearity": float(abs(corr))
            })
            
    # Merge overlapping or continuous sweeps
    merged_sweeps = []
    for sweep in sorted(sweeps, key=lambda x: x["start_time_s"]):
        if not merged_sweeps:
            merged_sweeps.append(sweep)
            continue
            
        last = merged_sweeps[-1]
        # If they overlap or are close and have similar slopes
        time_gap = sweep["start_time_s"] - last["end_time_s"]
        slope_diff = abs(sweep["slope_hz_s"] - last["slope_hz_s"]) / (abs(last["slope_hz_s"]) + 1e-10)
        
        if time_gap < 0.2 and slope_diff < 0.25:
            last["end_time_s"] = sweep["end_time_s"]
            last["end_frequency_hz"] = sweep["end_frequency_hz"]
            # Recalculate average slope
            duration = last["end_time_s"] - last["start_time_s"]
            if duration > 0:
                last["slope_hz_s"] = (last["end_frequency_hz"] - last["start_frequency_hz"]) / duration
            last["linearity"] = (last["linearity"] + sweep["linearity"]) / 2.0
        else:
            merged_sweeps.append(sweep)
            
    return merged_sweeps

def analyze_carriers_and_signals(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Orchestrates Phase 2 carrier and sweep detection.
    """
    candidates = detect_carrier_candidates(samples, sample_rate)
    harmonic_groups = group_harmonics(candidates)
    sweeps = detect_sweeps(samples, sample_rate)
    
    return {
        "carrier_candidates": candidates,
        "harmonic_groups": harmonic_groups,
        "sweeps": sweeps
    }
