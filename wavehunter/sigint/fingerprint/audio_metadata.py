import numpy as np
from typing import Dict, Any, List, Tuple

def detect_dc_offset(samples: np.ndarray) -> List[float]:
    """
    Computes the DC offset (mean amplitude) for each channel.
    """
    if len(samples) == 0:
        return []
    if len(samples.shape) == 1:
        return [float(np.mean(samples))]
    return [float(np.mean(samples[:, ch])) for ch in range(samples.shape[1])]

def analyze_dynamic_range(samples: np.ndarray) -> List[float]:
    """
    Estimates the dynamic range in dB for each channel.
    Dynamic range is calculated as 20 * log10(peak / RMS_noise_floor).
    """
    if len(samples) == 0:
        return []
    
    channels = 1 if len(samples.shape) == 1 else samples.shape[1]
    dr_results = []
    
    for ch in range(channels):
        ch_samples = samples if channels == 1 else samples[:, ch]
        peak = np.max(np.abs(ch_samples))
        if peak == 0:
            dr_results.append(0.0)
            continue
        
        # Estimate noise floor using small values (excluding silence if possible, or overall RMS)
        rms = np.sqrt(np.mean(ch_samples ** 2))
        if rms == 0:
            dr_results.append(0.0)
            continue
            
        dr_db = 20 * np.log10(peak / (rms + 1e-10))
        dr_results.append(float(dr_db))
        
    return dr_results

def analyze_silence_segments(samples: np.ndarray, sample_rate: int, threshold_db: float = -45.0, min_duration_s: float = 0.1) -> List[Tuple[float, float]]:
    """
    Identifies contiguous segments of silence.
    Returns a list of tuples containing (start_time_seconds, end_time_seconds).
    """
    if len(samples) == 0:
        return []
    
    # Use mono or left channel for silence analysis
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    
    # Compute short-term energy/RMS in small blocks
    block_size = int(sample_rate * 0.02)  # 20ms blocks
    if block_size == 0:
        block_size = 100
        
    n_blocks = len(sig) // block_size
    if n_blocks == 0:
        return []
        
    block_rms = []
    for i in range(n_blocks):
        block = sig[i * block_size : (i + 1) * block_size]
        rms = np.sqrt(np.mean(block ** 2))
        block_rms.append(rms)
        
    block_rms = np.array(block_rms)
    # Convert RMS to dB
    block_db = 20 * np.log10(block_rms + 1e-10)
    
    is_silent = block_db < threshold_db
    
    silence_segments = []
    in_silence = False
    start_block = 0
    
    for i, silent in enumerate(is_silent):
        if silent and not in_silence:
            in_silence = True
            start_block = i
        elif not silent and in_silence:
            in_silence = False
            duration = (i - start_block) * (block_size / sample_rate)
            if duration >= min_duration_s:
                silence_segments.append((start_block * block_size / sample_rate, i * block_size / sample_rate))
                
    if in_silence:
        duration = (len(is_silent) - start_block) * (block_size / sample_rate)
        if duration >= min_duration_s:
            silence_segments.append((start_block * block_size / sample_rate, len(sig) / sample_rate))
            
    return silence_segments

def compute_channel_correlation(samples: np.ndarray) -> float:
    """
    Computes the Pearson correlation coefficient between Left and Right channels.
    Returns 0.0 if mono or if one channel is completely silent.
    """
    if len(samples) == 0 or len(samples.shape) < 2 or samples.shape[1] < 2:
        return 0.0
        
    ch1 = samples[:, 0]
    ch2 = samples[:, 1]
    
    std1 = np.std(ch1)
    std2 = np.std(ch2)
    
    if std1 == 0 or std2 == 0:
        return 0.0
        
    with np.errstate(divide='ignore', invalid='ignore'):
        corr = np.corrcoef(ch1, ch2)[0, 1]
    return float(corr) if not np.isnan(corr) else 0.0

def extract_statistical_profile(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Performs full statistical and metadata analysis of audio samples.
    """
    dc_offsets = detect_dc_offset(samples)
    dynamic_ranges = analyze_dynamic_range(samples)
    silences = analyze_silence_segments(samples, sample_rate)
    correlation = compute_channel_correlation(samples)
    
    # Calculate stats per channel
    channels = 1 if len(samples.shape) == 1 else samples.shape[1]
    channel_stats = []
    
    for ch in range(channels):
        ch_samples = samples if channels == 1 else samples[:, ch]
        peak = float(np.max(np.abs(ch_samples)))
        rms = float(np.sqrt(np.mean(ch_samples ** 2)))
        crest_factor = peak / (rms + 1e-10)
        
        channel_stats.append({
            "channel_index": ch,
            "peak_amplitude": peak,
            "rms_amplitude": rms,
            "crest_factor": crest_factor,
            "dc_offset": dc_offsets[ch] if ch < len(dc_offsets) else 0.0,
            "dynamic_range_db": dynamic_ranges[ch] if ch < len(dynamic_ranges) else 0.0
        })
        
    duration = len(samples) / sample_rate if sample_rate > 0 and len(samples) > 0 else 0.0
    return {
        "channel_correlation": correlation,
        "silence_segments": silences,
        "silence_ratio": float(sum(end - start for start, end in silences) / duration) if duration > 0 else 0.0,
        "channel_stats": channel_stats
    }
