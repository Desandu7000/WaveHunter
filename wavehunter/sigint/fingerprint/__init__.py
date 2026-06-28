from typing import Dict, Any
import numpy as np
from wavehunter.sigint.fingerprint.audio_metadata import extract_statistical_profile
from wavehunter.sigint.fingerprint.spectral import analyze_spectral_profile

def fingerprint_signal(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Generate a complete signal fingerprint and profile of the input audio samples.
    """
    if len(samples) == 0:
        return {}
        
    mono_samples = samples if len(samples.shape) == 1 else samples[:, 0]
    
    # Run statistical/metadata profiling
    stat_profile = extract_statistical_profile(samples, sample_rate)
    
    # Run spectral profiling
    spectral_profile = analyze_spectral_profile(mono_samples, sample_rate)
    
    # Combine findings
    profile = {
        "duration_s": float(len(samples) / sample_rate) if sample_rate > 0 else 0.0,
        "sample_rate": sample_rate,
        "channels": 1 if len(samples.shape) == 1 else samples.shape[1],
        **stat_profile,
        **spectral_profile
    }
    
    # Compute initial overall confidence metrics for covert steganography or signals
    # High DC offset or extreme kurtosis/skewness can indicate anomalies
    has_anomaly = False
    reasons = []
    
    for stat in stat_profile.get("channel_stats", []):
        if abs(stat["dc_offset"]) > 0.01:
            has_anomaly = True
            reasons.append(f"Significant DC Offset detected in channel {stat['channel_index']}: {stat['dc_offset']:.4f}")
        if stat["crest_factor"] > 15.0:
            has_anomaly = True
            reasons.append(f"High crest factor in channel {stat['channel_index']}: {stat['crest_factor']:.2f}")
            
    if spectral_profile.get("spectral_kurtosis", 0) > 10.0:
        has_anomaly = True
        reasons.append(f"Highly peaky spectrum (Kurtosis: {spectral_profile['spectral_kurtosis']:.2f})")
        
    profile["fingerprint_anomalies"] = {
        "detected": has_anomaly,
        "reasons": reasons
    }
    
    return profile
