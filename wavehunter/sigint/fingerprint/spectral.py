import numpy as np
from typing import Dict, Any, Tuple

def compute_fft(samples: np.ndarray, sample_rate: int) -> Tuple[np.ndarray, np.ndarray]:
    """
    Computes the 1D Fast Fourier Transform of a signal.
    Returns: (frequencies_hz, magnitude_spectrum)
    """
    if len(samples) == 0:
        return np.array([]), np.array([])
        
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    n = len(sig)
    
    # Compute one-sided FFT (real FFT)
    fft_out = np.fft.rfft(sig)
    freqs = np.fft.rfftfreq(n, d=1.0/sample_rate)
    mags = np.abs(fft_out)
    
    return freqs, mags

def compute_stft(samples: np.ndarray, sample_rate: int, frame_size: int = 1024, overlap: int = 512) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Computes the Short-Time Fourier Transform (spectrogram).
    Returns: (frequencies_hz, times_seconds, magnitude_matrix_shape_N_frames_x_fft_bins)
    """
    if len(samples) == 0:
        return np.array([]), np.array([]), np.array([[]])
        
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    n_samples = len(sig)
    step = frame_size - overlap
    
    if n_samples < frame_size:
        # Pad with zeros to fit at least one frame
        sig = np.pad(sig, (0, frame_size - n_samples), mode='constant')
        n_samples = len(sig)
        
    n_frames = (n_samples - overlap) // step
    window = np.hanning(frame_size)
    fft_size = frame_size // 2 + 1
    
    stft_matrix = np.zeros((n_frames, fft_size), dtype=np.float32)
    times = np.zeros(n_frames, dtype=np.float32)
    
    for i in range(n_frames):
        start = i * step
        frame = sig[start : start + frame_size] * window
        rfft_out = np.fft.rfft(frame)
        stft_matrix[i, :] = np.abs(rfft_out)
        times[i] = (start + frame_size / 2.0) / sample_rate
        
    freqs = np.fft.rfftfreq(frame_size, d=1.0/sample_rate)
    return freqs, times, stft_matrix

def compute_spectral_features(freqs: np.ndarray, magnitudes: np.ndarray, roll_off_percent: float = 0.85) -> Dict[str, float]:
    """
    Computes spectral statistics for a given magnitude spectrum.
    Includes centroid, bandwidth, roll-off, skewness, and kurtosis.
    """
    if len(magnitudes) == 0 or np.sum(magnitudes) == 0:
        return {
            "spectral_centroid": 0.0,
            "spectral_bandwidth": 0.0,
            "spectral_rolloff": 0.0,
            "spectral_skewness": 0.0,
            "spectral_kurtosis": 0.0
        }
        
    # Normalize magnitudes to treat them as weights/probabilities
    mags_norm = magnitudes / np.sum(magnitudes)
    
    # Centroid: E[f]
    centroid = float(np.sum(freqs * mags_norm))
    
    # Bandwidth: sqrt(E[(f - centroid)^2])
    variance = np.sum(((freqs - centroid) ** 2) * mags_norm)
    bandwidth = float(np.sqrt(variance))
    
    # Rolloff: frequency under which roll_off_percent of the power resides
    cumulative_power = np.cumsum(magnitudes)
    total_power = cumulative_power[-1]
    rolloff_idx = np.searchsorted(cumulative_power, roll_off_percent * total_power)
    rolloff_freq = float(freqs[min(rolloff_idx, len(freqs) - 1)])
    
    # Skewness: E[((f - centroid)/bandwidth)^3]
    std_freqs = (freqs - centroid) / (bandwidth + 1e-10)
    skewness = float(np.sum((std_freqs ** 3) * mags_norm))
    
    # Kurtosis: E[((f - centroid)/bandwidth)^4]
    kurtosis = float(np.sum((std_freqs ** 4) * mags_norm))
    
    return {
        "spectral_centroid": centroid,
        "spectral_bandwidth": bandwidth,
        "spectral_rolloff": rolloff_freq,
        "spectral_skewness": skewness,
        "spectral_kurtosis": kurtosis
    }

def analyze_spectral_profile(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Analyzes the spectral characteristics of the audio signal.
    """
    freqs, mags = compute_fft(samples, sample_rate)
    features = compute_spectral_features(freqs, mags)
    
    # Compute dominant peak frequency
    if len(mags) > 0:
        peak_idx = np.argmax(mags)
        peak_freq = float(freqs[peak_idx])
    else:
        peak_freq = 0.0
        
    features["dominant_peak_hz"] = peak_freq
    return features
