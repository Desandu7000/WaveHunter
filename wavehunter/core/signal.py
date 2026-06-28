import numpy as np
from typing import Dict, Any, List, Tuple

def compute_spectrogram(samples: np.ndarray, 
                        frame_size: int = 1024, 
                        overlap: int = 512) -> Tuple[np.ndarray, np.ndarray]:
    """
    Computes a sliding-window Short-Time Fourier Transform (spectrogram) magnitude spectrum.
    Returns: (frequencies, spectrogram_magnitude_matrix)
    """
    n_samples = len(samples)
    step = frame_size - overlap
    if n_samples < frame_size:
        return np.array([]), np.array([])
        
    n_frames = (n_samples - overlap) // step
    window = np.hanning(frame_size)
    
    # Pre-allocate STFT matrix
    fft_size = frame_size // 2 + 1
    stft = np.zeros((n_frames, fft_size), dtype=np.float32)
    
    for i in range(n_frames):
        start = i * step
        frame = samples[start : start + frame_size] * window
        rfft_out = np.fft.rfft(frame)
        stft[i, :] = np.abs(rfft_out)
        
    freqs = np.fft.rfftfreq(frame_size)
    return freqs, stft

def compute_stereo_phase_difference(normalized_samples: np.ndarray, 
                                    frame_size: int = 1024, 
                                    overlap: int = 512) -> np.ndarray:
    """
    Computes the phase difference between Left and Right channels over time.
    Returns an array of phase differences in radians [-pi, pi] per frame.
    """
    if normalized_samples.shape[1] < 2:
        return np.array([], dtype=np.float32)
        
    n_samples = normalized_samples.shape[0]
    step = frame_size - overlap
    if n_samples < frame_size:
        return np.array([], dtype=np.float32)
        
    n_frames = (n_samples - overlap) // step
    window = np.hanning(frame_size)
    phase_diffs = []
    
    for i in range(n_frames):
        start = i * step
        left_frame = normalized_samples[start : start + frame_size, 0] * window
        right_frame = normalized_samples[start : start + frame_size, 1] * window
        
        l_fft = np.fft.rfft(left_frame)
        r_fft = np.fft.rfft(right_frame)
        
        l_phase = np.angle(l_fft)
        r_phase = np.angle(r_fft)
        
        # Calculate mean phase difference for active bins (excluding DC offset)
        diff = np.mean(np.arctan2(np.sin(l_phase[1:] - r_phase[1:]), np.cos(l_phase[1:] - r_phase[1:])))
        phase_diffs.append(diff)
        
    return np.array(phase_diffs, dtype=np.float32)

def compute_amplitude_envelope(samples: np.ndarray, window_size: int = 100) -> np.ndarray:
    """
    Computes the amplitude envelope of a signal using rolling RMS (Root Mean Square).
    """
    if len(samples) < window_size:
        return np.abs(samples)
        
    squared = samples.astype(np.float64) ** 2
    # Moving average of squared signal
    kernel = np.ones(window_size) / window_size
    mean_squared = np.convolve(squared, kernel, mode="same")
    return np.sqrt(mean_squared).astype(np.float32)

def invert_polarity(samples: np.ndarray) -> np.ndarray:
    """
    Returns the signal with inverted polarity (multiplied by -1).
    """
    return -samples


def analyze_signal_characteristics(
    samples: np.ndarray, sample_rate: int
) -> Dict[str, Any]:
    """
    Summarize signal properties relevant to covert channel detection.
    """
    if len(samples) == 0:
        return {"sample_rate": sample_rate, "duration_s": 0.0}

    freqs, spec = compute_spectrogram(samples, frame_size=2048, overlap=1024)
    envelope = compute_amplitude_envelope(samples, window_size=int(sample_rate * 0.01) or 100)

    # Dominant frequency
    if len(freqs) > 0 and spec.size > 0:
        mean_spectrum = np.mean(spec, axis=0)
        dominant_bin = int(np.argmax(mean_spectrum))
        dominant_hz = float(freqs[dominant_bin] * sample_rate)
    else:
        dominant_hz = 0.0

    # Polarity balance
    positive_ratio = float(np.sum(samples >= 0) / len(samples))

    # Envelope periodicity via autocorrelation peak
    env_ac = np.correlate(
        envelope - np.mean(envelope), envelope - np.mean(envelope), mode="full"
    )
    mid = len(env_ac) // 2
    env_ac = env_ac[mid : mid + min(5000, len(env_ac) - mid)]
    if len(env_ac) > 10 and env_ac[0] > 0:
        env_ac = env_ac / env_ac[0]
        # Find first secondary peak after lag 10
        secondary_peaks = [
            i for i in range(10, len(env_ac) - 1)
            if env_ac[i] > env_ac[i - 1] and env_ac[i] > env_ac[i + 1] and env_ac[i] > 0.3
        ]
        repeat_lag = int(secondary_peaks[0]) if secondary_peaks else None
        repeat_hz = float(sample_rate / repeat_lag) if repeat_lag else None
    else:
        repeat_lag = None
        repeat_hz = None

    return {
        "sample_rate": sample_rate,
        "duration_s": float(len(samples) / sample_rate),
        "dominant_frequency_hz": dominant_hz,
        "rms_amplitude": float(np.sqrt(np.mean(samples**2))),
        "peak_amplitude": float(np.max(np.abs(samples))),
        "positive_sample_ratio": positive_ratio,
        "envelope_repeat_lag_samples": repeat_lag,
        "envelope_repeat_hz": repeat_hz,
    }
