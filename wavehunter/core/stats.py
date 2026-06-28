import numpy as np
from typing import List, Dict, Any
from wavehunter.core.entropy import shannon_entropy

def compute_rolling_variance(samples: np.ndarray, window_size: int = 1000) -> np.ndarray:
    """
    Computes rolling variance across the signal samples.
    """
    if len(samples) < window_size:
        return np.zeros_like(samples, dtype=np.float32)
        
    mean = np.convolve(samples, np.ones(window_size)/window_size, mode='same')
    mean_sq = np.convolve(samples**2, np.ones(window_size)/window_size, mode='same')
    variance = mean_sq - mean**2
    return np.clip(variance, 0, None).astype(np.float32)

def compute_bit_bias(bits: np.ndarray) -> float:
    """
    Computes the bias of a bitstream (returns fraction of 1s, from 0.0 to 1.0).
    A value of 0.5 indicates perfectly balanced noise/stego stream.
    """
    if not len(bits):
        return 0.0
    return float(np.sum(bits == 1) / len(bits))

def find_statistical_anomalies(samples: np.ndarray, 
                               window_size: int = 2048, 
                               threshold: float = 2.5) -> List[Dict[str, Any]]:
    """
    Scans the audio samples for regions where variance or local entropy
    differs significantly from global averages (indicating anomalies or boundaries).
    """
    anomalies = []
    n = len(samples)
    if n < window_size * 4:
        return anomalies
        
    # Calculate rolling variances
    rolling_var = compute_rolling_variance(samples, window_size)
    global_mean_var = np.mean(rolling_var)
    global_std_var = np.std(rolling_var)
    
    if global_std_var == 0:
        return anomalies

    # Find indices where rolling variance is an anomaly
    anomaly_indices = np.where(np.abs(rolling_var - global_mean_var) > threshold * global_std_var)[0]
    
    if len(anomaly_indices) == 0:
        return anomalies
        
    # Group contiguous anomaly indices into segments
    starts = []
    ends = []
    if len(anomaly_indices) > 0:
        starts.append(anomaly_indices[0])
        for i in range(1, len(anomaly_indices)):
            if anomaly_indices[i] > anomaly_indices[i-1] + window_size:
                ends.append(anomaly_indices[i-1])
                starts.append(anomaly_indices[i])
        ends.append(anomaly_indices[-1])
        
    for start, end in zip(starts, ends):
        anomalies.append({
            "start_sample": int(start),
            "end_sample": int(end),
            "length_samples": int(end - start),
            "mean_variance": float(np.mean(rolling_var[start:end])),
            "global_variance_ratio": float(np.mean(rolling_var[start:end]) / (global_mean_var + 1e-10))
        })
        
    return anomalies


def compute_autocorrelation(samples: np.ndarray, max_lag: int = 512) -> np.ndarray:
    """Normalized autocorrelation for detecting periodic patterns."""
    if len(samples) < max_lag * 2:
        max_lag = max(1, len(samples) // 4)
    signal = samples.astype(np.float64)
    signal -= np.mean(signal)
    n = len(signal)
    corr = np.correlate(signal, signal, mode="full")[n - 1 : n + max_lag]
    if corr[0] != 0:
        corr = corr / corr[0]
    return corr.astype(np.float32)


def compute_printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (32-126)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126)
    return printable / len(data)


def analyze_stream_statistics(data: bytes) -> Dict[str, Any]:
    """Comprehensive statistical profile of a candidate byte stream."""
    if not data:
        return {"size": 0, "entropy": 0.0, "printable_ratio": 0.0}

    arr = np.frombuffer(data[: min(len(data), 65536)], dtype=np.uint8)
    bit_ones = np.unpackbits(arr).sum()
    total_bits = len(arr) * 8
    bit_bias = float(bit_ones / total_bits) if total_bits else 0.5

    hist, _ = np.histogram(arr, bins=256, range=(0, 256))
    peak_ratio = float(np.max(hist) / (len(arr) + 1e-10))

    if len(data) >= 8:
        chunks = [data[i : i + 4] for i in range(0, min(len(data) - 3, 4096), 4)]
        unique_ratio = len(set(chunks)) / len(chunks) if chunks else 1.0
    else:
        unique_ratio = 1.0

    return {
        "size": len(data),
        "entropy": shannon_entropy(data),
        "printable_ratio": compute_printable_ratio(data),
        "bit_bias": bit_bias,
        "peak_byte_ratio": peak_ratio,
        "unique_4byte_ratio": unique_ratio,
    }
