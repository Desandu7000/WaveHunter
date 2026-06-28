import numpy as np
from typing import Dict, Any, List
from wavehunter.core.signal import compute_spectrogram, compute_amplitude_envelope

def detect_fsk_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Checks if the signal exhibits FSK characteristics (bi-modal frequency peaks alternating over time).
    """
    freqs, spec = compute_spectrogram(samples, frame_size=1024, overlap=512)
    if len(freqs) == 0:
        return {"similarity": 0.0, "reason": "Signal too short"}
        
    # Get peak frequency index per frame
    peak_indices = np.argmax(spec, axis=1)
    peak_freqs = freqs[peak_indices] * sample_rate
    
    # Calculate histogram of peak frequencies
    hist, bin_edges = np.histogram(peak_freqs, bins=30)
    
    # Locate local peaks in the histogram
    peaks = []
    for i in range(1, len(hist) - 1):
        if hist[i] > hist[i-1] and hist[i] > hist[i+1] and hist[i] > np.max(hist) * 0.15:
            # Calculate frequency center
            freq_center = (bin_edges[i] + bin_edges[i+1]) / 2
            peaks.append((freq_center, hist[i]))
            
    similarity = 0.0
    reason = "Single frequency or broad spectrum"
    
    if len(peaks) >= 2:
        # Sort by peak count descending
        peaks.sort(key=lambda x: -x[1])
        # Two dominant frequency peaks suggest BFSK
        f1, count1 = peaks[0]
        f2, count2 = peaks[1]
        
        # Calculate ratio of peaks compared to overall distribution
        similarity = min(1.0, (count1 + count2) / np.sum(hist))
        reason = f"Detected bi-modal frequency centers at {f1:.1f} Hz and {f2:.1f} Hz (FSK match)"
        
    return {
        "similarity": float(similarity),
        "reason": reason,
        "peaks": [float(p[0]) for p in peaks[:4]]
    }

def detect_morse_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Detects if the amplitude envelope has dit/dah pulse patterns (lengths in a 1:3 ratio).
    """
    envelope = compute_amplitude_envelope(samples, window_size=200)
    threshold = np.mean(envelope) * 1.2
    
    # Binarize envelope
    active = (envelope > threshold).astype(np.int8)
    
    # Find active/inactive pulse lengths
    diff = np.diff(active)
    starts = np.where(diff == 1)[0]
    ends = np.where(diff == -1)[0]
    
    # Align starts and ends
    if len(starts) > 0 and len(ends) > 0:
        if ends[0] < starts[0]:
            ends = ends[1:]
        min_len = min(len(starts), len(ends))
        starts = starts[:min_len]
        ends = ends[:min_len]
        
        durations = (ends - starts) / sample_rate
        
        if len(durations) < 6:
            return {"similarity": 0.0, "reason": "Insufficient pulses to identify Morse timing"}
            
        # Histogram of pulse durations
        hist, bin_edges = np.histogram(durations, bins=20)
        
        # Look for two distinct duration peaks
        peaks = []
        for i in range(1, len(hist)-1):
            if hist[i] > hist[i-1] and hist[i] > hist[i+1] and hist[i] > np.max(hist) * 0.15:
                dur_center = (bin_edges[i] + bin_edges[i+1]) / 2
                peaks.append(dur_center)
                
        if len(peaks) >= 2:
            peaks.sort()
            ratio = peaks[1] / (peaks[0] + 1e-10)
            if 2.2 <= ratio <= 3.8:
                return {
                    "similarity": 0.85,
                    "reason": f"Morse-like timing detected. Dits: {peaks[0]*1000:.1f} ms | Dahs: {peaks[1]*1000:.1f} ms (Ratio: {ratio:.2f})"
                }
                
    return {"similarity": 0.0, "reason": "No dual-duration pulse timings detected"}

def detect_manchester_similarity(samples: np.ndarray) -> Dict[str, Any]:
    """
    Checks if zero-crossing intervals conform to Manchester split-phase encoding (T and 2T intervals).
    """
    zero_crossings = np.where(np.diff(np.sign(samples) >= 0))[0]
    if len(zero_crossings) < 30:
        return {"similarity": 0.0, "reason": "Too few transitions"}
        
    # Calculate intervals between crossings
    intervals = np.diff(zero_crossings)
    
    # Find mode of intervals (clock period T/2)
    hist, bin_edges = np.histogram(intervals, bins=50)
    mode_idx = np.argmax(hist)
    t_half = (bin_edges[mode_idx] + bin_edges[mode_idx+1]) / 2
    
    # We expect intervals to concentrate around t_half and 2*t_half (representing T/2 and T)
    half_count = np.sum((intervals >= t_half * 0.8) & (intervals <= t_half * 1.2))
    full_count = np.sum((intervals >= t_half * 1.6) & (intervals <= t_half * 2.4))
    
    ratio = (half_count + full_count) / len(intervals)
    
    similarity = 0.0
    reason = "Random crossing intervals"
    if ratio > 0.65:
        similarity = ratio
        reason = f"Clock-aligned transitions detected (Manchester similarity: {ratio*100:.1f}%)"
        
    return {
        "similarity": float(similarity),
        "reason": reason
    }

def detect_psk_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Heuristic PSK detection: looks for phase jumps at consistent symbol intervals.
    """
    if len(samples) < 4096:
        return {"similarity": 0.0, "reason": "Signal too short for PSK analysis"}

    frame = 512
    step = 256
    n_frames = (len(samples) - frame) // step
    if n_frames < 8:
        return {"similarity": 0.0, "reason": "Insufficient frames"}

    phase_jumps = []
    prev_phase = None
    for i in range(n_frames):
        chunk = samples[i * step : i * step + frame] * np.hanning(frame)
        fft = np.fft.rfft(chunk)
        phase = np.angle(fft[1:32])
        mean_phase = np.mean(phase)
        if prev_phase is not None:
            jump = abs(np.arctan2(np.sin(mean_phase - prev_phase), np.cos(mean_phase - prev_phase)))
            phase_jumps.append(jump)
        prev_phase = mean_phase

    if not phase_jumps:
        return {"similarity": 0.0, "reason": "No phase transitions measured"}

    jumps = np.array(phase_jumps)
    # PSK shows bimodal phase jump distribution (0 and ~pi)
    near_zero = np.sum(jumps < 0.5) / len(jumps)
    near_pi = np.sum(jumps > 2.5) / len(jumps)
    similarity = min(1.0, near_zero + near_pi)

    if similarity > 0.5:
        return {
            "similarity": float(similarity),
            "reason": f"Phase jump bimodality detected ({near_zero*100:.0f}% small, {near_pi*100:.0f}% large jumps)",
        }
    return {"similarity": 0.0, "reason": "No PSK-like phase jump pattern"}


def detect_rtty_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    RTTY heuristic: dual-tone FSK with mark/space frequencies typically 170 Hz apart.
    """
    freqs, spec = compute_spectrogram(samples, frame_size=2048, overlap=1024)
    if len(freqs) == 0:
        return {"similarity": 0.0, "reason": "Signal too short"}

    mean_spec = np.mean(spec, axis=0)
    freq_hz = freqs * sample_rate
    band_mask = (freq_hz > 300) & (freq_hz < 3000)
    if not np.any(band_mask):
        return {"similarity": 0.0, "reason": "No teletype-band energy"}

    band_power = np.sum(spec[:, band_mask], axis=1)

    if len(band_power) < 10:
        return {"similarity": 0.0, "reason": "Insufficient teletype-band activity"}

    active = band_power > np.mean(band_power) * 1.1
    transitions = np.sum(np.abs(np.diff(active.astype(int))))
    transition_rate = transitions / (len(samples) / sample_rate)

    if 5 <= transition_rate <= 200:
        return {
            "similarity": min(1.0, transition_rate / 100),
            "reason": f"RTTY-like mark/space transitions (~{transition_rate:.1f}/s in teletype band)",
        }
    return {"similarity": 0.0, "reason": "No RTTY-like transition rate"}


def detect_sstv_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    SSTV heuristic: slow frequency sweeps over 1500-2300 Hz range lasting several seconds.
    """
    freqs, spec = compute_spectrogram(samples, frame_size=4096, overlap=2048)
    if spec.shape[0] < 20:
        return {"similarity": 0.0, "reason": "Signal too short for SSTV"}

    peak_freqs = freqs[np.argmax(spec, axis=1)] * sample_rate
    sstv_mask = (peak_freqs > 1200) & (peak_freqs < 2500)
    sstv_ratio = np.sum(sstv_mask) / len(peak_freqs)

    freq_range = float(np.max(peak_freqs[sstv_mask]) - np.min(peak_freqs[sstv_mask])) if np.any(sstv_mask) else 0

    if sstv_ratio > 0.6 and freq_range > 200:
        return {
            "similarity": float(min(1.0, sstv_ratio)),
            "reason": f"SSTV-like frequency sweep in {freq_range:.0f} Hz range ({sstv_ratio*100:.0f}% of frames)",
        }
    return {"similarity": 0.0, "reason": "No SSTV-like frequency sweep pattern"}


def detect_bfsk_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """Binary FSK: two stable tone frequencies alternating."""
    result = detect_fsk_similarity(samples, sample_rate)
    if result["similarity"] > 0.4 and len(result.get("peaks", [])) >= 2:
        peaks = result["peaks"][:2]
        separation = abs(peaks[0] - peaks[1])
        return {
            **result,
            "similarity": min(1.0, result["similarity"] * 1.1),
            "reason": f"BFSK-like dual tones at {peaks[0]:.0f} Hz and {peaks[1]:.0f} Hz (Δ{separation:.0f} Hz)",
        }
    return {"similarity": 0.0, "reason": "No stable dual-tone BFSK pattern"}


def scan_modem_carrier(samples: np.ndarray, sample_rate: int) -> List[Dict[str, Any]]:
    """
    Evaluates the signal against multiple digital modulations.
    """
    # Use one channel if stereo
    if len(samples.shape) > 1:
        signal = samples[:, 0]
    else:
        signal = samples
        
    results = []
    
    fsk = detect_fsk_similarity(signal, sample_rate)
    if fsk["similarity"] > 0.3:
        results.append({**fsk, "type": "FSK/AFSK"})

    bfsk = detect_bfsk_similarity(signal, sample_rate)
    if bfsk["similarity"] > 0.3:
        results.append({**bfsk, "type": "BFSK"})

    psk = detect_psk_similarity(signal.astype(np.float64), sample_rate)
    if psk["similarity"] > 0.3:
        results.append({**psk, "type": "PSK"})

    rtty = detect_rtty_similarity(signal, sample_rate)
    if rtty["similarity"] > 0.3:
        results.append({**rtty, "type": "RTTY"})

    sstv = detect_sstv_similarity(signal, sample_rate)
    if sstv["similarity"] > 0.3:
        results.append({**sstv, "type": "SSTV"})
        
    morse = detect_morse_similarity(signal, sample_rate)
    if morse["similarity"] > 0.3:
        results.append({**morse, "type": "Morse Code"})
        
    manc = detect_manchester_similarity(signal)
    if manc["similarity"] > 0.3:
        results.append({**manc, "type": "Manchester Link"})
        
    return results
