import numpy as np
from typing import Dict, Any, List
from wavehunter.core.signal import compute_spectrogram, compute_amplitude_envelope
from wavehunter.core.modem import (
    detect_fsk_similarity,
    detect_morse_similarity,
    detect_manchester_similarity,
    detect_psk_similarity
)

def detect_ask_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Detects Amplitude Shift Keying (ASK).
    ASK is characterized by a stable carrier frequency whose amplitude alternates 
    between two or more distinct levels.
    """
    envelope = compute_amplitude_envelope(samples, window_size=int(sample_rate * 0.005) or 20)
    if len(envelope) == 0:
        return {"similarity": 0.0, "reason": "Signal too short"}
        
    # Standard deviation of envelope to see if it fluctuates significantly
    env_mean = np.mean(envelope)
    if env_mean == 0:
        return {"similarity": 0.0, "reason": "Zero signal amplitude"}
        
    env_std = np.std(envelope)
    normalized_std = env_std / env_mean
    
    # We look for a bimodal distribution of envelope amplitudes
    hist, bin_edges = np.histogram(envelope, bins=30)
    peaks = []
    for i in range(1, len(hist) - 1):
        if hist[i] > hist[i-1] and hist[i] > hist[i+1] and hist[i] > np.max(hist) * 0.15:
            peaks.append((bin_edges[i] + bin_edges[i+1]) / 2)
            
    similarity = 0.0
    reason = "Continuous signal level"
    
    # If we have 2 distinct peaks in amplitude envelope (on/off or high/low states)
    if len(peaks) >= 2 and normalized_std > 0.3:
        similarity = min(0.9, normalized_std)
        reason = f"ASK detected: Bimodal envelope states around {peaks[0]:.3f} and {peaks[1]:.3f} (confidence: {similarity:.2f})"
        
    return {
        "similarity": float(similarity),
        "reason": reason,
        "parameters": {
            "states": [float(p) for p in peaks[:2]],
            "modulation": "ASK"
        }
    }

def detect_afsk_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    AFSK (Audio Frequency Shift Keying) is BFSK where mark/space frequencies are audio band.
    """
    fsk_res = detect_fsk_similarity(samples, sample_rate)
    similarity = fsk_res["similarity"]
    peaks = fsk_res.get("peaks", [])
    
    # Check if peak frequencies are in the typical audio range (300 Hz - 3000 Hz)
    is_audio = all(300 <= p <= 3000 for p in peaks) if peaks else False
    
    if similarity > 0.4 and is_audio:
        return {
            "similarity": float(similarity * 0.95),
            "reason": f"AFSK detected: FSK tones in audio band {peaks} (confidence: {similarity:.2f})",
            "parameters": {
                "mark_hz": float(peaks[0]) if len(peaks) > 0 else 0.0,
                "space_hz": float(peaks[1]) if len(peaks) > 1 else 0.0,
                "modulation": "AFSK"
            }
        }
    return {"similarity": 0.0, "reason": "No audio-band FSK pattern detected"}

def detect_dtmf_similarity(samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
    """
    Detects Dual-Tone Multi-Frequency (DTMF) tones.
    Checks for the simultaneous presence of DTMF grid frequencies.
    """
    # DTMF frequency groups
    low_group = [697, 770, 852, 941]
    high_group = [1209, 1336, 1477, 1633]
    
    freqs, spec = compute_spectrogram(samples, frame_size=1024, overlap=512)
    if len(freqs) == 0 or spec.size == 0:
        return {"similarity": 0.0, "reason": "Signal too short"}
        
    mean_spec = np.mean(spec, axis=0)
    freqs_hz = freqs * sample_rate
    
    # Find peaks in DTMF bands
    detected_low = []
    detected_high = []
    
    for f in low_group:
        # Find index near f
        idx = np.argmin(np.abs(freqs_hz - f))
        # Check if local peak
        if mean_spec[idx] > np.median(mean_spec) * 4.0:
            detected_low.append(f)
            
    for f in high_group:
        idx = np.argmin(np.abs(freqs_hz - f))
        if mean_spec[idx] > np.median(mean_spec) * 4.0:
            detected_high.append(f)
            
    similarity = 0.0
    reason = "No DTMF tones detected"
    
    if detected_low and detected_high:
        similarity = 0.9
        reason = f"DTMF tones detected: Low {detected_low} Hz, High {detected_high} Hz"
        
    return {
        "similarity": float(similarity),
        "reason": reason,
        "parameters": {
            "low_tones": [float(f) for f in detected_low],
            "high_tones": [float(f) for f in detected_high],
            "modulation": "DTMF"
        }
    }

def detect_nrz_similarity(samples: np.ndarray) -> Dict[str, Any]:
    """
    Detects NRZ (Non-Return-to-Zero) encoding.
    NRZ doesn't return to zero between consecutive bits of the same value.
    """
    zero_crossings = np.where(np.diff(np.sign(samples) >= 0))[0]
    if len(zero_crossings) < 15:
        return {"similarity": 0.0, "reason": "Too few crossings"}
        
    intervals = np.diff(zero_crossings)
    
    # For NRZ, the crossing intervals should be integer multiples of a fundamental bit duration Tb.
    # We check if intervals are closely grouped around multiples of the minimum interval.
    min_interval = np.percentile(intervals, 10)
    if min_interval == 0:
        return {"similarity": 0.0, "reason": "Zero transition intervals"}
        
    ratios = intervals / min_interval
    errors = np.abs(ratios - np.round(ratios))
    
    nrz_like = np.sum(errors < 0.25) / len(intervals)
    similarity = 0.0
    reason = "Irregular transition intervals"
    
    if nrz_like > 0.7:
        similarity = float(nrz_like)
        reason = f"NRZ transition timing detected (regular multiples of base rate, similarity: {similarity*100:.1f}%)"
        
    return {
        "similarity": similarity,
        "reason": reason,
        "parameters": {
            "base_interval_samples": float(min_interval),
            "modulation": "NRZ"
        }
    }

def scan_digital_modulations(samples: np.ndarray, sample_rate: int) -> List[Dict[str, Any]]:
    """
    Orchestrates all modulation detection algorithms.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    
    detections = []
    
    # 1. FSK
    fsk = detect_fsk_similarity(sig, sample_rate)
    if fsk["similarity"] > 0.3:
        detections.append({
            "type": "FSK",
            "confidence": fsk["similarity"],
            "reason": fsk["reason"],
            "suggested_demodulator": "fsk",
            "parameters": {"peaks": fsk.get("peaks", [])}
        })
        
    # 2. AFSK
    afsk = detect_afsk_similarity(sig, sample_rate)
    if afsk["similarity"] > 0.3:
        detections.append({
            "type": "AFSK",
            "confidence": afsk["similarity"],
            "reason": afsk["reason"],
            "suggested_demodulator": "fsk",
            "parameters": afsk.get("parameters", {})
        })
        
    # 3. ASK
    ask = detect_ask_similarity(sig, sample_rate)
    if ask["similarity"] > 0.3:
        detections.append({
            "type": "ASK",
            "confidence": ask["similarity"],
            "reason": ask["reason"],
            "suggested_demodulator": "ask",
            "parameters": ask.get("parameters", {})
        })
        
    # 4. PSK
    psk = detect_psk_similarity(sig.astype(np.float64), sample_rate)
    if psk["similarity"] > 0.3:
        detections.append({
            "type": "BPSK",
            "confidence": psk["similarity"],
            "reason": psk["reason"],
            "suggested_demodulator": "bpsk",
            "parameters": {}
        })
        
    # 5. DTMF
    dtmf = detect_dtmf_similarity(sig, sample_rate)
    if dtmf["similarity"] > 0.3:
        detections.append({
            "type": "DTMF",
            "confidence": dtmf["similarity"],
            "reason": dtmf["reason"],
            "suggested_demodulator": "dtmf",
            "parameters": dtmf.get("parameters", {})
        })
        
    # 6. Morse
    morse = detect_morse_similarity(sig, sample_rate)
    if morse["similarity"] > 0.3:
        detections.append({
            "type": "Morse",
            "confidence": morse["similarity"],
            "reason": morse["reason"],
            "suggested_demodulator": "morse",
            "parameters": {}
        })
        
    # 7. Manchester
    manc = detect_manchester_similarity(sig)
    if manc["similarity"] > 0.3:
        detections.append({
            "type": "Manchester",
            "confidence": manc["similarity"],
            "reason": manc["reason"],
            "suggested_demodulator": "manchester",
            "parameters": {}
        })
        
    # 8. NRZ
    nrz = detect_nrz_similarity(sig)
    if nrz["similarity"] > 0.3:
        detections.append({
            "type": "NRZ",
            "confidence": nrz["similarity"],
            "reason": nrz["reason"],
            "suggested_demodulator": "nrz",
            "parameters": nrz.get("parameters", {})
        })
        
    # Sort detections by confidence score
    detections.sort(key=lambda x: -x["confidence"])
    return detections
