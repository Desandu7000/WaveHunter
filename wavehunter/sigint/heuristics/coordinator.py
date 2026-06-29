from typing import Dict, Any, List
import numpy as np

from wavehunter.sigint.fingerprint import fingerprint_signal
from wavehunter.sigint.detection.carrier import analyze_carriers_and_signals
from wavehunter.sigint.detection.modulation import scan_digital_modulations
from wavehunter.sigint.demodulation.synchronization import estimate_symbol_rate
from wavehunter.sigint.demodulation.demodulators import (
    demodulate_fsk,
    demodulate_ask,
    demodulate_bpsk,
    demodulate_morse,
    demodulate_dtmf,
    demodulate_manchester,
    demodulate_nrz
)
from wavehunter.sigint.decoders.pipeline import run_decoder_pipeline
from wavehunter.sigint.intelligence.patterns import scan_intelligence_patterns

def coordinate_sigint_analysis(
    samples: np.ndarray, 
    sample_rate: int,
    max_depth: int = 2,
    flag_format: str | None = None
) -> Dict[str, Any]:
    """
    Heuristic coordination engine that runs signal fingerprinting,
    modulation detection, demodulation, multi-stage decoding, and pattern intelligence.

    For files with sample rates above 22,050 Hz (e.g. 44.1kHz/48kHz), the input is
    downsampled by 2x before STFT-based analysis. This halves the computation without
    affecting detection quality for typical CTF radio signals (which are <10kHz bandwidth).
    """
    if len(samples) == 0:
        return {}

    # Downsample high sample-rate audio for faster SIGINT analysis.
    # CTF carrier signals are rarely above 10kHz, so a 22050Hz Nyquist rate is sufficient.
    analysis_samples = samples
    analysis_rate = sample_rate
    if sample_rate > 22050:
        analysis_samples = samples[::2]
        analysis_rate = sample_rate // 2

    mono_samples = analysis_samples[:, 0] if len(analysis_samples.shape) > 1 else analysis_samples

    # 1. Fingerprint signal
    fingerprint = fingerprint_signal(analysis_samples, analysis_rate)

    # 2. Carriers & Sweeps
    carriers = analyze_carriers_and_signals(analysis_samples, analysis_rate)

    # 3. Modulation Detections
    modulations = scan_digital_modulations(analysis_samples, analysis_rate)
    
    # 4. Attempt Demodulations & Decodings on active carriers
    demod_candidates = []
    
    for mod in modulations:
        mod_type = mod["type"]
        conf = mod["confidence"]
        
        # We only demodulate if confidence is reasonable
        if conf < 0.4:
            continue
            
        demod_data = b""
        estimated_baud = estimate_symbol_rate(mono_samples, sample_rate)
        
        try:
            if mod_type in ["FSK", "AFSK"]:
                peaks = mod["parameters"].get("peaks", [])
                mark = peaks[0] if len(peaks) > 0 else 1200.0
                space = peaks[1] if len(peaks) > 1 else 2200.0
                demod_data = demodulate_fsk(mono_samples, sample_rate, mark, space, estimated_baud)
            elif mod_type == "ASK":
                demod_data = demodulate_ask(mono_samples, sample_rate, estimated_baud)
            elif mod_type == "BPSK":
                # Find dominant carrier frequency
                dom_peak = fingerprint.get("dominant_peak_hz", 1000.0)
                demod_data = demodulate_bpsk(mono_samples, sample_rate, dom_peak, estimated_baud)
            elif mod_type == "Manchester":
                demod_data = demodulate_manchester(mono_samples, sample_rate, estimated_baud)
            elif mod_type == "NRZ":
                demod_data = demodulate_nrz(mono_samples, sample_rate, estimated_baud)
            elif mod_type == "Morse":
                decoded_text = demodulate_morse(mono_samples, sample_rate)
                demod_data = decoded_text.encode("utf-8")
            elif mod_type == "DTMF":
                decoded_digits = demodulate_dtmf(mono_samples, sample_rate)
                demod_data = decoded_digits.encode("utf-8")
        except Exception:
            # Demodulation failed, skip
            continue
            
        if demod_data and len(demod_data) >= 4:
            demod_candidates.append({
                "source": f"demod_{mod_type.lower()}",
                "data": demod_data,
                "confidence": conf
            })
            
    # 5. Run Decoding Pipeline on Demodulated Candidates
    decoded_findings = []
    seen_decoded_data = set()
    
    for cand in demod_candidates:
        dec_results = run_decoder_pipeline(cand["data"], max_depth=max_depth, flag_format=flag_format)
        for r in dec_results:
            d_hash = hash(r["data"])
            if d_hash not in seen_decoded_data:
                seen_decoded_data.add(d_hash)
                decoded_findings.append({
                    "source": cand["source"],
                    "path": r["path"],
                    "data": r["data"],
                    "entropy": r["entropy"],
                    "printable_ratio": r["printable_ratio"]
                })
                
    # 6. Apply Pattern Intelligence (Scan for Flags, Credentials, etc.)
    ranked_findings = []
    
    # Also scan direct demodulated data if not fully decoded
    for cand in demod_candidates:
        direct_matches = scan_intelligence_patterns(cand["data"], flag_format=flag_format)
        for m in direct_matches:
            ranked_findings.append({
                "source": cand["source"],
                "path": ["demod_raw"],
                "type": m["type"],
                "value": m["value"],
                "confidence": m["confidence"] * cand["confidence"]
            })
            
    # Scan all decoded outcomes
    for df in decoded_findings:
        matches = scan_intelligence_patterns(df["data"], flag_format=flag_format)
        for m in matches:
            # Combined confidence score of finding and decoding success
            score = m["confidence"] * (1.0 - (df["entropy"] / 8.0) * 0.1)
            ranked_findings.append({
                "source": df["source"],
                "path": df["path"],
                "type": m["type"],
                "value": m["value"],
                "confidence": float(np.clip(score, 0.0, 1.0))
            })
            
    # Sort findings by confidence descending
    ranked_findings.sort(key=lambda x: -x["confidence"])
    
    # 7. Formulate Recommendations
    recommendations = []
    if modulations:
        top_mod = modulations[0]
        if top_mod["confidence"] > 0.6:
            recommendations.append(
                f"Highly confident {top_mod['type']} modulation detected ({top_mod['confidence']*100:.1f}%). "
                f"Attempt demodulation with custom {top_mod['suggested_demodulator']} configuration."
            )
            
    if not ranked_findings and modulations:
        recommendations.append("Digital carrier observed, but no clear flag/text payload recovered. Try adjusting carrier band/frequency shift.")
    elif ranked_findings:
        top_find = ranked_findings[0]
        recommendations.append(
            f"Successfully recovered {top_find['type']} via path '{' -> '.join(top_find['path'])}'. "
            f"Review extracted payload: {top_find['value']}"
        )
        
    return {
        "fingerprint": fingerprint,
        "carriers": carriers,
        "modulations": modulations,
        "decoded_streams_count": len(decoded_findings),
        "findings": ranked_findings,
        "recommendations": recommendations
    }
