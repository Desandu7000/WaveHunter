"""
Analysis pipeline orchestrating all WaveHunter extractors, scanners, and signal modules.
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile
import gzip
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from wavehunter.core.audio import WavFile
from wavehunter.core.entropy import sliding_window_entropy
from wavehunter.core.modem import scan_modem_carrier
from wavehunter.core.scoring import rank_candidates
from wavehunter.core.signal import (
    analyze_signal_characteristics,
    compute_stereo_phase_difference,
    invert_polarity,
)
from wavehunter.core.stats import analyze_stream_statistics, find_statistical_anomalies
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.channels import extract_channels
from wavehunter.extractors.delta import extract_delta
from wavehunter.extractors.graycode import extract_graycode
from wavehunter.extractors.interleave import extract_interleaved
from wavehunter.extractors.multibit import (
    extract_bit_inverted_streams,
    extract_combined_bitplanes,
    extract_multibit_bitplanes,
    extract_multibit_transforms,
    extract_nibbles,
    extract_reconstructed_bytes,
    extract_sign_bit_streams,
)
from wavehunter.extractors.phase import extract_phase
from wavehunter.extractors.printable import extract_printable_text
from wavehunter.extractors.relationships import extract_relationships
from wavehunter.extractors.reverse import extract_reversed
from wavehunter.extractors.stride import extract_strided
from wavehunter.extractors.wavelet import extract_dwt_lsb
from wavehunter.extractors.parity import extract_sample_parity
from wavehunter.extractors.spread_spectrum import extract_dsss

# SIGINT v2.0 Imports
from wavehunter.sigint.heuristics.coordinator import coordinate_sigint_analysis
from wavehunter.sigint.reconstruction.signals import reconstruct_signal_variations

@dataclass
class AnalysisResult:
    """Complete forensic analysis output."""

    info: Dict[str, Any]
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    ranked: List[Dict[str, Any]] = field(default_factory=list)
    modem_findings: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    signal_summary: Dict[str, Any] = field(default_factory=dict)
    stream_stats: List[Dict[str, Any]] = field(default_factory=list)
    extraction_log: List[str] = field(default_factory=list)
    entropy_windows: List[float] = field(default_factory=list)
    
    # SIGINT v2.0 Additions
    sigint_report: Dict[str, Any] = field(default_factory=dict)
    recursive_results: List[AnalysisResult] = field(default_factory=list)

def _run_extractor(name: str, fn, *args, log: List[str]) -> List[Dict[str, Any]]:
    results = fn(*args)
    log.append(f"{name}: {len(results)} candidates")
    return results

def run_extraction_pipeline(wav: WavFile, thorough: bool = False) -> tuple[List[Dict[str, Any]], List[str]]:
    """
    Runs all steganography extractors and returns raw candidates + extraction log.
    
    This function coordinates all active digital audio steganography extraction 
    methods (e.g., bitplanes, interleaved streams, strides, Gray code, Delta encoding, 
    FFT phase, polarity-inversion LSB, stereo phase-difference LSB, discrete wavelet 
    transform, and direct sequence spread spectrum) to collect raw data candidates.

    Pass thorough=True to enable exhaustive stride offset permutations (much slower but
    leaves no stone unturned).
    """
    candidates: List[Dict[str, Any]] = []
    log: List[str] = []
    samples = wav.raw_samples
    bps = wav.bits_per_sample

    extractors = [
        ("multibit_bitplanes", extract_multibit_bitplanes, (samples, bps)),
        ("relationships", extract_relationships, (samples, bps)),
        ("channels", extract_channels, (samples, bps)),
        ("interleaved", extract_interleaved, (samples, bps)),
        # stride extractor respects thorough flag for offset coverage
        ("strided", lambda s, b: extract_strided(s, b, thorough=thorough), (samples, bps)),
        ("reversed", extract_reversed, (samples, bps)),
        ("nibbles", extract_nibbles, (samples, bps)),
        ("reconstructed_bytes", extract_reconstructed_bytes, (samples, bps)),
        ("bit_inverted", extract_bit_inverted_streams, (samples, bps)),
        ("combined_bitplanes", extract_combined_bitplanes, (samples, bps)),
        ("sign_bits", extract_sign_bit_streams, (samples, bps)),
        ("multibit_transforms", extract_multibit_transforms, (samples, bps)),
        ("graycode", extract_graycode, (samples, bps)),
        ("delta", extract_delta, (samples, bps)),
        ("phase_fft", extract_phase, (wav.normalized_samples,)),
        ("printable", extract_printable_text, (samples, bps)),
        ("dwt_lsb", extract_dwt_lsb, (samples, bps)),
        ("sample_parity", extract_sample_parity, (samples, bps)),
        ("dsss", extract_dsss, (samples, bps)),
    ]

    for name, fn, args in extractors:
        candidates.extend(_run_extractor(name, fn, *args, log=log))

    # Signal-derived extractors: polarity-inverted and phase-difference bitstreams
    if samples.shape[0] > 0:
        for ch in range(samples.shape[1]):
            inverted = invert_polarity(samples[:, ch].astype(np.float64))
            mask = (1 << bps) - 1
            unsigned = (inverted.astype(np.int64) & mask).astype(np.int32)
            for msb in (True, False):
                bits = unsigned & 1
                b_data = bits_to_bytes(bits, pack_msb=msb)
                if len(b_data) >= 8:
                    candidates.append(
                        {
                            "name": f"Channel {ch} Polarity-Inverted LSB ({'MSB' if msb else 'LSB'} packed)",
                            "source": f"signal_polarity_inv_ch{ch}_{'msb' if msb else 'lsb'}",
                            "data": b_data,
                        }
                    )
        log.append("signal_polarity: polarity-inverted LSB streams")

    if wav.normalized_samples.shape[1] >= 2:
        phase_diffs = compute_stereo_phase_difference(wav.normalized_samples)
        if len(phase_diffs) > 8:
            # Quantize phase diff to bits: positive vs negative
            phase_bits = (phase_diffs > 0).astype(np.int8)
            for msb in (True, False):
                b_data = bits_to_bytes(phase_bits, pack_msb=msb)
                if len(b_data) >= 8:
                    candidates.append(
                        {
                            "name": f"Stereo Phase-Difference Bits ({'MSB' if msb else 'LSB'} packed)",
                            "source": f"signal_phase_diff_{'msb' if msb else 'lsb'}",
                            "data": b_data,
                        }
                    )
        log.append("signal_phase_diff: stereo phase-difference bitstream")

    # Trailer payload appended outside RIFF container
    if wav.trailer_data:
        candidates.append(
            {
                "name": "File Trailer Payload",
                "source": "trailer",
                "data": wav.trailer_data,
            }
        )
        log.append(f"trailer: {len(wav.trailer_data)} bytes")

    return candidates, log

def run_full_analysis(
    wav: WavFile, 
    depth: int = 0, 
    max_depth: int = 2,
    flag_format: Optional[str] = None,
    thorough: bool = False
) -> AnalysisResult:
    """
    Executes the complete WaveHunter forensic analysis pipeline with recursive processing.
    
    This is the core analysis orchestrator. It:
    1. Runs all extraction sub-modules on the input audio file to collect candidate byte streams.
    2. Runs the decoder pipeline recursively to uncover nested, hidden, or encrypted data layers.
    3. Profiles and scores candidate data streams to rank them by likelihood of being a payload.
    4. Computes digital signal characteristics, statistical carrier anomalies, and modulations.
    5. Returns an AnalysisResult aggregating all findings.

    Pass thorough=True to enable exhaustive analysis (all stride offsets, full scoring of every
    candidate). Slower but leaves nothing untested.
    """
    candidates, extraction_log = run_extraction_pipeline(wav, thorough=thorough)
    
    # Run decoder pipeline on all candidates to uncover hidden/encrypted layers
    from wavehunter.sigint.decoders.pipeline import run_decoder_pipeline
    
    decoded_candidates = []
    for cand in candidates:
        # Fast filter: only decode suspected candidate sources (e.g. Bit 9, Stride 256, or DWT)
        is_suspected = "_b9_" in cand["source"] or "s256" in cand["source"] or "dwt" in cand["source"]
        if not is_suspected:
            continue
            
        dec_results = run_decoder_pipeline(cand["data"], max_depth=1, fast_mode=True, flag_format=flag_format)
        for r in dec_results:
            path_str = " -> ".join(r["path"])
            if len(r["path"]) > 1:
                flag_lower = flag_format.lower().encode("utf-8", errors="ignore") if flag_format else b""
                contains_flag = b"flag" in r["data"].lower() or b"ctf" in r["data"].lower() or (bool(flag_lower) and flag_lower in r["data"].lower())
                if r["printable_ratio"] > 0.7 or contains_flag:
                    decoded_candidates.append({
                        "name": f"{cand['name']} ({path_str})",
                        "source": f"{cand['source']}_{path_str.replace(' ', '_').replace('->', '_')}",
                        "data": r["data"]
                    })
                    
    candidates.extend(decoded_candidates)
    ranked = rank_candidates(candidates, thorough=thorough)

    # Map source -> raw data for statistical profiling (ranked results omit data)
    data_by_source = {c["source"]: c["data"] for c in candidates}

    # Signal analysis on left channel
    signal = wav.raw_samples[:, 0].astype(np.float64)
    signal_summary = analyze_signal_characteristics(signal, wav.sample_rate)

    modem_findings = scan_modem_carrier(wav.raw_samples, wav.sample_rate)

    anomalies = find_statistical_anomalies(signal)
    if wav.raw_samples.shape[1] >= 2:
        anomalies.extend(find_statistical_anomalies(wav.raw_samples[:, 1]))

    # Statistical profiling of top-ranked candidates
    stream_stats = []
    for cand in ranked[:20]:
        raw = data_by_source.get(cand["source"], b"")
        stats = analyze_stream_statistics(raw)
        stats["source"] = cand["source"]
        stats["name"] = cand["name"]
        stream_stats.append(stats)

    entropy_windows = sliding_window_entropy(wav.raw_data_bytes, window_size=2048, step_size=1024)

    # Run SIGINT Coordinator
    sigint_report = coordinate_sigint_analysis(wav.normalized_samples, wav.sample_rate, max_depth=max_depth, flag_format=flag_format)

    # Compile initial AnalysisResult
    result = AnalysisResult(
        info=wav.info_dict,
        candidates=candidates,
        ranked=ranked,
        modem_findings=modem_findings,
        anomalies=anomalies,
        signal_summary=signal_summary,
        stream_stats=stream_stats,
        extraction_log=extraction_log,
        entropy_windows=entropy_windows,
        sigint_report=sigint_report,
        recursive_results=[]
    )

    # Recursive payload exploration (Phase 6)
    if depth < max_depth:
        # Check top ranked candidates and trailer data for embedded audio or archives
        payloads_to_check: List[Tuple[str, bytes]] = []
        
        # Add trailer
        if wav.trailer_data:
            payloads_to_check.append(("Trailer Payload", wav.trailer_data))
            
        # Add top 5 candidates
        for cand in ranked[:5]:
            raw_data = data_by_source.get(cand["source"])
            if raw_data:
                payloads_to_check.append((cand["name"], raw_data))
                
        # Also check demodulated findings from SIGINT
        for finding in sigint_report.get("findings", []):
            # If we don't have the raw bytes of findings, skip, but we can reconstruct or scan
            pass

        for name, data in payloads_to_check:
            # 1. Check for embedded WAV file
            if data.startswith(b"RIFF") and b"WAVE" in data[:20]:
                try:
                    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                        tf.write(data)
                        tf.flush()
                        temp_path = Path(tf.name)
                        
                    nested_wav = WavFile(temp_path)
                    nested_result = run_full_analysis(nested_wav, depth=depth + 1, max_depth=max_depth, flag_format=flag_format, thorough=thorough)
                    nested_result.info["file_name"] = f"[Embedded WAV in {name}] {nested_result.info['file_name']}"
                    result.recursive_results.append(nested_result)
                    
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                except Exception:
                    pass

            # 2. Check for ZIP archive
            elif data.startswith(b"PK\x03\x04"):
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for file_info in z.infolist():
                            if file_info.file_size > 0:
                                with z.open(file_info) as f:
                                    file_bytes = f.read()
                                    
                                # If the file in ZIP is a WAV, analyze it
                                if file_bytes.startswith(b"RIFF") and b"WAVE" in file_bytes[:20]:
                                    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                                        tf.write(file_bytes)
                                        tf.flush()
                                        temp_path = Path(tf.name)
                                        
                                    nested_wav = WavFile(temp_path)
                                    nested_result = run_full_analysis(nested_wav, depth=depth + 1, max_depth=max_depth, flag_format=flag_format, thorough=thorough)
                                    nested_result.info["file_name"] = f"[ZIP:{file_info.filename} in {name}] {nested_result.info['file_name']}"
                                    result.recursive_results.append(nested_result)
                                    
                                    try:
                                        temp_path.unlink()
                                    except Exception:
                                        pass
                except Exception:
                    pass

            # 3. Check for GZIP archive
            elif data.startswith(b"\x1f\x8b"):
                try:
                    decompressed = gzip.decompress(data)
                    if decompressed.startswith(b"RIFF") and b"WAVE" in decompressed[:20]:
                        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
                            tf.write(decompressed)
                            tf.flush()
                            temp_path = Path(tf.name)
                            
                        nested_wav = WavFile(temp_path)
                        nested_result = run_full_analysis(nested_wav, depth=depth + 1, max_depth=max_depth, flag_format=flag_format, thorough=thorough)
                        nested_result.info["file_name"] = f"[GZIP Decompressed WAV in {name}] {nested_result.info['file_name']}"
                        result.recursive_results.append(nested_result)
                        
                        try:
                            temp_path.unlink()
                        except Exception:
                            pass
                except Exception:
                    pass

            # 4. Check for Base64 encoding
            import re
            import base64
            # Look for base64 strings longer than 40 chars
            b64_matches = re.finditer(br'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', data)
            for m in b64_matches:
                try:
                    decoded = base64.b64decode(m.group(0))
                    flag_upper = flag_format.upper().encode("utf-8", errors="ignore") if flag_format else b"FLAG{"
                    if flag_upper in decoded or b"FLAG{" in decoded:
                        dummy = AnalysisResult(info={"file_name": f"[Base64 decoded in {name}]"}, candidates=[{"name": "Base64 Flag", "source": "base64", "data": decoded}])
                        result.recursive_results.append(dummy)
                except Exception:
                    pass

    return result
