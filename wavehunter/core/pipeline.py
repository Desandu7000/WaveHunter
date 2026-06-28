"""
Analysis pipeline orchestrating all WaveHunter extractors, scanners, and signal modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

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


def _run_extractor(name: str, fn, *args, log: List[str]) -> List[Dict[str, Any]]:
    results = fn(*args)
    log.append(f"{name}: {len(results)} candidates")
    return results


def run_extraction_pipeline(wav: WavFile) -> tuple[List[Dict[str, Any]], List[str]]:
    """Run all steganography extractors and return raw candidates + extraction log."""
    candidates: List[Dict[str, Any]] = []
    log: List[str] = []
    samples = wav.raw_samples
    bps = wav.bits_per_sample

    extractors = [
        ("multibit_bitplanes", extract_multibit_bitplanes, (samples, bps)),
        ("relationships", extract_relationships, (samples, bps)),
        ("channels", extract_channels, (samples, bps)),
        ("interleaved", extract_interleaved, (samples, bps)),
        ("strided", extract_strided, (samples, bps)),
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


def run_full_analysis(wav: WavFile) -> AnalysisResult:
    """Execute the complete WaveHunter forensic analysis pipeline."""
    candidates, extraction_log = run_extraction_pipeline(wav)
    ranked = rank_candidates(candidates)

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

    return AnalysisResult(
        info=wav.info_dict,
        candidates=candidates,
        ranked=ranked,
        modem_findings=modem_findings,
        anomalies=anomalies,
        signal_summary=signal_summary,
        stream_stats=stream_stats,
        extraction_log=extraction_log,
        entropy_windows=entropy_windows,
    )
