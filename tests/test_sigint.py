import pytest
import numpy as np
import tempfile
from pathlib import Path

from wavehunter.sigint.fingerprint.audio_metadata import extract_statistical_profile
from wavehunter.sigint.fingerprint.spectral import analyze_spectral_profile, compute_fft, compute_stft
from wavehunter.sigint.fingerprint import fingerprint_signal

from wavehunter.sigint.detection.carrier import detect_carrier_candidates, detect_sweeps
from wavehunter.sigint.detection.modulation import scan_digital_modulations

from wavehunter.sigint.demodulation.synchronization import estimate_symbol_rate, synchronize_symbols
from wavehunter.sigint.demodulation.demodulators import (
    demodulate_fsk,
    demodulate_ask,
    demodulate_bpsk,
    demodulate_morse,
    demodulate_dtmf
)

from wavehunter.sigint.reconstruction.signals import reconstruct_signal_variations
from wavehunter.sigint.decoders.decoder_library import (
    decode_base64,
    decode_base32,
    decode_base16,
    decode_rot,
    decode_xor_single,
    brute_force_xor
)
from wavehunter.sigint.decoders.pipeline import run_decoder_pipeline
from wavehunter.sigint.intelligence.patterns import scan_intelligence_patterns
from wavehunter.sigint.heuristics.coordinator import coordinate_sigint_analysis

from wavehunter.plugins.base import BasePlugin, SignalDetectorPlugin
from wavehunter.plugins.manager import PluginManager

from wavehunter.core.audio import WavFile
from wavehunter.core.pipeline import run_full_analysis
from tests.generate_test_wav import generate_test_wav

def test_fingerprinting():
    # Generate 1s of sine wave at 440 Hz
    fs = 8000
    t = np.linspace(0, 1.0, fs, endpoint=False)
    samples = np.sin(2 * np.pi * 440 * t).astype(np.float32)
    
    # 1. Check metadata stats
    meta = extract_statistical_profile(samples, fs)
    assert meta["channel_correlation"] == 0.0
    assert len(meta["channel_stats"]) == 1
    assert pytest.approx(meta["channel_stats"][0]["peak_amplitude"], 0.01) == 1.0
    
    # 2. Check spectral analysis
    spec = analyze_spectral_profile(samples, fs)
    assert pytest.approx(spec["dominant_peak_hz"], 10.0) == 440.0
    
    # 3. Check combined fingerprint
    fp = fingerprint_signal(samples, fs)
    assert fp["channels"] == 1
    assert fp["sample_rate"] == fs
    assert pytest.approx(fp["dominant_peak_hz"], 10.0) == 440.0

def test_carrier_and_modulation_detection():
    fs = 8000
    t = np.linspace(0, 1.0, fs, endpoint=False)
    # Pure carrier at 1000Hz
    carrier = np.sin(2 * np.pi * 1000 * t).astype(np.float32)
    
    # Carrier check
    cands = detect_carrier_candidates(carrier, fs)
    assert len(cands) > 0
    assert pytest.approx(cands[0]["frequency_hz"], 20.0) == 1000.0
    
    # Frequency sweep check
    # Chirp from 500Hz to 1500Hz
    chirp = np.sin(2 * np.pi * (500 + 500 * t) * t).astype(np.float32)
    sweeps = detect_sweeps(chirp, fs)
    assert len(sweeps) > 0
    
    # Modulation check
    mods = scan_digital_modulations(carrier, fs)
    # A single carrier is a trivial FSK or ASK or NRZ candidate (high stability)
    assert len(mods) > 0

def test_demodulators():
    fs = 8000
    baud = 50.0
    symbol_len = int(fs / baud)
    
    # Generate FSK (2 symbols: Mark at 1200Hz, Space at 2200Hz)
    t_sym = np.linspace(0, 1.0/baud, symbol_len, endpoint=False)
    mark_wave = np.sin(2 * np.pi * 1200 * t_sym)
    space_wave = np.sin(2 * np.pi * 2200 * t_sym)
    
    # Let's transmit bits: [1, 0, 1, 0, 1, 1, 0, 0] = b'\xac'
    bits = [1, 0, 1, 0, 1, 1, 0, 0]
    signal = []
    for b in bits:
        signal.extend(mark_wave if b == 1 else space_wave)
    signal = np.array(signal, dtype=np.float32)
    
    # Demodulate FSK
    demod = demodulate_fsk(signal, fs, 1200.0, 2200.0, baud)
    assert demod == b'\xac'

def test_decoders():
    # Test individual decoders
    assert decode_base64(b"YW5pbXVz") == b"animus"
    assert decode_base16(b"616e696d7573") == b"animus"
    assert decode_rot(b"navzhf", 13) == b"animus"
    assert decode_xor_single(b"\x00\x0f\x08\x0c\x14\x12", 0x61) == b"animus"
    
    # Test recursive decoder pipeline
    # nested: "ANIMUS{flag}" -> ROT13 ("NAVZHF{synt}") -> B64 ("TkFWWkhGe3N5bnR9")
    original = b"TkFWWkhGe3N5bnR9"
    results = run_decoder_pipeline(original)
    
    decoded_values = [r["data"] for r in results]
    assert b"ANIMUS{flag}" in decoded_values
    
    # Verify that the path to success was captured
    path_found = False
    for r in results:
        if r["data"] == b"ANIMUS{flag}" and "base64" in r["path"] and "caesar_s13" in r["path"]:
            path_found = True
            break
    assert path_found is True

def test_pattern_intelligence():
    data = b"Some filler data animus{f0r3ns1cs_is_fun} more filler"
    findings = scan_intelligence_patterns(data)
    assert len(findings) > 0
    assert findings[0]["type"] == "Specific Flag (ANIMUS)"
    assert findings[0]["value"] == "animus{f0r3ns1cs_is_fun}"

def test_reconstruction():
    stereo_samples = np.array([[1.0, -1.0], [2.0, -2.0], [3.0, -3.0]], dtype=np.float32)
    variations = reconstruct_signal_variations(stereo_samples, 1000)
    assert "mid" in variations
    assert "side" in variations
    assert "reverse_time" in variations

def test_plugin_manager():
    # Define a mock plugin
    class MockDetector(SignalDetectorPlugin):
        name = "MockDetector"
        description = "For testing"
        def detect(self, samples, sample_rate):
            return {"similarity": 0.99, "reason": "Test success", "suggested_demodulator": "mock", "parameters": {}}
            
    pm = PluginManager()
    pm.register_plugin(MockDetector())
    assert len(pm.detectors) == 1
    assert pm.detectors[0].name == "MockDetector"
    assert pm.detectors[0].detect(None, 0)["similarity"] == 0.99

def test_coordinator():
    # Generate 1s of sine wave at 440 Hz
    fs = 8000
    t = np.linspace(0, 1.0, fs, endpoint=False)
    samples = np.sin(2 * np.pi * 440 * t).astype(np.float32)
    
    report = coordinate_sigint_analysis(samples, fs)
    assert "fingerprint" in report
    assert "carriers" in report
    assert "modulations" in report

def test_end_to_end_analysis():
    with tempfile.TemporaryDirectory() as tmpdir:
        wav_path = Path(tmpdir) / "test.wav"
        generate_test_wav(wav_path)
        
        wav = WavFile(wav_path)
        result = run_full_analysis(wav)
        
        # Verify backward compatibility
        assert wav.channels == 2
        assert len(result.candidates) > 0
        assert len(result.ranked) > 0
        
        # Verify recursive results (since test.wav has an appended zip archive)
        assert len(result.sigint_report) > 0
