import pytest
import numpy as np
import tempfile
import gzip
import zipfile
import io
from pathlib import Path

from wavehunter.core.audio import WavFile
from wavehunter.core.entropy import shannon_entropy, sliding_window_entropy
from wavehunter.core.utils import bits_to_bytes, format_bytes, hexdump
from wavehunter.core.signatures import find_signatures
from wavehunter.core.scoring import score_candidate, rank_candidates
from wavehunter.core.validation import validate_embedded_file
from wavehunter.core.stats import analyze_stream_statistics, compute_printable_ratio, compute_autocorrelation
from wavehunter.core.pipeline import run_extraction_pipeline, run_full_analysis

from wavehunter.extractors.bitplanes import extract_bitplane, extract_all_bitplanes
from wavehunter.extractors.channels import extract_channels
from wavehunter.extractors.graycode import gray_to_binary, extract_graycode
from wavehunter.extractors.delta import delta_decode, extract_delta
from wavehunter.extractors.phase import extract_phase
from wavehunter.extractors.multibit import (
    extract_bit_inverted_streams,
    extract_combined_bitplanes,
    extract_sign_bit_streams,
)
from wavehunter.extractors.stride import extract_strided
from wavehunter.extractors.interleave import extract_interleaved
from wavehunter.extractors.relationships import extract_relationships

from wavehunter.scanners.ascii import scan_ascii
from wavehunter.scanners.regex import scan_regex
from wavehunter.scanners.compression import scan_compression

from tests.generate_test_wav import generate_test_wav


def test_entropy():
    data_high = bytes(range(256))
    assert shannon_entropy(data_high) == 8.0

    data_low = b"\x00" * 100
    assert shannon_entropy(data_low) == 0.0

    sliding = sliding_window_entropy(data_high, window_size=64, step_size=32)
    assert len(sliding) > 1


def test_utils():
    bits = [1, 1, 0, 0, 0, 0, 0, 0]
    assert bits_to_bytes(bits, pack_msb=True) == b"\xc0"
    assert bits_to_bytes(bits, pack_msb=False) == b"\x03"

    assert format_bytes(500) == "500 B"
    assert format_bytes(1024) == "1.00 KB"

    dump = hexdump(b"Hello World!", limit=5)
    assert "Hello" in dump or "48 65 6c 6c 6f" in dump


def test_scanners():
    flag_data = b"Some random garbage and flag{this_is_a_flag} then more garbage"
    matches = scan_regex(flag_data)
    assert len(matches) > 0
    assert matches[0]["type"] == "Flag"
    assert matches[0]["value"] == "flag{this_is_a_flag}"

    ascii_data = b"\x00\x01Hello World!\x02\x03"
    matches = scan_ascii(ascii_data, min_len=4)
    assert len(matches) > 0
    assert matches[0]["text"] == "Hello World!"

    zip_magic = b"PK\x03\x04Some zip data bytes herePK\x05\x06"
    matches = find_signatures(zip_magic)
    assert len(matches) > 0
    assert matches[0]["name"] == "ZIP Archive"
    assert matches[0]["confidence"] == "high"


def test_validation_rejects_false_positive_jpeg():
    """Magic bytes alone must not pass JPEG validation."""
    fake_jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 100  # no SOF, no EOI
    valid, detail = validate_embedded_file(fake_jpeg, "JPEG Image")
    assert valid is False
    assert "SOF" in detail or "EOI" in detail or "marker" in detail.lower()


def test_validation_accepts_real_gzip():
    payload = b"hidden flag data here"
    compressed = gzip.compress(payload)
    valid, detail = validate_embedded_file(compressed, "GZIP Archive")
    assert valid is True
    assert "decompressed" in detail.lower()


def test_validation_accepts_real_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test.txt", "hello")
    valid, _ = validate_embedded_file(buf.getvalue(), "ZIP Archive")
    assert valid is True


def test_gray_and_delta():
    arr = np.array([0, 1, 3, 2], dtype=np.int32)
    decoded = gray_to_binary(arr, 16)
    assert np.array_equal(decoded, [0, 1, 2, 3])

    d_arr = np.array([10, 2, 3, 65532], dtype=np.int32)
    decoded_delta = delta_decode(d_arr, 16)
    assert np.array_equal(decoded_delta, [10, 12, 15, 11])


def test_stream_statistics():
    text = b"ANIMUS{test_flag}" + b"\x00" * 100
    stats = analyze_stream_statistics(text)
    assert stats["printable_ratio"] > 0.1
    assert stats["entropy"] < 8.0
    assert compute_printable_ratio(text) > 0.1


def test_autocorrelation():
    # Sine wave should show periodic autocorrelation
    t = np.linspace(0, 4 * np.pi, 1000)
    signal = np.sin(t)
    ac = compute_autocorrelation(signal, max_lag=100)
    assert ac[0] == pytest.approx(1.0, abs=0.01)
    assert len(ac) > 10


def test_multibit_extractors():
    samples = np.arange(64, dtype=np.int32).reshape(32, 2)
    inverted = extract_bit_inverted_streams(samples, 16)
    assert len(inverted) >= 2

    combined = extract_combined_bitplanes(samples, 16)
    assert len(combined) >= 1

    sign = extract_sign_bit_streams(samples, 16)
    assert len(sign) >= 1


def test_extraction_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        wav_path = Path(tmpdir) / "test.wav"
        generate_test_wav(wav_path)
        wav = WavFile(wav_path)

        candidates, log = run_extraction_pipeline(wav)
        assert len(candidates) > 50
        assert len(log) > 10
        assert any(c["source"] == "trailer" for c in candidates)


def test_wav_file_parsing_and_analysis():
    with tempfile.TemporaryDirectory() as tmpdir:
        wav_path = Path(tmpdir) / "test.wav"
        generate_test_wav(wav_path)
        wav = WavFile(wav_path)

        assert wav.channels == 2
        assert wav.bits_per_sample == 16
        assert wav.sample_rate == 44100
        assert wav.has_trailer is True
        assert wav.trailer_size > 0

        result = run_full_analysis(wav)
        ratings = [r["rating"] for r in result.ranked]

        assert 5 in ratings
        assert len(result.extraction_log) > 10


def test_stride_and_interleave():
    samples = np.arange(16, dtype=np.int32).reshape(8, 2)
    strided = extract_strided(samples, 16)
    assert len(strided) > 0

    interleaved = extract_interleaved(samples, 16)
    assert len(interleaved) >= 6


def test_relationships_extractor():
    samples = np.array([[100, 200], [300, 400]], dtype=np.int32)
    rels = extract_relationships(samples, 16)
    sources = {r["source"] for r in rels}
    assert "rel_ch_xor" in sources
    assert any("rel_consec_diff" in s for s in sources)
