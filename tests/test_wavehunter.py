import pytest
import numpy as np
import tempfile
import shutil
from pathlib import Path

# Imports from wavehunter
from wavehunter.core.audio import WavFile
from wavehunter.core.entropy import shannon_entropy, sliding_window_entropy
from wavehunter.core.utils import bits_to_bytes, format_bytes, hexdump
from wavehunter.core.signatures import find_signatures
from wavehunter.core.scoring import score_candidate, rank_candidates

# Extractors
from wavehunter.extractors.bitplanes import extract_bitplane, extract_all_bitplanes
from wavehunter.extractors.channels import extract_channels
from wavehunter.extractors.graycode import gray_to_binary, extract_graycode
from wavehunter.extractors.delta import delta_decode, extract_delta
from wavehunter.extractors.phase import extract_phase

# Scanners
from wavehunter.scanners.ascii import scan_ascii
from wavehunter.scanners.regex import scan_regex
from wavehunter.scanners.compression import scan_compression

# Synthetic generator
from tests.generate_test_wav import generate_test_wav

def test_entropy():
    # Uniform bytes should have high entropy
    data_high = bytes(range(256))
    assert shannon_entropy(data_high) == 8.0
    
    # Constant bytes should have 0 entropy
    data_low = b"\x00" * 100
    assert shannon_entropy(data_low) == 0.0

    # Sliding window check
    sliding = sliding_window_entropy(data_high, window_size=64, step_size=32)
    assert len(sliding) > 1

def test_utils():
    # bits_to_bytes tests
    bits = [1, 1, 0, 0, 0, 0, 0, 0] # 192 if MSB, 3 if LSB
    assert bits_to_bytes(bits, pack_msb=True) == b"\xc0"
    assert bits_to_bytes(bits, pack_msb=False) == b"\x03"
    
    # format_bytes
    assert format_bytes(500) == "500 B"
    assert format_bytes(1024) == "1.00 KB"
    
    # hexdump
    dump = hexdump(b"Hello World!", limit=5)
    assert "Hello" in dump or "48 65 6c 6c 6f" in dump

def test_scanners():
    # Regex
    flag_data = b"Some random garbage and flag{this_is_a_flag} then more garbage"
    matches = scan_regex(flag_data)
    assert len(matches) > 0
    assert matches[0]["type"] == "Flag"
    assert matches[0]["value"] == "flag{this_is_a_flag}"
    
    # ASCII text
    ascii_data = b"\x00\x01Hello World!\x02\x03"
    matches = scan_ascii(ascii_data, min_len=4)
    assert len(matches) > 0
    assert matches[0]["text"] == "Hello World!"
    
    # Magic
    zip_magic = b"PK\x03\x04Some zip data bytes herePK\x05\x06"
    matches = find_signatures(zip_magic)
    assert len(matches) > 0
    assert matches[0]["name"] == "ZIP Archive"
    assert matches[0]["confidence"] == "high"

def test_gray_and_delta():
    # Gray to binary
    # Gray values: 0 -> 0, 1 -> 1, 3 -> 2, 2 -> 3
    arr = np.array([0, 1, 3, 2], dtype=np.int32)
    decoded = gray_to_binary(arr, 16)
    assert np.array_equal(decoded, [0, 1, 2, 3])
    
    # Delta decode
    # Delta encoding of [10, 12, 15, 11] starting at 0:
    # d = [10, 2, 3, -4] -> in unsigned 16-bit: [10, 2, 3, 65532]
    d_arr = np.array([10, 2, 3, 65532], dtype=np.int32)
    decoded_delta = delta_decode(d_arr, 16)
    assert np.array_equal(decoded_delta, [10, 12, 15, 11])

def test_wav_file_parsing_and_analysis():
    # Create temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        wav_path = Path(tmpdir) / "test.wav"
        
        # Generate synthetic WAV using our generator
        generate_test_wav(wav_path)
        
        # Load and parse WAV
        wav = WavFile(wav_path)
        
        assert wav.channels == 2
        assert wav.bits_per_sample == 16
        assert wav.sample_rate == 44100
        assert wav.has_trailer is True
        assert wav.trailer_size > 0
        
        # Check extraction and scoring
        candidates = []
        candidates.extend(extract_all_bitplanes(wav.raw_samples, wav.bits_per_sample))
        candidates.extend(extract_channels(wav.raw_samples, wav.bits_per_sample))
        candidates.extend(extract_graycode(wav.raw_samples, wav.bits_per_sample))
        candidates.extend(extract_delta(wav.raw_samples, wav.bits_per_sample))
        candidates.extend(extract_phase(wav.normalized_samples))
        
        if wav.trailer_data:
            candidates.append({
                "name": "Trailer",
                "source": "trailer",
                "data": wav.trailer_data
            })
            
        ranked = rank_candidates(candidates)
        
        # Ensure our score detects the LSB flag and the Zip trailer
        ratings = [r["rating"] for r in ranked]
        
        # We should find at least one 5-star rating (for the flag or the zip archive)
        assert 5 in ratings
