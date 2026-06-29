"""
Example flag finder script demonstrating how to programmatically use WaveHunter 
to search for hidden stego flags in an audio file.
"""
import sys
import re
import numpy as np
from pathlib import Path

# Add project root to path if running directly
sys.path.insert(0, str(Path(__file__).parent))

from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes
from wavehunter.extractors.graycode import gray_to_binary
from wavehunter.extractors.delta import delta_decode

# Target flag format to search for
FLAG_RE = re.compile(rb'D7CTF\{[^\}]+\}')

def search_data(data: bytes, label: str) -> str | None:
    """Helper to scan binary buffers for flag patterns."""
    for m in FLAG_RE.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        print(f"  *** FLAG FOUND in [{label}] at offset {m.start()}: {flag}")
        return flag
    return None

def main():
    target_file = "sample.wav"
    if not Path(target_file).exists():
        print(f"Error: {target_file} not found. Please place a WAV file in this directory named '{target_file}'.")
        sys.exit(1)

    print(f"Loading WAV file: {target_file}...")
    wav = WavFile(target_file)
    print(f"  Channels: {wav.channels}")
    print(f"  Sample Rate: {wav.sample_rate} Hz")
    print(f"  Bit Depth: {wav.bits_per_sample} bits")
    print(f"  Samples shape: {wav.raw_samples.shape}")
    print(f"  Trailer Payload: {len(wav.trailer_data)} bytes")

    all_flags = []

    # 1. Check trailer data (data appended to the end of the WAV RIFF container)
    if wav.trailer_data:
        print("\n[1] Checking trailer data...")
        flag = search_data(wav.trailer_data, "Trailer")
        if flag:
            all_flags.append(flag)

    # 2. Check standard LSB (Least Significant Bit) of Channel 0 and Channel 1
    print("\n[2] Checking standard LSB bitplanes...")
    for ch in range(wav.channels):
        samples = wav.raw_samples[:, ch]
        lsb = (samples & 1).astype(np.uint8)
        
        # Try both MSB-first and LSB-first bit packing
        for msb in (True, False):
            packed = bits_to_bytes(lsb, pack_msb=msb)
            flag = search_data(packed, f"ch{ch}_lsb_{'msb' if msb else 'lsb'}")
            if flag and flag not in all_flags:
                all_flags.append(flag)

    # 3. Check raw file bytes
    print("\n[3] Checking raw file bytes for flag patterns...")
    with open(target_file, "rb") as fh:
        raw_file = fh.read()
    flag = search_data(raw_file, "raw_file_bytes")
    if flag and flag not in all_flags:
        all_flags.append(flag)

    # Summary
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE. FLAGS FOUND:")
    if all_flags:
        for i, f in enumerate(all_flags, 1):
            print(f"  {i}. {f}")
    else:
        print("  No flags matching D7CTF{...} were found.")
    print("=" * 60)

if __name__ == "__main__":
    main()
