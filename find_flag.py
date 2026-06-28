"""
Targeted flag finder for sparrows_layered_drop.wav.
The decoy flag says "lsb is not the drop" — search all extraction layers.
"""
import numpy as np
import re
import sys

sys.path.insert(0, ".")

from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes
from wavehunter.extractors.graycode import gray_to_binary
from wavehunter.extractors.delta import delta_decode

FLAG_RE = re.compile(rb'ANIMUS\{[^\}]+\}')

def search_data(data: bytes, label: str):
    for m in FLAG_RE.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        print(f"  *** FLAG FOUND in [{label}] at offset {m.start()}: {flag}")
        return flag
    return None

print("Loading WAV file...")
wav = WavFile("sparrows_layered_drop.wav")
print(f"  Channels: {wav.channels}, Sample Rate: {wav.sample_rate}, Bits: {wav.bits_per_sample}")
print(f"  Samples shape: {wav.raw_samples.shape}")
print(f"  Trailer: {len(wav.trailer_data)} bytes")

# Check trailer
if wav.trailer_data:
    print("\n[1] Checking trailer data...")
    search_data(wav.trailer_data, "Trailer")

all_flags = []

print("\n[2] Checking LSB bitplanes (bits 0-15) for all channels...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    for bit in range(min(wav.bits_per_sample, 16)):
        bits = (unsigned >> bit) & 1
        for msb in [True, False]:
            data = bits_to_bytes(bits, pack_msb=msb)
            f = search_data(data, f"ch{ch}_bit{bit}_{'msb' if msb else 'lsb'}")
            if f and f not in all_flags:
                all_flags.append(f)

print("\n[3] Checking raw LSB byte (bits 0-7) and MSB byte (bits 8-15)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    lsb_bytes = (unsigned & 0xFF).astype(np.uint8).tobytes()
    f = search_data(lsb_bytes, f"ch{ch}_lsb_byte")
    if f and f not in all_flags:
        all_flags.append(f)
    
    if wav.bits_per_sample >= 16:
        msb_bytes = ((unsigned >> 8) & 0xFF).astype(np.uint8).tobytes()
        f = search_data(msb_bytes, f"ch{ch}_msb_byte")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[4] Checking Gray-decoded streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    gray_decoded = gray_to_binary(samples, wav.bits_per_sample)
    
    # LSB byte of gray decoded
    data = (gray_decoded & 0xFF).astype(np.uint8).tobytes()
    f = search_data(data, f"ch{ch}_gray_lsb_byte")
    if f and f not in all_flags:
        all_flags.append(f)
    
    # Gray decoded bit 0
    bits = gray_decoded & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_gray_bit0_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[5] Checking Delta-decoded streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    delta_decoded = delta_decode(samples, wav.bits_per_sample)
    
    data = (delta_decoded & 0xFF).astype(np.uint8).tobytes()
    f = search_data(data, f"ch{ch}_delta_lsb_byte")
    if f and f not in all_flags:
        all_flags.append(f)
    
    bits = delta_decoded & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_delta_bit0_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[6] Checking channel relationships (XOR, Diff, Sum)...")
if wav.channels >= 2:
    ch0 = wav.raw_samples[:, 0]
    ch1 = wav.raw_samples[:, 1]
    
    for label, result in [("XOR", ch0 ^ ch1), ("Diff", ch0 - ch1), ("Sum", ch0 + ch1)]:
        data = pack_to_bytes(result, wav.bits_per_sample)
        f = search_data(data, f"channel_{label}")
        if f and f not in all_flags:
            all_flags.append(f)
        
        # Also check LSB byte of result
        mask_val = (1 << wav.bits_per_sample) - 1
        unsigned = result & mask_val
        lsb_data = (unsigned & 0xFF).astype(np.uint8).tobytes()
        f = search_data(lsb_data, f"channel_{label}_lsb_byte")
        if f and f not in all_flags:
            all_flags.append(f)
        
        # Bit 0 of result
        bits = unsigned & 1
        for msb in [True, False]:
            data = bits_to_bytes(bits, pack_msb=msb)
            f = search_data(data, f"channel_{label}_bit0_{'msb' if msb else 'lsb'}")
            if f and f not in all_flags:
                all_flags.append(f)

print("\n[7] Checking nibble streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    nibbles_lsb = unsigned & 0x0F
    n_bytes = len(nibbles_lsb) // 2
    if n_bytes > 0:
        n1 = nibbles_lsb[0::2][:n_bytes]
        n2 = nibbles_lsb[1::2][:n_bytes]
        pack1 = ((n1 << 4) | n2).astype(np.uint8).tobytes()
        f = search_data(pack1, f"ch{ch}_nibble_lsb_p1")
        if f and f not in all_flags:
            all_flags.append(f)
        pack2 = ((n2 << 4) | n1).astype(np.uint8).tobytes()
        f = search_data(pack2, f"ch{ch}_nibble_lsb_p2")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[8] Checking reversed streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    rev = samples[::-1]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = rev & mask_val
    
    bits = unsigned & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_reversed_bit0_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[9] Checking strided samples for flag...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    for stride in [2, 3, 4, 5, 6, 7, 8, 10, 16, 32, 64, 128]:
        for offset in range(stride):
            strided = unsigned[offset::stride]
            if len(strided) < 8:
                continue
            
            # Check LSB byte
            lsb_data = (strided & 0xFF).astype(np.uint8).tobytes()
            f = search_data(lsb_data, f"ch{ch}_stride{stride}_off{offset}_lsb_byte")
            if f and f not in all_flags:
                all_flags.append(f)
            
            # Check bit 0
            bits = strided & 1
            for msb in [True, False]:
                data = bits_to_bytes(bits, pack_msb=msb)
                f = search_data(data, f"ch{ch}_stride{stride}_off{offset}_bit0_{'msb' if msb else 'lsb'}")
                if f and f not in all_flags:
                    all_flags.append(f)

print("\n[10] Checking Polarity-inverted streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    from wavehunter.core.signal import invert_polarity
    inverted = invert_polarity(samples.astype(np.float64))
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = (inverted.astype(np.int64) & mask).astype(np.int32)
    
    bits = unsigned & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_polarity_inv_bit0_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[11] Checking bit-inverted streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    inverted = (~samples) & mask_val
    
    lsb_data = (inverted & 0xFF).astype(np.uint8).tobytes()
    f = search_data(lsb_data, f"ch{ch}_bitinv_lsb_byte")
    if f and f not in all_flags:
        all_flags.append(f)
    
    bits = inverted & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_bitinv_bit0_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[12] Checking combined bitplane operations (XOR/OR of bits 0-3)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    planes = [(unsigned >> b) & 1 for b in range(min(wav.bits_per_sample, 8))]
    
    # XOR of bits 0-1
    xor01 = planes[0] ^ planes[1]
    for msb in [True, False]:
        data = bits_to_bytes(xor01, pack_msb=msb)
        f = search_data(data, f"ch{ch}_xor01_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)
    
    # XOR of bits 0-3
    xor03 = planes[0] ^ planes[1] ^ planes[2] ^ planes[3]
    for msb in [True, False]:
        data = bits_to_bytes(xor03, pack_msb=msb)
        f = search_data(data, f"ch{ch}_xor03_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[13] Checking sign bit streams...")
sign_bit = wav.bits_per_sample - 1
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    bits = (samples & mask_val) >> sign_bit
    for msb in [True, False]:
        data = bits_to_bytes(bits, pack_msb=msb)
        f = search_data(data, f"ch{ch}_signbit_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[14] Checking phase (FFT) extracted streams...")
from wavehunter.extractors.phase import extract_phase
phase_candidates = extract_phase(wav.normalized_samples)
for c in phase_candidates:
    f = search_data(c["data"], c["source"])
    if f and f not in all_flags:
        all_flags.append(f)

print("\n[15] Checking consecutive diff and parity transition streams...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    diffs = np.diff(samples)
    
    # Parity transitions
    parity = (samples & 1).astype(np.int8)
    parity_trans = parity[1:] ^ parity[:-1]
    for msb in [True, False]:
        data = bits_to_bytes(parity_trans, pack_msb=msb)
        f = search_data(data, f"ch{ch}_parity_trans_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)
    
    # Zero crossings
    sign_crossings = ((samples[1:] >= 0) != (samples[:-1] >= 0)).astype(np.int8)
    for msb in [True, False]:
        data = bits_to_bytes(sign_crossings, pack_msb=msb)
        f = search_data(data, f"ch{ch}_zero_cross_{'msb' if msb else 'lsb'}")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[16] Checking multi-bit combinations: bits 0+1 packed as 2-bit values...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    # Extract 2-bit values from bits 0-1, pack 4 per byte
    twobits = unsigned & 0x03
    n_bytes = len(twobits) // 4
    if n_bytes > 0:
        t = twobits[:n_bytes * 4].reshape(-1, 4)
        packed = (t[:, 0] << 6 | t[:, 1] << 4 | t[:, 2] << 2 | t[:, 3]).astype(np.uint8).tobytes()
        f = search_data(packed, f"ch{ch}_2bit_01_msb")
        if f and f not in all_flags:
            all_flags.append(f)
        # Reverse order
        packed2 = (t[:, 3] << 6 | t[:, 2] << 4 | t[:, 1] << 2 | t[:, 0]).astype(np.uint8).tobytes()
        f = search_data(packed2, f"ch{ch}_2bit_01_lsb")
        if f and f not in all_flags:
            all_flags.append(f)

print("\n[17] Checking raw file bytes for ANIMUS pattern...")
with open("sparrows_layered_drop.wav", "rb") as fh:
    raw_file = fh.read()
f = search_data(raw_file, "raw_file_bytes")
if f and f not in all_flags:
    all_flags.append(f)

print("\n" + "=" * 60)
print("ALL FLAGS FOUND:")
for i, flag in enumerate(all_flags, 1):
    is_decoy = "decoy" in flag.lower()
    print(f"  {i}. {flag}{'  <-- DECOY' if is_decoy else '  <-- REAL FLAG?'}")

if not all_flags:
    print("  No ANIMUS{...} flags found!")
print("=" * 60)
