"""
Ultra-deep flag search: Look at steganography within steganography (layered),
JPEG LSB extraction, byte-level XOR, frequency domain encoding, etc.
"""
import numpy as np
import re
import struct
import sys

sys.path.insert(0, ".")

from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

FLAG_RE = re.compile(rb'ANIMUS\{[^\}]+\}')
# Also try case-insensitive
FLAG_CI = re.compile(rb'(?i)animus\{[^\}]+\}')

def search_data(data, label, pattern=FLAG_RE):
    found = []
    if isinstance(data, str):
        data = data.encode("utf-8")
    for m in pattern.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        print(f"  *** FLAG in [{label}] at offset {m.start()}: {flag}")
        found.append(flag)
    return found

print("Loading WAV file...")
wav = WavFile("sparrows_layered_drop.wav")
all_flags = []

# ===== 1: JPEG LSB steganography =====
print("\n[1] Extracting and checking LSB of embedded JPEGs...")
import os
for jpgfile in ["extracted_jpeg_128_9.jpg", "extracted_jpeg_16_11.jpg"]:
    if not os.path.exists(jpgfile):
        continue
    with open(jpgfile, "rb") as f:
        jpgdata = f.read()
    
    # Extract LSB from JPEG data bytes
    arr = np.frombuffer(jpgdata, dtype=np.uint8)
    bits = arr & 1
    for msb_pack in [True, False]:
        extracted = bits_to_bytes(bits, pack_msb=msb_pack)
        flags = search_data(extracted, f"{jpgfile}_lsb_{'msb' if msb_pack else 'lsb'}")
        all_flags.extend(flags)
    
    # Also check bit 1
    bits1 = (arr >> 1) & 1
    for msb_pack in [True, False]:
        extracted = bits_to_bytes(bits1, pack_msb=msb_pack)
        flags = search_data(extracted, f"{jpgfile}_bit1_{'msb' if msb_pack else 'lsb'}")
        all_flags.extend(flags)

# ===== 2: Extract from specific portions of the WAV (second half, etc.) =====
print("\n[2] Checking second half of WAV, specific regions...")
total_samples = wav.raw_samples.shape[0]
half = total_samples // 2

for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    # Second half only
    bits_second_half = unsigned[half:] & 1
    data = bits_to_bytes(bits_second_half, pack_msb=True)
    flags = search_data(data, f"ch{ch}_second_half_lsb")
    all_flags.extend(flags)
    
    # Last quarter
    quarter = total_samples * 3 // 4
    bits_last_quarter = unsigned[quarter:] & 1
    data = bits_to_bytes(bits_last_quarter, pack_msb=True)
    flags = search_data(data, f"ch{ch}_last_quarter_lsb")
    all_flags.extend(flags)

# ===== 3: Check channel 1 specifically (decoy was in channel 0) =====
print("\n[3] Extensive channel 1 analysis...")
ch1_samples = wav.raw_samples[:, 1]
mask_val = (1 << wav.bits_per_sample) - 1
ch1_unsigned = ch1_samples & mask_val

# All bitplanes of channel 1
for bit in range(wav.bits_per_sample):
    bits = (ch1_unsigned >> bit) & 1
    data = bits_to_bytes(bits, pack_msb=True)
    flags = search_data(data, f"ch1_bit{bit}_msb", FLAG_CI)
    all_flags.extend(flags)

# ===== 4: XOR channel 0 LSB with channel 1 LSB =====
print("\n[4] XOR/Diff of LSB bitplanes between channels...")
ch0_bits = wav.raw_samples[:, 0] & mask_val & 1
ch1_bits = ch1_unsigned & 1

xor_bits = ch0_bits ^ ch1_bits
for msb_pack in [True, False]:
    data = bits_to_bytes(xor_bits, pack_msb=msb_pack)
    flags = search_data(data, f"xor_lsb_{'msb' if msb_pack else 'lsb'}")
    all_flags.extend(flags)

# ===== 5: Steganography in the frequency domain =====
print("\n[5] FFT magnitude LSB extraction...")
for ch in range(wav.channels):
    channel_data = wav.normalized_samples[:, ch]
    # Take FFT of the whole signal
    fft = np.fft.rfft(channel_data)
    magnitudes = np.abs(fft)
    # Quantize magnitudes and check LSB
    mag_int = (magnitudes * 1000).astype(np.int64)
    bits = mag_int & 1
    # Take only first portion
    for msb_pack in [True, False]:
        data = bits_to_bytes(bits[:100000], pack_msb=msb_pack)
        flags = search_data(data, f"ch{ch}_fft_mag_lsb_{'msb' if msb_pack else 'lsb'}")
        all_flags.extend(flags)

# ===== 6: Byte-level XOR with common keys =====
print("\n[6] XOR decryption attempts on LSB data...")
ch0_samples = wav.raw_samples[:, 0]
ch0_unsigned = ch0_samples & mask_val
ch0_lsb_bits = ch0_unsigned & 1
ch0_lsb_data = bits_to_bytes(ch0_lsb_bits, pack_msb=True)

# Skip the decoy flag area, focus on what's after
decoy_text = b"ABSTERGO NOTICE: synchronization failed. ANIMUS{decoy_visible_lsb_is_not_the_drop}"
decoy_idx = ch0_lsb_data.find(decoy_text)
if decoy_idx >= 0:
    # Check for XOR-encoded data after decoy
    after_data = ch0_lsb_data[decoy_idx + len(decoy_text):]
    for key_byte in range(1, 256):
        xored = bytes(b ^ key_byte for b in after_data[:500])
        flags = search_data(xored, f"xor_key_{key_byte:#04x}", FLAG_CI)
        all_flags.extend(flags)

# ===== 7: Check the "ABSTERGO" text for steganographic clues =====
print("\n[7] Analyzing the decoy message in detail...")
if decoy_idx >= 0:
    # Print more surrounding context
    context_start = max(0, decoy_idx - 50)
    context_end = min(len(ch0_lsb_data), decoy_idx + len(decoy_text) + 500)
    context = ch0_lsb_data[context_start:context_end]
    printable = bytes(b if 32 <= b <= 126 else 46 for b in context)
    print(f"  Full context: {printable.decode('ascii')}")

# ===== 8: "Layered" = multiple extraction on same data =====
print("\n[8] Layered: Gray-decode then LSB then bit-extract...")
from wavehunter.extractors.graycode import gray_to_binary
from wavehunter.extractors.delta import delta_decode

for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    
    # Gray -> LSB byte -> LSB bit
    gray = gray_to_binary(samples, wav.bits_per_sample)
    gray_bytes = (gray & 0xFF).astype(np.uint8)
    gray_bits = gray_bytes & 1
    data = bits_to_bytes(gray_bits, pack_msb=True)
    flags = search_data(data, f"ch{ch}_gray_byte_lsb")
    all_flags.extend(flags)
    
    # Delta -> LSB byte -> LSB bit
    delta = delta_decode(samples, wav.bits_per_sample)
    delta_bytes = (delta & 0xFF).astype(np.uint8)
    delta_bits = delta_bytes & 1
    data = bits_to_bytes(delta_bits, pack_msb=True)
    flags = search_data(data, f"ch{ch}_delta_byte_lsb")
    all_flags.extend(flags)
    
    # Reverse -> Gray -> LSB
    rev_samples = samples[::-1]
    rev_gray = gray_to_binary(rev_samples, wav.bits_per_sample)
    rev_gray_bytes = (rev_gray & 0xFF).astype(np.uint8)
    rev_gray_bits = rev_gray_bytes & 1
    data = bits_to_bytes(rev_gray_bits, pack_msb=True)
    flags = search_data(data, f"ch{ch}_rev_gray_byte_lsb")
    all_flags.extend(flags)

# ===== 9: Check every Nth sample's bit for different N =====
print("\n[9] Every Nth sample extraction with prime strides...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    
    for stride in [3, 5, 7, 9, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        bits = unsigned[::stride] & 1
        if len(bits) >= 64:
            data = bits_to_bytes(bits, pack_msb=True)
            flags = search_data(data, f"ch{ch}_prime_stride{stride}_bit0")
            all_flags.extend(flags)

# ===== 10: Specific byte offsets that might encode data =====
print("\n[10] Extracting specific bit combinations (bit 0 of even samples + bit 1 of odd samples)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    
    # Even samples bit 0, odd samples bit 1
    even_bits = unsigned[::2] & 1
    odd_bits = (unsigned[1::2] >> 1) & 1
    min_len = min(len(even_bits), len(odd_bits))
    interleaved = np.empty(min_len * 2, dtype=np.uint8)
    interleaved[0::2] = even_bits[:min_len]
    interleaved[1::2] = odd_bits[:min_len]
    data = bits_to_bytes(interleaved, pack_msb=True)
    flags = search_data(data, f"ch{ch}_even_b0_odd_b1")
    all_flags.extend(flags)

# ===== 11: Read the WAV file chunks for hidden data =====
print("\n[11] Checking WAV chunk structure for hidden chunks...")
with open("sparrows_layered_drop.wav", "rb") as f:
    file_bytes = f.read()

print(f"  File size: {len(file_bytes)} bytes")
print(f"  RIFF size declared: {wav.riff_size}")
print(f"  Chunks found: {len(wav.chunks)}")
for chunk in wav.chunks:
    print(f"    Chunk: '{chunk['id']}' size={chunk['size']} offset={chunk['offset']}")
    # Read chunk data and search
    chunk_data = file_bytes[chunk['offset']:chunk['offset']+chunk['size']]
    flags = search_data(chunk_data, f"chunk_{chunk['id']}")
    all_flags.extend(flags)

# Check for data after RIFF container
riff_end = wav.riff_size + 8
if riff_end < len(file_bytes):
    print(f"  Data after RIFF: {len(file_bytes) - riff_end} bytes")
    after_riff = file_bytes[riff_end:]
    flags = search_data(after_riff, "after_riff")
    all_flags.extend(flags)

# ===== 12: Check for base64-encoded flag =====
print("\n[12] Checking for base64-encoded flag in LSB data...")
import base64
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    bits = unsigned & 1
    data = bits_to_bytes(bits, pack_msb=True)
    
    # Find base64-like strings
    b64_pattern = re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')
    for m in b64_pattern.finditer(data):
        try:
            decoded = base64.b64decode(m.group())
            flags = search_data(decoded, f"ch{ch}_b64_decoded")
            all_flags.extend(flags)
        except:
            pass

# ===== Summary =====
print("\n" + "=" * 60)
print("ALL ANIMUS FLAGS FOUND:")
unique = list(set(all_flags))
for i, flag in enumerate(unique, 1):
    is_decoy = "decoy" in flag.lower()
    print(f"  {i}. {flag}{'  <-- DECOY' if is_decoy else '  <-- POTENTIAL REAL FLAG'}")

if not unique:
    print("  No ANIMUS{...} flags found!")
elif all("decoy" in f.lower() for f in unique):
    print("\n  Only decoy flags found. Need different technique!")
print("=" * 60)
