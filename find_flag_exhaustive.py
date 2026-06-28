"""
Exhaustive layered analysis. The name says "layered" so try:
1. Extract JPEG from stride, then stego-analyze the JPEG pixel data
2. Apply stego analysis to the ch0/ch1 difference signal  
3. Look for zlib/gzip/encoded data within extracted layers
4. Try SSTV-like decoding
5. Extract from specific sample ranges
"""
import numpy as np
import re
import struct
import sys
import os

sys.path.insert(0, ".")

from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

FLAG_RE = re.compile(rb'ANIMUS\{[^\}]+\}')

def sf(data, label):
    """Search for flag"""
    found = []
    if isinstance(data, str):
        data = data.encode("utf-8")
    for m in FLAG_RE.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        print(f"  *** FLAG [{label}]: {flag}")
        found.append(flag)
    return found

wav = WavFile("sparrows_layered_drop.wav")
all_flags = []

# ===== A: JPEG pixel LSB analysis =====
print("[A] JPEG pixel-level LSB extraction...")
try:
    from PIL import Image
    import io
    for jpgfile in ["extracted_jpeg_128_9.jpg", "extracted_jpeg_16_11.jpg"]:
        if not os.path.exists(jpgfile):
            continue
        try:
            img = Image.open(jpgfile)
        except Exception as e:
            print(f"  Could not open {jpgfile}: {e}")
            continue
        pixels = np.array(img)
        print(f"  {jpgfile}: shape={pixels.shape}, dtype={pixels.dtype}")
        
        # Extract LSB from all pixel values
        flat = pixels.flatten()
        bits = flat & 1
        for msb in [True, False]:
            data = bits_to_bytes(bits, pack_msb=msb)
            flags = sf(data, f"{jpgfile}_pixel_lsb_{'msb' if msb else 'lsb'}")
            all_flags.extend(flags)
        
        # Extract bit 1
        bits1 = (flat >> 1) & 1
        for msb in [True, False]:
            data = bits_to_bytes(bits1, pack_msb=msb)
            flags = sf(data, f"{jpgfile}_pixel_bit1_{'msb' if msb else 'lsb'}")
            all_flags.extend(flags)
        
        # Try per-channel (R, G, B)
        if len(pixels.shape) == 3:
            for c_idx, c_name in enumerate(["R", "G", "B"]):
                if c_idx < pixels.shape[2]:
                    channel_bits = pixels[:, :, c_idx].flatten() & 1
                    data = bits_to_bytes(channel_bits, pack_msb=True)
                    flags = sf(data, f"{jpgfile}_{c_name}_lsb")
                    all_flags.extend(flags)
except ImportError:
    print("  PIL not available, skipping pixel analysis")

# ===== B: Sample value mod encoding =====
print("\n[B] Sample value modular encoding (mod 2, mod 3, mod 5, mod 7)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    
    for mod_val in [2, 3, 5, 7]:
        mod_vals = unsigned % mod_val
        if mod_val == 2:
            bits = mod_vals.astype(np.uint8)
            data = bits_to_bytes(bits, pack_msb=True)
            flags = sf(data, f"ch{ch}_mod{mod_val}")
            all_flags.extend(flags)
        else:
            # Pack as bytes directly
            byte_data = mod_vals.astype(np.uint8).tobytes()
            flags = sf(byte_data, f"ch{ch}_mod{mod_val}_raw")
            all_flags.extend(flags)

# ===== C: Look at raw data bytes directly for patterns =====
print("\n[C] Direct byte search in raw audio data...")
raw_audio = wav.raw_data_bytes
# Search in raw audio bytes
flags = sf(raw_audio, "raw_audio_bytes")
all_flags.extend(flags)

# ===== D: Combine channels differently =====
print("\n[D] Advanced channel combinations...")
ch0 = wav.raw_samples[:, 0]
ch1 = wav.raw_samples[:, 1]
mask = (1 << wav.bits_per_sample) - 1

# Average
avg = ((ch0.astype(np.int64) + ch1.astype(np.int64)) // 2).astype(np.int32)
avg_unsigned = avg & mask
bits = avg_unsigned & 1
data = bits_to_bytes(bits, pack_msb=True)
flags = sf(data, "avg_ch01_lsb")
all_flags.extend(flags)

# Mid-side: M = (L+R)/2, S = (L-R)/2
mid = avg_unsigned
side = ((ch0.astype(np.int64) - ch1.astype(np.int64)) // 2).astype(np.int32) & mask

for label, vals in [("mid", mid), ("side", side)]:
    bits = vals & 1
    data = bits_to_bytes(bits, pack_msb=True)
    flags = sf(data, f"{label}_lsb")
    all_flags.extend(flags)
    
    lsb_byte = (vals & 0xFF).astype(np.uint8).tobytes()
    flags = sf(lsb_byte, f"{label}_lsb_byte")
    all_flags.extend(flags)

# ===== E: Differential between adjacent samples =====
print("\n[E] Adjacent sample differences -> LSB byte...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    diffs = np.diff(samples)
    mask_d = (1 << wav.bits_per_sample) - 1
    diff_unsigned = diffs.astype(np.int32) & mask_d
    
    lsb_byte = (diff_unsigned & 0xFF).astype(np.uint8).tobytes()
    flags = sf(lsb_byte, f"ch{ch}_diff_lsb_byte")
    all_flags.extend(flags)

# ===== F: Try reading every Nth byte of the raw data =====
print("\n[F] Strided raw data byte extraction...")
for stride in [2, 3, 4, 8, 16]:
    for offset in range(stride):
        strided = raw_audio[offset::stride]
        flags = sf(strided, f"raw_stride{stride}_off{offset}")
        all_flags.extend(flags)

# ===== G: Spectrogram-based text (check if flag is written in spectrogram) =====
print("\n[G] Spectrogram analysis for encoded text...")
from wavehunter.core.signal import compute_spectrogram
for ch in range(wav.channels):
    channel_data = wav.normalized_samples[:, ch]
    freqs, spec = compute_spectrogram(channel_data, frame_size=2048, overlap=1024)
    if spec.size > 0:
        # Flatten spectrogram and check LSBs
        spec_int = (spec * 1000).astype(np.int64).flatten()
        bits = spec_int & 1
        data = bits_to_bytes(bits.astype(np.uint8), pack_msb=True)
        flags = sf(data, f"ch{ch}_spectrogram_lsb")
        all_flags.extend(flags)

# ===== H: DCT-based stego (common in images, sometimes in audio) =====
print("\n[H] DCT coefficient LSB extraction...")
from scipy.fft import dct
for ch in range(wav.channels):
    channel_data = wav.raw_samples[:, ch].astype(np.float64)
    # Process in blocks of 8 (like JPEG)
    n = len(channel_data) // 8 * 8
    blocks = channel_data[:n].reshape(-1, 8)
    dct_coeffs = dct(blocks, type=2, axis=1)
    
    # Extract LSB of quantized DCT coefficients
    quantized = np.round(dct_coeffs).astype(np.int64)
    bits = quantized.flatten() & 1
    data = bits_to_bytes(bits.astype(np.uint8), pack_msb=True)
    flags = sf(data, f"ch{ch}_dct_lsb")
    all_flags.extend(flags)

# ===== I: Specific bit patterns from the report =====
print("\n[I] Analyzing specific stride/offset combinations found in reports...")
# The report found verified JPEG at stride 128 offset 9 and stride 16 offset 11
# These are embedded images. Check if there's text/flag embedded in their metadata
# or after them in the strided data

for stride, offset in [(128, 9), (16, 11), (8, 0), (4, 2)]:
    strided = ch1[offset::stride]
    data = pack_to_bytes(strided, wav.bits_per_sample)
    
    # Find all JPEG instances and check after each
    pos = 0
    jpeg_count = 0
    while True:
        start = data.find(b'\xff\xd8', pos)
        if start == -1:
            break
        end = data.find(b'\xff\xd9', start + 2)
        if end == -1:
            break
        end += 2
        jpeg_count += 1
        
        # Check the non-JPEG data
        jpeg = data[start:end]
        
        # Check after this JPEG
        after = data[end:end + 1000]
        flags = sf(after, f"s{stride}_o{offset}_after_jpeg{jpeg_count}")
        all_flags.extend(flags)
        
        pos = end
    
    if jpeg_count > 0:
        print(f"  stride={stride}, offset={offset}: found {jpeg_count} JPEGs")
        # Check data before first JPEG
        first_jpeg = data.find(b'\xff\xd8')
        if first_jpeg > 0:
            before = data[:first_jpeg]
            flags = sf(before, f"s{stride}_o{offset}_before_jpeg")
            all_flags.extend(flags)

# ===== J: Reversed entire file =====
print("\n[J] Reversed raw audio bytes...")
reversed_raw = raw_audio[::-1]
flags = sf(reversed_raw, "reversed_raw_audio")
all_flags.extend(flags)

# ===== K: LSB of absolute values =====
print("\n[K] LSB of absolute sample values...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    abs_samples = np.abs(samples)
    bits = abs_samples & 1
    data = bits_to_bytes(bits.astype(np.uint8), pack_msb=True)
    flags = sf(data, f"ch{ch}_abs_lsb")
    all_flags.extend(flags)

# ===== L: Check for ANIMUS encoded byte-by-byte in sample values =====
print("\n[L] Check if flag is encoded in sample LSB bytes directly...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    # Low byte of each sample
    low_bytes = (samples & 0xFF).astype(np.uint8)
    # Filter printable
    printable_mask = (low_bytes >= 32) & (low_bytes <= 126)
    # Look for ANIMUS in low bytes
    low_str = low_bytes.tobytes()
    flags = sf(low_str, f"ch{ch}_sample_low_byte")
    all_flags.extend(flags)
    
    # High byte
    if wav.bits_per_sample >= 16:
        high_bytes = ((samples >> 8) & 0xFF).astype(np.uint8)
        high_str = high_bytes.tobytes()
        flags = sf(high_str, f"ch{ch}_sample_high_byte")
        all_flags.extend(flags)

# ===== M: Combine bit 0 from ch0 with bit 0 from ch1 alternating =====
print("\n[M] Interleaved bits from both channels...")
ch0_b0 = wav.raw_samples[:, 0] & 1
ch1_b0 = wav.raw_samples[:, 1] & 1

# Interleave: ch0, ch1, ch0, ch1...
interleaved = np.empty(len(ch0_b0) + len(ch1_b0), dtype=np.uint8)
interleaved[0::2] = ch0_b0.astype(np.uint8)
interleaved[1::2] = ch1_b0.astype(np.uint8)
data = bits_to_bytes(interleaved, pack_msb=True)
flags = sf(data, "interleaved_ch0ch1_b0")
all_flags.extend(flags)

# ch1 first
interleaved2 = np.empty(len(ch0_b0) + len(ch1_b0), dtype=np.uint8)
interleaved2[0::2] = ch1_b0.astype(np.uint8)
interleaved2[1::2] = ch0_b0.astype(np.uint8)
data = bits_to_bytes(interleaved2, pack_msb=True)
flags = sf(data, "interleaved_ch1ch0_b0")
all_flags.extend(flags)

# ===== N: Check LSB of channel 1 more deeply =====
print("\n[N] Channel 1 LSB full context...")
ch1_unsigned = wav.raw_samples[:, 1] & ((1 << wav.bits_per_sample) - 1)
ch1_bits = ch1_unsigned & 1
ch1_lsb = bits_to_bytes(ch1_bits, pack_msb=True)

# Print first printable content
printable = bytes(b if 32 <= b <= 126 else 46 for b in ch1_lsb[:300])
print(f"  Ch1 LSB start: {printable[:200].decode('ascii')}")
flags = sf(ch1_lsb, "ch1_lsb_full")
all_flags.extend(flags)

# ===== Summary =====
print("\n" + "=" * 60)
unique = list(set(all_flags))
if unique:
    for i, flag in enumerate(unique, 1):
        is_decoy = "decoy" in flag.lower()
        print(f"  {i}. {flag}{'  <-- DECOY' if is_decoy else '  <-- REAL FLAG!'}")
else:
    print("  No ANIMUS{...} flags found with current techniques!")
print("=" * 60)
