"""
Deep flag search: Look at embedded files, compressed streams, multi-layer stego,
and more advanced techniques.
"""
import numpy as np
import re
import zlib
import sys

sys.path.insert(0, ".")

from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes
from wavehunter.extractors.graycode import gray_to_binary
from wavehunter.extractors.delta import delta_decode
from wavehunter.scanners.compression import scan_compression

FLAG_RE = re.compile(rb'ANIMUS\{[^\}]+\}')
ANY_FLAG_RE = re.compile(rb'[A-Z]{2,15}\{[a-zA-Z0-9_\-\.!\?#@\$%\^&\*\s]{3,80}\}')

def search_data(data: bytes, label: str, pattern=FLAG_RE, verbose=True):
    found = []
    for m in pattern.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        if verbose:
            print(f"  *** FLAG in [{label}] at offset {m.start()}: {flag}")
        found.append(flag)
    return found

print("Loading WAV file...")
wav = WavFile("sparrows_layered_drop.wav")
print(f"  Shape: {wav.raw_samples.shape}, Rate: {wav.sample_rate}, Bits: {wav.bits_per_sample}")

all_flags = []

# ===== TECHNIQUE 1: Extract embedded JPEG from stride 128 offset 9 channel 1 =====
print("\n[A] Extracting embedded JPEG from stride 128, offset 9, channel 1...")
ch1 = wav.raw_samples[:, 1]
strided_128_9 = ch1[9::128]
stride_data = pack_to_bytes(strided_128_9, wav.bits_per_sample)

# Find JPEG in this data
jpeg_start = stride_data.find(b'\xff\xd8\xff')
jpeg_end = stride_data.find(b'\xff\xd9', jpeg_start) + 2 if jpeg_start >= 0 else -1
if jpeg_start >= 0 and jpeg_end > jpeg_start:
    jpeg_data = stride_data[jpeg_start:jpeg_end]
    print(f"  JPEG found at offset {jpeg_start}, size {len(jpeg_data)} bytes")
    with open("extracted_jpeg_128_9.jpg", "wb") as f:
        f.write(jpeg_data)
    # Scan the JPEG for hidden data
    flags = search_data(jpeg_data, "JPEG_128_9")
    all_flags.extend(flags)
    # Also check after the JPEG
    after_jpeg = stride_data[jpeg_end:]
    flags = search_data(after_jpeg, "after_JPEG_128_9")
    all_flags.extend(flags)
    # Check before JPEG too
    before_jpeg = stride_data[:jpeg_start]
    flags = search_data(before_jpeg, "before_JPEG_128_9")
    all_flags.extend(flags)

# ===== TECHNIQUE 2: Extract embedded JPEG from stride 16 offset 11 channel 1 =====
print("\n[B] Extracting embedded JPEG from stride 16, offset 11, channel 1...")
strided_16_11 = ch1[11::16]
stride_data2 = pack_to_bytes(strided_16_11, wav.bits_per_sample)

jpeg_start2 = stride_data2.find(b'\xff\xd8\xff')
jpeg_end2 = stride_data2.find(b'\xff\xd9', jpeg_start2) + 2 if jpeg_start2 >= 0 else -1
if jpeg_start2 >= 0 and jpeg_end2 > jpeg_start2:
    jpeg_data2 = stride_data2[jpeg_start2:jpeg_end2]
    print(f"  JPEG found at offset {jpeg_start2}, size {len(jpeg_data2)} bytes")
    with open("extracted_jpeg_16_11.jpg", "wb") as f:
        f.write(jpeg_data2)
    flags = search_data(jpeg_data2, "JPEG_16_11")
    all_flags.extend(flags)
    after_jpeg2 = stride_data2[jpeg_end2:]
    flags = search_data(after_jpeg2, "after_JPEG_16_11")
    all_flags.extend(flags)

# ===== TECHNIQUE 3: Search ALL strided raw bytes for compressed streams =====
print("\n[C] Scanning for compressed streams in strided data...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    for stride in [2, 3, 4, 8, 16, 32, 64, 128]:
        for offset in range(min(stride, 16)):
            strided = samples[offset::stride]
            if len(strided) < 16:
                continue
            data = pack_to_bytes(strided, wav.bits_per_sample)
            comps = scan_compression(data)
            for comp in comps:
                if comp["decompressed_size"] > 10:
                    print(f"  Compressed stream in ch{ch}_s{stride}_o{offset}: {comp['type']} "
                          f"({comp['compressed_size']}B -> {comp['decompressed_size']}B)")
                    flags = search_data(comp["decompressed_data"], 
                                       f"decomp_ch{ch}_s{stride}_o{offset}")
                    all_flags.extend(flags)

# ===== TECHNIQUE 4: LSB of LSB byte (layered extraction) =====
print("\n[D] Checking layered extraction: LSB bit of LSB-extracted bytes...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    # First layer: extract bit 0 as MSB packed bytes
    bits0 = unsigned & 1
    layer1 = bits_to_bytes(bits0, pack_msb=True)
    
    # Second layer: extract bit 0 from layer1 bytes
    layer1_arr = np.frombuffer(layer1, dtype=np.uint8)
    bits1 = layer1_arr & 1
    layer2 = bits_to_bytes(bits1, pack_msb=True)
    flags = search_data(layer2, f"ch{ch}_layered_lsb_of_lsb")
    all_flags.extend(flags)

# ===== TECHNIQUE 5: Multi-bit extraction (bits 0-1 as 2-bit, bits 0-2 as 3-bit) =====
print("\n[E] Multi-bit extraction (2-bit, 3-bit, 4-bit from LSB)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    # 2-bit: extract 2 LSBs, pack 4 per byte (MSB first)
    twobits = unsigned & 0x03
    n4 = len(twobits) // 4
    if n4 > 0:
        t = twobits[:n4*4].reshape(-1, 4)
        packed = (t[:, 0] << 6 | t[:, 1] << 4 | t[:, 2] << 2 | t[:, 3]).astype(np.uint8).tobytes()
        flags = search_data(packed, f"ch{ch}_2lsb_msb")
        all_flags.extend(flags)
    
    # 3-bit: extract 3 LSBs, pack... 
    # Actually let's try direct 8-bit approach: mask with 2 LSBs per sample, 
    # concatenate bits differently
    for nbits in [2, 3, 4]:
        extracted_bits = unsigned & ((1 << nbits) - 1)
        # Pack nbits from each sample into a bitstream
        all_bits = []
        for s in extracted_bits[:100000]:  # limit for speed
            for b in range(nbits-1, -1, -1):
                all_bits.append((int(s) >> b) & 1)
        all_bits_arr = np.array(all_bits, dtype=np.uint8)
        packed = bits_to_bytes(all_bits_arr, pack_msb=True)
        flags = search_data(packed, f"ch{ch}_{nbits}lsb_bitstream")
        all_flags.extend(flags)

# ===== TECHNIQUE 6: XOR between channels then LSB =====
print("\n[F] XOR/Diff between channels, then extract LSB/bytes...")
if wav.channels >= 2:
    ch0 = wav.raw_samples[:, 0]
    ch1 = wav.raw_samples[:, 1]
    
    for label, result in [("XOR", ch0 ^ ch1), ("Diff", ch0 - ch1), ("Sum", ch0 + ch1)]:
        mask_val = (1 << wav.bits_per_sample) - 1
        unsigned = result & mask_val
        
        # Check compressed streams in the result
        data = pack_to_bytes(result, wav.bits_per_sample)
        comps = scan_compression(data)
        for comp in comps:
            if comp["decompressed_size"] > 10:
                print(f"  Compressed in channel {label}: {comp['type']} "
                      f"({comp['compressed_size']}B -> {comp['decompressed_size']}B)")
                flags = search_data(comp["decompressed_data"], f"decomp_{label}")
                all_flags.extend(flags)
        
        # Gray-decode the result
        gray = gray_to_binary(result.astype(np.int32), wav.bits_per_sample)
        gray_data = (gray & 0xFF).astype(np.uint8).tobytes()
        flags = search_data(gray_data, f"{label}_gray_lsb_byte")
        all_flags.extend(flags)
        
        # Delta-decode the result
        delta = delta_decode(result.astype(np.int32), wav.bits_per_sample)
        delta_data = (delta & 0xFF).astype(np.uint8).tobytes()
        flags = search_data(delta_data, f"{label}_delta_lsb_byte")
        all_flags.extend(flags)

# ===== TECHNIQUE 7: Scan for any flag pattern in LSB data =====
print("\n[G] Broad pattern scan in LSB data (any FLAG{...} pattern)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    bits = unsigned & 1
    data = bits_to_bytes(bits, pack_msb=True)
    
    # Look for any text near "decoy"
    decoy_idx = data.find(b"ANIMUS{decoy")
    if decoy_idx >= 0:
        # Print surrounding context
        context = data[max(0, decoy_idx-100):decoy_idx+200]
        # Filter printable
        printable = bytes(b if 32 <= b <= 126 else 46 for b in context)
        print(f"  Context around decoy in ch{ch} LSB:")
        print(f"  {printable.decode('ascii')}")

# ===== TECHNIQUE 8: Metadata chunks =====
print("\n[H] Checking WAV metadata chunks...")
print(f"  Metadata: {wav.metadata}")
for key, val in wav.metadata.items():
    flags = search_data(val.encode("utf-8"), f"metadata_{key}")
    all_flags.extend(flags)

# ===== TECHNIQUE 9: Scan LSB bit 1 (second LSB) with various techniques =====
print("\n[I] Deep scan of bit 1 (second LSB) for hidden messages...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    
    # Bit 1 extraction
    bits1 = (unsigned >> 1) & 1
    for msb in [True, False]:
        data = bits_to_bytes(bits1, pack_msb=msb)
        # Search compressed
        comps = scan_compression(data)
        for comp in comps:
            if comp["decompressed_size"] > 10:
                print(f"  Compressed in ch{ch}_bit1_{'msb' if msb else 'lsb'}: {comp['type']} "
                      f"({comp['compressed_size']}B -> {comp['decompressed_size']}B)")
                flags = search_data(comp["decompressed_data"], f"decomp_ch{ch}_bit1")
                all_flags.extend(flags)

# ===== TECHNIQUE 10: Check EXIF/metadata in extracted JPEGs =====
print("\n[J] Checking extracted JPEG files for hidden data/strings...")
import os
for jpgfile in ["extracted_jpeg_128_9.jpg", "extracted_jpeg_16_11.jpg", 
                "extracted_128_9.jpg", "extracted_16_11.jpg"]:
    if os.path.exists(jpgfile):
        with open(jpgfile, "rb") as f:
            jpgdata = f.read()
        print(f"  Scanning {jpgfile} ({len(jpgdata)} bytes)...")
        flags = search_data(jpgdata, jpgfile)
        all_flags.extend(flags)
        # Also look for broader patterns
        broad = search_data(jpgdata, f"{jpgfile}_broad", ANY_FLAG_RE)

# ===== TECHNIQUE 11: Bit manipulation on the decoy LSB stream =====
print("\n[K] Checking for flag hidden AFTER the decoy flag in LSB stream...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    bits = unsigned & 1
    data = bits_to_bytes(bits, pack_msb=True)
    
    # Find end of decoy flag
    decoy_end = data.find(b"ANIMUS{decoy_visible_lsb_is_not_the_drop}")
    if decoy_end >= 0:
        decoy_end += len(b"ANIMUS{decoy_visible_lsb_is_not_the_drop}")
        after = data[decoy_end:decoy_end+500]
        printable = bytes(b if 32 <= b <= 126 else 46 for b in after)
        print(f"  After decoy in ch{ch}: {printable[:200].decode('ascii')}")
        # Search for another flag pattern after decoy
        flags = search_data(data[decoy_end:], f"ch{ch}_after_decoy")
        all_flags.extend(flags)
        
        # What about before the decoy?
        before = data[:decoy_end - len(b"ANIMUS{decoy_visible_lsb_is_not_the_drop}")]
        printable_before = bytes(b if 32 <= b <= 126 else 46 for b in before[:200])
        print(f"  Before decoy in ch{ch}: {printable_before.decode('ascii')}")

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
    print("\n  WARNING: Only decoy flags found. Real flag uses a different technique!")
print("=" * 60)
