"""
Final approach: Look for the flag using completely different strategies.
Since standard and advanced stego techniques haven't found it,
maybe the flag is:
1. In the JPEG EXIF/APP markers (not the pixel data)
2. Encoded via spectrogram visually (need visual check)
3. Hidden in the time-domain amplitude patterns  
4. Using multi-sample encoding (multiple samples encode one byte)
5. Hidden in zlib/compressed streams within extracted data
6. Hidden in the WAV file at non-standard positions
"""
import numpy as np
import re
import struct
import sys
import zlib

sys.path.insert(0, ".")
from wavehunter.core.audio import WavFile
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.interleave import pack_to_bytes

FLAG_RE = re.compile(rb'ANIMUS\{[^\}]+\}')

def sf(data, label):
    if isinstance(data, str):
        data = data.encode("utf-8")
    for m in FLAG_RE.finditer(data):
        flag = m.group().decode("utf-8", errors="ignore")
        print(f"  *** FLAG [{label}]: {flag}")
        return flag
    return None

wav = WavFile("sparrows_layered_drop.wav")
all_flags = []

# ===== Strategy 1: JPEG internal structure analysis =====
print("[1] Analyzing JPEG internal structure and APP markers...")
ch1 = wav.raw_samples[:, 1]
for stride, offset in [(128, 9), (16, 11)]:
    strided = ch1[offset::stride]
    data = pack_to_bytes(strided, wav.bits_per_sample)
    
    jpeg_start = data.find(b'\xff\xd8\xff')
    if jpeg_start < 0:
        continue
    jpeg_end = data.find(b'\xff\xd9', jpeg_start) + 2
    if jpeg_end <= jpeg_start:
        continue
    
    jpeg = data[jpeg_start:jpeg_end]
    print(f"  JPEG s={stride} o={offset}: {len(jpeg)} bytes")
    
    # Walk through JPEG markers
    pos = 2
    while pos < len(jpeg) - 1:
        if jpeg[pos] != 0xFF:
            pos += 1
            continue
        marker = jpeg[pos+1]
        if marker == 0xD9:  # EOI
            break
        if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0x00):
            pos += 2
            continue
        if pos + 3 >= len(jpeg):
            break
        seg_len = struct.unpack(">H", jpeg[pos+2:pos+4])[0]
        seg_data = jpeg[pos+4:pos+2+seg_len]
        
        marker_name = f"0x{marker:02X}"
        if 0xE0 <= marker <= 0xEF:
            marker_name = f"APP{marker-0xE0}"
        elif marker == 0xFE:
            marker_name = "COM"
        
        # Search for flag in segment data
        f = sf(seg_data, f"JPEG_s{stride}_o{offset}_{marker_name}")
        if f: all_flags.append(f)
        
        # Print text-like content
        printable = bytes(b if 32 <= b <= 126 else 46 for b in seg_data[:100])
        if any(32 <= b <= 126 for b in seg_data[:20]):
            print(f"    Marker {marker_name}: {printable[:80].decode('ascii')}")
        
        pos += 2 + seg_len

# ===== Strategy 2: Check JPEG comment markers specifically =====
print("\n[2] Checking for JPEG COM markers (0xFE)...")
for stride, offset in [(128, 9), (16, 11)]:
    strided = ch1[offset::stride]
    data = pack_to_bytes(strided, wav.bits_per_sample)
    
    # Search for COM marker directly
    com_pos = 0
    while True:
        com_pos = data.find(b'\xff\xfe', com_pos)
        if com_pos < 0:
            break
        if com_pos + 4 <= len(data):
            com_len = struct.unpack(">H", data[com_pos+2:com_pos+4])[0]
            com_data = data[com_pos+4:com_pos+2+com_len]
            printable = bytes(b if 32 <= b <= 126 else 46 for b in com_data)
            print(f"  COM at offset {com_pos}: {printable.decode('ascii')}")
            f = sf(com_data, f"JPEG_COM_s{stride}_o{offset}")
            if f: all_flags.append(f)
        com_pos += 2

# ===== Strategy 3: Extract data between JPEGs (non-JPEG data in strided stream) =====
print("\n[3] Extracting non-JPEG data from strided streams...")
for stride, offset in [(128, 9), (16, 11)]:
    strided = ch1[offset::stride]
    data = pack_to_bytes(strided, wav.bits_per_sample)
    
    # Collect non-JPEG regions
    non_jpeg = bytearray()
    pos = 0
    while True:
        start = data.find(b'\xff\xd8', pos)
        if start < 0:
            non_jpeg.extend(data[pos:])
            break
        non_jpeg.extend(data[pos:start])
        end = data.find(b'\xff\xd9', start + 2)
        if end < 0:
            break
        pos = end + 2
    
    if non_jpeg:
        print(f"  s={stride} o={offset}: {len(non_jpeg)} non-JPEG bytes")
        f = sf(bytes(non_jpeg), f"nonJPEG_s{stride}_o{offset}")
        if f: all_flags.append(f)
        
        # Try decompressing
        for i in range(len(non_jpeg) - 2):
            if non_jpeg[i:i+2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01'):
                try:
                    decomp = zlib.decompress(bytes(non_jpeg[i:]))
                    print(f"    zlib at offset {i}: {len(decomp)} bytes decompressed")
                    f = sf(decomp, f"zlib_s{stride}_o{offset}_{i}")
                    if f: all_flags.append(f)
                    # Print first bytes
                    printable = bytes(b if 32 <= b <= 126 else 46 for b in decomp[:100])
                    print(f"    Content: {printable.decode('ascii')}")
                except:
                    pass

# ===== Strategy 4: Multi-sample byte encoding =====
print("\n[4] Multi-sample encoding (every N samples' LSBs form a byte)...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    
    # Try: each sample's low 2 bits form pairs, 4 samples make a byte
    for nbits in [2, 3, 4]:
        low_bits = unsigned & ((1 << nbits) - 1)
        samples_per_byte = 8 // nbits
        n_bytes = len(low_bits) // samples_per_byte
        
        if n_bytes > 0:
            reshaped = low_bits[:n_bytes * samples_per_byte].reshape(-1, samples_per_byte)
            result = np.zeros(n_bytes, dtype=np.uint8)
            for i in range(samples_per_byte):
                shift = (samples_per_byte - 1 - i) * nbits
                result |= (reshaped[:, i].astype(np.uint8) << shift)
            
            byte_data = result.tobytes()
            f = sf(byte_data, f"ch{ch}_{nbits}bit_multisample_msb")
            if f: all_flags.append(f)
            
            # Try LSB order
            result2 = np.zeros(n_bytes, dtype=np.uint8)
            for i in range(samples_per_byte):
                shift = i * nbits
                result2 |= (reshaped[:, i].astype(np.uint8) << shift)
            
            byte_data2 = result2.tobytes()
            f = sf(byte_data2, f"ch{ch}_{nbits}bit_multisample_lsb")
            if f: all_flags.append(f)

# ===== Strategy 5: Amplitude quantization encoding =====
print("\n[5] Amplitude modulation encoding...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch].astype(np.float64)
    
    # Check if amplitude values map to ASCII
    abs_samples = np.abs(samples)
    # Maybe every Nth sample encodes a character via amplitude
    for stride in [100, 200, 480, 500, 960, 1000, 1500, 2000, 4800]:
        strided_amps = abs_samples[::stride]
        # Scale to ASCII range
        if len(strided_amps) > 10:
            max_amp = np.max(strided_amps)
            if max_amp > 0:
                scaled = (strided_amps / max_amp * 126).astype(np.uint8)
                byte_data = scaled.tobytes()
                f = sf(byte_data, f"ch{ch}_amp_stride{stride}")
                if f: all_flags.append(f)

# ===== Strategy 6: Check for flag encoded across both channels =====
print("\n[6] Cross-channel bit encoding...")
ch0 = wav.raw_samples[:, 0]
ch1 = wav.raw_samples[:, 1]
mask = (1 << wav.bits_per_sample) - 1

# ch0 bit 0 = even bits, ch1 bit 0 = odd bits of message
ch0_b0 = (ch0 & mask) & 1
ch1_b0 = (ch1 & mask) & 1

# Method: take ch0[i] bit 0 for even message bits, ch1[i] bit 0 for odd
n = min(len(ch0_b0), len(ch1_b0))
for pack_order in ["ch0_ch1", "ch1_ch0"]:
    combined = np.empty(n * 2, dtype=np.uint8)
    if pack_order == "ch0_ch1":
        combined[0::2] = ch0_b0[:n]
        combined[1::2] = ch1_b0[:n]
    else:
        combined[0::2] = ch1_b0[:n]
        combined[1::2] = ch0_b0[:n]
    
    data = bits_to_bytes(combined, pack_msb=True)
    f = sf(data, f"cross_channel_{pack_order}")
    if f: all_flags.append(f)

# Method 2: ch0 even samples bit0 + ch1 odd samples bit0
ch0_even_b0 = ch0_b0[::2]
ch1_odd_b0 = ch1_b0[1::2]
min_n = min(len(ch0_even_b0), len(ch1_odd_b0))
combined2 = np.empty(min_n * 2, dtype=np.uint8)
combined2[0::2] = ch0_even_b0[:min_n]
combined2[1::2] = ch1_odd_b0[:min_n]
data = bits_to_bytes(combined2, pack_msb=True)
f = sf(data, "cross_ch0even_ch1odd")
if f: all_flags.append(f)

# ===== Strategy 7: Check printable text in Ch0 LSB more carefully =====
print("\n[7] Deep analysis of Ch0 LSB message content...")
ch0_unsigned = ch0 & mask
ch0_bits = ch0_unsigned & 1
ch0_lsb = bits_to_bytes(ch0_bits, pack_msb=True)

# Print ALL printable content in the LSB stream
all_text = ""
for i, b in enumerate(ch0_lsb[:5000]):
    if 32 <= b <= 126:
        all_text += chr(b)
    elif all_text:
        if len(all_text) >= 4:
            print(f"  offset {i - len(all_text)}: '{all_text}'")
        all_text = ""

# ===== Strategy 8: Try different bit orders =====
print("\n[8] Bit reversal within bytes...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    
    # Extract LSB byte and reverse bit order within each byte
    lsb_bytes = (unsigned & 0xFF).astype(np.uint8)
    # Reverse bits in each byte
    reversed_bits = np.zeros_like(lsb_bytes)
    for bit in range(8):
        reversed_bits |= ((lsb_bytes >> bit) & 1) << (7 - bit)
    
    byte_data = reversed_bits.tobytes()
    f = sf(byte_data, f"ch{ch}_lsb_byte_bitrev")
    if f: all_flags.append(f)

# ===== Strategy 9: Try Baudot/ITA2 encoding =====
print("\n[9] Checking for Baudot/ITA2 encoding in LSB...")
BAUDOT_LTRS = {
    0: '\0', 1: 'E', 2: '\n', 3: 'A', 4: ' ', 5: 'S', 6: 'I', 7: 'U',
    8: '\r', 9: 'D', 10: 'R', 11: 'J', 12: 'N', 13: 'F', 14: 'C', 15: 'K',
    16: 'T', 17: 'Z', 18: 'L', 19: 'W', 20: 'H', 21: 'Y', 22: 'P', 23: 'Q',
    24: 'O', 25: 'B', 26: '', 27: '', 28: 'G', 29: '', 30: 'M', 31: 'X', 32: 'V'
}

for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask
    bits = unsigned & 1
    
    # 5 bits per character
    n_chars = len(bits) // 5
    if n_chars > 0:
        reshaped = bits[:n_chars * 5].reshape(-1, 5)
        # MSB first
        values = reshaped[:, 0] * 16 + reshaped[:, 1] * 8 + reshaped[:, 2] * 4 + reshaped[:, 3] * 2 + reshaped[:, 4]
        text = ''.join(BAUDOT_LTRS.get(int(v), '?') for v in values[:200])
        if 'ANIMUS' in text:
            print(f"  Baudot ch{ch}: {text[:100]}")

# ===== Strategy 10: Look for zlib compressed data in the LSB stream =====
print("\n[10] Scanning LSB data for zlib compressed payload...")
for ch in range(wav.channels):
    samples = wav.raw_samples[:, ch]
    mask_val = (1 << wav.bits_per_sample) - 1
    unsigned = samples & mask_val
    bits = unsigned & 1
    lsb_data = bits_to_bytes(bits, pack_msb=True)
    
    # Scan for zlib headers
    for header in [b'\x78\x9c', b'\x78\xda', b'\x78\x01']:
        pos = 0
        while True:
            idx = lsb_data.find(header, pos)
            if idx < 0:
                break
            try:
                decomp = zlib.decompress(lsb_data[idx:idx+10000])
                if len(decomp) > 4:
                    printable = bytes(b if 32 <= b <= 126 else 46 for b in decomp[:100])
                    print(f"  ch{ch} zlib at offset {idx}: {len(decomp)} bytes -> {printable.decode('ascii')}")
                    f = sf(decomp, f"ch{ch}_lsb_zlib_{idx}")
                    if f: all_flags.append(f)
            except:
                pass
            pos = idx + 1

# ===== Strategy 11: Maybe the flag requires the WaveHunter tool to fully work =====
# Check if there are any imports or features that are broken/missing
print("\n[11] Checking report.json for any flag references...")
import json
for report_file in ["sparrows_report.json", "report.json"]:
    if os.path.exists(report_file):
        with open(report_file, "r") as f:
            report = json.load(f)
        report_str = json.dumps(report)
        flags = re.findall(r'ANIMUS\{[^}]+\}', report_str)
        for flag in flags:
            print(f"  Found in {report_file}: {flag}")
            if flag not in all_flags:
                all_flags.append(flag)

import os

# ===== Summary =====
print("\n" + "=" * 60)
unique = list(set(all_flags))
if unique:
    for i, flag in enumerate(unique, 1):
        is_decoy = "decoy" in flag.lower()
        print(f"  {i}. {flag}{'  <-- DECOY' if is_decoy else '  <-- REAL FLAG!'}")
else:
    print("  No ANIMUS flags found with these approaches!")
print("=" * 60)
