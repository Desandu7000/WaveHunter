import wave
import struct
import numpy as np
import zipfile
import io
import sys
from pathlib import Path

def generate_test_wav(output_path: str | Path):
    """
    Generates a synthetic 16-bit stereo WAV file with:
    1. A secret flag hidden in the LSB of the left channel.
    2. A ZIP archive appended to the end of the file (trailer payload).
    """
    output_path = Path(output_path)
    sample_rate = 44100
    duration = 1.0 # 1 second is enough for testing
    freq_l = 440.0 # A4 note
    freq_r = 660.0 # E5 note
    
    n_frames = int(sample_rate * duration)
    t = np.linspace(0, duration, n_frames, endpoint=False)
    
    # Generate stereo channels
    left = (np.sin(2 * np.pi * freq_l * t) * 16384).astype(np.int16)
    right = (np.sin(2 * np.pi * freq_r * t) * 16384).astype(np.int16)
    
    # Interleave left and right
    samples = np.zeros(2 * n_frames, dtype=np.int16)
    samples[0::2] = left
    samples[1::2] = right
    
    # Embed flag in Channel 0 LSB (MSB-first packing)
    flag_text = b"flag{wavehunter_lsb_steg_is_working}"
    bits = []
    for byte in flag_text:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
            
    # Embed bits into left channel LSB (even indices)
    for idx, bit in enumerate(bits):
        sample_idx = idx * 2
        if sample_idx < len(samples):
            # Mask out bit 0 and insert flag bit
            samples[sample_idx] = (samples[sample_idx] & ~1) | bit
            
    # Write WAV file to memory buffer
    wav_buf = io.BytesIO()
    with wave.open(wav_buf, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        w.writeframes(samples.tobytes())
        
    wav_bytes = wav_buf.getvalue()
    
    # Create a small zip file to append (trailer)
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("secret.txt", "Congratulations! You found the hidden trailer zip file.")
    zip_bytes = zip_buf.getvalue()
    
    # Append zip bytes
    full_bytes = wav_bytes + zip_bytes
    
    output_path.write_bytes(full_bytes)
    print(f"Generated test WAV file at: {output_path}")
    print(f"WAV size: {len(wav_bytes)} bytes | Zip size: {len(zip_bytes)} bytes | Total: {len(full_bytes)} bytes")

if __name__ == "__main__":
    out_file = "test.wav"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    generate_test_wav(out_file)
