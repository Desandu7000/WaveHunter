import numpy as np
from typing import Dict, Any, List
from wavehunter.core.utils import bits_to_bytes

def extract_bitplane(raw_samples: np.ndarray, 
                     bits_per_sample: int, 
                     channel: int, 
                     bit_position: int, 
                     pack_msb: bool = True) -> bytes:
    """
    Extracts the bit at bit_position from the specified channel of raw_samples.
    Packs the bits into bytes.
    
    Steganography often hides data in the Least Significant Bits (LSB, bit_position=0) 
    of audio samples. This function extracts that bit layer across all samples and packs 
    8 consecutive bits into a single byte.
    
    - pack_msb: If True, the first sample's bit is placed in the MSB (bit 7) of the output byte (standard big-endian bit packing).
                If False, the first sample's bit is placed in the LSB (bit 0) of the output byte (little-endian bit packing).
    """
    if channel >= raw_samples.shape[1]:
        raise ValueError(f"Channel index {channel} out of range (total channels: {raw_samples.shape[1]})")
        
    if bit_position >= bits_per_sample:
        raise ValueError(f"Bit position {bit_position} exceeds bits per sample ({bits_per_sample})")

    # Extract the channel samples
    samples = raw_samples[:, channel]
    
    # Mask to treat them as unsigned based on the bit depth
    mask = (1 << bits_per_sample) - 1
    unsigned_samples = samples & mask
    
    # Extract the specific bit
    bits = (unsigned_samples >> bit_position) & 1
    
    # Convert bits to packed bytes
    return bits_to_bytes(bits, pack_msb=pack_msb)

def extract_all_bitplanes(raw_samples: np.ndarray, 
                          bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts all bitplanes for all channels, returning both MSB and LSB packed versions.
    Yields list of candidate dicts.
    
    Loops through all channels and low-order bitplanes (bits 0 to 4), extracting both 
    MSB-packed and LSB-packed variants. Higher bitplanes (above bit 4) are typically 
    skipped as hiding data in those layers causes audible distortion (white noise).
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    # Typically only LSB bitplanes are interesting (e.g. bit 0, 1, 2)
    # But for completeness, we check bits from 0 to 4 (as higher bitplanes rarely have hidden info without sounding terrible)
    max_bit = min(bits_per_sample, 8)
    
    for ch in range(n_channels):
        for bit in range(max_bit):
            for msb in [True, False]:
                data = extract_bitplane(raw_samples, bits_per_sample, ch, bit, pack_msb=msb)
                if len(data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} Bit {bit} ({'MSB' if msb else 'LSB'} packed)",
                        "source": f"bitplane_ch{ch}_b{bit}_{'msb' if msb else 'lsb'}",
                        "data": data
                    })
    return candidates
