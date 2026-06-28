import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes
from wavehunter.extractors.graycode import gray_to_binary
from wavehunter.extractors.delta import delta_decode
from wavehunter.extractors.interleave import pack_to_bytes

def extract_multibit_bitplanes(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts all bitplanes from 0 to 15 for all channels.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    # We scan all bitplanes up to bits_per_sample
    max_bit = min(bits_per_sample, 16)
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        mask_val = (1 << bits_per_sample) - 1
        unsigned_samples = samples & mask_val
        
        for bit in range(max_bit):
            bits = (unsigned_samples >> bit) & 1
            for msb in [True, False]:
                b_data = bits_to_bytes(bits, pack_msb=msb)
                if len(b_data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} Bitplane {bit} ({'MSB' if msb else 'LSB'} packed)",
                        "source": f"multi_bitplane_ch{ch}_b{bit}_{'msb' if msb else 'lsb'}",
                        "data": b_data
                    })
    return candidates

def extract_nibbles(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts 4-bit nibbles from the samples and packs them (2 nibbles per byte).
    Supports packing bits 0-3 (LSB nibble) or other positions.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    # We check bits 0-3 (LSB nibble) and bits 4-7 (next nibble)
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        mask_val = (1 << bits_per_sample) - 1
        unsigned = samples & mask_val
        
        # LSB Nibble (bits 0-3)
        nibbles_lsb = unsigned & 0x0F
        # Pack two nibbles per byte: (n1 << 4) | n2
        # Support both packing orders: first nibble in high part or low part
        n_bytes = len(nibbles_lsb) // 2
        if n_bytes > 0:
            n1 = nibbles_lsb[0::2][:n_bytes]
            n2 = nibbles_lsb[1::2][:n_bytes]
            
            # Pack order 1: n1 high, n2 low
            pack1 = ((n1 << 4) | n2).astype(np.uint8).tobytes()
            candidates.append({
                "name": f"Channel {ch} LSB Nibble (0-3) Pack1",
                "source": f"multi_nibble_ch{ch}_b0_3_p1",
                "data": pack1
            })
            
            # Pack order 2: n2 high, n1 low
            pack2 = ((n2 << 4) | n1).astype(np.uint8).tobytes()
            candidates.append({
                "name": f"Channel {ch} LSB Nibble (0-3) Pack2",
                "source": f"multi_nibble_ch{ch}_b0_3_p2",
                "data": pack2
            })

        # Upper nibble (bits 4-7) for 8+ bit samples
        if bits_per_sample >= 8:
            nibbles_hi = (unsigned >> 4) & 0x0F
            n_bytes_hi = len(nibbles_hi) // 2
            if n_bytes_hi > 0:
                h1 = nibbles_hi[0::2][:n_bytes_hi]
                h2 = nibbles_hi[1::2][:n_bytes_hi]
                pack_hi1 = ((h1 << 4) | h2).astype(np.uint8).tobytes()
                candidates.append({
                    "name": f"Channel {ch} Upper Nibble (4-7) Pack1",
                    "source": f"multi_nibble_ch{ch}_b4_7_p1",
                    "data": pack_hi1
                })
                pack_hi2 = ((h2 << 4) | h1).astype(np.uint8).tobytes()
                candidates.append({
                    "name": f"Channel {ch} Upper Nibble (4-7) Pack2",
                    "source": f"multi_nibble_ch{ch}_b4_7_p2",
                    "data": pack_hi2
                })
            
    return candidates

def extract_reconstructed_bytes(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Extracts 8-bit bytes directly from sample bit ranges (e.g. bits 0-7, or 8-15) and packs them.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        mask_val = (1 << bits_per_sample) - 1
        unsigned = samples & mask_val
        
        # 1. Bits 0-7 (LSB Byte)
        bytes_lsb = (unsigned & 0xFF).astype(np.uint8).tobytes()
        candidates.append({
            "name": f"Channel {ch} LSB Byte (0-7) Stream",
            "source": f"multi_byte_ch{ch}_b0_7",
            "data": bytes_lsb
        })
        
        # 2. Bits 8-15 (MSB Byte for 16-bit)
        if bits_per_sample >= 16:
            bytes_msb = ((unsigned >> 8) & 0xFF).astype(np.uint8).tobytes()
            candidates.append({
                "name": f"Channel {ch} MSB Byte (8-15) Stream",
                "source": f"multi_byte_ch{ch}_b8_15",
                "data": bytes_msb
            })
            
    return candidates

def extract_multibit_transforms(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Applies Gray-code and Delta-decoding directly to the sample values, then extracts
    reconstructed LSB byte streams to catch layered steganography.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    
    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        
        # 1. Gray-decoded -> LSB Byte
        gray_decoded = gray_to_binary(samples, bits_per_sample)
        candidates.append({
            "name": f"Channel {ch} Gray-Decoded LSB Byte",
            "source": f"multi_gray_byte_ch{ch}",
            "data": (gray_decoded & 0xFF).astype(np.uint8).tobytes()
        })
        
        # 2. Delta-decoded -> LSB Byte
        delta_decoded = delta_decode(samples, bits_per_sample)
        candidates.append({
            "name": f"Channel {ch} Delta-Decoded LSB Byte",
            "source": f"multi_delta_byte_ch{ch}",
            "data": (delta_decoded & 0xFF).astype(np.uint8).tobytes()
        })
        
    return candidates

def extract_bit_inverted_streams(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Inverts all sample bits, then extracts LSB byte streams and bitplane 0.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    mask_val = (1 << bits_per_sample) - 1

    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        inverted = (~samples) & mask_val

        bytes_lsb = (inverted & 0xFF).astype(np.uint8).tobytes()
        candidates.append({
            "name": f"Channel {ch} Bit-Inverted LSB Byte",
            "source": f"multi_inverted_byte_ch{ch}",
            "data": bytes_lsb,
        })

        bits = inverted & 1
        for msb in (True, False):
            b_data = bits_to_bytes(bits, pack_msb=msb)
            if len(b_data) >= 8:
                candidates.append({
                    "name": f"Channel {ch} Bit-Inverted Plane 0 ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"multi_inverted_b0_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": b_data,
                })

    return candidates


def extract_combined_bitplanes(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """
    Combines multiple bitplanes via OR/XOR and packs the result as bytes.
    """
    candidates = []
    n_channels = raw_samples.shape[1]
    max_bit = min(bits_per_sample, 8)

    for ch in range(n_channels):
        samples = raw_samples[:, ch]
        mask_val = (1 << bits_per_sample) - 1
        unsigned = samples & mask_val

        planes = [(unsigned >> b) & 1 for b in range(max_bit)]

        if len(planes) >= 2:
            or_bits = planes[0].copy()
            xor_bits = planes[0].copy()
            for p in planes[1:]:
                or_bits = or_bits | p
                xor_bits = xor_bits ^ p

            for label, bits, op in (
                ("OR bits 0-3", or_bits if max_bit <= 4 else None, "or03"),
                ("XOR bits 0-3", xor_bits if max_bit <= 4 else None, "xor03"),
            ):
                if bits is None:
                    # Recompute for bits 0-3 only
                    or03 = planes[0] | planes[1] | planes[2] | planes[3]
                    xor03 = planes[0] ^ planes[1] ^ planes[2] ^ planes[3]
                    bits = or03 if "OR" in label else xor03
                    op = "or03" if "OR" in label else "xor03"

                for msb in (True, False):
                    b_data = bits_to_bytes(bits, pack_msb=msb)
                    if len(b_data) >= 1:
                        candidates.append({
                            "name": f"Channel {ch} Combined {label} ({'MSB' if msb else 'LSB'} packed)",
                            "source": f"multi_combined_{op}_ch{ch}_{'msb' if msb else 'lsb'}",
                            "data": b_data,
                        })

    return candidates


def extract_sign_bit_streams(raw_samples: np.ndarray, bits_per_sample: int) -> List[Dict[str, Any]]:
    """Extracts the sign bit (MSB) of each sample as a packed bitstream."""
    candidates = []
    sign_bit = bits_per_sample - 1

    for ch in range(raw_samples.shape[1]):
        samples = raw_samples[:, ch]
        mask_val = (1 << bits_per_sample) - 1
        bits = (samples & mask_val) >> sign_bit

        for msb in (True, False):
            b_data = bits_to_bytes(bits, pack_msb=msb)
            if len(b_data) >= 1:
                candidates.append({
                    "name": f"Channel {ch} Sign Bit ({'MSB' if msb else 'LSB'} packed)",
                    "source": f"multi_sign_bit_ch{ch}_{'msb' if msb else 'lsb'}",
                    "data": b_data,
                })

    return candidates
