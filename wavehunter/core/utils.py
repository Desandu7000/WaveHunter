import numpy as np
from typing import Union, List

def format_bytes(n_bytes: int) -> str:
    """
    Formats byte size to human readable representation.
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n_bytes < 1024.0:
            return f"{n_bytes:.2f} {unit}" if unit != "B" else f"{n_bytes} B"
        n_bytes /= 1024.0
    return f"{n_bytes:.2f} PB"

def hexdump(data: bytes, limit: int = 128) -> str:
    """
    Generates a standard formatted hex dump string for visual feedback.
    """
    lines = []
    length = len(data)
    truncated = length > limit
    display_len = min(length, limit)
    
    for i in range(0, display_len, 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        if len(chunk) < 16:
            hex_str += " " * (3 * (16 - len(chunk)))
        
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_str[:23]}  {hex_str[24:]}  |{ascii_str}|")
        
    if truncated:
        lines.append(f"... (truncated, total size: {format_bytes(length)})")
        
    return "\n".join(lines)

def bits_to_bytes(bits: Union[List[int], np.ndarray], pack_msb: bool = True) -> bytes:
    """
    Converts an array/list of binary bits (0 or 1) into packed bytes.
    - pack_msb: If True, the first bit becomes the MSB (bit 7) of the byte (Standard LSB Stego ordering).
                If False, the first bit becomes the LSB (bit 0) of the byte.
    """
    arr = np.asarray(bits, dtype=np.uint8).flatten()
    n_bits = len(arr)
    n_bytes = n_bits // 8
    
    if n_bytes == 0:
        return b""
        
    # Truncate to multiple of 8
    bits_truncated = arr[:n_bytes * 8].reshape(-1, 8)
    
    if pack_msb:
        weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)
    else:
        weights = np.array([1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint8)
        
    byte_values = np.sum(bits_truncated * weights, axis=1).astype(np.uint8)
    return byte_values.tobytes()
