import base64
import urllib.parse
import html
from typing import Dict, Any, List, Tuple

def decode_base64(data: bytes) -> bytes:
    """Decodes Base64 encoded byte stream."""
    try:
        # Clean data from non-b64 characters
        clean = bytes([b for b in data if (b'A' <= bytes([b]) <= b'Z' or 
                                          b'a' <= bytes([b]) <= b'z' or 
                                          b'0' <= bytes([b]) <= b'9' or 
                                          b in b'+/=')])
        # Add padding if needed
        padding = (4 - len(clean) % 4) % 4
        clean += b'=' * padding
        return base64.b64decode(clean)
    except Exception:
        return b""

def decode_base32(data: bytes) -> bytes:
    """Decodes Base32 encoded byte stream."""
    try:
        clean = bytes([b for b in data if (b'A' <= bytes([b]) <= b'Z' or 
                                          b'2' <= bytes([b]) <= b'7' or 
                                          b == ord('='))])
        padding = (8 - len(clean) % 8) % 8
        clean += b'=' * padding
        return base64.b32decode(clean, casefold=True)
    except Exception:
        return b""

def decode_base16(data: bytes) -> bytes:
    """Decodes Base16 (Hex) encoded byte stream."""
    try:
        clean = bytes([b for b in data if (b'A' <= bytes([b]) <= b'F' or 
                                          b'a' <= bytes([b]) <= b'f' or 
                                          b'0' <= bytes([b]) <= b'9')])
        if len(clean) % 2 != 0:
            clean = clean[:-1]
        return base64.b16decode(clean, casefold=True)
    except Exception:
        return b""

def decode_base85(data: bytes) -> bytes:
    """Decodes Base85/Ascii85 encoded byte stream."""
    try:
        return base64.b85decode(data)
    except Exception:
        try:
            return base64.a85decode(data)
        except Exception:
            return b""

# Base58 Alphabet
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def decode_base58(data: bytes) -> bytes:
    """Decodes Base58 encoded byte stream."""
    try:
        # Strip whitespace/newlines
        clean = [b for b in data if b in B58_ALPHABET]
        if not clean:
            return b""
            
        # Convert base58 digits to a big int
        val = 0
        for b in clean:
            val = val * 58 + B58_ALPHABET.index(b)
            
        # Convert big int back to bytes
        res = bytearray()
        while val > 0:
            res.append(val & 0xFF)
            val >>= 8
            
        # Add leading zeros matching leading '1's
        for b in clean:
            if b == ord('1'):
                res.append(0)
            else:
                break
                
        return bytes(reversed(res))
    except Exception:
        return b""

def decode_url(data: bytes) -> bytes:
    """Decodes URL-encoded byte stream."""
    try:
        decoded_str = urllib.parse.unquote_to_bytes(data)
        return decoded_str
    except Exception:
        return b""

def decode_html(data: bytes) -> bytes:
    """Decodes HTML entity encoded byte stream."""
    try:
        text = data.decode("utf-8", errors="ignore")
        decoded_text = html.unescape(text)
        return decoded_text.encode("utf-8")
    except Exception:
        return b""

def decode_rot(data: bytes, shift: int) -> bytes:
    """Decodes ROT/Caesar shifted byte stream (ASCII letters only)."""
    res = bytearray()
    for b in data:
        if 65 <= b <= 90:  # A-Z
            res.append((b - 65 + shift) % 26 + 65)
        elif 97 <= b <= 122:  # a-z
            res.append((b - 97 + shift) % 26 + 97)
        else:
            res.append(b)
    return bytes(res)

def decode_caesar_all(data: bytes) -> List[Tuple[int, bytes]]:
    """Generates all 25 possible Caesar shifts."""
    return [(shift, decode_rot(data, shift)) for shift in range(1, 26)]

def decode_xor_single(data: bytes, key: int) -> bytes:
    """Performs single-byte XOR decryption."""
    return bytes([b ^ key for b in data])

def brute_force_xor(data: bytes) -> List[Tuple[int, bytes, float]]:
    """
    Brute-forces single-byte XOR and returns candidates ranked by their 
    printable character ratio.
    """
    results = []
    if len(data) == 0:
        return []
        
    for key in range(256):
        decrypted = decode_xor_single(data, key)
        # Compute printable ratio
        printable = sum(32 <= b <= 126 or b in [9, 10, 13] for b in decrypted)
        ratio = printable / len(decrypted)
        results.append((key, decrypted, ratio))
        
    # Sort by printable ratio descending
    results.sort(key=lambda x: -x[2])
    return results

def decode_gray(data: bytes) -> bytes:
    """
    Converts Gray-coded byte stream back to binary.
    """
    # For each byte, convert Gray to binary
    res = bytearray()
    for b in data:
        # Standard Gray-to-binary loop for 8-bit values
        mask = b >> 1
        val = b
        while mask != 0:
            val ^= mask
            mask >>= 1
        res.append(val)
    return bytes(res)

def decode_rc4(data: bytes, key: bytes) -> bytes:
    """Decodes RC4 encrypted byte stream."""
    try:
        from Crypto.Cipher import ARC4
        return ARC4.new(key).decrypt(data)
    except Exception:
        return b""

def decode_vigenere(data: bytes, key: bytes) -> bytes:
    """Decodes Vigenere (XOR) encrypted byte stream."""
    try:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    except Exception:
        return b""

