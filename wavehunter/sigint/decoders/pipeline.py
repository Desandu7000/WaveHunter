from typing import List, Dict, Any, Set
import numpy as np
from wavehunter.sigint.decoders.decoder_library import (
    decode_base64,
    decode_base32,
    decode_base16,
    decode_base85,
    decode_base58,
    decode_url,
    decode_html,
    decode_rot,
    decode_caesar_all,
    decode_xor_single,
    brute_force_xor,
    decode_gray,
    decode_rc4,
    decode_vigenere
)
from wavehunter.core.entropy import shannon_entropy
from wavehunter.core.stats import compute_printable_ratio

def is_useful_stream(original: bytes, current: bytes) -> bool:
    """
    Checks if the decoded stream is valid, different from original, 
    and potentially useful for further decoding or scanning.
    """
    if not current or len(current) < 4:
        return False
    if current == original:
        return False
    
    # Exclude highly redundant blocks (e.g. all same character)
    if len(set(current)) == 1:
        return False
        
    return True

def run_decoder_pipeline(
    data: bytes, 
    max_depth: int = 3, 
    current_path: List[str] = None,
    visited_hashes: Set[int] = None,
    fast_mode: bool = False
) -> List[Dict[str, Any]]:
    """
    Recursively applies multiple decoding layers to a byte stream.
    Returns: A list of candidate dicts: {"data": bytes, "path": List[str], "entropy": float, "printable_ratio": float}
    """
    if current_path is None:
        current_path = ["raw"]
    if visited_hashes is None:
        visited_hashes = set()
        
    # Prevent circular paths and deep infinite loops
    data_hash = hash(data)
    if data_hash in visited_hashes or len(current_path) > max_depth + 1:
        return []
    visited_hashes.add(data_hash)
    
    candidates = []
    
    if not fast_mode:
        # 1. Base64
        b64 = decode_base64(data)
        if is_useful_stream(data, b64):
            candidates.append({"data": b64, "path": current_path + ["base64"]})
            
        # 2. Base32
        b32 = decode_base32(data)
        if is_useful_stream(data, b32):
            candidates.append({"data": b32, "path": current_path + ["base32"]})
            
        # 3. Base16 (Hex)
        b16 = decode_base16(data)
        if is_useful_stream(data, b16):
            candidates.append({"data": b16, "path": current_path + ["hex"]})
            
        # 4. Base85
        b85 = decode_base85(data)
        if is_useful_stream(data, b85):
            candidates.append({"data": b85, "path": current_path + ["base85"]})
            
        # 5. Base58
        b58 = decode_base58(data)
        if is_useful_stream(data, b58):
            candidates.append({"data": b58, "path": current_path + ["base58"]})
            
        # 6. URL
        url = decode_url(data)
        if is_useful_stream(data, url):
            candidates.append({"data": url, "path": current_path + ["url"]})
            
        # 7. HTML
        html_dec = decode_html(data)
        if is_useful_stream(data, html_dec):
            candidates.append({"data": html_dec, "path": current_path + ["html"]})
            
        # 8. Gray Code
        gray = decode_gray(data)
        if is_useful_stream(data, gray):
            candidates.append({"data": gray, "path": current_path + ["graycode"]})
            
        # 9. Caesar / ROT (All shifts)
        text_ratio = sum(65 <= b <= 90 or 97 <= b <= 122 for b in data) / len(data) if len(data) > 0 else 0.0
        if text_ratio > 0.3:
            for shift, rotated in decode_caesar_all(data):
                if is_useful_stream(data, rotated):
                    candidates.append({"data": rotated, "path": current_path + [f"caesar_s{shift}"]})
                    
        # 10. Single Byte XOR
        xor_candidates = brute_force_xor(data)
        for key, xored, ratio in xor_candidates[:3]:
            contains_flag = any(b"flag" in xored.lower() or b"ctf" in xored.lower() or b"animus" in xored.lower() for b in [True])
            if is_useful_stream(data, xored) and (ratio > 0.65 or contains_flag):
                candidates.append({"data": xored, "path": current_path + [f"xor_k{key}"]})


            
    # 11. Multi-byte XOR (Vigenere) and RC4 with common keys
    import hashlib
    common_keys = [b"EDEN-1499", b"EDEN1499", b"sparrows", b"sparrow", b"abstergo", b"animus", b"CELL-NINE"]
    all_keys = []
    for k in common_keys:
        all_keys.extend([k, hashlib.md5(k).digest(), hashlib.sha256(k).digest()])
        
    for k in all_keys:
        vig = decode_vigenere(data, k)
        contains_flag_vig = any(b"flag" in vig.lower() or b"ctf" in vig.lower() or b"animus" in vig.lower() for b in [True])
        if is_useful_stream(data, vig) and (compute_printable_ratio(vig) > 0.6 or contains_flag_vig):
            candidates.append({"data": vig, "path": current_path + [f"vigenere_{k.hex()[:8]}"]})
            
        rc4 = decode_rc4(data, k)
        contains_flag_rc4 = any(b"flag" in rc4.lower() or b"ctf" in rc4.lower() or b"animus" in rc4.lower() for b in [True])
        if is_useful_stream(data, rc4) and (compute_printable_ratio(rc4) > 0.6 or contains_flag_rc4):
            candidates.append({"data": rc4, "path": current_path + [f"rc4_{k.hex()[:8]}"]})

    # Process child candidates recursively
    all_results = []
    
    # Add self first if not the root raw input
    if len(current_path) > 1:
        pr = compute_printable_ratio(data)
        ent = shannon_entropy(data)
        all_results.append({
            "data": data,
            "path": current_path,
            "entropy": ent,
            "printable_ratio": pr
        })
        
    for cand in candidates:
        # Recursive step
        child_res = run_decoder_pipeline(
            cand["data"],
            max_depth=max_depth,
            current_path=cand["path"],
            visited_hashes=visited_hashes
        )
        all_results.extend(child_res)
        
        # If no deeper results, add the child itself
        if not child_res:
            pr = compute_printable_ratio(cand["data"])
            ent = shannon_entropy(cand["data"])
            all_results.append({
                "data": cand["data"],
                "path": cand["path"],
                "entropy": ent,
                "printable_ratio": pr
            })
            
    # Deduplicate results by path and data hash
    seen_paths = set()
    dedup_results = []
    for r in all_results:
        path_str = " -> ".join(r["path"])
        if path_str not in seen_paths:
            seen_paths.add(path_str)
            dedup_results.append(r)
            
    return dedup_results
