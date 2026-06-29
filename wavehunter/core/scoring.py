from typing import List, Dict, Any
from wavehunter.core.entropy import shannon_entropy
from wavehunter.scanners.ascii import scan_ascii
from wavehunter.scanners.regex import scan_regex
from wavehunter.scanners.magic import scan_magic
from wavehunter.scanners.compression import scan_compression
from wavehunter.core.utils import format_bytes
from wavehunter.core.validation import validate_embedded_file
from wavehunter.core.stats import compute_printable_ratio


def _fast_prefilter(data: bytes) -> bool:
    """
    Cheap pre-filter to decide if a candidate stream is worth full scoring.

    Returns True if the candidate passes (worth scoring), False if it's almost certainly noise.
    Avoids running heavy regex, magic, and ASCII scanners on thousands of noise streams by only
    inspecting entropy and a quick 512-byte preview scan.
    """
    if not data or len(data) < 4:
        return False

    # Quick entropy check: if entropy is mid-range, content may be structured
    ent = shannon_entropy(data)

    # Very high entropy (>= 7.95) -> possible encrypted/random data
    if ent >= 7.95:
        return True

    # Very low entropy (< 0.5) -> constant/padding stream -> skip
    if ent < 0.5:
        return False

    # Quick printable check on first 512 bytes only (cheap)
    preview = data[:512]
    printable_count = sum(1 for b in preview if 32 <= b <= 126)
    if printable_count / len(preview) >= 0.1:
        return True

    # Quick regex scan on first 512 bytes (catches flags early)
    quick_matches = scan_regex(preview)
    if quick_matches:
        return True

    return False


def score_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes a candidate byte stream using all scanners, computes entropy,
    and assigns a rating from 1 to 5 stars.
    """
    data = candidate["data"]
    name = candidate["name"]
    source = candidate["source"]
    
    if not data or len(data) < 4:
        return {
            **candidate,
            "rating": 1,
            "stars": "★☆☆☆☆",
            "reason": "Empty or too small",
            "matches": []
        }

    # 1. Calculate entropy
    entropy = shannon_entropy(data)
    printable_ratio = compute_printable_ratio(data)
    
    # 2. Run scanners
    magic_matches = scan_magic(data)
    regex_matches = scan_regex(data)
    compression_matches = scan_compression(data)
    ascii_matches = scan_ascii(data, min_len=6)
    
    # 3. Determine rating & reason
    rating = 1
    reason = "Low confidence candidate (noise)"
    findings = []
    
    # Check for direct flags
    flags = [m for m in regex_matches if m["type"] == "Flag"]
    if flags:
        rating = 5
        reason = f"Flag found: '{flags[0]['value']}'"
        for f in flags:
            findings.append(f"Flag: {f['value']}")
            
    # Check for embedded files with active parser validation
    elif magic_matches:
        best_magic = magic_matches[0]
        carved = data[best_magic["start_offset"]:]
        if best_magic["end_offset"] is not None:
            carved = data[best_magic["start_offset"]:best_magic["end_offset"]]
            
        is_valid, validation_detail = validate_embedded_file(carved, best_magic["name"])
        
        if is_valid:
            if best_magic["confidence"] == "high":
                rating = 5
                size_str = format_bytes(best_magic["estimated_size"]) if best_magic["estimated_size"] else "unknown size"
                reason = f"Verified embedded file: {best_magic['name']} ({size_str}) — {validation_detail}"
            else:
                rating = 4
                reason = f"Verified potential embedded file: {best_magic['name']} at offset {best_magic['start_offset']} — {validation_detail}"
        else:
            rating = 2
            reason = f"False positive: magic header for {best_magic['name']} rejected by parser ({validation_detail})"
            
        for m in magic_matches:
            findings.append(f"Magic Signature: {m['name']} at offset {m['start_offset']} (Validated: {is_valid})")
            
    # Check for compressed streams
    elif compression_matches:
        best_comp = compression_matches[0]
        rating = 4
        comp_size = format_bytes(best_comp["compressed_size"])
        decomp_size = format_bytes(best_comp["decompressed_size"])
        reason = f"Compressed stream ({best_comp['type']}) found. Size: {comp_size} -> Decompressed: {decomp_size}"
        
        decomp_flags = scan_regex(best_comp["decompressed_data"])
        decomp_flags = [m for m in decomp_flags if m["type"] == "Flag"]
        if decomp_flags:
            rating = 5
            reason = f"Flag found in decompressed stream: '{decomp_flags[0]['value']}'"
            findings.append(f"Decompressed Flag: {decomp_flags[0]['value']}")
            
        for c in compression_matches:
            findings.append(f"Compression ({c['type']}): offset {c['offset']}, size {format_bytes(c['compressed_size'])}")

    # Check for other regex matches (URLs, IPs, Emails, Hashes)
    elif regex_matches:
        non_flag_regexes = [m for m in regex_matches if m["type"] != "Flag"]
        if non_flag_regexes:
            rating = 3
            reason = f"Found matches for {non_flag_regexes[0]['type']}: '{non_flag_regexes[0]['value']}'"
            for r in non_flag_regexes:
                findings.append(f"Regex ({r['type']}): {r['value']}")

    # Check for ASCII density and structured text
    else:
        total_ascii_len = sum(len(m["text"]) for m in ascii_matches)
        ascii_ratio = total_ascii_len / len(data) if len(data) > 0 else 0
        
        if ascii_ratio >= 0.25 and len(data) >= 32:
            rating = 3
            reason = f"High density printable text: {ascii_ratio*100:.1f}% of stream"
            findings.append(f"ASCII density: {ascii_ratio*100:.1f}%")
        elif printable_ratio >= 0.15 and len(data) >= 64:
            rating = 3
            reason = f"Structured printable content: {printable_ratio*100:.1f}% printable bytes"
            findings.append(f"Printable ratio: {printable_ratio*100:.1f}%")
        elif len(ascii_matches) > 0:
            rating = 2
            reason = f"Contains printable strings (e.g. '{ascii_matches[0]['text'][:30]}...')"
            findings.append(f"Printable strings count: {len(ascii_matches)}")
        elif 7.95 <= entropy <= 8.0:
            rating = 2
            reason = f"Anomalous high entropy ({entropy:.4f}), potential encrypted/random payload"
            findings.append(f"Anomalous entropy: {entropy:.4f}")
            
    stars_map = {
        1: "★☆☆☆☆",
        2: "★★☆☆☆",
        3: "★★★☆☆",
        4: "★★★★☆",
        5: "★★★★★"
    }
    
    preview = data[:64]
    
    return {
        "name": name,
        "source": source,
        "size": len(data),
        "entropy": entropy,
        "printable_ratio": printable_ratio,
        "rating": rating,
        "stars": stars_map[rating],
        "reason": reason,
        "findings": findings,
        "magic_count": len(magic_matches),
        "regex_count": len(regex_matches),
        "ascii_count": len(ascii_matches),
        "comp_count": len(compression_matches),
        "preview_hex": " ".join(f"{b:02x}" for b in preview),
        "preview_ascii": "".join(chr(b) if 32 <= b <= 126 else "." for b in preview)
    }


def rank_candidates(candidates: List[Dict[str, Any]], thorough: bool = False) -> List[Dict[str, Any]]:
    """
    Scores all candidates, filters out uninteresting ones (rating 1 with low entropy),
    and sorts them so the highest rated candidates appear first.

    In default (fast) mode, a cheap pre-filter is applied before full scoring to skip
    obvious noise streams. Pass thorough=True to score every candidate fully.
    """
    scored = []
    for c in candidates:
        # Always score trailer payloads fully — they are always worth inspecting
        is_trailer = "trailer" in c.get("source", "")
        if not thorough and not is_trailer:
            # Fast pre-filter: skip candidates that are clearly noise
            if not _fast_prefilter(c.get("data", b"")):
                continue

        res = score_candidate(c)
        if res["rating"] > 1 or res["entropy"] > 7.5 or is_trailer:
            scored.append(res)
            
    scored.sort(key=lambda x: (-x["rating"], -x["entropy"]))
    return scored
