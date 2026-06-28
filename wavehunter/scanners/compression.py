import zlib
import gzip
from typing import List, Dict, Any

def scan_compression(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans a byte array for compressed data streams (zlib / gzip) by searching for
    common headers and trying to decompress them.
    """
    matches = []
    data_len = len(data)
    
    # Common headers:
    # zlib: 78 01 (no/low compression), 78 9c (default compression), 78 da (best compression)
    # gzip: 1f 8b
    headers = [
        (b"\x78\x9c", "zlib"),
        (b"\x78\xda", "zlib"),
        (b"\x78\x01", "zlib"),
        (b"\x1f\x8b", "gzip")
    ]
    
    for header, comp_type in headers:
        start = 0
        while True:
            offset = data.find(header, start)
            if offset == -1:
                break
                
            # Attempt decompression from this offset
            try:
                if comp_type == "zlib":
                    dobj = zlib.decompressobj()
                    decompressed = dobj.decompress(data[offset:])
                    compressed_len = len(data[offset:]) - len(dobj.unused_data)
                else:  # gzip
                    # Gzip is basically zlib with 16 added to MAX_WBITS
                    dobj = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
                    decompressed = dobj.decompress(data[offset:])
                    compressed_len = len(data[offset:]) - len(dobj.unused_data)
                
                # Check if we got meaningful decompressed output
                if len(decompressed) >= 4:
                    matches.append({
                        "offset": offset,
                        "type": comp_type,
                        "compressed_size": compressed_len,
                        "decompressed_size": len(decompressed),
                        "decompressed_preview": decompressed[:128],
                        "decompressed_data": decompressed
                    })
            except Exception:
                pass
                
            start = offset + 1
            
    # Filter overlapping matches: if one compressed stream is contained inside another, keep the first one
    matches.sort(key=lambda x: x["offset"])
    filtered = []
    last_end = -1
    for m in matches:
        if m["offset"] >= last_end:
            filtered.append(m)
            last_end = m["offset"] + m["compressed_size"]
            
    return filtered
