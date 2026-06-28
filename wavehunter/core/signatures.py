from typing import Dict, Any, List, Optional

SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "ZIP Archive",
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "extension": "zip",
        "min_size": 22
    },
    {
        "name": "PNG Image",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xae\x42\x60\x82",
        "extension": "png",
        "min_size": 12
    },
    {
        "name": "JPEG Image",
        "header": b"\xff\xd8\xff",
        "footer": b"\xff\xd9",
        "extension": "jpg",
        "min_size": 10
    },
    {
        "name": "ELF Executable",
        "header": b"\x7fELF",
        "footer": None,
        "extension": "elf",
        "min_size": 64
    },
    {
        "name": "Windows PE Executable",
        "header": b"MZ",
        "footer": None,
        "extension": "exe",
        "min_size": 64
    },
    {
        "name": "PDF Document",
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "extension": "pdf",
        "min_size": 20
    },
    {
        "name": "GZIP Archive",
        "header": b"\x1f\x8b\x08",
        "footer": None,
        "extension": "gz",
        "min_size": 18
    },
    {
        "name": "BZIP2 Archive",
        "header": b"BZh",
        "footer": None,
        "extension": "bz2",
        "min_size": 14
    },
    {
        "name": "7-Zip Archive",
        "header": b"7z\xbc\xaf\x27\x1c",
        "footer": None,
        "extension": "7z",
        "min_size": 32
    },
    {
        "name": "GIF Image",
        "header": b"GIF89a",
        "footer": b"\x00\x3b",
        "extension": "gif",
        "min_size": 14
    },
    {
        "name": "GIF Image (Alt)",
        "header": b"GIF87a",
        "footer": b"\x00\x3b",
        "extension": "gif",
        "min_size": 14
    },
    {
        "name": "RAR Archive",
        "header": b"Rar!\x1a\x07\x00",
        "footer": None,
        "extension": "rar",
        "min_size": 20
    },
    {
        "name": "RAR Archive (v5)",
        "header": b"Rar!\x1a\x07\x01\x00",
        "footer": None,
        "extension": "rar",
        "min_size": 20
    },
    {
        "name": "SQLite Database",
        "header": b"SQLite format 3\x00",
        "footer": None,
        "extension": "sqlite",
        "min_size": 100
    },
    {
        "name": "WAV Audio",
        "header": b"RIFF",
        "footer": None,
        "extension": "wav",
        "min_size": 44,
        "header_check": lambda d, idx: idx + 12 <= len(d) and d[idx + 8 : idx + 12] == b"WAVE",
    },
    {
        "name": "BMP Image",
        "header": b"BM",
        "footer": None,
        "extension": "bmp",
        "min_size": 54,
    },
    {
        "name": "MP3 Audio (ID3)",
        "header": b"ID3",
        "footer": None,
        "extension": "mp3",
        "min_size": 10,
    },
    {
        "name": "MP3 Audio (MPEG sync)",
        "header": b"\xff\xfb",
        "footer": None,
        "extension": "mp3",
        "min_size": 4,
    },
    {
        "name": "OGG Audio",
        "header": b"OggS",
        "footer": None,
        "extension": "ogg",
        "min_size": 27,
    },
]

def find_signatures(data: bytes) -> List[Dict[str, Any]]:
    """
    Scans the given byte array for known file headers and footers.
    Returns details of detected signatures.
    """
    matches = []
    data_len = len(data)
    
    for sig in SIGNATURES:
        header = sig["header"]
        footer = sig["footer"]
        
        # Find all header offsets
        start = 0
        while True:
            idx = data.find(header, start)
            if idx == -1:
                break

            header_check = sig.get("header_check")
            if header_check is not None and not header_check(data, idx):
                start = idx + 1
                continue

            match_info = {
                "name": sig["name"],
                "extension": sig["extension"],
                "start_offset": idx,
                "end_offset": None,
                "estimated_size": None,
                "confidence": "medium"
            }
            
            # If footer exists, find the nearest footer after this header
            if footer:
                f_idx = data.find(footer, idx + len(header))
                if f_idx != -1:
                    match_info["end_offset"] = f_idx + len(footer)
                    match_info["estimated_size"] = match_info["end_offset"] - idx
                    match_info["confidence"] = "high"
            
            # Filter matches that are too small
            if match_info["estimated_size"] is None or match_info["estimated_size"] >= sig["min_size"]:
                matches.append(match_info)
                
            start = idx + 1
            
    # Sort matches by start_offset
    matches.sort(key=lambda x: x["start_offset"])
    return matches
