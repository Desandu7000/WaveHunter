"""
Active parser validation for embedded file candidates.
Magic-byte matches alone are not trusted — each format is verified structurally.
"""
from __future__ import annotations

import gzip
import struct
import zipfile
from typing import Tuple


def validate_embedded_file(data: bytes, file_type: str) -> Tuple[bool, str]:
    """
    Parse and validate a candidate byte stream for the given file type.
    Returns (is_valid, detail_message).
    """
    if not data or len(data) < 4:
        return False, "Empty or too small"

    name = file_type.upper()

    try:
        if "GZIP" in name:
            return _validate_gzip(data)
        if "BZIP" in name:
            return _validate_bzip2(data)
        if "7-ZIP" in name or "7Z" in name:
            return _validate_7z(data)
        if "ZIP" in name:
            return _validate_zip(data)
        if "PNG" in name:
            return _validate_png(data)
        if "JPEG" in name or "JPG" in name:
            return _validate_jpeg(data)
        if "GIF" in name:
            return _validate_gif(data)
        if "PDF" in name:
            return _validate_pdf(data)
        if "ELF" in name:
            return _validate_elf(data)
        if "PE" in name or "MZ" in name:
            return _validate_pe(data)
        if "SQLITE" in name:
            return _validate_sqlite(data)
        if "WAV" in name or "RIFF" in name:
            return _validate_wav(data)
        if "BMP" in name:
            return _validate_bmp(data)
        if "MP3" in name:
            return _validate_mp3(data)
        if "OGG" in name:
            return _validate_ogg(data)
        if "RAR" in name:
            return _validate_rar(data)
    except Exception as exc:
        return False, f"Parser error: {exc}"

    return False, f"No validator for {file_type}"


def validate_candidate_file(data: bytes, file_type: str) -> bool:
    """Backward-compatible boolean wrapper."""
    valid, _ = validate_embedded_file(data, file_type)
    return valid


def _validate_zip(data: bytes) -> Tuple[bool, str]:
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return False, "zipfile rejected structure"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        if not names:
            return False, "ZIP has no entries"
        # Attempt to read central directory without extracting
        bad = zf.testzip()
        if bad is not None:
            return False, f"CRC failure in entry: {bad}"
    return True, f"Valid ZIP ({len(names)} entries)"


def _validate_png(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False, "Missing PNG signature"
    if b"IEND" not in data:
        return False, "Missing IEND chunk"
    # Verify IHDR chunk immediately after signature
    if len(data) < 24 or data[12:16] != b"IHDR":
        return False, "Missing IHDR chunk"
    length = struct.unpack(">I", data[8:12])[0]
    if length != 13:
        return False, f"Invalid IHDR length ({length})"
    return True, "Valid PNG structure"


def _validate_jpeg(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\xff\xd8"):
        return False, "Missing SOI marker"
    if b"\xff\xd9" not in data:
        return False, "Missing EOI marker"
    # Walk markers — reject if no valid APP/SOF marker after SOI
    i = 2
    found_frame = False
    while i < len(data) - 1:
        if data[i] != 0xFF:
            return False, "Invalid marker alignment"
        marker = data[i + 1]
        if marker == 0xD9:
            break
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            found_frame = True
        if marker == 0xD8:
            return False, "Nested SOI marker"
        if marker == 0x00 or (0xD0 <= marker <= 0xD7):
            i += 2
            continue
        if i + 3 >= len(data):
            break
        seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
        if seg_len < 2:
            return False, f"Invalid segment length at 0x{i:x}"
        i += 2 + seg_len
    if not found_frame:
        return False, "No SOF frame marker found"
    return True, "Valid JPEG marker structure"


def _validate_gif(data: bytes) -> Tuple[bool, str]:
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return False, "Missing GIF header"
    if len(data) < 13:
        return False, "Truncated GIF header"
    if data[-1:] != b"\x3b":
        return False, "Missing GIF trailer (0x3B)"
    return True, "Valid GIF structure"


def _validate_pdf(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"%PDF-"):
        return False, "Missing PDF header"
    if b"%%EOF" not in data[-1024:] and b"%%EOF" not in data:
        return False, "Missing %%EOF trailer"
    return True, "Valid PDF structure"


def _validate_gzip(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x1f\x8b"):
        return False, "Missing GZIP header"
    try:
        decompressed = gzip.decompress(data)
    except Exception as exc:
        return False, f"gzip decompress failed: {exc}"
    return True, f"Valid GZIP ({len(decompressed)} bytes decompressed)"


def _validate_bzip2(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"BZh"):
        return False, "Missing BZIP2 header"
    import bz2

    try:
        decompressed = bz2.decompress(data)
    except Exception as exc:
        return False, f"bzip2 decompress failed: {exc}"
    return True, f"Valid BZIP2 ({len(decompressed)} bytes decompressed)"


def _validate_7z(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return False, "Missing 7z signature"
    if len(data) < 32:
        return False, "Truncated 7z header"
    return True, "Valid 7z header"


def _validate_elf(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"\x7fELF"):
        return False, "Missing ELF magic"
    if len(data) < 52:
        return False, "Truncated ELF header"
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        return False, f"Invalid ELF class ({ei_class})"
    if ei_data not in (1, 2):
        return False, f"Invalid ELF endianness ({ei_data})"
    return True, "Valid ELF header"


def _validate_pe(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"MZ"):
        return False, "Missing DOS header"
    if len(data) < 64:
        return False, "Truncated DOS header"
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data):
        return False, "PE offset out of range"
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return False, "Missing PE signature"
    return True, "Valid PE structure"


def _validate_sqlite(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"SQLite format 3\x00"):
        return False, "Missing SQLite header"
    if len(data) < 100:
        return False, "Truncated SQLite header"
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
        return False, f"Invalid page size ({page_size})"
    return True, f"Valid SQLite header (page size {page_size})"


def _validate_wav(data: bytes) -> Tuple[bool, str]:
    if len(data) < 12:
        return False, "Too small for WAV"
    if data[0:4] != b"RIFF" or data[8:12] != b"WAVE":
        return False, "Missing RIFF/WAVE header"
    riff_size = struct.unpack("<I", data[4:8])[0]
    if riff_size + 8 > len(data) + 8:
        return False, "RIFF size exceeds data"
    return True, "Valid WAV/RIFF structure"


def _validate_bmp(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"BM"):
        return False, "Missing BMP signature"
    if len(data) < 14:
        return False, "Truncated BMP header"
    file_size = struct.unpack("<I", data[2:6])[0]
    if file_size > len(data) * 2:
        return False, f"Declared size ({file_size}) implausible"
    return True, "Valid BMP header"


def _validate_mp3(data: bytes) -> Tuple[bool, str]:
    if data.startswith(b"ID3"):
        if len(data) < 10:
            return False, "Truncated ID3 header"
        tag_size = (
            ((data[6] & 0x7F) << 21)
            | ((data[7] & 0x7F) << 14)
            | ((data[8] & 0x7F) << 7)
            | (data[9] & 0x7F)
        )
        if 10 + tag_size > len(data):
            return False, "ID3 size exceeds data"
        return True, f"Valid ID3 tag ({tag_size} bytes)"
    # MPEG audio sync word: 0xFFE or 0xFFF high 11 bits set
    for i in range(min(len(data) - 1, 4096)):
        if data[i] == 0xFF and (data[i + 1] & 0xE0) == 0xE0:
            return True, f"MPEG sync at offset {i}"
    return False, "No ID3 or MPEG sync found"


def _validate_ogg(data: bytes) -> Tuple[bool, str]:
    if not data.startswith(b"OggS"):
        return False, "Missing OggS page header"
    if len(data) < 27:
        return False, "Truncated Ogg page"
    return True, "Valid Ogg page header"


def _validate_rar(data: bytes) -> Tuple[bool, str]:
    if data.startswith(b"Rar!\x1a\x07\x00") or data.startswith(b"Rar!\x1a\x07\x01\x00"):
        if len(data) < 20:
            return False, "Truncated RAR header"
        return True, "Valid RAR header"
    return False, "Missing RAR signature"
