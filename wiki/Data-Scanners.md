# Data Scanners

Once WaveHunter extracts a candidate byte stream (via time/frequency extraction or carrier demodulation), it passes the bytes through a multi-stage **Data Scanner Engine**. This engine flags indicators of structure, readability, and obfuscation.

---

## 1. Magic Signature Scanner
The magic signature scanner behaves like `file` or `binwalk` by searching for file format headers and footers to locate embedded files within a stream.

### Supported Formats
WaveHunter maintains a signatures database that matches headers and footers for:
* **Archives**: ZIP (`PK\x03\x04`), GZIP (`\x1f\x8b\x08`), BZIP2 (`BZh`), 7-Zip (`7z\xbc\xaf\x27\x1c`), RAR (`Rar!\x1a\x07\x00`).
* **Images**: PNG (`\x89PNG\r\n\x1a\n`), JPEG (`\xff\xd8\xff`), BMP (`BM`), GIF (`GIF89a` / `GIF87a`).
* **Documents**: PDF (`%PDF-`).
* **Executables**: ELF (`\x7fELF`), Windows PE (`MZ`).
* **Multimedia**: WAV (`RIFF...WAVE`), MP3 (`ID3` or `\xff\xfb` sync frame), Ogg (`OggS`).
* **Databases**: SQLite (`SQLite format 3\x00`).

### Size & Confidence Estimation
* **Footer Matching**: If the file signature defines a known footer (e.g. JPEG `\xff\xd9` or PNG `IEND\xae\x42\x60\x82`), WaveHunter searches for the nearest footer instance to calculate the exact **estimated size** and updates the detection confidence to **High**.
* **Header-Only**: If no footer is defined or found, the file boundary is marked as unknown, and confidence is set to **Medium**.

---

## 2. Regex Scanner
The regex scanner scans for text sequences matching pattern-based indicators of CTF flags, credentials, or network details.

### Predefined Patterns
| Name | Pattern Logic | Example Matches |
| :--- | :--- | :--- |
| **Flag** | Matches standard formats like `flag{...}`, `CTF{...}`, `key{...}` or assignments like `secret = ...` | `flag{th1s_is_s3cret}`, `CTF{w4v3_hunt}` |
| **Custom Flag** | Dynamic user-specified formats passed via `--flag-format` (e.g. `HTB`, `ANIMUS`) | `HTB{fl4g_1s_h3r3}` |
| **URL** | Matches standard HTTP and HTTPS web URLs | `http://example.com/payload` |
| **Email** | Matches typical email addresses | `admin@wavehunter.org` |
| **IPv4 Address**| Matches valid IPv4 dot-decimal representations | `192.168.1.100` |
| **Base64** | Detects contiguous alphanumeric blocks (16+ chars) with optional padding | `d2F2ZWh1bnRlcg==` |
| **MD5 Hash** | 32-character hexadecimal strings | `5d41402abc4b2a76b9719d911017c592` |
| **SHA256 Hash**| 64-character hexadecimal strings | `e3b0c44298fc1c149afbf4c8996fb924...` |

---

## 3. Compression Scanner
Steganography programs often compress data using `zlib` or `deflate` algorithms before embedding to minimize size and reduce statistical anomalies. 

WaveHunter automatically scans for and decompress these streams:
1. **Header Identification**: Checks for common zlib compression level headers (`\x78\x9c` default, `\x78\xda` maximum, `\x78\x01` low/none) and gzip headers (`\x1f\x8b`).
2. **Decompression Trials**: Spawns a Python `zlib.decompressobj()` to test decompression from that offset.
3. **Boundary Calculation**: Evaluates where the compressed block ends by tracking the length of the unused data.
4. **Deduplication**: Filters overlapping matches to maintain a clean list of unique compressed files.

---

## 4. ASCII Scanner
The ASCII scanner searches for blocks of readable text.
* **Character Set**: Matches bytes in the printable range of $0x20$ (space) to $0x7e$ (`~`), including common control characters like newlines (`\n`, `\r`) and tabs (`\t`).
* **Length Constraint**: Employs a configurable minimum length threshold (default: 4 or 6 characters depending on invocation) to filter out random byte patterns that happen to fall within the printable range.
* **CTF Utility**: Highly useful for finding base64 blocks, cleartext strings, and plaintext credentials hidden within sample noise.
