# WaveHunter

**WaveHunter** is an open-source Python toolkit for audio forensics, steganography, CTFs, malware analysis, and reverse engineering. Designed as a professional, modular, GitHub-ready command-line tool, it functions as the **"Binwalk for audio"**—automatically parsing audio streams, extracting hidden payloads, and ranking potential data candidates.

Created and maintained by **Desandu Hettiarachchi**.

---

## Features

- **Custom WAV RIFF Parser**: Robust binary parsing of format headers, custom/unknown chunks, list tags, and trailing payload detections (e.g. files appended to the end of WAV data).
- **Steganography Extractors**:
  - **Bitplanes**: Extract LSB/MSB bits from channel samples.
  - **Channels**: Left, Right, XOR, Difference, and Sum channel manipulations.
  - **Interleaving**: Stereo/multi-channel de-interleaving.
  - **Strides**: Analyze sample offsets and periodic sample patterns.
  - **Reversals**: Reversed sample indices, bit sequences, or byte streams.
  - **Gray Code & Delta Decoding**: Decode Gray-coded and differential sample encoding.
  - **Phase Analysis**: Analysis of sample phase angles and Fourier phase coding.
- **Data Scanners**:
  - **Magic Signatures**: Database-driven matching for file formats (ZIP, PNG, JPEG, ELF, EXE, PDF, GZIP, etc.).
  - **Regex Scanner**: Flags (`flag{...}`, `CTF{...}`), URLs, IPs, base64 strings, and hex sequences.
  - **ASCII & Printable Text**: Locate sequences of readable characters.
  - **Decompression**: Auto-extract zlib/gzip/deflate streams embedded in sample data.
- **Reporting & Visualization**:
  - Direct Rich console report tables.
  - Machine-readable JSON output.
  - Premium HTML dashboard with dark mode, interactive sliding entropy graphs, and candidates sorted by confidence scores (1-5 stars).

---

## Installation

Ensure you have Python 3.12+ installed. Install the package and dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Usage

WaveHunter is invoked via the CLI:

### 1. Analyze an Audio File
Runs the full suite of extractors, scanners, and entropy checks, scoring candidate streams and generating reports:
```bash
wavehunter analyze sample.wav --html-report report.html --json-report report.json
```

### 2. Extract Specific Streams
Extract specific bitplanes or channel configurations and output them to a file:
```bash
wavehunter extract sample.wav bitplane --channel 0 --bit 0 --out output.bin
```

### 3. Scan a Stream File
Scan raw binary files for flags, magic headers, or ASCII strings:
```bash
wavehunter scan output.bin
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
