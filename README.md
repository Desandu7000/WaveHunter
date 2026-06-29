# WaveHunter

<img width="1075" height="728" alt="Screenshot 2026-06-29 203028" src="https://github.com/user-attachments/assets/41567f86-1fbf-4507-bb03-1d84874b3273" />

**WaveHunter** is an open-source Python toolkit for audio forensics, steganography, CTFs, malware analysis, and reverse engineering. Designed as a professional, modular, GitHub-ready command-line tool, it functions as the **"Binwalk for audio"**—automatically parsing audio streams, extracting hidden payloads, and ranking potential data candidates.

Created and maintained by **Desandu Hettiarachchi**.

---

## Features

- **Custom WAV RIFF Parser**: Robust binary parsing of format headers, custom/unknown chunks, list tags, and trailing payload detections (e.g. files appended to the end of WAV data).
- **Multi-Format Audio Support**: Built-in fallback utilizing `soundfile` to seamlessly load, decode, and run the steganography pipeline on non-WAV formats such as MP3, FLAC, OGG, and more.
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
  - **Regex Scanner**: Flags (`flag{...}`, `CTF{...}`), custom user formats, URLs, IPs, base64 strings, and hex sequences.
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
Runs the full suite of extractors, scanners, and entropy checks, scoring candidate streams and generating reports. You can also specify a custom flag format (e.g. `D7CTF`, `HTB`, `FLAG`).

For example, if you want to scan for flags matching the format `D7CTF{1337_F0UND}`, you should pass `D7CTF` as the flag format:
```bash
wavehunter analyze sample.wav --html report.html --json report.json --flag-format D7CTF
```

### 2. Extract Specific Streams
Extract specific bitplanes or channel configurations and output them to a file:
```bash
wavehunter extract sample.wav bitplane --channel 0 --bit 0 --out output.bin
```

### 3. Scan a Stream File
Scan raw binary files for flags, magic headers, or ASCII strings.

For example, to scan a file for custom flag formats matching `D7CTF{...}`:
```bash
wavehunter scan output.bin --flag-format D7CTF
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
