# Command Line Interface (CLI)

WaveHunter is designed as a developer-friendly command-line utility. Once installed in editable mode (`pip install -e .`), it becomes globally available in your terminal via the `wavehunter` executable.

```bash
wavehunter [COMMAND] [ARGS] [OPTIONS]
```

To display global help or help for a specific command:
```bash
wavehunter --help
wavehunter analyze --help
```

---

## 1. The `analyze` Command

Runs the full forensic analysis pipeline on a WAV file. This includes parsing metadata, evaluating statistical variances, searching for digital carrier modulations, extracting steganographic streams across multiple configurations, running data scanners on all candidate streams, and ranking the findings by confidence.

### Syntax
```bash
wavehunter analyze FILE_PATH [OPTIONS]
```

### Options
* `--html`, `-o` `PATH`: Saves an interactive, premium HTML report dashboard.
* `--json`, `-j` `PATH`: Saves all metadata, candidates, and detection logs in a raw JSON document.
* `--txt`, `-t` `PATH`: Saves a plain text report matching the console output.

### Examples
Perform a silent full analysis and save reports in all formats:
```bash
wavehunter analyze audio_mystery.wav -o report.html -j report.json -t report.txt
```

---

## 2. The `extract` Command

Extracts a specific raw binary stream from the audio file using a selected extractor and writes it to a file. Useful for isolating specific bitplanes or channels once `analyze` has flagged them.

### Syntax
```bash
wavehunter extract FILE_PATH EXTRACTOR [OPTIONS]
```

### Arguments
* `FILE_PATH`: Path to the input WAV file.
* `EXTRACTOR`: One of:
  * `bitplane`: Extract individual bitplanes (LSB to MSB) of a specific channel.
  * `channel`: Extract the raw, unmanipulated sample bytes of a specific channel.
  * `reverse`: Extract sample/bit/byte reversed streams.
  * `stride`: Extract sample bytes at specific stride offsets.
  * `gray`: Extract Gray-decoded sample streams.
  * `delta`: Extract differential/delta-decoded sample streams.
  * `phase`: Extract Fourier phase angle bitstreams.

### Options
* `-c`, `--channel` `INTEGER`: Channel index to target (default: `0`).
* `-b`, `--bit` `INTEGER`: Bit position to target (0 for LSB, default: `0`).
* `-s`, `--stride` `INTEGER`: Stride interval (default: `2`).
* `--offset` `INTEGER`: Stride starting sample index (default: `0`).
* `-p`, `--pack` `TEXT`: Bit packing order: `msb` or `lsb` (default: `msb`).
* `-o`, `--out` `PATH`: **(Required)** Output path to save the extracted binary file.

### Examples
Extract LSB (Bit 0) from Channel 0, packed as MSB, and save to a file:
```bash
wavehunter extract chall.wav bitplane --channel 0 --bit 0 --pack msb --out lsb_channel0.bin
```

Extract sample bytes at every 8th index, starting at offset 3:
```bash
wavehunter extract mystery.wav stride --channel 0 --stride 8 --offset 3 --out stride_8.bin
```

---

## 3. The `scan` Command

Scans a raw binary file (such as one extracted via the `extract` command, or an arbitrary payload) for hidden signatures, CTF flags, ASCII strings, and decompression structures.

### Syntax
```bash
wavehunter scan FILE_PATH
```

### Examples
Scan a suspected LSB bitstream for flags or embedded files:
```bash
wavehunter scan lsb_channel0.bin
```

*Output Console Highlights:*
* **Entropy**: Calculated Shannon entropy (e.g., ~8.0 for encrypted/compressed data, lower for text).
* **Detected File Signatures**: Lists matched Magic Bytes (e.g., `PK` zip header, `\x89PNG` png header).
* **Regex Patterns**: Matches common flag formats (e.g. `flag{...}`, `CTF{...}`), base64, IPs, and URLs.
* **Decompressible Streams**: Offsets where `zlib`, `gzip`, or raw `deflate` streams start.
* **Readable ASCII Strings**: Lists occurrences of printable character blocks.

---

## 4. The `plot` Command

Generates diagnostic signal visualizations of the WAV file to help in manual analysis, identification of carrier frequencies, and steganography detection.

### Syntax
```bash
wavehunter plot FILE_PATH [OPTIONS]
```

### Options
* `-d`, `--dir` `PATH`: Directory to save the generated plots (default: `./plots`).

### Generated Visualizations
The command produces 5 high-resolution PNG images:
1. `waveform.png`: A time-domain view of amplitude values across channels.
2. `spectrogram.png`: Time-frequency-intensity distribution to locate hidden signal bursts or spectral anomalies.
3. `fft.png`: Fast Fourier Transform power spectrum to identify dominant carrier spikes.
4. `entropy.png`: Sliding-window Shannon entropy mapping across the file to isolate high-randomness payloads.
5. `constellation.png`: Complex IQ constellation mapping (if carrier and symbol rates are detected) to view modulation structures (e.g., BPSK, QAM).

### Examples
Generate diagnostic plots for a signal:
```bash
wavehunter plot signal_burst.wav --dir ./diagnostics
```
