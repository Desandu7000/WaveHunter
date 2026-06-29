# Welcome to the WaveHunter Wiki

**WaveHunter** is an open-source Python toolkit designed for audio forensics, steganography extraction, digital signal intelligence (SIGINT), CTF challenges, malware analysis, and reverse engineering. 

Functioning as the **"Binwalk for audio"**, WaveHunter automatically parses audio streams, extracts hidden payloads across multiple domains (time, frequency, and bit-level), detects and demodulates digital carrier signals, and ranks potential data candidates using statistical confidence modeling.

---

## Technical Architecture

WaveHunter processes audio files through a modular multi-stage pipeline:

```mermaid
graph TD
    A["Input WAV File"] --> B["Custom WAV RIFF Parser"]
    B --> C["Metadata & Trailer Detection"]
    B --> D["Signal Characteristics & Entropy Analysis"]
    
    D --> E["Forensic Extraction Pipeline"]
    D --> F["SIGINT Analysis Engine"]
    
    E --> E1["Bitplanes & Multibit"]
    E --> E2["Strides & Reversals"]
    E --> E3["Gray Code & Delta"]
    E --> E4["Wavelet & Phase"]
    
    F --> F1["Carrier Detection"]
    F --> F2["Baud/Symbol Sync"]
    F --> F3["Demodulators (FSK, ASK, BPSK, etc.)"]
    F --> F4["Recursive Signal Decoding"]
    
    E1 --> G["Data Scanners"]
    E2 --> G
    E3 --> G
    E4 --> G
    F3 --> G
    F4 --> G
    
    G --> G1["Magic Signatures"]
    G --> G2["Regex & Flags"]
    G --> G3["ASCII & Printable Strings"]
    G --> G4["Compression Decompressors"]
    
    G1 --> H["Confidence Scoring Engine"]
    G2 --> H
    G3 --> H
    G4 --> H
    
    H --> I["Reports & Dashboards"]
    I --> I1["Rich Terminal Table"]
    I --> I2["JSON Report"]
    I --> I3["HTML Dark-Mode Dashboard"]
    I --> I4["Diagnostic Signal Plots"]
```

---

## Wiki Contents

Explore the details of WaveHunter's components and capabilities:

1. **[[Installation]]**: System requirements, package dependencies, and developer environment setup.
2. **[[Command-Line-Interface]]**: Reference manual for `analyze`, `extract`, `scan`, and `plot` commands with usage examples.
3. **[[Steganography-Extractors]]**: Deep dive into the physical and mathematical mechanisms behind our time and frequency domain extractors.
4. **[[Data-Scanners]]**: Explanation of signature-matching, regex scanners, character heuristics, and automatic decompression.
5. **[[SIGINT-Analysis-Engine]]**: Technical breakdown of carrier detection, digital modulation analysis, clock recovery, demodulation, and constellation plotting.
6. **[[Plugin-System]]**: How to write custom signal detectors, demodulators, decoders, and pattern scanners to extend WaveHunter.
