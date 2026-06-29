# Steganography Extractors

WaveHunter contains a robust collection of modular extractors designed to reconstruct hidden binary data streams from raw WAV samples. These extractors operate in both the **time domain** (sample values, bit levels, strides) and the **frequency domain** (spectral phases, wavelet levels).

---

## 1. Bitplane & Multi-Bit Extractor
Bitplane steganography is the most common technique for hiding data in audio. It involves replacing the least significant bits (LSB) of audio samples with payload bits. WaveHunter implements extensive extraction variations to handle custom steganographic formats.

* **Single Bitplane Extraction**: Isolates a single bit position $b \in [0, \text{bit-depth}-1]$ from all samples of a specific channel. It supports:
  * **MSB Packing**: Packs the first sample's bit into the MSB (bit 7) of the output byte, shifting subsequent bits right.
  * **LSB Packing**: Packs the first sample's bit into the LSB (bit 0) of the output byte, shifting subsequent bits left.
* **Nibbles**: Extracts 4-bit structures (e.g., bits 0-3 or 4-7) and packs two consecutive nibbles into a single byte.
* **Reconstructed Bytes**: Reconstructs complete 8-bit bytes directly from sample ranges (e.g., bits 0-7 or bits 8-15) for cases where an entire byte is embedded per sample.
* **Combined Bitplanes**: Performs logical `OR` or `XOR` operations between multiple bitplanes (e.g. planes 0-3) before byte packing.
* **Sign Bit**: Extracts the sign bit (the highest bit based on sample depth) as a packed bitstream.

---

## 2. Channel Mixing & Layout De-Interleaving
Multi-channel audio files (such as stereo files) store samples alternately (interleaved) as `L R L R`. Hiding schemes can exploit this structure.

* **Layouts Reconstructed**:
  * **LLLL**: Mono Left channel only.
  * **RRRR**: Mono Right channel only.
  * **LRLR**: Standard interleaved stereo samples.
  * **RLRL**: Swapped channel stereo.
  * **LLRR / RRLL**: Paired channel grouping.
* **Channel Arithmetic**: Generates mixed virtual channels including:
  * **Sum Channel**: $L + R$
  * **Difference Channel**: $L - R$
  * **XOR Channel**: $L \oplus R$

---

## 3. Gray Code & Delta Decoding
Some steganography tools apply simple sample-value transformations before embedding to make changes less audible or harder to scan.

* **Gray Code**: Converts Gray-encoded samples back to binary ($B[i] = B[i+1] \oplus G[i]$) before extracting bitplanes.
* **Delta (Differential) Decoding**: Decodes differential amplitude encoding. It reconstructs the sequence using:
  $$s[n] = (raw[n] - raw[n-1]) \pmod{2^{\text{bit-depth}}}$$

---

## 4. Stride Extractor
Steganographic payloads are not always embedded contiguously. A tool might embed data in every $N$-th sample, starting at a specific sample offset. 

The Stride Extractor runs permutations of:
* **Stride ($s$)**: Checks periodic sample intervals (e.g., every 2nd, 3rd, ..., 16th sample).
* **Offset ($o$)**: Shifts the starting sample index to intercept patterns that begin late.

---

## 5. Reversals
Data can be written backwards to evade simple signatures. WaveHunter tests:
* **Sample Reversal**: Reads the sample array from end to start.
* **Bit Reversal**: Reverses the order of bits within each reconstructed byte.
* **Byte Reversal**: Reverses the final sequence of reconstructed bytes.

---

## 6. Phase Analysis Extractor
Phase steganography hides data by altering the phase of specific frequency components in the signal.
* WaveHunter performs short-term Fast Fourier Transforms (FFT) on the audio signal.
* It extracts the phase angle $\theta = \angle X(f)$ of the frequency bins.
* The sign of the phase angle (positive vs. negative) or its phase offsets are converted into binary sequences (`0` or `1`) and packed into bytes.

---

## 7. Discrete Wavelet Transform (DWT) Extractor
Advanced steganography tools hide information in the frequency subbands of a wavelet decomposition to avoid detection by standard time-domain analysis.

* WaveHunter applies a **Discrete Wavelet Transform (DWT)** using Haar wavelets (db1) decomposed up to **8 levels**.
* This yields 9 subbands: approximation coefficients (`cA8`) and detail coefficients (`cD8` to `cD1`).
* The extractor rounds these floating-point coefficients to integers, extracts bits 0-15 from each layer, and packs them into bytes.
