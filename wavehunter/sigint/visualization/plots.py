import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from typing import Optional
from wavehunter.sigint.fingerprint.spectral import compute_stft, compute_fft
from wavehunter.core.entropy import sliding_window_entropy

def plot_waveform(
    samples: np.ndarray, 
    sample_rate: int, 
    output_path: str | Path
) -> None:
    """Plots the time-domain waveform of the signal."""
    plt.figure(figsize=(10, 4))
    
    is_stereo = len(samples.shape) > 1 and samples.shape[1] >= 2
    times = np.arange(len(samples)) / sample_rate
    
    if is_stereo:
        plt.plot(times, samples[:, 0], label='Left Channel', color='#3b82f6', alpha=0.8)
        plt.plot(times, samples[:, 1], label='Right Channel', color='#10b981', alpha=0.6)
    else:
        plt.plot(times, samples, color='#3b82f6')
        
    plt.title('Time Domain Waveform', fontsize=12, fontweight='bold')
    plt.xlabel('Time (seconds)', fontsize=10)
    plt.ylabel('Amplitude', fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.5)
    if is_stereo:
        plt.legend()
        
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

def plot_spectrogram(
    samples: np.ndarray, 
    sample_rate: int, 
    output_path: str | Path
) -> None:
    """Plots a 2D spectrogram (waterfall plot) of the signal."""
    freqs, times, stft = compute_stft(samples, sample_rate, frame_size=1024, overlap=512)
    if len(freqs) == 0 or stft.size == 0:
        return
        
    # Convert magnitudes to dB
    stft_db = 20 * np.log10(stft + 1e-10)
    
    plt.figure(figsize=(10, 5))
    
    # Render spectrogram waterfall
    extent = [times[0], times[-1], freqs[0], freqs[-1]]
    plt.imshow(
        stft_db.T, 
        origin='lower', 
        aspect='auto', 
        extent=extent, 
        cmap='inferno',
        vmax=np.max(stft_db),
        vmin=np.max(stft_db) - 60
    )
    
    plt.title('Spectral Waterfall (Spectrogram)', fontsize=12, fontweight='bold')
    plt.xlabel('Time (seconds)', fontsize=10)
    plt.ylabel('Frequency (Hz)', fontsize=10)
    plt.colorbar(label='Power (dB)')
    plt.ylim(0, min(8000, sample_rate // 2))  # Zoom into first 8kHz for clarity
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

def plot_fft(
    samples: np.ndarray, 
    sample_rate: int, 
    output_path: str | Path
) -> None:
    """Plots the overall magnitude spectrum (FFT)."""
    freqs, mags = compute_fft(samples, sample_rate)
    if len(freqs) == 0:
        return
        
    # Convert magnitudes to dB
    mags_db = 20 * np.log10(mags + 1e-10)
    
    plt.figure(figsize=(10, 4))
    plt.plot(freqs, mags_db, color='#ef4444')
    
    plt.title('Overall Power Spectrum (FFT)', fontsize=12, fontweight='bold')
    plt.xlabel('Frequency (Hz)', fontsize=10)
    plt.ylabel('Magnitude (dB)', fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.xlim(0, min(8000, sample_rate // 2))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

def plot_constellation(
    samples: np.ndarray, 
    sample_rate: int, 
    carrier_hz: float, 
    symbol_rate: float, 
    output_path: str | Path
) -> None:
    """
    Plots a Constellation/Phase diagram (I/Q channels) by extracting phase
    components at the carrier frequency.
    """
    sig = samples[:, 0] if len(samples.shape) > 1 else samples
    symbol_period = sample_rate / symbol_rate
    n_symbols = int(len(sig) / symbol_period)
    
    # Calculate I/Q channels using quadrature downconversion
    t = np.arange(len(sig)) / sample_rate
    lo_i = np.cos(2.0 * np.pi * carrier_hz * t)
    lo_q = -np.sin(2.0 * np.pi * carrier_hz * t)
    
    i_signal = sig * lo_i
    q_signal = sig * lo_q
    
    # Integrate/dump over symbol periods to get symbols
    i_symbols = []
    q_symbols = []
    
    for s in range(n_symbols):
        start = int(s * symbol_period)
        end = int(start + symbol_period)
        if end > len(sig):
            break
        i_symbols.append(np.mean(i_signal[start:end]))
        q_symbols.append(np.mean(q_signal[start:end]))
        
    plt.figure(figsize=(5, 5))
    plt.scatter(i_symbols, q_symbols, color='#a855f7', alpha=0.7, edgecolors='none', s=15)
    
    plt.title(f'Constellation Diagram ({symbol_rate:.0f} Baud / {carrier_hz:.0f} Hz Carrier)', fontsize=10, fontweight='bold')
    plt.xlabel('In-Phase (I)', fontsize=9)
    plt.ylabel('Quadrature (Q)', fontsize=9)
    plt.grid(True, linestyle='--', alpha=0.5)
    
    # Equal aspect ratio centered at 0
    max_lim = max(max(np.abs(i_symbols)), max(np.abs(q_symbols))) * 1.2 if i_symbols else 1.0
    plt.xlim(-max_lim, max_lim)
    plt.ylim(-max_lim, max_lim)
    plt.axhline(0, color='black', linewidth=0.5, alpha=0.5)
    plt.axvline(0, color='black', linewidth=0.5, alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()

def plot_entropy(
    raw_data_bytes: bytes, 
    output_path: str | Path
) -> None:
    """Plots the sliding-window Shannon entropy profile of raw bytes."""
    window = 2048
    step = 1024
    entropy_vals = sliding_window_entropy(raw_data_bytes, window_size=window, step_size=step)
    
    if len(entropy_vals) == 0:
        return
        
    x = np.arange(len(entropy_vals)) * step
    
    plt.figure(figsize=(10, 4))
    plt.plot(x, entropy_vals, color='#fbbf24', linewidth=1.5)
    plt.fill_between(x, entropy_vals, color='#fbbf24', alpha=0.15)
    
    plt.title('Sliding Shannon Entropy Profile', fontsize=12, fontweight='bold')
    plt.xlabel('Offset (bytes)', fontsize=10)
    plt.ylabel('Entropy (bits/symbol)', fontsize=10)
    plt.ylim(0, 8.2)
    plt.grid(True, linestyle='--', alpha=0.5)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
