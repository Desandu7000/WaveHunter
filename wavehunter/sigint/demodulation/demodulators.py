import numpy as np
from typing import List, Dict, Any, Tuple
from wavehunter.core.utils import bits_to_bytes
from wavehunter.sigint.demodulation.synchronization import synchronize_symbols, estimate_symbol_rate
from wavehunter.core.signal import compute_amplitude_envelope

def demodulate_fsk(
    samples: np.ndarray, 
    sample_rate: int, 
    mark_hz: float, 
    space_hz: float, 
    symbol_rate: float
) -> bytes:
    """
    Demodulates Frequency Shift Keying (FSK/AFSK).
    Compares the energy of each symbol interval at the mark and space frequencies.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    symbol_period = sample_rate / symbol_rate
    n_symbols = int(len(sig) / symbol_period)
    
    bits = []
    
    # Goertzel/DFT at mark and space frequency for each symbol window
    for i in range(n_symbols):
        start = int(i * symbol_period)
        end = int(start + symbol_period)
        if end > len(sig):
            break
            
        symbol_data = sig[start:end]
        
        # DFT at mark and space frequencies
        t = np.arange(len(symbol_data)) / sample_rate
        mark_ref = np.exp(-2j * np.pi * mark_hz * t)
        space_ref = np.exp(-2j * np.pi * space_hz * t)
        
        mark_energy = np.abs(np.sum(symbol_data * mark_ref))
        space_energy = np.abs(np.sum(symbol_data * space_ref))
        
        bits.append(1 if mark_energy > space_energy else 0)
        
    return bits_to_bytes(bits, pack_msb=True)

def demodulate_ask(
    samples: np.ndarray, 
    sample_rate: int, 
    symbol_rate: float
) -> bytes:
    """
    Demodulates Amplitude Shift Keying (ASK).
    Uses clock recovery and thresholds the amplitude envelope.
    """
    envelope = compute_amplitude_envelope(samples, window_size=int(sample_rate * 0.005) or 20)
    sampled_vals, _ = synchronize_symbols(envelope, sample_rate, symbol_rate)
    
    if len(sampled_vals) == 0:
        return b""
        
    threshold = np.mean(sampled_vals)
    bits = [1 if val > threshold else 0 for val in sampled_vals]
    
    return bits_to_bytes(bits, pack_msb=True)

def demodulate_bpsk(
    samples: np.ndarray, 
    sample_rate: int, 
    carrier_hz: float, 
    symbol_rate: float
) -> bytes:
    """
    Demodulates Differential Binary Phase Shift Keying (DBPSK).
    Compares the phase difference of consecutive symbols at the carrier frequency.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    symbol_period = sample_rate / symbol_rate
    n_symbols = int(len(sig) / symbol_period)
    
    phases = []
    
    for i in range(n_symbols):
        start = int(i * symbol_period)
        end = int(start + symbol_period)
        if end > len(sig):
            break
            
        symbol_data = sig[start:end]
        # Compute FFT bin at carrier
        t = np.arange(len(symbol_data)) / sample_rate
        ref = np.exp(-2j * np.pi * carrier_hz * t)
        phase = np.angle(np.sum(symbol_data * ref))
        phases.append(phase)
        
    bits = []
    # Differential decoding
    for i in range(1, len(phases)):
        diff = np.arctan2(np.sin(phases[i] - phases[i-1]), np.cos(phases[i] - phases[i-1]))
        # Phase change of ~pi (180 deg) represents 1, ~0 represents 0
        bits.append(1 if abs(diff) > np.pi / 2 else 0)
        
    return bits_to_bytes(bits, pack_msb=True)

def demodulate_morse(samples: np.ndarray, sample_rate: int) -> str:
    """
    Demodulates Morse code signals and returns the translated ASCII string.
    """
    envelope = compute_amplitude_envelope(samples, window_size=200)
    threshold = np.mean(envelope) * 1.2
    active = (envelope > threshold).astype(np.int8)
    
    # Run-length encode the active/inactive states
    diff = np.diff(active)
    transitions = np.where(diff != 0)[0]
    
    if len(transitions) < 2:
        return ""
        
    lengths = []
    states = []
    
    # Initial state
    states.append(active[0])
    lengths.append(transitions[0] / sample_rate)
    
    for i in range(1, len(transitions)):
        states.append(active[transitions[i-1] + 1])
        lengths.append((transitions[i] - transitions[i-1]) / sample_rate)
        
    # Append final segment
    states.append(active[-1])
    lengths.append((len(active) - transitions[-1]) / sample_rate)
    
    # We filter out very short segments (noise)
    filtered_states = []
    filtered_lengths = []
    for state, length in zip(states, lengths):
        if length > 0.01:  # min 10ms
            filtered_states.append(state)
            filtered_lengths.append(length)
            
    # Find dit duration (the shortest active pulse)
    active_lengths = [l for s, l in zip(filtered_states, filtered_lengths) if s == 1]
    if not active_lengths:
        return ""
        
    dit_len = np.percentile(active_lengths, 15)  # Estimate dit length
    
    # Morse code dictionary
    MORSE_CODE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
        '--..--': ',', '..--..': '?', '.----.': "'", '-..-.': '/',
        '-....-': '-', '-...-': '=', '---...': ':', '.-.-.': '+',
        '-.-.--': '!',
    }
    
    morse_str = ""
    current_char = []
    
    for state, length in zip(filtered_states, filtered_lengths):
        if state == 1:  # Signal is active
            if length < dit_len * 2.0:
                current_char.append(".")
            else:
                current_char.append("-")
        else:  # Signal is inactive (space)
            if length >= dit_len * 5.0:
                # Word boundary
                char_symbol = "".join(current_char)
                if char_symbol in MORSE_CODE:
                    morse_str += MORSE_CODE[char_symbol]
                morse_str += " "
                current_char = []
            elif length >= dit_len * 2.5:
                # Character boundary
                char_symbol = "".join(current_char)
                if char_symbol in MORSE_CODE:
                    morse_str += MORSE_CODE[char_symbol]
                current_char = []
                
    # Append final character
    if current_char:
        char_symbol = "".join(current_char)
        if char_symbol in MORSE_CODE:
            morse_str += MORSE_CODE[char_symbol]
            
    return morse_str.strip()

def demodulate_dtmf(samples: np.ndarray, sample_rate: int) -> str:
    """
    Demodulates Dual-Tone Multi-Frequency (DTMF) tones.
    Returns the sequence of numbers/symbols.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    
    # DTMF frequencies mapping
    low_freqs = [697, 770, 852, 941]
    high_freqs = [1209, 1336, 1477, 1633]
    
    GRID = [
        ['1', '2', '3', 'A'],
        ['4', '5', '6', 'B'],
        ['7', '8', '9', 'C'],
        ['*', '0', '#', 'D']
    ]
    
    # DTMF tone duration is typically >40ms. We analyze in 50ms blocks.
    block_len = int(sample_rate * 0.05)
    if block_len == 0:
        return ""
        
    n_blocks = len(sig) // block_len
    sequence = []
    last_char = None
    
    for i in range(n_blocks):
        block = sig[i * block_len : (i + 1) * block_len]
        
        # Calculate power at each target frequency using Goertzel algorithm
        low_powers = []
        for lf in low_freqs:
            low_powers.append(goertzel_magnitude(block, lf, sample_rate))
            
        high_powers = []
        for hf in high_freqs:
            high_powers.append(goertzel_magnitude(block, hf, sample_rate))
            
        max_low_idx = np.argmax(low_powers)
        max_high_idx = np.argmax(high_powers)
        
        # Check threshold
        median_power = np.median(low_powers + high_powers)
        if low_powers[max_low_idx] > median_power * 5.0 and high_powers[max_high_idx] > median_power * 5.0:
            char = GRID[max_low_idx][max_high_idx]
            if char != last_char:
                sequence.append(char)
                last_char = char
        else:
            last_char = None
            
    return "".join(sequence)

def goertzel_magnitude(samples: np.ndarray, target_frequency: float, sample_rate: int) -> float:
    """
    Computes Goertzel algorithm magnitude for a specific frequency.
    """
    N = len(samples)
    if N == 0:
        return 0.0
    k = int(0.5 + (N * target_frequency) / sample_rate)
    w = (2.0 * np.pi / N) * k
    cosine = np.cos(w)
    coeff = 2.0 * cosine
    
    q1 = 0.0
    q2 = 0.0
    
    for sample in samples:
        q0 = coeff * q1 - q2 + sample
        q2 = q1
        q1 = q0
        
    magnitude = np.sqrt(q1**2 + q2**2 - coeff * q1 * q2)
    return float(magnitude)

def demodulate_manchester(
    samples: np.ndarray, 
    sample_rate: int, 
    symbol_rate: float
) -> bytes:
    """
    Demodulates Manchester encoded signals.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    symbol_period = sample_rate / symbol_rate
    n_symbols = int(len(sig) / symbol_period)
    
    bits = []
    
    for i in range(n_symbols):
        start = int(i * symbol_period)
        mid = int(start + symbol_period / 2.0)
        end = int(start + symbol_period)
        
        if end > len(sig):
            break
            
        # Manchester: transition in the middle determines value
        # 1-to-0 (positive to negative) is 0, 0-to-1 (negative to positive) is 1
        first_half = np.mean(sig[start:mid])
        second_half = np.mean(sig[mid:end])
        
        if first_half > second_half:
            bits.append(0)
        else:
            bits.append(1)
            
    return bits_to_bytes(bits, pack_msb=True)

def demodulate_nrz(
    samples: np.ndarray, 
    sample_rate: int, 
    symbol_rate: float
) -> bytes:
    """
    Demodulates Non-Return-to-Zero (NRZ) encoded signals.
    """
    sig = samples if len(samples.shape) == 1 else samples[:, 0]
    sampled_vals, _ = synchronize_symbols(sig, sample_rate, symbol_rate)
    
    if len(sampled_vals) == 0:
        return b""
        
    threshold = np.mean(sampled_vals)
    bits = [1 if val > threshold else 0 for val in sampled_vals]
    
    return bits_to_bytes(bits, pack_msb=True)
