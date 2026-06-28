import numpy as np
from typing import List, Dict, Any
from wavehunter.core.utils import bits_to_bytes

def extract_phase(normalized_samples: np.ndarray, frame_size: int = 1024) -> List[Dict[str, Any]]:
    """
    Performs Fourier Phase analysis on the audio channels.
    Splits the audio into frames, computes the DFT (FFT) of each frame,
    extracts the phase angle of the first few frequency bins, binarizes them
    (positive phase = 1, negative phase = 0), and packs them.
    """
    candidates = []
    n_samples, n_channels = normalized_samples.shape
    
    # We need enough samples to form frames
    if n_samples < frame_size:
        return candidates
        
    for ch in range(n_channels):
        channel_data = normalized_samples[:, ch]
        
        # Calculate number of frames (no overlap for simple extraction)
        n_frames = n_samples // frame_size
        frames = channel_data[:n_frames * frame_size].reshape(n_frames, frame_size)
        
        # Compute FFT for each frame (along rows)
        fft_out = np.fft.rfft(frames, axis=1)
        
        # Extract the phase angles of the first few AC frequency components (bins 1 to 8)
        # Bin 0 is DC offset, which has no phase information
        if fft_out.shape[1] > 9:
            # Phase shape: (n_frames, 8)
            phases = np.angle(fft_out[:, 1:9])
            
            # Binarize: True/1 if phase is positive, False/0 if phase is negative
            bits = (phases > 0.0).flatten()
            
            for msb in [True, False]:
                bits_data = bits_to_bytes(bits, pack_msb=msb)
                if len(bits_data) >= 8:
                    candidates.append({
                        "name": f"Channel {ch} FFT Phase Bins 1-8 ({'MSB' if msb else 'LSB'} packed)",
                        "source": f"phase_fft_ch{ch}_{'msb' if msb else 'lsb'}",
                        "data": bits_data
                    })
                    
    return candidates
