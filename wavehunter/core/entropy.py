import math
import numpy as np
from typing import List, Union

def shannon_entropy(data: Union[bytes, bytearray, np.ndarray]) -> float:
    """
    Computes the Shannon entropy of a byte array (returns a value between 0.0 and 8.0).
    """
    if not len(data):
        return 0.0
        
    if isinstance(data, (bytes, bytearray)):
        arr = np.frombuffer(data, dtype=np.uint8)
    else:
        arr = np.asarray(data)
        if arr.dtype != np.uint8:
            arr = arr.view(dtype=np.uint8).flatten()
            
    if not len(arr):
        return 0.0

    counts = np.bincount(arr)
    probs = counts[counts > 0] / len(arr)
    return -float(np.sum(probs * np.log2(probs)))

def sliding_window_entropy(data: Union[bytes, bytearray, np.ndarray], 
                           window_size: int = 2048, 
                           step_size: int = 1024) -> List[float]:
    """
    Calculates Shannon entropy across the data using a sliding window.
    Useful for plotting and finding localized high-entropy regions (e.g. encrypted files).
    """
    if isinstance(data, (bytes, bytearray)):
        arr = np.frombuffer(data, dtype=np.uint8)
    else:
        arr = np.asarray(data)
        if arr.dtype != np.uint8:
            arr = arr.view(dtype=np.uint8).flatten()

    n = len(arr)
    if n <= window_size:
        return [shannon_entropy(arr)]

    entropies = []
    for offset in range(0, n - window_size + 1, step_size):
        window = arr[offset : offset + window_size]
        entropies.append(shannon_entropy(window))
        
    return entropies
