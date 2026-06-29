import struct
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

class WavFile:
    """
    A custom robust RIFF/WAV parser for digital forensics.
    Parses headers, custom chunks, metadata lists, trailing data, and handles
    various bit depths (8, 16, 24, 32-bit PCM and 32-bit IEEE float).
    """
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.file_size = self.file_path.stat().st_size
        
        self.riff_size: int = 0
        self.channels: int = 0
        self.sample_rate: int = 0
        self.bits_per_sample: int = 0
        self.audio_format: int = 0
        self.block_align: int = 0
        self.byte_rate: int = 0
        
        self.chunks: List[Dict[str, Any]] = []
        self.metadata: Dict[str, str] = {}
        self.trailer_data: bytes = b""
        self.raw_data_bytes: bytes = b""
        
        self.raw_samples: np.ndarray = np.array([], dtype=np.int32)
        self.normalized_samples: np.ndarray = np.array([], dtype=np.float32)
        
        self._parse()

    def _parse(self):
        """
        Parses the binary structure of the audio file.
        Attempts to read RIFF/WAV chunks first. If the file is not a WAV, 
        falls back to decoding via the 'soundfile' library.
        """
        with open(self.file_path, "rb") as f:
            file_bytes = f.read()

        if len(file_bytes) < 12:
            raise ValueError("File is too small to be a valid audio file.")

        is_wav = False
        try:
            # Check RIFF header
            riff_header, riff_size, wave_header = struct.unpack("<4sI4s", file_bytes[0:12])
            if riff_header == b"RIFF" and wave_header == b"WAVE":
                is_wav = True
        except Exception:
            pass

        if is_wav:
            self.riff_size = riff_size
            
            # Traverse chunks
            offset = 12
            max_chunk_end = 12
            file_len = len(file_bytes)

            while offset + 8 <= file_len:
                chunk_id, chunk_size = struct.unpack("<4sI", file_bytes[offset:offset+8])
                chunk_start = offset
                data_start = offset + 8
                
                # Align chunk_size to even bytes as per RIFF standard
                aligned_size = chunk_size + (chunk_size % 2)
                chunk_end = data_start + aligned_size
                
                if chunk_end > file_len:
                    # Truncated chunk or malformed file, read as much as possible
                    chunk_data_bytes = file_bytes[data_start:file_len]
                    chunk_end = file_len
                else:
                    chunk_data_bytes = file_bytes[data_start:data_start+chunk_size]

                chunk_info = {
                    "id": chunk_id.decode("ascii", errors="ignore").strip(),
                    "size": chunk_size,
                    "offset": data_start,
                    "raw_id": chunk_id.decode("ascii", errors="ignore")
                }
                self.chunks.append(chunk_info)

                # Parse known chunks
                if chunk_id == b"fmt ":
                    self._parse_fmt_chunk(chunk_data_bytes)
                elif chunk_id == b"data":
                    self.raw_data_bytes = chunk_data_bytes
                elif chunk_id == b"LIST":
                    self._parse_list_chunk(chunk_data_bytes)

                offset = chunk_end
                if chunk_end > max_chunk_end:
                    max_chunk_end = chunk_end

            # Calculate trailer data (appended payload)
            # 1. Bytes after the maximum chunk end
            # 2. Bytes after the RIFF size + 8 boundary
            trailer_start_by_chunks = max_chunk_end
            trailer_start_by_riff = riff_size + 8
            
            # We take the minimum of these two to be safe, or chunks end
            trailer_start = min(trailer_start_by_chunks, trailer_start_by_riff)
            if trailer_start < file_len:
                self.trailer_data = file_bytes[trailer_start:]

            # If data chunk was found, decode the samples
            if self.raw_data_bytes and self.channels > 0:
                self._decode_samples()
        else:
            # Fallback to soundfile for other formats (MP3, FLAC, OGG, etc.)
            try:
                import soundfile as sf
                data, samplerate = sf.read(self.file_path, dtype='float32')
                info = sf.info(self.file_path)
                
                self.riff_size = 0
                self.sample_rate = samplerate
                
                if len(data.shape) > 1:
                    self.channels = data.shape[1]
                else:
                    self.channels = 1
                    data = data.reshape(-1, 1)
                    
                subtype = info.subtype
                if "16" in subtype:
                    self.bits_per_sample = 16
                elif "24" in subtype:
                    self.bits_per_sample = 24
                elif "32" in subtype:
                    self.bits_per_sample = 32
                elif "FLOAT" in subtype:
                    self.bits_per_sample = 32
                elif "64" in subtype:
                    self.bits_per_sample = 64
                elif "8" in subtype:
                    self.bits_per_sample = 8
                else:
                    self.bits_per_sample = 16
                    
                self.audio_format = 3 if "FLOAT" in subtype or "DOUBLE" in subtype else 1
                self.normalized_samples = data
                
                if self.bits_per_sample == 16:
                    self.raw_samples = (data * 32768.0).astype(np.int32)
                elif self.bits_per_sample == 24:
                    self.raw_samples = (data * 8388608.0).astype(np.int32)
                elif self.bits_per_sample == 32:
                    self.raw_samples = (data * 2147483648.0).astype(np.int32)
                elif self.bits_per_sample == 8:
                    self.raw_samples = (data * 128.0 + 128.0).astype(np.int32)
                else:
                    self.raw_samples = (data * 32768.0).astype(np.int32)
                    
                self.raw_samples = self.raw_samples.reshape(-1, self.channels)
                self.normalized_samples = self.normalized_samples.reshape(-1, self.channels)
                
                self.raw_data_bytes = file_bytes
                self.chunks = []
                self.metadata = {}
                self.trailer_data = b""
            except Exception as e:
                raise ValueError(f"Failed to parse audio file with WAV parser and soundfile fallback: {e}")

    def _parse_fmt_chunk(self, data: bytes):
        """
        Parses the 'fmt ' subchunk of a WAV file to retrieve sample rate,
        bit depth, channels, block alignment, and encoding format.
        """
        if len(data) < 16:
            raise ValueError("fmt chunk is too short.")
        
        fmt_data = struct.unpack("<HHIIHH", data[:16])
        self.audio_format = fmt_data[0]
        self.channels = fmt_data[1]
        self.sample_rate = fmt_data[2]
        self.byte_rate = fmt_data[3]
        self.block_align = fmt_data[4]
        self.bits_per_sample = fmt_data[5]

    def _parse_list_chunk(self, data: bytes):
        """
        Parses 'LIST' chunks containing 'INFO' subchunks to extract 
        standard tags and metadata (such as author, title, creation date).
        """
        if len(data) < 4:
            return
        
        list_type = data[0:4]
        if list_type == b"INFO":
            # Parse INFO sub-chunks
            offset = 4
            while offset + 8 <= len(data):
                sub_id, sub_size = struct.unpack("<4sI", data[offset:offset+8])
                sub_start = offset + 8
                aligned_size = sub_size + (sub_size % 2)
                sub_end = sub_start + aligned_size
                
                tag_name = sub_id.decode("ascii", errors="ignore").strip()
                tag_value = data[sub_start:min(sub_start+sub_size, len(data))].decode("utf-8", errors="ignore").rstrip("\x00")
                
                if tag_name:
                    self.metadata[tag_name] = tag_value
                
                offset = sub_end

    def _decode_samples(self):
        """
        Decodes the raw binary data subchunk bytes into numpy arrays.
        Supports 8-bit unsigned PCM, 16/24/32-bit signed PCM, and 32/64-bit IEEE float formats.
        Normalizes samples to the range [-1.0, 1.0].
        """
        bytes_per_sample = self.bits_per_sample // 8
        if bytes_per_sample == 0:
            return
        
        n_samples_total = len(self.raw_data_bytes) // bytes_per_sample
        
        if self.audio_format == 1:  # PCM Integer
            if self.bits_per_sample == 8:
                samples = np.frombuffer(self.raw_data_bytes[:n_samples_total], dtype=np.uint8).astype(np.int16)
                # WAV 8-bit is unsigned (0 to 255), we normalize around 128
                self.raw_samples = samples
                self.normalized_samples = (samples.astype(np.float32) - 128.0) / 128.0
            
            elif self.bits_per_sample == 16:
                samples = np.frombuffer(self.raw_data_bytes[:n_samples_total * 2], dtype=np.int16)
                self.raw_samples = samples.astype(np.int32)
                self.normalized_samples = samples.astype(np.float32) / 32768.0
            
            elif self.bits_per_sample == 24:
                # 24-bit PCM: 3 bytes per sample
                raw_bytes = np.frombuffer(self.raw_data_bytes[:n_samples_total * 3], dtype=np.uint8)
                # High performance unpacking using numpy
                padded = np.zeros(n_samples_total * 4, dtype=np.uint8)
                padded[0::4] = raw_bytes[0::3]
                padded[1::4] = raw_bytes[1::3]
                padded[2::4] = raw_bytes[2::3]
                # Sign extension
                sign_mask = (raw_bytes[2::3] >= 128)
                padded[3::4] = np.where(sign_mask, 255, 0)
                
                samples = padded.view(dtype=np.int32)
                self.raw_samples = samples
                self.normalized_samples = samples.astype(np.float32) / 8388608.0
            
            elif self.bits_per_sample == 32:
                samples = np.frombuffer(self.raw_data_bytes[:n_samples_total * 4], dtype=np.int32)
                self.raw_samples = samples
                self.normalized_samples = samples.astype(np.float32) / 2147483648.0
                
        elif self.audio_format == 3:  # IEEE Float
            if self.bits_per_sample == 32:
                samples = np.frombuffer(self.raw_data_bytes[:n_samples_total * 4], dtype=np.float32)
                self.normalized_samples = samples
                # Scaled integer values for bitplane extraction
                self.raw_samples = (samples * 2147483648.0).astype(np.int32)
            elif self.bits_per_sample == 64:
                samples = np.frombuffer(self.raw_data_bytes[:n_samples_total * 8], dtype=np.float64).astype(np.float32)
                self.normalized_samples = samples
                self.raw_samples = (samples * 2147483648.0).astype(np.int32)
        
        # Reshape to (N_samples, Channels)
        n_frames = len(self.raw_samples) // self.channels
        self.raw_samples = self.raw_samples[:n_frames * self.channels].reshape(-1, self.channels)
        self.normalized_samples = self.normalized_samples[:n_frames * self.channels].reshape(-1, self.channels)

    @property
    def duration(self) -> float:
        if self.sample_rate == 0:
            return 0.0
        return self.raw_samples.shape[0] / self.sample_rate

    @property
    def has_trailer(self) -> bool:
        return len(self.trailer_data) > 0

    @property
    def trailer_size(self) -> int:
        return len(self.trailer_data)

    @property
    def info_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_path.name,
            "file_size": self.file_size,
            "riff_size": self.riff_size,
            "channels": self.channels,
            "sample_rate": self.sample_rate,
            "bits_per_sample": self.bits_per_sample,
            "audio_format": "PCM" if self.audio_format == 1 else "Float" if self.audio_format == 3 else f"Unknown ({self.audio_format})",
            "duration_seconds": self.duration,
            "total_samples": self.raw_samples.shape[0],
            "has_trailer": len(self.trailer_data) > 0,
            "trailer_size": len(self.trailer_data),
            "metadata": self.metadata,
            "chunks": self.chunks
        }
