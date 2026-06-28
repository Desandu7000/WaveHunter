from typing import Dict, Any, List
import numpy as np

class BasePlugin:
    """Base class for all WaveHunter plugins."""
    name: str = "Base Plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = ""

    def register(self) -> Dict[str, Any]:
        """Declares plugin metadata and capabilities."""
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
        }

class SignalDetectorPlugin(BasePlugin):
    """Plugin interface for custom signal carrier/modulation detectors."""
    def detect(self, samples: np.ndarray, sample_rate: int) -> Dict[str, Any]:
        """
        Runs custom detection logic.
        Returns: {
            "similarity": float (0.0 to 1.0),
            "reason": str,
            "suggested_demodulator": str,
            "parameters": Dict[str, Any]
        }
        """
        raise NotImplementedError

class DemodulatorPlugin(BasePlugin):
    """Plugin interface for custom demodulators."""
    def demodulate(self, samples: np.ndarray, sample_rate: int, parameters: Dict[str, Any]) -> bytes:
        """
        Runs custom demodulator logic.
        Returns: byte stream.
        """
        raise NotImplementedError

class DecoderPlugin(BasePlugin):
    """Plugin interface for custom byte/payload decoders."""
    def decode(self, data: bytes) -> bytes:
        """
        Runs custom decoder logic.
        Returns: decoded bytes or empty bytes if failed.
        """
        raise NotImplementedError

class PatternScannerPlugin(BasePlugin):
    """Plugin interface for custom pattern/intelligence scanners."""
    def scan(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Runs custom scanning logic.
        Returns: List of findings: [{"offset": int, "type": str, "value": str, "confidence": float}]
        """
        raise NotImplementedError
