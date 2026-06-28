import importlib.util
import inspect
from pathlib import Path
from typing import List, Dict, Any, Type
from wavehunter.plugins.base import (
    BasePlugin,
    SignalDetectorPlugin,
    DemodulatorPlugin,
    DecoderPlugin,
    PatternScannerPlugin
)

class PluginManager:
    """Manages the discovery, loading, and registration of WaveHunter plugins."""
    def __init__(self, plugins_dir: str | Path = None):
        if plugins_dir is None:
            # Default to the plugins/ folder inside the workspace or wavehunter package
            plugins_dir = Path(__file__).parent.parent / "plugins"
        self.plugins_dir = Path(plugins_dir)
        
        self.detectors: List[SignalDetectorPlugin] = []
        self.demodulators: Dict[str, DemodulatorPlugin] = {}
        self.decoders: List[DecoderPlugin] = []
        self.scanners: List[PatternScannerPlugin] = []
        
        self.loaded_plugins: List[BasePlugin] = []

    def discover_and_load(self) -> None:
        """
        Discovers all Python files in the plugins directory and loads 
        any subclasses of WaveHunter plugin types.
        """
        if not self.plugins_dir.exists() or not self.plugins_dir.is_dir():
            return
            
        for path in self.plugins_dir.glob("*.py"):
            if path.name in ["__init__.py", "base.py", "manager.py"]:
                continue
                
            try:
                # Load module dynamically
                spec = importlib.util.spec_from_file_location(path.stem, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Scan module for classes
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    # Class must belong to the module loaded and be a subclass of BasePlugin (but not the base classes themselves)
                    if obj.__module__ == path.stem and issubclass(obj, BasePlugin) and obj not in [
                        BasePlugin, SignalDetectorPlugin, DemodulatorPlugin, DecoderPlugin, PatternScannerPlugin
                    ]:
                        instance = obj()
                        self.register_plugin(instance)
            except Exception:
                # Fail silently or log error for malformed plugins
                continue

    def register_plugin(self, instance: BasePlugin) -> None:
        """Registers a plugin instance into its corresponding category."""
        self.loaded_plugins.append(instance)
        
        if isinstance(instance, SignalDetectorPlugin):
            self.detectors.append(instance)
        if isinstance(instance, DemodulatorPlugin):
            # Key demodulators by name/type or custom identifier
            self.demodulators[instance.name.lower()] = instance
        if isinstance(instance, DecoderPlugin):
            self.decoders.append(instance)
        if isinstance(instance, PatternScannerPlugin):
            self.scanners.append(instance)
            
    def get_plugin_summary(self) -> List[Dict[str, Any]]:
        """Returns metadata summaries for all loaded plugins."""
        return [p.register() for p in self.loaded_plugins]
