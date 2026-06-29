# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-06-29
### Added
- Multi-format audio support: built-in fallback utilizing `soundfile` to load and analyze MP3, FLAC, OGG, and other audio formats.
- Custom flag format parameter (`--flag-format` / `-f`) for `analyze` and `scan` commands to dynamically scan for custom flags.
- Dynamic intelligence pattern and regex scanner compilation for custom flag formats.
- Improved setuptools package discovery configurations in `pyproject.toml`.

### Removed
- Hardcoded `"animus"` and other AC specific keys/seeds from the scanning engines and spread spectrum chipping configurations.

## [0.1.0] - 2026-06-28
### Added
- Initial project bootstrap.
- Custom WAV RIFF binary parser.
- Core entropy analysis modules.
- Multiple analysis extractors (Bitplanes, Channels, Interleaving, Strides, Reversals, Gray code, Delta, Phase, Printable strings).
- Scanners (ASCII, Regex, Magic Signatures, Compression).
- Typer-based console command line interface.
- Rich-based interactive console output.
- HTML, JSON, and text reporting modules.
