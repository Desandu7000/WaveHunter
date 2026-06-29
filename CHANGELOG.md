# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-06-29
### Added
- `--thorough` / `-T` flag on the `analyze` command for fully exhaustive scanning (all stride offsets, full candidate scoring).
- Fast pre-filter in the scoring pipeline to skip clear noise streams before running expensive scanners.
- SIGINT input auto-downsampling: files with sample rates above 22,050 Hz are downsampled 2x before STFT analysis, halving computation time with no meaningful detection loss.

### Changed
- Default behavior of `analyze` is now **fast mode**: stride extractor limits offset permutations for large strides (>16), and the scoring pre-filter is active. Use `--thorough` to restore full exhaustive analysis.
- `extract_strided()` now accepts a `thorough` parameter; large strides (>16) only test offset 0 in fast mode.
- `rank_candidates()` now accepts a `thorough` parameter; fast mode applies cheap entropy + preview scan before full scoring.

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
