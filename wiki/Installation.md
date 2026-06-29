# Installation Guide

This guide covers the prerequisites, dependencies, and setup instructions for WaveHunter.

## Prerequisites

WaveHunter requires **Python 3.12+**. 

The following system libraries may be required for signal plotting and mathematical computations:
* **FFTW** (Optional, for optimized FFTs under SciPy)
* **Tkinter** or another Matplotlib backend (For displaying interactive plots, though WaveHunter defaults to saving plots directly to files)

---

## Installation Steps

### 1. Clone the Repository

Clone the project from GitHub:

```bash
git clone https://github.com/Desandu7000/WaveHunter.git
cd WaveHunter
```

### 2. Set Up a Virtual Environment (Recommended)

It is highly recommended to use a virtual environment to prevent package version conflicts:

```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Package and Dependencies

Install the core dependencies and build the package in editable mode:

```bash
pip install -r requirements.txt
pip install -e .
```

*Note: The editable flag (`-e`) enables you to run the global `wavehunter` CLI command directly, reflecting any changes you make to the source code immediately.*

### 4. Optional / Developer Dependencies

If you plan to run tests, write plugins, or contribute to WaveHunter, install the development dependencies:

```bash
pip install -e .[dev]
```

This installs `pytest`, allowing you to run:
```bash
pytest
```

---

## Dependencies List

WaveHunter depends on several packages to perform scientific calculations and command-line rendering:

| Package | Purpose | Minimum Version |
| :--- | :--- | :--- |
| `typer` | Clean CLI parsing and command generation | `0.9.0` |
| `rich` | Terminal banner, tables, progress bars, and syntax highlighting | `13.0.0` |
| `numpy` | High-performance array operations for sample data manipulation | `1.24.0` |
| `scipy` | DSP utilities: filter designs, FFT, spectrograms, and signal analysis | `1.11.0` |
| `matplotlib` | High-quality diagnostic visualizations and constellation plotting | `3.8.0` |
| `PyWavelets` | Wavelet analysis (`pywt`) for multiresolution discrete wavelet transform | `1.4.0` |

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'pywt'`
If you encounter this error, install the wavelet package manually:
```bash
pip install PyWavelets
```

### Matplotlib Backend Warning on headless Linux
If you run `wavehunter plot` on a headless Linux server, Matplotlib might complain about missing graphical backends. WaveHunter saves plots to disk and does not require an active display. You can ignore this warning or set the backend to non-interactive manually:
```bash
export MPLBACKEND=Agg
```
