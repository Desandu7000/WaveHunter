import sys
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

# WaveHunter modules
from wavehunter import __version__, __author__
from wavehunter.core.audio import WavFile
from wavehunter.core.entropy import sliding_window_entropy, shannon_entropy
from wavehunter.core.scoring import rank_candidates
from wavehunter.core.report import generate_html_report, generate_json_report, generate_text_report

# Extractors
from wavehunter.extractors.bitplanes import extract_all_bitplanes, extract_bitplane
from wavehunter.extractors.channels import extract_channels
from wavehunter.extractors.interleave import extract_interleaved
from wavehunter.extractors.stride import extract_strided
from wavehunter.extractors.reverse import extract_reversed
from wavehunter.extractors.graycode import extract_graycode
from wavehunter.extractors.delta import extract_delta
from wavehunter.extractors.phase import extract_phase
from wavehunter.extractors.printable import extract_printable_text

# Scanners
from wavehunter.scanners.magic import scan_magic
from wavehunter.scanners.regex import scan_regex
from wavehunter.scanners.ascii import scan_ascii
from wavehunter.scanners.compression import scan_compression

app = typer.Typer(
    name="wavehunter",
    help="WaveHunter: An open-source Python toolkit for audio forensics, steganography, and CTF challenges."
)
console = Console()

BANNER = f"""[bold blue]
██╗    ██╗ █████╗ ██╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║    ██║██╔══██╗██║   ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║███████║██║   ██║█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║███╗██║██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║ ╚████╔╝ ███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
[/bold blue][bold cyan]                 Forensics and Steganography Toolkit v{__version__}[/bold cyan]
[bold white]                         by {__author__}[/bold white]
"""

def print_banner():
    console.print(BANNER)

@app.command()
def analyze(
    file_path: Path = typer.Argument(..., help="Path to the WAV file to analyze.", exists=True, dir_okay=False),
    html_report: Optional[Path] = typer.Option(None, "--html", "-o", help="Path to save the HTML dashboard report."),
    json_report: Optional[Path] = typer.Option(None, "--json", "-j", help="Path to save the JSON data report."),
    txt_report: Optional[Path] = typer.Option(None, "--txt", "-t", help="Path to save the text report.")
):
    """
    Performs a full forensic analysis scan on a WAV file.
    Applies all extractors and scanners, ranks candidates, and generates reports.
    """
    print_banner()
    
    console.print(f"[yellow][*][/yellow] Loading WAV file: [bold green]{file_path}[/bold green]")
    try:
        wav = WavFile(file_path)
    except Exception as e:
        console.print(f"[bold red]Error parsing WAV file: {e}[/bold red]")
        sys.exit(1)
        
    info = wav.info_dict
    
    # Render Metadata Table
    table = Table(title="Audio File Metadata", show_header=True, header_style="bold blue")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("File Name", info["file_name"])
    table.add_row("File Size", f"{info['file_size']} bytes")
    table.add_row("Format", info["audio_format"])
    table.add_row("Channels", str(info["channels"]))
    table.add_row("Sample Rate", f"{info['sample_rate']} Hz")
    table.add_row("Bit Depth", f"{info['bits_per_sample']} bits")
    table.add_row("Duration", f"{info['duration_seconds']:.3f} seconds")
    table.add_row("Trailer Payload Detected", f"[bold red]YES ({info['trailer_size']} bytes)[/bold red]" if info["has_trailer"] else "NO")
    
    console.print(table)
    
    candidates = []
    
    # Run pipeline with progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # Task 1: Bitplane
        task = progress.add_task("[cyan]Extracting bitplanes...", total=1)
        candidates.extend(extract_all_bitplanes(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 2: Channel Math
        task = progress.add_task("[cyan]Extracting channels & logical products...", total=1)
        candidates.extend(extract_channels(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 3: Stereo Interleaving
        task = progress.add_task("[cyan]Extracting interleaved frames...", total=1)
        candidates.extend(extract_interleaved(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 4: Sample Strides
        task = progress.add_task("[cyan]Extracting strided bitstreams...", total=1)
        candidates.extend(extract_strided(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 5: Reversals
        task = progress.add_task("[cyan]Extracting reversed audio streams...", total=1)
        candidates.extend(extract_reversed(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 6: Gray Decoding
        task = progress.add_task("[cyan]Extracting Gray-decoded sequences...", total=1)
        candidates.extend(extract_graycode(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 7: Delta Decoding
        task = progress.add_task("[cyan]Extracting Delta-decoded streams...", total=1)
        candidates.extend(extract_delta(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)
        
        # Task 8: Phase Coding
        task = progress.add_task("[cyan]Extracting Fourier phase bits...", total=1)
        candidates.extend(extract_phase(wav.normalized_samples))
        progress.update(task, completed=1)
        
        # Task 9: Printable Text
        task = progress.add_task("[cyan]Extracting raw printable text segments...", total=1)
        candidates.extend(extract_printable_text(wav.raw_samples, wav.bits_per_sample))
        progress.update(task, completed=1)

        # Task 10: Trailer
        if wav.trailer_data:
            task = progress.add_task("[bold red]Extracting appended WAV trailer...", total=1)
            candidates.append({
                "name": "WAV Trailer (Appended Bytes)",
                "source": "wav_trailer_payload",
                "data": wav.trailer_data
            })
            progress.update(task, completed=1)

        # Task 11: Scoring & Ranking
        task = progress.add_task("[cyan]Scoring & ranking stego candidates...", total=1)
        ranked = rank_candidates(candidates)
        progress.update(task, completed=1)
        
    # Render Findings
    console.print("\n[yellow][*][/yellow] [bold]Analysis Summary - Top Suspicious Findings:[/bold]\n")
    
    findings_table = Table(show_header=True, header_style="bold blue")
    findings_table.add_column("Rating", style="yellow", justify="center")
    findings_table.add_column("Candidate Source", style="cyan")
    findings_table.add_column("Size", style="green")
    findings_table.add_column("Entropy", style="magenta")
    findings_table.add_column("Finding Summary", style="white")
    
    interesting = [r for r in ranked if r["rating"] >= 2]
    
    for r in interesting[:10]:
        findings_table.add_row(
            r["stars"],
            r["name"],
            f"{r['size']} B",
            f"{r['entropy']:.4f}",
            r["reason"]
        )
        
    if not interesting:
        console.print(Panel("No suspicious steganography or hidden payloads found in the audio stream.", style="green"))
    else:
        console.print(findings_table)
        
    # Write Reports
    if txt_report:
        txt_str = generate_text_report(info, ranked)
        txt_report.write_text(txt_str, encoding="utf-8")
        console.print(f"[green][+][/green] Text report saved to: [bold white]{txt_report}[/bold white]")
        
    if json_report:
        generate_json_report(info, ranked, json_report)
        console.print(f"[green][+][/green] JSON report saved to: [bold white]{json_report}[/bold white]")
        
    if html_report:
        # Generate sliding window entropy of raw data chunk bytes for the HTML chart
        ent_data = sliding_window_entropy(wav.raw_data_bytes, window_size=2048, step_size=1024)
        generate_html_report(info, ranked, ent_data, html_report)
        console.print(f"[green][+][/green] Interactive HTML report dashboard saved to: [bold white]{html_report}[/bold white]")

@app.command()
def extract(
    file_path: Path = typer.Argument(..., help="Path to the WAV file.", exists=True, dir_okay=False),
    extractor: str = typer.Argument(..., help="Extractor type: bitplane, channel, reverse, stride, gray, delta, phase"),
    channel: int = typer.Option(0, "--channel", "-c", help="Channel index to extract (starting at 0)."),
    bit: int = typer.Option(0, "--bit", "-b", help="Bit position (0 for LSB)."),
    stride: int = typer.Option(2, "--stride", "-s", help="Stride interval (for stride extractor)."),
    pack: str = typer.Option("msb", "--pack", "-p", help="Bit packing order: msb or lsb."),
    out: Path = typer.Option(..., "--out", "-o", help="Output file path to save extracted bytes.")
):
    """
    Extracts a specific raw binary byte stream from the audio file and saves it.
    """
    print_banner()
    
    console.print(f"[yellow][*][/yellow] Loading: [bold]{file_path}[/bold]")
    wav = WavFile(file_path)
    
    pack_msb = pack.lower() == "msb"
    extracted_bytes = b""
    
    if extractor == "bitplane":
        console.print(f"[yellow][*][/yellow] Extracting bitplane [bold]channel {channel}, bit {bit} ({pack} packed)[/bold]...")
        extracted_bytes = extract_bitplane(wav.raw_samples, wav.bits_per_sample, channel, bit, pack_msb=pack_msb)
        
    elif extractor == "channel":
        console.print(f"[yellow][*][/yellow] Extracting [bold]channel {channel}[/bold] raw stream...")
        # Get channel raw stream
        ch_candidates = extract_channels(wav.raw_samples, wav.bits_per_sample)
        # Search for requested channel
        target_src = f"channel_{channel}_raw"
        for cand in ch_candidates:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
                
    elif extractor == "reverse":
        console.print(f"[yellow][*][/yellow] Extracting reversed stream...")
        revs = extract_reversed(wav.raw_samples, wav.bits_per_sample)
        target_src = f"reverse_samples_ch{channel}"
        for cand in revs:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
                
    elif extractor == "stride":
        console.print(f"[yellow][*][/yellow] Extracting strided samples with stride {stride}...")
        strides = extract_strided(wav.raw_samples, wav.bits_per_sample)
        target_src = f"stride_samples_ch{channel}_s{stride}"
        for cand in strides:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
                
    elif extractor == "gray":
        console.print(f"[yellow][*][/yellow] Extracting Gray-decoded channel {channel} samples...")
        grays = extract_graycode(wav.raw_samples, wav.bits_per_sample)
        target_src = f"gray_samples_ch{channel}"
        for cand in grays:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
                
    elif extractor == "delta":
        console.print(f"[yellow][*][/yellow] Extracting Delta-decoded channel {channel} samples...")
        deltas = extract_delta(wav.raw_samples, wav.bits_per_sample)
        target_src = f"delta_samples_ch{channel}"
        for cand in deltas:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
                
    elif extractor == "phase":
        console.print(f"[yellow][*][/yellow] Extracting Fourier phase bits from channel {channel}...")
        phases = extract_phase(wav.normalized_samples)
        target_src = f"phase_fft_ch{channel}_{'msb' if pack_msb else 'lsb'}"
        for cand in phases:
            if cand["source"] == target_src:
                extracted_bytes = cand["data"]
                break
    else:
        console.print(f"[bold red]Unknown extractor: {extractor}[/bold red]")
        sys.exit(1)
        
    if not extracted_bytes:
        console.print("[bold red]Failed to extract bytes. Source stream was empty or invalid.[/bold red]")
        sys.exit(1)
        
    out.write_bytes(extracted_bytes)
    console.print(f"[green][+][/green] Saved [bold]{len(extracted_bytes)} bytes[/bold] to: [bold white]{out}[/bold white]")

@app.command()
def scan(
    file_path: Path = typer.Argument(..., help="Path to raw binary file or stream to scan.", exists=True, dir_okay=False)
):
    """
    Scans a raw binary file for signs of hidden payloads (signatures, flags, text).
    """
    print_banner()
    
    console.print(f"[yellow][*][/yellow] Scanning raw file: [bold]{file_path}[/bold]")
    data = file_path.read_bytes()
    
    entropy = shannon_entropy(data)
    console.print(f"[yellow][*][/yellow] Entropy: [bold]{entropy:.4f}[/bold] / 8.00")
    
    magics = scan_magic(data)
    regexes = scan_regex(data)
    comps = scan_compression(data)
    asciis = scan_ascii(data, min_len=6)
    
    if magics:
        table = Table(title="Detected File Signatures (Magic Bytes)", show_header=True, header_style="bold blue")
        table.add_column("Offset (Dec)", style="cyan")
        table.add_column("Offset (Hex)", style="cyan")
        table.add_column("File Type", style="green")
        table.add_column("Estimated Size", style="magenta")
        table.add_column("Confidence", style="white")
        
        for m in magics:
            table.add_row(
                str(m["start_offset"]),
                f"0x{m['start_offset']:08x}",
                m["name"],
                f"{m['estimated_size']} B" if m["estimated_size"] else "Unknown",
                m["confidence"]
            )
        console.print(table)
        
    if regexes:
        table = Table(title="Regex Pattern Matches", show_header=True, header_style="bold blue")
        table.add_column("Offset (Hex)", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Matched Value", style="magenta")
        
        for r in regexes:
            table.add_row(
                f"0x{r['offset']:08x}",
                r["type"],
                r["value"]
            )
        console.print(table)
        
    if comps:
        table = Table(title="Decompressible Streams", show_header=True, header_style="bold blue")
        table.add_column("Offset (Hex)", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Compressed Size", style="magenta")
        table.add_column("Decompressed Size", style="magenta")
        
        for c in comps:
            table.add_row(
                f"0x{c['offset']:08x}",
                c["type"],
                f"{c['compressed_size']} bytes",
                f"{c['decompressed_size']} bytes"
            )
        console.print(table)

    if asciis:
        console.print(f"[green][+][/green] Found [bold]{len(asciis)}[/bold] readable ASCII text strings (min length 6).")
        # Print first 10
        for idx, a in enumerate(asciis[:15]):
            console.print(f"  [cyan]0x{a['offset']:08x}[/cyan]: '{a['text']}'")
        if len(asciis) > 15:
            console.print(f"  ... and {len(asciis)-15} more.")

    if not (magics or regexes or comps or asciis):
        console.print("[yellow][*][/yellow] No headers, flags, or readable text patterns found.")

if __name__ == "__main__":
    app()
