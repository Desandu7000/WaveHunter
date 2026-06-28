import json
from pathlib import Path
from typing import Dict, Any, List
from wavehunter import __version__, __author__
from wavehunter.core.utils import format_bytes

def generate_json_report(info: Dict[str, Any], candidates: List[Dict[str, Any]], output_path: str | Path):
    """
    Saves the analysis results to a JSON file.
    """
    report_data = {
        "wavehunter_version": __version__,
        "author": __author__,
        "audio_info": info,
        # Exclude raw byte arrays from candidates in JSON to keep size small
        "candidates": [
            {k: v for k, v in c.items() if k != "data"}
            for c in candidates
        ]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

def generate_text_report(info: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """
    Generates a plain text summary report of the analysis.
    """
    lines = [
        f"WaveHunter v{__version__} Analysis Report",
        f"Author: {__author__}",
        "=" * 60,
        f"File:            {info['file_name']}",
        f"Size:            {info['file_size']} bytes",
        f"Format:          {info['audio_format']}",
        f"Channels:        {info['channels']}",
        f"Sample Rate:     {info['sample_rate']} Hz",
        f"Bit Depth:       {info['bits_per_sample']} bits",
        f"Duration:        {info['duration_seconds']:.2f} seconds",
        f"Trailer Payload: {'Yes (' + str(info['trailer_size']) + ' bytes)' if info['has_trailer'] else 'No'}",
        "=" * 60,
        "TOP CANDIDATES FINDINGS:",
    ]
    
    interesting = [c for c in candidates if c["rating"] >= 2]
    if not interesting:
        lines.append("No suspicious candidates or hidden patterns detected.")
    else:
        for idx, c in enumerate(interesting[:10]):
            lines.append(f"{idx+1}. {c['name']} [{c['stars']}] (Size: {c['size']} B, Entropy: {c['entropy']:.4f})")
            lines.append(f"   Reason: {c['reason']}")
            if c["findings"]:
                lines.append("   Findings:")
                for f in c["findings"]:
                    lines.append(f"     - {f}")
            lines.append(f"   Hex Preview: {c['preview_hex'][:60]}...")
            lines.append(f"   Asc Preview: {c['preview_ascii'][:40]}")
            lines.append("-" * 60)
            
    return "\n".join(lines)

def generate_html_report(info: Dict[str, Any], 
                         candidates: List[Dict[str, Any]], 
                         entropy_data: List[float], 
                         output_path: str | Path):
    """
    Generates a premium dark-themed HTML forensics report.
    """
    # Filter candidates to show top findings first
    interesting_candidates = [c for c in candidates if c["rating"] >= 2]
    low_candidates = [c for c in candidates if c["rating"] < 2]

    # Convert entropy list to string for Javascript
    entropy_js_list = json.dumps(entropy_data)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WaveHunter Forensics Report - {info['file_name']}</title>
    <!-- Premium Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <!-- ChartJS for interactive graphs -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --panel-bg: rgba(20, 30, 55, 0.4);
            --panel-border: rgba(255, 255, 255, 0.08);
            --accent-primary: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.35);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --star-gold: #fbbf24;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(20, 32, 60, 0.3) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            line-height: 1.5;
            min-height: 100vh;
            padding: 2rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        /* Header Style */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--panel-border);
            margin-bottom: 2.5rem;
        }}

        .brand {{
            display: flex;
            flex-direction: column;
        }}

        .brand h1 {{
            font-size: 2.5rem;
            font-weight: 800;
            letter-spacing: -0.05em;
            background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px var(--accent-glow);
        }}

        .brand span {{
            font-size: 0.9rem;
            color: var(--text-muted);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }}

        .meta-badge {{
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            padding: 0.5rem 1rem;
            border-radius: 12px;
            font-size: 0.9rem;
            text-align: right;
            backdrop-filter: blur(8px);
        }}

        .meta-badge strong {{
            color: var(--accent-primary);
        }}

        /* Grid Layout */
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2.5rem;
        }}

        @media (max-width: 1024px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}
        }}

        /* Card Panels */
        .panel {{
            background: var(--panel-bg);
            border: 1px solid var(--panel-border);
            border-radius: 20px;
            padding: 1.75rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
            transition: transform 0.3s ease, border-color 0.3s ease;
        }}

        .panel:hover {{
            border-color: rgba(59, 130, 246, 0.2);
            transform: translateY(-2px);
        }}

        .panel h2 {{
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            border-left: 4px solid var(--accent-primary);
            padding-left: 0.75rem;
            letter-spacing: -0.02em;
        }}

        /* Info Grid */
        .info-list {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1.25rem;
        }}

        .info-item {{
            display: flex;
            flex-direction: column;
            background: rgba(255, 255, 255, 0.02);
            padding: 0.75rem 1rem;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }}

        .info-item .label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }}

        .info-item .value {{
            font-size: 1.1rem;
            font-weight: 600;
        }}

        /* Chunks Table */
        .table-container {{
            overflow-x: auto;
            max-height: 350px;
            overflow-y: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }}

        th {{
            padding: 0.75rem 1rem;
            color: var(--text-muted);
            border-bottom: 1px solid var(--panel-border);
            font-weight: 500;
        }}

        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* Findings List */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}

        .finding-card {{
            border-radius: 16px;
            border: 1px solid var(--panel-border);
            background: rgba(255, 255, 255, 0.015);
            padding: 1.25rem;
            transition: background-color 0.2s;
        }}

        .finding-card:hover {{
            background: rgba(255, 255, 255, 0.03);
        }}

        .finding-card.star-5 {{
            border-left: 5px solid var(--danger);
        }}
        .finding-card.star-4 {{
            border-left: 5px solid var(--warning);
        }}
        .finding-card.star-3 {{
            border-left: 5px solid var(--accent-primary);
        }}
        .finding-card.star-2 {{
            border-left: 5px solid var(--success);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 0.75rem;
        }}

        .finding-title {{
            font-weight: 600;
            font-size: 1.05rem;
        }}

        .finding-source {{
            font-size: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            background: rgba(59, 130, 246, 0.1);
            color: #93c5fd;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            margin-top: 0.25rem;
            display: inline-block;
        }}

        .finding-rating {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
        }}

        .stars {{
            color: var(--star-gold);
            font-size: 1.2rem;
            letter-spacing: 0.1em;
        }}

        .finding-meta {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.1rem;
        }}

        .finding-reason {{
            background: rgba(0, 0, 0, 0.15);
            padding: 0.75rem 1rem;
            border-radius: 10px;
            margin-bottom: 0.75rem;
            font-weight: 500;
            font-size: 0.95rem;
        }}

        .finding-details {{
            list-style-type: none;
            padding-left: 0.5rem;
            margin-bottom: 0.75rem;
        }}

        .finding-details li {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
            display: flex;
            align-items: center;
        }}

        .finding-details li::before {{
            content: "•";
            color: var(--accent-primary);
            font-weight: bold;
            display: inline-block; 
            width: 1em;
            margin-left: -1em;
            padding-left: 0.5rem;
        }}

        /* Hex & ASCII Preview Box */
        .preview-box {{
            background: #060913;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre;
        }}

        .preview-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.35rem;
        }}

        .preview-box .hex {{
            color: #cbd5e1;
            margin-bottom: 0.25rem;
        }}

        .preview-box .ascii {{
            color: var(--success);
        }}

        /* Collapsible List */
        .collapse-btn {{
            background: none;
            border: 1px solid var(--panel-border);
            color: var(--text-muted);
            padding: 0.5rem 1rem;
            border-radius: 10px;
            cursor: pointer;
            font-family: inherit;
            margin-top: 1rem;
            transition: all 0.2s;
        }}

        .collapse-btn:hover {{
            border-color: var(--accent-primary);
            color: var(--text-main);
        }}

        .collapsible-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}

        .collapsible-content.expanded {{
            max-height: 1000px;
            overflow-y: auto;
            margin-top: 1rem;
        }}

        footer {{
            text-align: center;
            padding-top: 3rem;
            border-top: 1px solid var(--panel-border);
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 4rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>WAVEHUNTER</h1>
                <span>Audio Steganography & Forensics Toolkit</span>
            </div>
            <div class="meta-badge">
                Report generated by <strong>WaveHunter v{__version__}</strong><br>
                Lead Architect: <strong>{__author__}</strong>
            </div>
        </header>

        <!-- Chart Container -->
        <div class="panel" style="margin-bottom: 2.5rem;">
            <h2>Sliding Window Shannon Entropy Plot</h2>
            <div style="height: 250px; position: relative; width: 100%;">
                <canvas id="entropyChart"></canvas>
            </div>
        </div>

        <div class="grid">
            <!-- Metadata Panel -->
            <div class="panel">
                <h2>Audio Metadata & Specifications</h2>
                <div class="info-list" style="margin-bottom: 1.5rem;">
                    <div class="info-item">
                        <span class="label">File Name</span>
                        <span class="value" style="word-break: break-all;">{info['file_name']}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">File Size</span>
                        <span class="value">{format_bytes(info['file_size'])}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Channels</span>
                        <span class="value">{info['channels']}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Sample Rate</span>
                        <span class="value">{info['sample_rate']} Hz</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Bit Depth</span>
                        <span class="value">{info['bits_per_sample']} bits</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Format</span>
                        <span class="value">{info['audio_format']}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Duration</span>
                        <span class="value">{info['duration_seconds']:.3f} s</span>
                    </div>
                    <div class="info-item" style="border-color: {'var(--danger)' if info['has_trailer'] else 'rgba(255,255,255,0.03)'}">
                        <span class="label">Trailer Payload</span>
                        <span class="value" style="color: {'var(--danger)' if info['has_trailer'] else 'inherit'}">
                            {f"Yes ({format_bytes(info['trailer_size'])})" if info['has_trailer'] else "No"}
                        </span>
                    </div>
                </div>

                <h3>WAV RIFF Chunks</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Chunk ID</th>
                                <th>Offset</th>
                                <th>Size (Declared)</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {"".join(f'''
                            <tr>
                                <td><code style="font-family: 'JetBrains Mono', monospace; font-weight: bold; color: var(--accent-primary);">{c['id']}</code></td>
                                <td>{c['offset']}</td>
                                <td>{format_bytes(c['size'])}</td>
                                <td>{"Audio Sample Data" if c['id'] == "data" else "Format Specifier" if c['id'] == "fmt" else "Metadata / Info" if c['id'] == "LIST" else "Auxiliary chunk"}</td>
                            </tr>
                            ''' for c in info['chunks'])}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Findings Panel -->
            <div class="panel">
                <h2>Top Forensics Findings & Stego Candidates</h2>
                <div class="findings-list">
                    {"".join(f'''
                    <div class="finding-card star-{c['rating']}">
                        <div class="finding-header">
                            <div>
                                <div class="finding-title">{c['name']}</div>
                                <span class="finding-source">Source: {c['source']}</span>
                            </div>
                            <div class="finding-rating">
                                <span class="stars">{c['stars']}</span>
                                <span class="finding-meta">Entropy: {c['entropy']:.4f}</span>
                            </div>
                        </div>
                        <div class="finding-reason">{c['reason']}</div>
                        
                        {"<ul class='finding-details'>" + "".join(f"<li>{f}</li>" for f in c['findings']) + "</ul>" if c['findings'] else ""}
                        
                        <div class="preview-label">Sample Data Preview (First 64 Bytes)</div>
                        <div class="preview-box">
                            <div class="hex">{c['preview_hex']}</div>
                            <div class="ascii">{c['preview_ascii']}</div>
                        </div>
                    </div>
                    ''' for c in interesting_candidates[:8])}

                    {f"<p style='color: var(--text-muted);'>No high-confidence candidates found in stream analysis.</p>" if not interesting_candidates else ""}
                </div>

                {f'''
                <button class="collapse-btn" onclick="toggleLowCandidates()">Show {len(low_candidates)} lower-confidence candidates</button>
                <div id="lowCandidates" class="collapsible-content">
                    <div class="findings-list">
                        {"".join(f'''
                        <div class="finding-card star-{c['rating']}" style="opacity: 0.65;">
                            <div class="finding-header">
                                <div>
                                    <div class="finding-title">{c['name']}</div>
                                    <span class="finding-source">Source: {c['source']}</span>
                                </div>
                                <div class="finding-rating">
                                    <span class="stars">{c['stars']}</span>
                                    <span class="finding-meta">Entropy: {c['entropy']:.4f}</span>
                                </div>
                            </div>
                            <div class="finding-reason">{c['reason']}</div>
                        </div>
                        ''' for c in low_candidates)}
                    </div>
                </div>
                ''' if low_candidates else ""}
            </div>
        </div>

        <footer>
            WaveHunter Toolkit &bull; v{__version__} &bull; Desandu Hettiarachchi &bull; 2026
        </footer>
    </div>

    <script>
        function toggleLowCandidates() {{
            var content = document.getElementById("lowCandidates");
            content.classList.toggle("expanded");
            var btn = document.querySelector(".collapse-btn");
            if (content.classList.contains("expanded")) {{
                btn.textContent = "Hide lower-confidence candidates";
            }} else {{
                btn.textContent = "Show " + {len(low_candidates)} + " lower-confidence candidates";
            }}
        }}

        // Initialize Entropy sliding window chart
        const ctx = document.getElementById('entropyChart').getContext('2d');
        const dataValues = {entropy_js_list};
        const labels = dataValues.map((_, i) => "W" + i);

        new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [{{
                    label: 'Shannon Entropy (per 2048-byte window)',
                    data: dataValues,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.05)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 1,
                    pointHoverRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    tooltip: {{
                        mode: 'index',
                        intersect: false
                    }}
                }},
                scales: {{
                    x: {{
                        grid: {{
                            color: 'rgba(255, 255, 255, 0.03)'
                        }},
                        ticks: {{
                            display: false
                        }}
                    }},
                    y: {{
                        grid: {{
                            color: 'rgba(255, 255, 255, 0.03)'
                        }},
                        min: 0,
                        max: 8.1,
                        ticks: {{
                            color: '#9ca3af',
                            font: {{
                                family: 'Outfit'
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
