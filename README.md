# AEGIS — Adaptive Exploitation & Global Intelligence System

> An AI-powered automated vulnerability assessment pipeline for authorized penetration testing.

```
    █████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║
   ██║  ██║███████╗╚██████╔╝██║███████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**⚠️ For authorized lab testing only. Unauthorized scanning is illegal.**

---

## What It Does

AEGIS automates the full vulnerability assessment pipeline for a target host:

1. **Network Recon** — nmap service/version scan across all ports
2. **Web Scanning** — nikto vulnerability scan + gobuster directory enumeration (auto-triggered if HTTP detected)
3. **SMB Enumeration** — enum4linux shares, users, null sessions (auto-triggered if port 445 detected)
4. **FTP Probe** — anonymous login test + vsftpd 2.3.4 backdoor detection (CVE-2011-2523)
5. **SSH Probe** — banner grab + version-based CVE flagging
6. **MySQL Probe** — default credential testing
7. **AI Intelligence** — Qwen2.5-72B-Instruct (via Together AI) correlates all findings into CVE mappings, MITRE ATT&CK TTPs, and a risk narrative
8. **Report Generation** — Professional PDF, JSON, or Markdown report

---

## Quick Start

### Prerequisites (Kali Linux / Debian)

```bash
# System tools
sudo apt update && sudo apt install -y nmap nikto gobuster enum4linux dirb

# Python 3.10+
python3 --version
```

### Installation

```bash
# Clone
git clone https://github.com/<username>/aegis.git
cd aegis

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Python dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and set: TOGETHER_API_KEY="your_key_here"
```

### Usage

```bash
# Standard full scan (all ports, all modules, AI analysis, PDF report)
sudo python aegis.py --target 192.168.56.101

# Quick scan (top 1000 ports, faster)
sudo python aegis.py --target 192.168.56.101 --profile quick

# Web-only scan
python aegis.py --target 10.10.10.5 --profile web

# No AI (offline, no API key needed)
python aegis.py --target 192.168.56.101 --no-ai

# Markdown report for writeups
python aegis.py --target 192.168.56.101 --format markdown

# Verbose output (shows raw tool output)
sudo python aegis.py --target 192.168.56.101 --verbose

# Help
python aegis.py --help
```

---

## Scan Profiles

| Profile | Ports Scanned | Use Case |
|---------|--------------|----------|
| `full` | All 65535 | Thorough assessment (default) |
| `quick` | Top 1000 | Fast first look |
| `web` | 80, 443, 8080, 8443 | Web-only target |
| `stealth` | All 65535 (slow) | Low-detection rate (requires root) |

---

## Output Formats

| Format | Flag | Output |
|--------|------|--------|
| PDF | `--format pdf` | Professional multi-page report |
| JSON | `--format json` | Machine-readable full data |
| Markdown | `--format markdown` | Portfolio/writeup style |

Reports saved to `./reports/<target>_<timestamp>.<ext>`

---

## Architecture

```
aegis.py (entry point)
│
├── cli/parser.py          → argparse CLI
├── core/
│   ├── orchestrator.py    → main pipeline coordinator
│   ├── validator.py       → IP validation + scope authorization
│   └── dependency.py      → pre-flight tool checker
│
├── modules/
│   ├── nmap_scanner.py    → nmap XML parsing
│   ├── web_scanner.py     → nikto + gobuster
│   ├── smb_enum.py        → enum4linux
│   ├── ftp_probe.py       → ftplib anonymous login
│   ├── ssh_probe.py       → banner grab + CVE lookup
│   └── mysql_probe.py     → default credentials
│
├── ai/
│   ├── intelligence.py    → Together AI API client
│   └── prompts.py         → LLM system prompt + message builder
│
├── reporting/
│   ├── pdf_generator.py   → fpdf2 PDF builder
│   ├── json_exporter.py   → JSON serializer
│   └── markdown_gen.py    → Markdown generator
│
├── ui/console.py          → Rich panels, tables, spinners
└── utils/
    ├── subprocess_utils.py → safe subprocess.run wrapper
    └── file_utils.py       → temp file management
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11 |
| CLI | argparse (stdlib) |
| Terminal UI | Rich 13.7.1 |
| AI Provider | Together AI |
| LLM Model | Qwen/Qwen2.5-72B-Instruct |
| PDF Generation | fpdf2 2.7.9 |
| HTTP Client | requests 2.31.0 |
| Env Management | python-dotenv |

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
TOGETHER_API_KEY="your_api_key"     # Required for AI analysis
AEGIS_MODEL="Qwen/Qwen2.5-72B-Instruct"
AEGIS_API_TIMEOUT=60
AEGIS_API_RETRIES=3
AEGIS_DEFAULT_PROFILE="full"
AEGIS_WORDLIST="/usr/share/wordlists/dirb/common.txt"
AEGIS_REPORTS_DIR="./reports"
AEGIS_NMAP_TIMEOUT=600
AEGIS_DEBUG="false"
```

---

## Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v --cov=.

# Run specific test file
pytest tests/test_validator.py -v
pytest tests/test_ai_engine.py -v
pytest tests/test_nmap_parser.py -v
```

---

## Security Notes

- **No hardcoded secrets** — API keys loaded from `.env` only
- **No shell injection** — all subprocess calls use `shell=False` with list args
- **No data exfiltration** — scan results sent ONLY to Together AI API
- **Temp file cleanup** — `/tmp/aegis_*` files deleted after each run
- **Input validation** — all targets validated before any subprocess call

---

## Legal Disclaimer

AEGIS is for authorized penetration testing and educational use only.
**Scanning systems without explicit written authorization is illegal** under
computer crime laws in most jurisdictions (CFAA, Computer Misuse Act, etc.).
The author assumes no liability for misuse.

---

## License

MIT License — see [LICENSE](LICENSE)
