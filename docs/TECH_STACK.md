# Technology Stack Documentation
# AEGIS — Adaptive Exploitation & Global Intelligence System

**Last Updated**: 2026-04-26  
**Version**: 1.0  
**Architecture**: Modular Python CLI Application

---

## 1. Stack Overview

### Architecture Pattern
- **Type**: Monolithic CLI application with modular architecture
- **Pattern**: Orchestrator → Module Pipeline → AI Engine → Reporter
- **Language**: Python (100%) — no frontend, no backend server
- **Deployment**: Local installation on Kali Linux / Debian-based systems
- **Execution Model**: Single-process synchronous pipeline with subprocess calls to external security tools

### Why This Stack
Python was chosen because: (1) it is the dominant language in security tooling, (2) subprocess integration with nmap/nikto/gobuster is trivial, (3) Together AI has a Python-friendly REST API, (4) the target audience (security students) is most comfortable with Python.

No web framework, no database, no frontend — AEGIS is intentionally a lean CLI tool that demonstrates skill without unnecessary complexity.

---

## 2. Runtime & Language

### Python
- **Version**: 3.11.9
- **Why 3.11**: `tomllib` built-in, improved error messages, 10–60% faster than 3.9
- **Why not 3.12+**: `enum4linux` subprocess parsing has known encoding quirks on 3.12 (investigate before upgrading)
- **Documentation**: https://docs.python.org/3.11/
- **Package Manager**: pip 24.0

### Virtual Environment
- **Tool**: `venv` (stdlib)
- **Activation**: `source venv/bin/activate`
- **Reason**: Isolates dependencies from system Python; no conda required

---

## 3. Core Python Libraries

### CLI & Argument Parsing
- **Library**: `argparse`
- **Version**: stdlib (Python 3.11 built-in)
- **Reason**: No external dependency needed; sufficient for AEGIS's argument complexity
- **Documentation**: https://docs.python.org/3/library/argparse.html

### Terminal UI & Output
- **Library**: `rich`
- **Version**: 13.7.1
- **Reason**: Industry-standard for beautiful Python CLIs; spinners, tables, panels, color coding, progress bars in one package
- **Documentation**: https://rich.readthedocs.io/
- **License**: MIT
- **Alternatives Considered**: `colorama` (rejected: no tables/panels), `blessed` (rejected: less maintained)

### nmap Python Wrapper
- **Library**: `python-nmap`
- **Version**: 0.7.1
- **Reason**: Provides Python objects from nmap XML output; handles subprocess invocation cleanly
- **Documentation**: https://pypi.org/project/python-nmap/
- **License**: GPL
- **Note**: Used alongside direct subprocess calls for XML output parsing

### HTTP Requests (Together AI API)
- **Library**: `requests`
- **Version**: 2.31.0
- **Reason**: Simple, reliable, widely used; sufficient for REST API calls to Together AI
- **Documentation**: https://requests.readthedocs.io/
- **License**: Apache 2.0
- **Alternatives Considered**: `httpx` (considered but overkill for synchronous use)

### PDF Generation
- **Library**: `fpdf2`
- **Version**: 2.7.9
- **Reason**: Actively maintained fork of fpdf; no external dependencies (unlike reportlab); clean Python API for building PDFs programmatically
- **Documentation**: https://py-fpdf.readthedocs.io/
- **License**: LGPL
- **Alternatives Considered**: `reportlab` (rejected: heavier, more complex for simple reports), `weasyprint` (rejected: requires HTML/CSS which adds complexity)

### Environment Variable Management
- **Library**: `python-dotenv`
- **Version**: 1.0.1
- **Reason**: Load API keys from `.env` file safely; prevents hardcoding credentials
- **Documentation**: https://pypi.org/project/python-dotenv/
- **License**: BSD

### XML Parsing (nmap, nikto output)
- **Library**: `xml.etree.ElementTree`
- **Version**: stdlib (Python 3.11 built-in)
- **Reason**: Sufficient for parsing nmap and nikto XML output; no external dependency
- **Documentation**: https://docs.python.org/3/library/xml.etree.elementtree.html

### FTP Testing
- **Library**: `ftplib`
- **Version**: stdlib (Python 3.11 built-in)
- **Reason**: Anonymous FTP login testing doesn't need external libraries
- **Documentation**: https://docs.python.org/3/library/ftplib.html

### Date/Time Handling
- **Library**: `datetime`
- **Version**: stdlib (Python 3.11 built-in)
- **Use**: Report timestamps, scan duration calculation

### JSON Handling
- **Library**: `json`
- **Version**: stdlib (Python 3.11 built-in)
- **Use**: Parsing AI API responses, JSON report export

---

## 4. AI / LLM Integration

### LLM Provider
- **Provider**: Together AI
- **API**: REST (`https://api.together.xyz/v1/chat/completions`)
- **Documentation**: https://docs.together.ai/
- **Pricing**: Free tier available (rate limited); no credit card for basic use

### LLM Model
- **Model**: `Qwen/Qwen2.5-72B-Instruct`
- **Why Qwen2.5-72B**: Excellent instruction following, strong JSON output reliability, free on Together AI tier, strong at cybersecurity domain knowledge (CVE/TTP correlation)
- **Context Window**: 128K tokens (more than enough for large scan outputs)
- **Alternatives Considered**: `meta-llama/Meta-Llama-3-70B-Instruct` (also good option on Together AI free tier)

### Prompt Strategy
- **Format**: Structured system prompt + user message containing scan data as JSON
- **Output Format**: LLM instructed to respond in JSON only
- **Parsing**: `json.loads()` on response content; fallback on parse failure

---

## 5. External Security Tools (System Dependencies)

These are NOT Python packages — they must be installed on the system.

### nmap
- **Version**: 7.94 or higher
- **Install**: `sudo apt install nmap`
- **Usage in AEGIS**: Network port scanning, service version detection, OS fingerprinting
- **AEGIS flags**: `-sV -sC -O -p- --open -oX`
- **Documentation**: https://nmap.org/docs.html
- **License**: NPSL (Nmap Public Source License)

### nikto
- **Version**: 2.1.6 or higher
- **Install**: `sudo apt install nikto`
- **Usage in AEGIS**: Web server vulnerability scanning
- **AEGIS flags**: `-h <target> -Format xml -o /tmp/aegis_nikto.xml`
- **Documentation**: https://github.com/sullo/nikto
- **License**: GPL v2

### gobuster
- **Version**: 3.6.0 or higher
- **Install**: `sudo apt install gobuster`
- **Usage in AEGIS**: HTTP directory and file enumeration
- **AEGIS flags**: `dir -u <url> -w <wordlist> -o <output> -q`
- **Documentation**: https://github.com/OJ/gobuster
- **License**: Apache 2.0

### enum4linux
- **Version**: 0.9.1 or higher
- **Install**: `sudo apt install enum4linux`
- **Usage in AEGIS**: SMB/Windows enumeration (shares, users, OS info)
- **AEGIS flags**: `-a <target>`
- **Documentation**: https://github.com/CiscoCXSecurity/enum4linux
- **License**: GPL

### Wordlist (dirb)
- **Package**: `dirb` (installs wordlists to /usr/share/wordlists/dirb/)
- **Install**: `sudo apt install dirb`
- **File used**: `/usr/share/wordlists/dirb/common.txt` (4,614 entries)
- **Usage**: gobuster directory enumeration

---

## 6. Development Tools

### Code Formatting
- **Tool**: `black`
- **Version**: 24.4.2
- **Config**: Default (line length 88)
- **Run**: `black .`
- **Documentation**: https://black.readthedocs.io/
- **License**: MIT

### Linting
- **Tool**: `flake8`
- **Version**: 7.1.0
- **Config**: `.flake8` file (max-line-length = 88, ignore E203, W503)
- **Run**: `flake8 .`
- **Documentation**: https://flake8.pycqa.org/
- **License**: MIT

### Type Checking
- **Tool**: `mypy`
- **Version**: 1.10.0
- **Config**: `mypy.ini` (strict mode off for v1.0)
- **Run**: `mypy aegis/`
- **Documentation**: https://mypy.readthedocs.io/
- **License**: MIT

### Testing
- **Framework**: `pytest`
- **Version**: 8.2.0
- **Plugins**:
  - `pytest-mock` 3.14.0 (mocking subprocess calls)
  - `pytest-cov` 5.0.0 (coverage reporting)
- **Coverage Target**: 70% (realistic for a CLI security tool with subprocess dependencies)
- **Run**: `pytest tests/ -v --cov=aegis`
- **Documentation**: https://docs.pytest.org/
- **License**: MIT

### Git
- **Version**: 2.43+
- **Platform**: GitHub
- **Branch Strategy**:
  - `main` — stable, tagged releases
  - `dev` — active development
  - `feature/<name>` — individual feature branches

---

## 7. Environment Variables

All secrets loaded from `.env` file using `python-dotenv`. Never hardcoded.

```bash
# .env — DO NOT COMMIT THIS FILE

# Together AI API (required for AI intelligence engine)
TOGETHER_API_KEY="your_together_ai_api_key_here"

# LLM Model (can override default)
AEGIS_MODEL="Qwen/Qwen2.5-72B-Instruct"

# Request timeout for AI API calls (seconds)
AEGIS_API_TIMEOUT=60

# Maximum AI API retries on failure
AEGIS_API_RETRIES=3

# Default scan profile (quick|full|web|stealth)
AEGIS_DEFAULT_PROFILE="full"

# Default wordlist path
AEGIS_WORDLIST="/usr/share/wordlists/dirb/common.txt"

# Reports output directory
AEGIS_REPORTS_DIR="./reports"

# Nmap timeout (seconds, 0 = no timeout)
AEGIS_NMAP_TIMEOUT=600

# Enable debug logging (true|false)
AEGIS_DEBUG="false"
```

---

## 8. Project Structure

```
aegis/
├── aegis.py                    # Entry point — imports and calls CLI parser
│
├── cli/
│   └── parser.py               # argparse setup, argument validation
│
├── core/
│   ├── __init__.py
│   ├── orchestrator.py         # Main scan pipeline coordinator
│   ├── validator.py            # Target validation, scope authorization prompt
│   └── dependency.py           # Pre-flight tool/package dependency checker
│
├── modules/
│   ├── __init__.py
│   ├── nmap_scanner.py         # nmap execution + XML parsing
│   ├── web_scanner.py          # nikto + gobuster execution + parsing
│   ├── smb_enum.py             # enum4linux execution + output parsing
│   ├── ftp_probe.py            # ftplib anonymous login test
│   ├── ssh_probe.py            # SSH banner grab + version analysis
│   └── mysql_probe.py          # MySQL default credential test
│
├── ai/
│   ├── __init__.py
│   ├── intelligence.py         # Together AI API client, prompt builder, response parser
│   └── prompts.py              # Prompt templates as constants
│
├── reporting/
│   ├── __init__.py
│   ├── pdf_generator.py        # fpdf2 PDF report builder
│   ├── json_exporter.py        # JSON serialization
│   └── markdown_gen.py         # Markdown report generator
│
├── ui/
│   ├── __init__.py
│   └── console.py              # Rich panels, tables, banners, spinners
│
├── utils/
│   ├── __init__.py
│   ├── file_utils.py           # Temp file management, path utilities
│   └── subprocess_utils.py     # Safe subprocess.run wrapper with timeout + logging
│
├── tests/
│   ├── test_validator.py
│   ├── test_nmap_parser.py
│   ├── test_web_scanner.py
│   ├── test_ai_engine.py
│   └── test_pdf_generator.py
│
├── reports/                    # Generated reports (gitignored)
├── .env                        # Secrets (gitignored)
├── .env.example                # Template (committed)
├── .gitignore
├── requirements.txt
├── setup.py
└── README.md
```

---

## 9. Requirements Files

### requirements.txt
```
rich==13.7.1
requests==2.31.0
python-nmap==0.7.1
fpdf2==2.7.9
python-dotenv==1.0.1
```

### requirements-dev.txt
```
black==24.4.2
flake8==7.1.0
mypy==1.10.0
pytest==8.2.0
pytest-mock==3.14.0
pytest-cov==5.0.0
```

---

## 10. Installation & Setup

```bash
# 1. Clone repository
git clone https://github.com/<username>/aegis.git
cd aegis

# 2. Install system dependencies (Kali/Debian)
sudo apt update && sudo apt install -y nmap nikto gobuster enum4linux dirb

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Configure environment
cp .env.example .env
# Edit .env and add your TOGETHER_API_KEY

# 6. Verify installation
python aegis.py --version

# 7. Run on a lab target
sudo python aegis.py --target 192.168.1.100 --profile full
```

---

## 11. OS & System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Debian 12 / Ubuntu 22.04 | Kali Linux 2024.1+ |
| Python | 3.10 | 3.11.9 |
| RAM | 512MB | 2GB |
| Disk | 500MB (incl. wordlists) | 2GB |
| Network | Local LAN access to target | Dedicated lab NIC |
| Privileges | Standard user (some modules need sudo) | sudo available |

**Not supported**: Windows, macOS (subprocess paths and tool availability differ)

---

## 12. Security Considerations

- **API Key**: Stored in `.env`, loaded via `python-dotenv`, never printed to console or logs
- **`.gitignore`**: Must include `.env`, `reports/`, `/tmp/aegis_*` 
- **Subprocess Safety**: All tool arguments passed as list (not string) to prevent shell injection: `subprocess.run(["nmap", "-sV", target], ...)` — never `shell=True` with user input
- **No Scan Data Exfiltration**: Scan results sent ONLY to Together AI API; no other external service receives target data
- **Temp File Cleanup**: All `/tmp/aegis_*` files deleted after parsing
- **Input Validation**: Target IP/hostname validated with `ipaddress` module and regex before any subprocess call
