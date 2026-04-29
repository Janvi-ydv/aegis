# Implementation Plan & Build Sequence
# AEGIS — Adaptive Exploitation & Global Intelligence System

**Project**: AEGIS v1.0  
**Solo Developer**: Shubham  
**Target Environment**: Kali Linux + VirtualBox (Metasploitable 2 as test target)  
**MVP Target**: 30 days from start  
**Build Philosophy**: Documentation-first, test every step on Metasploitable 2 before moving on.

---

## Build Order Philosophy

AEGIS must be built in strict dependency order:
1. **Foundation first** — project structure, CLI, validation (nothing works without this)
2. **Nmap first** — all other modules depend on knowing what ports are open
3. **Conditional modules** — web/SMB/FTP/SSH/MySQL after nmap
4. **AI engine last** — needs all scan data as input
5. **Reports last** — needs both scan data and AI output

---

## Phase 1: Project Foundation (Days 1–4)

---

### Step 1.1: Initialize Project Structure

**Duration**: 2 hours  
**Goal**: Empty but correct project scaffold on disk

**Tasks**:
```bash
# 1. Create and enter project directory
mkdir aegis && cd aegis
git init

# 2. Create directory structure
mkdir -p cli core modules ai reporting ui utils tests reports

# 3. Create all __init__.py files
touch cli/__init__.py core/__init__.py modules/__init__.py \
      ai/__init__.py reporting/__init__.py ui/__init__.py utils/__init__.py

# 4. Create placeholder files (empty for now)
touch aegis.py
touch cli/parser.py
touch core/orchestrator.py core/validator.py core/dependency.py
touch modules/nmap_scanner.py modules/web_scanner.py modules/smb_enum.py
touch modules/ftp_probe.py modules/ssh_probe.py modules/mysql_probe.py
touch ai/intelligence.py ai/prompts.py
touch reporting/pdf_generator.py reporting/json_exporter.py reporting/markdown_gen.py
touch ui/console.py
touch utils/file_utils.py utils/subprocess_utils.py
touch tests/test_validator.py tests/test_nmap_parser.py tests/test_ai_engine.py

# 5. Create support files
touch requirements.txt requirements-dev.txt
touch .env.example .gitignore
touch README.md

# 6. Initial commit
git add .
git commit -m "chore: initialize project scaffold"
```

**`.gitignore` contents**:
```
.env
reports/
/tmp/aegis_*
venv/
__pycache__/
*.pyc
*.egg-info/
.pytest_cache/
aegis.log
```

**`requirements.txt`** (from TECH_STACK.md):
```
rich==13.7.1
requests==2.31.0
python-nmap==0.7.1
fpdf2==2.7.9
python-dotenv==1.0.1
```

**`requirements-dev.txt`**:
```
black==24.4.2
flake8==7.1.0
mypy==1.10.0
pytest==8.2.0
pytest-mock==3.14.0
pytest-cov==5.0.0
```

**Success Criteria**:
- [ ] `ls aegis/` shows all directories
- [ ] `git log --oneline` shows initial commit
- [ ] All `__init__.py` files exist

**Reference**: TECH_STACK.md §8 (Project Structure)

---

### Step 1.2: Python Environment & Dependencies

**Duration**: 1 hour  
**Goal**: Isolated Python environment with all packages installed

**Tasks**:
```bash
# 1. Verify Python version
python3 --version  # Must be 3.10+

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install production dependencies
pip install -r requirements.txt

# 4. Install dev dependencies
pip install -r requirements-dev.txt

# 5. Verify key installs
python -c "import rich; print(rich.__version__)"       # 13.7.1
python -c "import fpdf2; print('fpdf2 ok')"
python -c "import requests; print(requests.__version__)"  # 2.31.0
python -c "import dotenv; print('dotenv ok')"

# 6. Create .env from template
cp .env.example .env
# → Manually add your Together AI API key to .env
```

**`.env.example`** (commit this):
```bash
TOGETHER_API_KEY="your_together_ai_api_key_here"
AEGIS_MODEL="Qwen/Qwen2.5-72B-Instruct"
AEGIS_API_TIMEOUT=60
AEGIS_API_RETRIES=3
AEGIS_DEFAULT_PROFILE="full"
AEGIS_WORDLIST="/usr/share/wordlists/dirb/common.txt"
AEGIS_REPORTS_DIR="./reports"
AEGIS_NMAP_TIMEOUT=600
AEGIS_DEBUG="false"
```

**Success Criteria**:
- [ ] `source venv/bin/activate` works
- [ ] `pip list | grep rich` shows 13.7.1
- [ ] `.env` exists and has TOGETHER_API_KEY set
- [ ] `.env` is in `.gitignore` (never committed)

**Reference**: TECH_STACK.md §7, §10

---

### Step 1.3: System Dependencies Check

**Duration**: 30 minutes  
**Goal**: All external security tools installed and verified

**Tasks**:
```bash
# Install all required tools (Kali should have most)
sudo apt update
sudo apt install -y nmap nikto gobuster enum4linux dirb

# Verify each tool
nmap --version                    # Nmap 7.94+
nikto -Version                    # Nikto 2.1.6+
gobuster version                  # 3.6.0+
enum4linux --help 2>&1 | head -3  # Shows usage

# Verify wordlist exists
ls /usr/share/wordlists/dirb/common.txt

# Verify nmap can run (may need sudo for -O)
nmap --version
sudo nmap -sV 127.0.0.1 -p 22 --open   # Quick test, should work
```

**Metasploitable 2 setup** (your test target):
```bash
# In VirtualBox:
# 1. Metasploitable 2 is set to "Host-only Adapter"
# 2. Note its IP: usually 192.168.56.101
# 3. Verify reachability:
ping 192.168.56.101 -c 3

# Quick nmap to confirm it's up
nmap -sV -p 21,22,80 192.168.56.101
```

**Success Criteria**:
- [ ] `nmap --version` succeeds
- [ ] `nikto -Version` succeeds
- [ ] `gobuster version` succeeds
- [ ] `enum4linux --help` runs without error
- [ ] `/usr/share/wordlists/dirb/common.txt` exists
- [ ] `ping 192.168.56.101` succeeds (Metasploitable reachable)

---

### Step 1.4: CLI Parser & Banner

**Duration**: 2 hours  
**Goal**: `python aegis.py --help` and `--version` work with Rich output

**Implement**:

**`ui/console.py`** — Banner only for now:
```python
from rich.console import Console
from rich.panel import Panel

console = Console()

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════╗
    ║   AEGIS — Adaptive Exploitation & Global Intelligence║
    ║   Version 1.0.0 | For authorized testing only       ║
    ╚══════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

def print_info(msg: str):
    console.print(f"  [bold blue]ℹ[/bold blue]  {msg}")
```

**`cli/parser.py`**:
```python
import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — Adaptive Exploitation & Global Intelligence System",
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--profile", choices=["quick", "full", "web", "stealth"],
                        default="full", help="Scan profile preset")
    parser.add_argument("--format", choices=["pdf", "json", "markdown"],
                        default="pdf", dest="output_format")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version="AEGIS 1.0.0")
    return parser
```

**`aegis.py`**:
```python
#!/usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

from ui.console import print_banner
from cli.parser import build_parser

def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    print(f"Target: {args.target} | Profile: {args.profile}")  # Temp

if __name__ == "__main__":
    main()
```

**Test**:
```bash
python aegis.py --help
python aegis.py --version
python aegis.py --target 192.168.56.101
```

**Success Criteria**:
- [ ] `python aegis.py --help` shows Rich-formatted help
- [ ] `python aegis.py --version` prints AEGIS 1.0.0
- [ ] `python aegis.py --target 1.2.3.4` prints target without crashing
- [ ] Banner displays in cyan

**Reference**: FRONTEND_GUIDELINES.md §5.1, APP_FLOW.md §3 (Flow 3)

---

## Phase 2: Core Infrastructure (Days 5–7)

---

### Step 2.1: Target Validator

**Duration**: 2 hours  
**Goal**: IP/hostname validation and scope authorization prompt

**Implement `core/validator.py`**:
```python
import ipaddress
from ui.console import console, print_error

def validate_target(target: str) -> bool:
    """Returns True if valid IP or resolvable hostname."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Try hostname validation
        import re
        hostname_regex = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        return bool(re.match(hostname_regex, target))

def scope_authorization_prompt(target: str) -> bool:
    """Returns True if user confirms authorization."""
    from rich.panel import Panel
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n\n"
        "[yellow]AEGIS will perform active scanning. Unauthorized scanning is illegal.\n\n"
        "[bold white]Do you have explicit written authorization to scan this target?[/bold white]",
        title="[bold yellow][ ⚠ AUTHORIZATION CHECK ][/bold yellow]",
        border_style="yellow",
    ))
    answer = console.input("[bold yellow]Confirm [y/N]: [/bold yellow]").strip().lower()
    return answer == "y"
```

**Write tests** (`tests/test_validator.py`):
```python
from core.validator import validate_target

def test_valid_ip():
    assert validate_target("192.168.1.1") == True

def test_invalid_ip():
    assert validate_target("999.999.999.999") == False
    assert validate_target("not-an-ip") == False

def test_valid_hostname():
    assert validate_target("example.com") == True
```

```bash
pytest tests/test_validator.py -v
```

**Success Criteria**:
- [ ] All 3 test cases pass
- [ ] Scope prompt displays correctly
- [ ] 'n' input exits (test manually)
- [ ] 'y' input continues (test manually)

**Reference**: APP_FLOW.md §2 (Flow 1, Step 3)

---

### Step 2.2: Dependency Checker

**Duration**: 1.5 hours  
**Goal**: Pre-flight check that all tools are installed

**Implement `core/dependency.py`**:
```python
import shutil
from rich.table import Table
from rich import box
from ui.console import console

REQUIRED_TOOLS = {
    "nmap":       "sudo apt install nmap",
    "nikto":      "sudo apt install nikto",
    "gobuster":   "sudo apt install gobuster",
    "enum4linux": "sudo apt install enum4linux",
}

REQUIRED_PYTHON_PACKAGES = ["rich", "requests", "fpdf2", "dotenv"]

def check_dependencies() -> bool:
    """Returns True if all dependencies satisfied. Prints table."""
    table = Table(title="[ PREFLIGHT ] Dependency Check",
                  box=box.ROUNDED, title_style="bold cyan", header_style="bold white")
    table.add_column("Tool", width=15)
    table.add_column("Status", width=10)
    table.add_column("Install Command", width=35)
    
    all_ok = True
    for tool, install_cmd in REQUIRED_TOOLS.items():
        found = shutil.which(tool) is not None
        status = "[bold green]✓ Found[/bold green]" if found else "[bold red]✗ Missing[/bold red]"
        hint = "" if found else install_cmd
        table.add_row(tool, status, hint)
        if not found:
            all_ok = False
    
    console.print(table)
    return all_ok
```

**Success Criteria**:
- [ ] Table prints with correct status for all tools
- [ ] Returns False if nmap is removed (test by temporarily renaming)
- [ ] Returns True on fresh Kali with all tools

---

### Step 2.3: Subprocess Utilities

**Duration**: 1 hour  
**Goal**: Safe subprocess wrapper used by all modules

**Implement `utils/subprocess_utils.py`** (full code in BACKEND_STRUCTURE.md §6)

**Test** (`tests/test_subprocess_utils.py`):
```python
from utils.subprocess_utils import run_tool

def test_valid_command():
    rc, stdout, stderr = run_tool(["echo", "hello"])
    assert rc == 0
    assert "hello" in stdout

def test_command_not_found():
    rc, stdout, stderr = run_tool(["nonexistent_command_12345"])
    assert rc == -2
    assert "not found" in stderr.lower()

def test_timeout():
    rc, stdout, stderr = run_tool(["sleep", "10"], timeout=1)
    assert rc == -1
```

**Success Criteria**:
- [ ] All 3 subprocess tests pass
- [ ] `shell=False` verified (grep the code)

---

## Phase 3: Scan Modules (Days 8–15)

---

### Step 3.1: Nmap Scanner Module

**Duration**: 3 hours  
**Goal**: nmap runs and returns structured port data

**Implement `modules/nmap_scanner.py`** (per BACKEND_STRUCTURE.md §3.2)

**Manual test on Metasploitable 2**:
```bash
# Test the module directly
python3 -c "
from modules.nmap_scanner import NmapScanner
scanner = NmapScanner('192.168.56.101', 'quick', verbose=True)
result = scanner.run()
print('Ports found:', len(result['open_ports']))
for p in result['open_ports'][:5]:
    print(f\"  {p['port']}/{p['protocol']}: {p['service']} {p['version']}\")
"
```

**Expected Metasploitable 2 results**:
```
Ports found: 20+
  21/tcp: ftp vsftpd 2.3.4
  22/tcp: ssh OpenSSH 4.7p1
  80/tcp: http Apache httpd 2.2.8
  139/tcp: netbios-ssn Samba smbd 3.X
  445/tcp: microsoft-ds Samba smbd 3.X
```

**Write tests** (`tests/test_nmap_parser.py`):
```python
# Test XML parsing with a fixture file (saved real nmap output)
import xml.etree.ElementTree as ET
from modules.nmap_scanner import NmapScanner

def test_parse_xml_fixture():
    scanner = NmapScanner("192.168.56.101", "quick", verbose=False)
    result = scanner._parse_xml("tests/fixtures/metasploitable_nmap.xml")
    assert len(result["open_ports"]) > 10
    ports = [p["port"] for p in result["open_ports"]]
    assert 21 in ports
    assert 80 in ports
```

**Action**: Save a real nmap XML from Metasploitable 2 as `tests/fixtures/metasploitable_nmap.xml`

**Success Criteria**:
- [ ] Manual test shows 20+ ports on Metasploitable 2
- [ ] vsftpd 2.3.4 detected on port 21
- [ ] Apache on port 80 detected
- [ ] Samba on ports 139/445 detected
- [ ] `_parse_xml` test passes with fixture
- [ ] No crash when target is unreachable (test with wrong IP)

**Reference**: BACKEND_STRUCTURE.md §3.2

---

### Step 3.2: Web Scanner Module

**Duration**: 3 hours  
**Goal**: nikto + gobuster run on Metasploitable 2's web server

**Implement `modules/web_scanner.py`** (per BACKEND_STRUCTURE.md §3.3)

**Manual test**:
```bash
python3 -c "
from modules.web_scanner import WebScanner
scanner = WebScanner('192.168.56.101', 'http://192.168.56.101', verbose=True, 
                      wordlist='/usr/share/wordlists/dirb/common.txt')
result = scanner.run()
print('Nikto findings:', len(result['nikto']['findings']))
print('Gobuster paths:', len(result['gobuster']['paths']))
"
```

**Expected results on Metasploitable 2**:
```
Nikto findings: 15+   (outdated Apache, directory listing, PHP info, etc.)
Gobuster paths: 20+   (/phpinfo.php, /phpMyAdmin, /dvwa, /mutillidae, etc.)
```

**Success Criteria**:
- [ ] nikto finds at least 10 findings on Metasploitable 2
- [ ] gobuster discovers `/phpMyAdmin` and `/dvwa`
- [ ] No crash when nikto times out (set `maxtime=60` for testing)
- [ ] Graceful handling when gobuster wordlist missing

---

### Step 3.3: SMB Enumeration Module

**Duration**: 2 hours  
**Goal**: enum4linux extracts shares, users, null session status

**Manual test**:
```bash
python3 -c "
from modules.smb_enum import SmbEnum
smb = SmbEnum('192.168.56.101', verbose=True)
result = smb.run()
print('Shares:', result['shares'])
print('Users:', result['users'])
print('Null session:', result['null_session'])
"
```

**Expected Metasploitable 2 results**:
```
Shares: [{'name': 'IPC$', 'type': 'IPC', ...}, {'name': 'tmp', ...}]
Users: ['root', 'daemon', 'msfadmin', ...]
Null session: True
```

**Success Criteria**:
- [ ] Shares list extracted correctly
- [ ] Users list extracted correctly  
- [ ] Null session detected as True on Metasploitable 2

---

### Step 3.4: FTP, SSH, MySQL Probe Modules

**Duration**: 3 hours  
**Goal**: All three probe modules work on Metasploitable 2

**FTP test**:
```bash
python3 -c "
from modules.ftp_probe import FtpProbe
ftp = FtpProbe('192.168.56.101', verbose=True)
result = ftp.run()
print('Anonymous:', result['anonymous_login'])
print('Banner:', result['banner'])
"
# Expected: anonymous_login=True, banner contains 'vsFTPd 2.3.4'
```

**SSH test**:
```bash
python3 -c "
from modules.ssh_probe import SshProbe
ssh = SshProbe('192.168.56.101', verbose=True)
result = ssh.run()
print('Version:', result['version'])
print('CVEs:', result['known_cves'])
"
# Expected: version='OpenSSH_4.7p1', known_cves includes CVE-2008-0166
```

**MySQL test**:
```bash
pip install PyMySQL  # Add to requirements.txt after verifying
python3 -c "
from modules.mysql_probe import MySqlProbe
mysql = MySqlProbe('192.168.56.101', verbose=True)
result = mysql.run()
print('Accessible:', result['accessible'])
print('Creds:', result['credentials_found'])
"
# Expected: accessible=True, credentials_found='root:(empty)'
```

**Success Criteria**:
- [ ] FTP anonymous login = True on Metasploitable 2
- [ ] vsftpd 2.3.4 backdoor flagged in FTP result
- [ ] SSH version extracted correctly
- [ ] OpenSSH 4.7p1 triggers CVE flag
- [ ] MySQL root with empty password detected

---

### Step 3.5: Module Dispatcher & Orchestrator (Partial)

**Duration**: 2 hours  
**Goal**: Orchestrator sequences nmap → dispatches correct modules

**Implement `core/orchestrator.py`** with:
- `_init_scan_result()` — creates empty ScanResult dict
- `_dispatch_modules()` — reads nmap ports, queues and runs correct modules
- Partial `run()` — no AI or reporting yet

**Manual end-to-end test**:
```bash
python3 -c "
from core.orchestrator import Orchestrator
orch = Orchestrator('192.168.56.101', 'quick', 'pdf', no_ai=True, verbose=True)
# Run just nmap + dispatch (no AI, no reports)
import json
result = orch._init_scan_result()
print(json.dumps(result['meta'], indent=2))
"
```

**Success Criteria**:
- [ ] ScanResult dict initializes with all expected keys
- [ ] Web module triggered for port 80
- [ ] SMB module triggered for port 445
- [ ] FTP module triggered for port 21

---

## Phase 4: AI Intelligence Engine (Days 16–19)

---

### Step 4.1: AI Prompts & Request Builder

**Duration**: 2 hours  
**Goal**: `ai/prompts.py` has system prompt; `build_user_message()` works

**Implement `ai/prompts.py`** (full system prompt from BACKEND_STRUCTURE.md §4)

**Test the message builder manually**:
```python
# Load a saved ScanResult JSON from Phase 3 test
import json
from ai.intelligence import build_user_message

with open("tests/fixtures/sample_scan_result.json") as f:
    scan_result = json.load(f)

message = build_user_message(scan_result)
print(message)
print(f"\nMessage length: {len(message)} chars")
# Should be < 8000 chars to fit in LLM context comfortably
```

**Action**: Save a real ScanResult from Phase 3 as `tests/fixtures/sample_scan_result.json`

**Success Criteria**:
- [ ] User message includes all non-empty module results
- [ ] Message is under 8,000 characters for typical Metasploitable 2 scan
- [ ] All port/version/finding data present in message

---

### Step 4.2: Together AI API Client

**Duration**: 3 hours  
**Goal**: Full API call works and returns parseable JSON

**Implement `ai/intelligence.py`** (full code in BACKEND_STRUCTURE.md §4)

**Test with real API**:
```bash
python3 -c "
import json
from ai.intelligence import call_ai_engine
import os
from dotenv import load_dotenv
load_dotenv()

with open('tests/fixtures/sample_scan_result.json') as f:
    scan_result = json.load(f)

result = call_ai_engine(scan_result, os.getenv('TOGETHER_API_KEY'))

if result:
    print('Risk Level:', result['risk_level'])
    print('CVEs found:', len(result['cves']))
    print('TTPs found:', len(result['ttps']))
    print('Findings:', len(result['findings']))
    print()
    print('Executive Summary:')
    print(result['executive_summary'])
else:
    print('AI engine returned None (API failure)')
"
```

**Expected output on Metasploitable 2 data**:
```
Risk Level: Critical
CVEs found: 8
TTPs found: 12
Findings: 15

Executive Summary:
The target exposes multiple critical vulnerabilities including a vsftpd 2.3.4 backdoor 
(CVE-2011-2523), unauthenticated MySQL root access, open SMB null sessions, and a severely 
outdated Apache web server with multiple known exploits...
```

**Write tests** (`tests/test_ai_engine.py`):
```python
from unittest.mock import patch, MagicMock
from ai.intelligence import call_ai_engine
import json

MOCK_AI_RESPONSE = {
    "choices": [{
        "message": {
            "content": json.dumps({
                "risk_level": "Critical",
                "executive_summary": "Test summary",
                "cves": [{"id": "CVE-2011-2523", "cvss": "10.0",
                           "service": "ftp:vsftpd 2.3.4",
                           "description": "Backdoor", "recommendation": "Upgrade"}],
                "ttps": [{"id": "T1190", "name": "Exploit Public-Facing App",
                           "tactic": "Initial Access"}],
                "findings": [],
            })
        }
    }]
}

def test_ai_engine_success():
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_AI_RESPONSE
        mock_post.return_value = mock_response
        
        result = call_ai_engine({"meta": {"target": "192.168.1.1"}}, "fake_key")
        assert result["risk_level"] == "Critical"
        assert result["cves"][0]["id"] == "CVE-2011-2523"

def test_ai_engine_api_failure():
    with patch("requests.post") as mock_post:
        mock_post.side_effect = Exception("Connection error")
        result = call_ai_engine({}, "fake_key", max_retries=1)
        assert result is None
```

```bash
pytest tests/test_ai_engine.py -v
```

**Success Criteria**:
- [ ] Real API call returns `risk_level: "Critical"` for Metasploitable 2 data
- [ ] At least 5 CVEs returned (vsftpd, OpenSSH, Apache, MySQL, SMB)
- [ ] At least 8 TTPs returned
- [ ] Mock tests both pass
- [ ] Rate limit retry works (manually test by setting a very short timeout)

---

## Phase 5: Reporting (Days 20–23)

---

### Step 5.1: PDF Report Generator

**Duration**: 4 hours  
**Goal**: Professional PDF generated from full ScanResult

**Implement `reporting/pdf_generator.py`** (per BACKEND_STRUCTURE.md §5.1)

**Manual test**:
```bash
python3 -c "
import json
from reporting.pdf_generator import PdfGenerator
from dotenv import load_dotenv
load_dotenv()

# Load a complete ScanResult (with AI data)
with open('tests/fixtures/complete_scan_result.json') as f:
    scan_result = json.load(f)

gen = PdfGenerator(scan_result, './reports/test_report.pdf')
path = gen.generate()
print(f'Report generated: {path}')
"

# Open the PDF
xdg-open ./reports/test_report.pdf
```

**PDF quality checklist** (manual review):
- [ ] Cover page: target IP, date, risk level badge visible
- [ ] Executive summary text is legible
- [ ] Findings are severity-sorted (Critical first)
- [ ] CVE table has all columns
- [ ] ATT&CK TTP table present
- [ ] Raw nmap port table in appendix

**Action**: Save this PDF as your sample report for README/portfolio

---

### Step 5.2: JSON & Markdown Exporters

**Duration**: 1.5 hours  
**Goal**: `--format json` and `--format markdown` both work

**Implement `reporting/json_exporter.py`** and `reporting/markdown_gen.py`

**Tests**:
```bash
# JSON
python3 -c "
from reporting.json_exporter import export_json
import json
with open('tests/fixtures/complete_scan_result.json') as f:
    result = json.load(f)
path = export_json(result, './reports/test_export.json')
print('JSON saved:', path)
"

# Markdown
python3 -c "
from reporting.markdown_gen import generate_markdown
import json
with open('tests/fixtures/complete_scan_result.json') as f:
    result = json.load(f)
path = generate_markdown(result, './reports/test_report.md')
print('Markdown saved:', path)
"
```

**Success Criteria**:
- [ ] JSON export is valid JSON (`python -m json.tool` parses it)
- [ ] Markdown report renders correctly in VS Code preview
- [ ] Both files saved to `./reports/`

---

## Phase 6: Full Integration (Days 24–26)

---

### Step 6.1: Complete Orchestrator Integration

**Duration**: 4 hours  
**Goal**: Full `python aegis.py --target 192.168.56.101` runs start to finish

**Complete `core/orchestrator.py`**:
- Wire up validator → dependency check → nmap → dispatcher → modules → AI → reports → summary
- Add try/except for each module (fail-soft)
- Add `KeyboardInterrupt` handler
- Add temp file cleanup in `finally`

**Full integration test on Metasploitable 2**:
```bash
# Full scan (the moment of truth)
sudo python aegis.py --target 192.168.56.101 --profile full --verbose

# Expected: completes in < 10 minutes, generates PDF
# Check report:
ls -la reports/
xdg-open reports/192.168.56.101_*.pdf
```

**Success Criteria**:
- [ ] Banner displays
- [ ] Scope prompt appears and works
- [ ] Dependency check passes
- [ ] Nmap module runs and shows port table
- [ ] Web module triggers (port 80 detected)
- [ ] SMB module triggers (port 445 detected)
- [ ] FTP module triggers (port 21 detected)
- [ ] AI engine runs and returns analysis
- [ ] PDF generated and viewable
- [ ] Final summary panel shows correct counts
- [ ] No unhandled exceptions
- [ ] Ctrl+C handled gracefully

---

### Step 6.2: Edge Case & Error Handling Tests

**Duration**: 2 hours  
**Goal**: All error states from APP_FLOW.md §2 work correctly

**Test each error condition**:
```bash
# Invalid IP
python aegis.py --target 999.999.999.999
# Expected: "Invalid target" error panel, exit 1

# Authorization denial
python aegis.py --target 192.168.56.101
# When prompted, type 'n'
# Expected: "Scan aborted" message, exit 0

# Missing tool (simulate by temporarily renaming nmap)
sudo mv /usr/bin/nmap /usr/bin/nmap.bak
python aegis.py --target 192.168.56.101
sudo mv /usr/bin/nmap.bak /usr/bin/nmap
# Expected: "nmap not found" with install command, exit 1

# No-AI mode
python aegis.py --target 192.168.56.101 --no-ai
# Expected: PDF generated without CVE/TTP data, no API call made

# Unreachable target
python aegis.py --target 10.255.255.1 --profile quick
# Expected: Nmap completes with 0 ports, "No open ports detected" report
```

**Success Criteria**:
- [ ] All 5 error conditions produce correct output
- [ ] No unhandled exceptions in any error case
- [ ] Exit codes are correct (0 for auth denial, 1 for errors)

---

## Phase 7: Polish & Documentation (Days 27–30)

---

### Step 7.1: README.md

**Duration**: 3 hours  
**Goal**: GitHub-ready README that makes a recruiter want to clone it

**README sections**:
```markdown
# AEGIS — Adaptive Exploitation & Global Intelligence System

[Demo GIF here]

## What It Does
Brief description of the pipeline.

## Features
- Automated nmap + web + SMB + FTP + SSH + MySQL scanning
- AI-powered CVE correlation and MITRE ATT&CK mapping
- Professional PDF reports

## Demo
[Sample report screenshot here]

## Quick Start
Installation + usage commands

## Architecture
ASCII diagram of the pipeline

## Sample Report
[Link to sample PDF in /docs/sample_report.pdf]

## Tech Stack
Python, Rich, fpdf2, Together AI, Qwen2.5-72B

## Disclaimer
For authorized lab testing only.
```

---

### Step 7.2: Demo & Portfolio Assets

**Duration**: 2 hours  
**Goal**: Visual assets that make the project portfolio-ready

**Tasks**:
```bash
# 1. Record terminal demo with asciinema
sudo apt install asciinema
asciinema rec demo.cast
# Run a full scan on Metasploitable 2 during recording
asciinema play demo.cast

# 2. Convert to GIF for README
sudo apt install npm
npm install -g asciicast2gif  # OR use terminalizer
# → demo.gif → add to README

# 3. Take screenshot of generated PDF
# → Add as /docs/sample_report_preview.png to README

# 4. Add sample report PDF
mkdir docs
cp reports/192.168.56.101_<latest>.pdf docs/sample_report.pdf
git add docs/sample_report.pdf
```

---

### Step 7.3: Final Testing & GitHub Publish

**Duration**: 2 hours  
**Goal**: Clean repo published to GitHub

**Pre-publish checklist**:
```bash
# Run all tests
pytest tests/ -v --cov=aegis --cov-report=term-missing
# Target: 70%+ coverage

# Lint
flake8 .

# Format
black .

# Verify .env is not committed
git status  # .env must NOT appear

# Final scan test
sudo python aegis.py --target 192.168.56.101 --profile quick

# Git clean up
git add .
git commit -m "feat: AEGIS v1.0.0 complete"
git tag v1.0.0
```

**GitHub setup**:
```bash
# Create GitHub repo: aegis (public)
git remote add origin https://github.com/<username>/aegis.git
git push -u origin main
git push --tags
```

**Success Criteria**:
- [ ] `pytest` passes with ≥ 70% coverage
- [ ] `flake8` shows 0 errors
- [ ] `.env` not in `git log --all`
- [ ] GitHub repo is public
- [ ] README renders correctly on GitHub (check demo GIF loads)
- [ ] `docs/sample_report.pdf` downloadable from GitHub

---

## Milestones Summary

| Milestone | Day | Deliverable | Verified By |
|-----------|-----|-------------|-------------|
| M1: Foundation | Day 4 | CLI works, venv set up, all tools installed | `python aegis.py --help` |
| M2: Core Infra | Day 7 | Validator, dependency checker, subprocess utils | All unit tests pass |
| M3: Scan Modules | Day 15 | All 6 scan modules work on Metasploitable 2 | Manual test each module |
| M4: AI Engine | Day 19 | AI returns CVEs + TTPs for Metasploitable data | Mock + real API tests |
| M5: Reports | Day 23 | PDF, JSON, Markdown all generate correctly | Open each file manually |
| M6: Integration | Day 26 | Full `aegis.py --target` runs end-to-end | Complete scan + PDF review |
| **M7: MVP Launch** | **Day 30** | **GitHub published, README complete, demo GIF** | **Public GitHub repo live** |

---

## Risk Mitigation

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Together AI rate limit hits during dev | Medium | High | Use `--no-ai` for module testing; save API calls for integration testing |
| enum4linux output format changes | Medium | Low | Pin tool versions; test parser against fixture file |
| Metasploitable 2 unreachable | High | Low | Keep VirtualBox snapshot; document network adapter settings |
| nmap requires root for OS detection | Medium | High | Test with `--profile web` (no -O flag) first; add sudo guidance |
| PDF font rendering issues | Low | Medium | Test on clean VM; fpdf2 has built-in fonts that don't need installation |
| LLM returns non-JSON response | Medium | Medium | Retry logic + fallback to raw report already implemented in spec |

---

## Post-MVP Roadmap (v1.1+)

After MVP is live on GitHub:

1. **Shodan integration** (`--osint` flag) — passive recon for public IPs
2. **Multi-target support** (`--target-list targets.txt`) — scan multiple hosts
3. **CVE local database** — NVD JSON feed for offline CVE lookups
4. **CVSS-sorted PDF** — findings ordered by CVSS score, not just severity tier
5. **HTML report** — browser-viewable report with syntax highlighting
6. **Docker container** — `docker pull aegis:latest` for zero-dependency install
7. **Plugin system** — community can add new probe modules

---

## Overall MVP Success Criteria

AEGIS v1.0 is considered **COMPLETE** when:

- [ ] Full scan of Metasploitable 2 completes without error in < 10 minutes
- [ ] Discovers ≥ 15 distinct vulnerabilities on Metasploitable 2
- [ ] Maps ≥ 5 real CVEs (vsftpd, OpenSSH, Apache, MySQL, Samba)
- [ ] Maps ≥ 8 MITRE ATT&CK TTPs
- [ ] Generates a PDF report readable by a non-technical audience
- [ ] All 4 error conditions (invalid IP, auth denial, missing tool, API failure) handled gracefully
- [ ] `pytest` test suite at ≥ 70% coverage
- [ ] GitHub repo is public with README, demo GIF, and sample PDF
- [ ] Zero hardcoded API keys or secrets in git history
