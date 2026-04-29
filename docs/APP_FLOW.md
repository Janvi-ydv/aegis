# Application Flow Documentation
# AEGIS — Adaptive Exploitation & Global Intelligence System

---

## 1. Entry Points

AEGIS is a CLI tool. All entry points are terminal commands.

### Primary Entry Point
```bash
python aegis.py --target <IP/hostname> [options]
```

### All Valid Entry Commands
```bash
# Standard full scan
python aegis.py --target 192.168.1.100

# Scan with profile preset
python aegis.py --target 192.168.1.100 --profile quick
python aegis.py --target 192.168.1.100 --profile full
python aegis.py --target 192.168.1.100 --profile web
python aegis.py --target 192.168.1.100 --profile stealth

# Specify output format
python aegis.py --target 192.168.1.100 --format pdf
python aegis.py --target 192.168.1.100 --format json
python aegis.py --target 192.168.1.100 --format markdown

# Disable AI engine (raw scan only)
python aegis.py --target 192.168.1.100 --no-ai

# Verbose mode
python aegis.py --target 192.168.1.100 --verbose

# Help
python aegis.py --help

# Version
python aegis.py --version
```

---

## 2. Core Application Flows

---

### Flow 1: Full Scan — Happy Path

**Goal**: User completes a successful full vulnerability scan and receives a PDF report.  
**Entry Point**: `python aegis.py --target 192.168.1.100`  
**Frequency**: Primary use case — every scan session

#### Happy Path

```
Step 1: CLI Argument Parsing
├── argparse parses --target, --profile, --format, --no-ai, --verbose
├── Validates: target string is not empty
└── Passes args to Orchestrator

Step 2: Banner Display
├── AEGIS ASCII art banner prints (via Rich)
├── Version number displayed
└── Current timestamp + target shown

Step 3: Target Validation
├── Checks IP format with Python ipaddress module
├── Determines if IP is private (RFC1918) or public
│   ├── Private IP → marks as "Lab/Internal target"
│   └── Public IP → marks as "External target — confirm scope"
└── Scope Authorization Prompt:
    "⚠  Target: 192.168.1.100 | Do you have explicit written authorization to scan this target? [y/N]:"
    ├── User types 'y' → Proceed
    └── User types 'n' or anything else → Exit with code 0

Step 4: Dependency Check
├── Checks for: nmap, nikto, gobuster, enum4linux
├── Checks Python packages: rich, fpdf2, requests
├── All present → Rich panel: "✓ All dependencies satisfied"
└── Missing dependency → Print install command + exit

Step 5: Network Reconnaissance Module (nmap)
├── Rich spinner: "[ RECON ] Running nmap service/version scan..."
├── Executes: nmap -sV -sC -O -p- --open -oX /tmp/aegis_nmap.xml <target>
├── Parses XML output:
│   ├── Extracts open ports list
│   ├── Extracts service names + versions per port
│   ├── Extracts OS guess (if detected)
│   └── Flags: interesting services (ftp, ssh, http, smb, mysql, etc.)
├── Rich table printed:
│   PORT | SERVICE | VERSION | STATE
│   21   | ftp     | vsftpd 2.3.4 | OPEN
│   ...
└── Module result stored in scan_results['nmap']

Step 6: Module Dispatcher
├── Reads scan_results['nmap']['open_ports']
├── Checks for HTTP ports (80, 443, 8080, 8443):
│   └── True → Queue Web Module
├── Checks for SMB port (445, 139):
│   └── True → Queue SMB Enum Module
├── Checks for FTP port (21):
│   └── True → Queue FTP Module
├── Checks for SSH port (22):
│   └── True → Queue SSH Module
├── Checks for MySQL port (3306):
│   └── True → Queue MySQL Module
└── Dispatches queued modules sequentially

Step 7: Web Application Scanning Module (if HTTP detected)
├── Rich spinner: "[ WEB ] Running nikto web vulnerability scan..."
├── Executes: nikto -h http://<target> -Format xml -o /tmp/aegis_nikto.xml
├── Parses: findings list (vulnerability, path, method, description)
├── Rich spinner: "[ WEB ] Running gobuster directory enumeration..."
├── Executes: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -o /tmp/aegis_gobuster.txt -q
├── Parses: discovered paths list
├── Rich table: WEB FINDINGS
│   PATH | TYPE | FINDING
│   /admin | nikto | Directory listing enabled
│   /phpmyadmin | gobuster | 200 OK
└── Stored in scan_results['web']

Step 8: SMB Enumeration Module (if SMB detected)
├── Rich spinner: "[ SMB ] Running enum4linux..."
├── Executes: enum4linux -a <target> > /tmp/aegis_smb.txt
├── Parses: shares list, users list, OS version, workgroup
├── Rich table: SMB FINDINGS
└── Stored in scan_results['smb']

Step 9: FTP Module (if FTP detected)
├── Rich spinner: "[ FTP ] Testing FTP anonymous login..."
├── Python ftplib.FTP attempts anonymous:anonymous login
├── Success → flags "Anonymous FTP login allowed"
├── Lists root directory if accessible
└── Stored in scan_results['ftp']

Step 10: SSH Module (if SSH detected)
├── Rich spinner: "[ SSH ] Grabbing SSH banner..."
├── Banner grabs service version string
├── Checks version against known-vulnerable list:
│   ├── OpenSSH < 7.7 → flag CVE-2018-15473 (User enum)
│   └── Paramiko-based → flag potential MitM risk
└── Stored in scan_results['ssh']

Step 11: MySQL Module (if MySQL detected)
├── Rich spinner: "[ DB ] Testing MySQL default credentials..."
├── Attempts: root:'' (empty), root:root, root:toor
├── Records: accessible (yes/no), which creds if any
└── Stored in scan_results['mysql']

Step 12: AI Vulnerability Intelligence Engine
├── Rich spinner: "[ AI ] Sending findings to intelligence engine..."
├── Constructs structured prompt from all scan_results modules
├── Sends POST to Together AI API (Qwen2.5-72B-Instruct)
├── Receives JSON response containing:
│   ├── cves: [{id, cvss, service, description}]
│   ├── ttps: [{id, name, tactic}]
│   ├── risk_level: "Critical|High|Medium|Low"
│   ├── executive_summary: "string"
│   └── findings: [{title, description, severity, recommendation}]
├── Parses and validates JSON response
├── Rich panel: AI INTELLIGENCE REPORT
│   Risk Level: CRITICAL (displayed in red)
│   CVEs Found: 8
│   ATT&CK TTPs: 12
└── Stored in scan_results['ai']

Step 13: PDF Report Generation
├── Rich spinner: "[ REPORT ] Generating PDF report..."
├── Creates ./reports/ directory if not exists
├── Generates filename: <target>_<YYYYMMDD_HHMMSS>.pdf
├── Builds PDF sections:
│   ├── Cover Page
│   ├── Executive Summary (from AI)
│   ├── Findings Table (severity sorted)
│   ├── CVE List
│   ├── MITRE ATT&CK TTPs
│   └── Raw Scan Appendix
└── Saves to: ./reports/<target>_<timestamp>.pdf

Step 14: Final Summary
├── Rich panel: SCAN COMPLETE
│   Target: 192.168.1.100
│   Duration: 7m 23s
│   Risk Level: CRITICAL
│   Findings: 23 total (5 Critical, 8 High, 7 Medium, 3 Low)
│   CVEs: 8 mapped
│   TTPs: 12 identified
│   Report: ./reports/192.168.1.100_20260426_143022.pdf
└── Exit code 0
```

#### Error States

| Error | When | Display | Recovery |
|-------|------|---------|----------|
| Invalid IP format | `--target abc.def` | `[ERROR] Invalid target: 'abc.def' is not a valid IP or hostname` | Exit code 1 |
| Authorization denied | User types 'n' at prompt | `[AEGIS] Scan aborted. Always obtain explicit written authorization before scanning.` | Exit code 0 |
| nmap not found | Dependency check | `[ERROR] nmap not found. Install: sudo apt install nmap` | Exit code 1 |
| nmap requires root | Nmap execution | `[WARN] Some nmap features require sudo. Re-run with: sudo python aegis.py ...` | Continue with limited scan |
| nikto timeout | > 10 min | `[WARN] nikto timed out after 10m. Skipping web scan.` | Continue without web module |
| Together AI API down | HTTP 5xx | `[WARN] AI engine unavailable. Report will use raw scan data only.` | Generate PDF without AI |
| Together AI rate limited | HTTP 429 | `[WARN] Rate limited. Retrying in 30s... (attempt 1/3)` | Retry 3x then fallback |
| Wordlist not found | gobuster run | `[ERROR] Wordlist not found: /usr/share/wordlists/dirb/common.txt. Install: sudo apt install dirb` | Skip gobuster, continue |
| Reports directory write fail | PDF generation | `[ERROR] Cannot write to ./reports/. Check permissions.` | Exit code 1 |

#### Edge Cases

- **Target is localhost (127.0.0.1)**: Allow with a warning: "Scanning localhost — ensure this is intentional."
- **All ports filtered**: nmap returns no open ports → skip all modules, generate minimal report: "No open ports detected. Target may be offline or firewall blocking all ports."
- **LLM returns malformed JSON**: Retry once with simplified prompt, then fallback to raw template.
- **scan interrupted (Ctrl+C)**: Catch `KeyboardInterrupt` → print "Scan interrupted. Saving partial results..." → generate report from whatever data was collected.

---

### Flow 2: `--no-ai` Offline Mode

**Goal**: Run full scan without LLM API call.  
**Entry**: `python aegis.py --target 192.168.1.100 --no-ai`

```
Steps 1–11: Identical to Full Scan Flow
Step 12: AI Engine → SKIPPED
         Rich panel: "[ AI ] AI engine disabled (--no-ai). Generating raw report."
Step 13: PDF generated using raw scan data only (no CVE mappings, no TTP tags)
Step 14: Summary shows "AI Analysis: Disabled"
```

---

### Flow 3: `--help` Command

```
python aegis.py --help
→ Prints Rich-formatted help panel (no scan initiated):

  AEGIS — Adaptive Exploitation & Global Intelligence System v1.0
  
  Usage: python aegis.py --target <IP> [options]
  
  Options:
    --target   <IP/hostname>   Target to scan (required)
    --profile  <preset>        Scan profile: quick|full|web|stealth (default: full)
    --format   <type>          Output format: pdf|json|markdown (default: pdf)
    --no-ai                    Disable AI analysis (offline mode)
    --verbose                  Show raw tool output during scan
    --output   <path>          Custom report output path
    --version                  Show version
    --help                     Show this help

  Scan Profiles:
    quick    Top 1000 ports, fast timing
    full     All 65535 ports, service detection (default)
    web      HTTP/HTTPS ports only (80, 443, 8080, 8443)
    stealth  Slow timing, SYN scan, lower detection risk (requires root)

→ Exit code 0
```

---

## 3. Module Architecture Flow

```
aegis.py (entry point)
│
├── cli/
│   └── parser.py          → argparse, arg validation
│
├── core/
│   ├── orchestrator.py    → sequences all modules, holds scan_results dict
│   ├── validator.py       → target IP/hostname validation, scope prompt
│   └── dependency.py      → checks all required tools + Python packages
│
├── modules/
│   ├── nmap_scanner.py    → runs nmap, parses XML, returns structured dict
│   ├── web_scanner.py     → runs nikto + gobuster, parses output
│   ├── smb_enum.py        → runs enum4linux, parses output
│   ├── ftp_probe.py       → ftplib anonymous login test
│   ├── ssh_probe.py       → banner grab + version check
│   └── mysql_probe.py     → default credential test
│
├── ai/
│   └── intelligence.py    → builds prompt, calls Together AI, parses response
│
├── reporting/
│   ├── pdf_generator.py   → fpdf2 PDF builder
│   ├── json_exporter.py   → JSON serializer
│   └── markdown_gen.py    → Markdown report builder
│
├── ui/
│   └── console.py         → Rich panels, tables, spinners, colors
│
└── utils/
    ├── file_utils.py      → temp file management, path handling
    └── subprocess_utils.py → safe subprocess.run wrapper with timeout
```

---

## 4. Screen/Output Inventory

### Screen 1: Banner
- **Trigger**: Any aegis.py execution
- **Content**: ASCII art logo, version, tagline
- **States**: Always shown (no variants)

### Screen 2: Scope Authorization Prompt
- **Trigger**: After target validation passes
- **Content**: Target IP, warning text, yes/no prompt
- **States**: Waiting for input

### Screen 3: Dependency Check Panel
- **Trigger**: After authorization confirmed
- **Content**: Table of tools with ✓ / ✗ status
- **States**: All OK (green) | Missing (red, exits)

### Screen 4: Module Progress Display
- **Trigger**: Each module starts
- **Content**: Module name, spinner animation, elapsed time
- **States**: Running (spinner) | Complete (✓ + duration) | Failed (✗ + error msg)

### Screen 5: Module Result Table
- **Trigger**: Each module completes
- **Content**: Formatted table specific to module (ports, paths, shares, etc.)
- **States**: Has findings (colored rows) | No findings (dim "Nothing found")

### Screen 6: AI Analysis Panel
- **Trigger**: AI engine completes
- **Content**: Risk level (colored), CVE count, TTP count
- **States**: Success | Fallback (no-ai or API fail)

### Screen 7: Final Summary Panel
- **Trigger**: After report saved
- **Content**: All stats, report path, scan duration
- **States**: Complete | Partial (interrupted)

---

## 5. Decision Points

```
IF --target is not provided
THEN show: "Error: --target is required" + help hint
EXIT code 1

IF target IP is invalid format
THEN show: "Invalid target: not a valid IP or hostname"
EXIT code 1

IF user denies scope authorization
THEN show: "Scan aborted."
EXIT code 0

IF dependency missing
THEN show: tool name + install command
EXIT code 1

IF nmap open_ports is empty
THEN skip: all other modules
THEN generate: "No open ports" report

IF port 80 OR 443 OR 8080 OR 8443 in open_ports
THEN run: Web Module
ELSE skip: Web Module

IF port 445 OR 139 in open_ports
THEN run: SMB Module
ELSE skip: SMB Module

IF port 21 in open_ports
THEN run: FTP Module
ELSE skip: FTP Module

IF --no-ai flag is set OR Together AI API returns 5xx after 3 retries
THEN skip: AI engine
THEN generate: raw-only report (no CVE/TTP data)
ELSE run: AI engine

IF --format is "pdf"
THEN run: PDF generator
ELSE IF --format is "json"
THEN run: JSON exporter
ELSE IF --format is "markdown"
THEN run: Markdown generator
```

---

## 6. Data Flow Through Application

```
User Input (CLI args)
        │
        ▼
  Target Validation ──────────────────► EXIT (invalid/unauthorized)
        │
        ▼
  Dependency Check ───────────────────► EXIT (missing tools)
        │
        ▼
  Nmap Module ──────────────────────────────────────────┐
        │                                               │
        ▼                                               │
  Module Dispatcher                                     │
   ├── Web Module (conditional) ────────────────────────┤
   ├── SMB Module (conditional) ────────────────────────┤  → scan_results{}
   ├── FTP Module (conditional) ────────────────────────┤
   ├── SSH Module (conditional) ────────────────────────┤
   └── MySQL Module (conditional) ───────────────────────┘
        │
        ▼
  AI Intelligence Engine ──────────────────────────────► ai_results{}
   (takes scan_results as input)              (or fallback: None)
        │
        ▼
  Report Generator
   (takes scan_results + ai_results)
        │
        ▼
  ./reports/<target>_<timestamp>.{pdf|json|md}
        │
        ▼
  Final Summary Panel → EXIT code 0
```

---

## 7. Error Handling Flows

### Tool Execution Failure
```
subprocess.run() raises: FileNotFoundError
    → Catch exception
    → Rich error panel: "[Module] tool not found"
    → Log to scan_results['errors'] list
    → Continue to next module
```

### Network Timeout
```
subprocess.run() exceeds timeout=600s
    → subprocess.TimeoutExpired raised
    → Rich warning: "[Module] timed out after Xs"
    → Store partial output if available
    → Continue to next module
```

### API Failure (Together AI)
```
HTTP 5xx from API:
    → Retry after 30s (max 3 attempts)
    → After 3 failures: set ai_results = None
    → Rich warning panel: "AI engine unavailable. Generating raw report."
    → PDF/report generation continues without AI data
```

### Keyboard Interrupt
```
User presses Ctrl+C:
    → Catch KeyboardInterrupt in orchestrator
    → Stop current subprocess (process.terminate())
    → Rich panel: "Scan interrupted. Saving partial results..."
    → Generate report from scan_results collected so far
    → Exit code 130
```

---

## 8. Verbose Mode Behavior

When `--verbose` is active:
- Raw stdout/stderr of every tool is printed in a dim color below the spinner
- JSON prompt sent to AI engine is printed to terminal
- Raw AI response printed before parsing
- All subprocess commands printed before execution:
  ```
  [CMD] nmap -sV -sC -O -p- --open -oX /tmp/aegis_nmap.xml 192.168.1.100
  ```

---

## 9. File System Interactions

```
READS:
  /usr/share/wordlists/dirb/common.txt   (gobuster wordlist)
  .env                                    (API keys)
  /tmp/aegis_nmap.xml                     (nmap temp output)
  /tmp/aegis_nikto.xml                    (nikto temp output)
  /tmp/aegis_gobuster.txt                 (gobuster temp output)
  /tmp/aegis_smb.txt                      (enum4linux temp output)

WRITES:
  /tmp/aegis_*.{xml,txt}                 (temp scan outputs, deleted after parse)
  ./reports/<target>_<timestamp>.pdf     (final report)
  ./reports/<target>_<timestamp>.json    (if --format json)
  ./reports/<target>_<timestamp>.md      (if --format markdown)
  ./aegis.log                            (error log)
```
