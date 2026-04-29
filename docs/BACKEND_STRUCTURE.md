# Backend Structure & Module Architecture
# AEGIS — Adaptive Exploitation & Global Intelligence System

> Note: AEGIS has no web backend or database. This document defines the internal module architecture, data contracts between modules, the AI integration layer, and the reporting pipeline — the equivalent of a backend spec for a Python CLI application.

---

## 1. Architecture Overview

### Pattern
AEGIS uses a **Pipeline Orchestrator** pattern:
```
CLI Input → Validator → Orchestrator → [Module Pipeline] → AI Engine → Report Generator → Output
```

All data flows through a central `ScanResult` object (Python dict) that accumulates structured findings as each module completes. No shared state beyond this object.

### Key Design Decisions
- **No async**: All modules run synchronously. Simplicity over speed for v1.0.
- **No database**: All state is in-memory during execution; persisted only in final report files.
- **Subprocess isolation**: Each security tool runs as a subprocess with timeout and is never `shell=True`.
- **Fail-soft**: Any individual module failure is caught, logged, and execution continues.

---

## 2. Central Data Contract — `ScanResult` Object

This Python dict is the **single source of truth** passed between all modules. Every module reads from and writes to it.

```python
ScanResult = {
    "meta": {
        "target": str,               # IP or hostname
        "scan_start": str,           # ISO 8601 timestamp
        "scan_end": str,             # ISO 8601 timestamp  
        "duration_seconds": float,
        "profile": str,              # "quick"|"full"|"web"|"stealth"
        "aegis_version": str,
    },
    "nmap": {
        "raw_xml_path": str,         # /tmp/aegis_nmap.xml
        "os_guess": str | None,      # e.g. "Linux 4.x"
        "open_ports": [
            {
                "port": int,
                "protocol": str,     # "tcp"|"udp"
                "service": str,      # e.g. "ftp", "http", "ssh"
                "version": str,      # e.g. "vsftpd 2.3.4"
                "state": str,        # "open"|"filtered"
                "scripts": dict,     # nmap NSE script results
            }
        ],
        "interesting_services": list[str],  # list of service names flagged
        "error": str | None,
    },
    "web": {
        "enabled": bool,
        "base_url": str | None,      # e.g. "http://192.168.1.100"
        "nikto": {
            "findings": [
                {
                    "id": str,
                    "path": str,
                    "method": str,
                    "description": str,
                    "reference": str,
                }
            ],
            "error": str | None,
        },
        "gobuster": {
            "paths": [
                {
                    "path": str,     # e.g. "/admin"
                    "status_code": int,
                    "size": int,
                }
            ],
            "error": str | None,
        },
    },
    "smb": {
        "enabled": bool,
        "shares": [
            {
                "name": str,
                "type": str,
                "comment": str,
            }
        ],
        "users": list[str],
        "os_version": str | None,
        "workgroup": str | None,
        "null_session": bool,
        "error": str | None,
    },
    "ftp": {
        "enabled": bool,
        "anonymous_login": bool,
        "banner": str | None,
        "accessible_files": list[str],
        "error": str | None,
    },
    "ssh": {
        "enabled": bool,
        "banner": str | None,
        "version": str | None,       # e.g. "OpenSSH 4.7p1"
        "weak_algorithms": list[str],
        "known_cves": list[str],     # CVE IDs flagged by local check
        "error": str | None,
    },
    "mysql": {
        "enabled": bool,
        "accessible": bool,
        "credentials_found": str | None,  # e.g. "root:(empty)"
        "error": str | None,
    },
    "ai": {
        "enabled": bool,
        "risk_level": str | None,    # "Critical"|"High"|"Medium"|"Low"
        "executive_summary": str | None,
        "cves": [
            {
                "id": str,           # e.g. "CVE-2011-2523"
                "cvss": str,         # e.g. "10.0"
                "service": str,
                "description": str,
                "recommendation": str,
            }
        ],
        "ttps": [
            {
                "id": str,           # e.g. "T1110.001"
                "name": str,         # e.g. "Brute Force: Password Guessing"
                "tactic": str,       # e.g. "Credential Access"
            }
        ],
        "findings": [
            {
                "title": str,
                "severity": str,     # "Critical"|"High"|"Medium"|"Low"
                "description": str,
                "recommendation": str,
            }
        ],
        "raw_response": str | None,  # Full LLM response (for debug)
        "error": str | None,
    },
    "errors": list[str],             # Non-fatal errors from any module
}
```

---

## 3. Module Specifications

### 3.1 Orchestrator (`core/orchestrator.py`)

**Purpose**: Sequences all modules, manages `ScanResult`, calls reporter.

```python
class Orchestrator:
    def __init__(self, target: str, profile: str, output_format: str, no_ai: bool, verbose: bool):
        self.target = target
        self.profile = profile
        self.output_format = output_format
        self.no_ai = no_ai
        self.verbose = verbose
        self.scan_result: ScanResult = self._init_scan_result()

    def run(self) -> str:
        """
        Main pipeline. Returns path to generated report.
        Raises OrchestratorError on fatal failure.
        """
        ...

    def _init_scan_result(self) -> dict: ...
    def _dispatch_modules(self) -> None: ...
    def _should_run_web(self) -> bool: ...
    def _should_run_smb(self) -> bool: ...
    def _should_run_ftp(self) -> bool: ...
    def _should_run_ssh(self) -> bool: ...
    def _should_run_mysql(self) -> bool: ...
```

**Module dispatch logic**:
```python
PROFILE_PORT_LIMITS = {
    "quick":   "-p 1-1000",
    "full":    "-p-",
    "web":     "-p 80,443,8080,8443",
    "stealth": "-sS -p-",
}

TRIGGER_PORTS = {
    "web":   {80, 443, 8080, 8443},
    "smb":   {139, 445},
    "ftp":   {21},
    "ssh":   {22},
    "mysql": {3306},
}
```

---

### 3.2 Nmap Scanner (`modules/nmap_scanner.py`)

**Purpose**: Execute nmap and parse XML output into structured data.

```python
class NmapScanner:
    def __init__(self, target: str, profile: str, verbose: bool): ...

    def run(self) -> dict:
        """
        Returns nmap section of ScanResult.
        Never raises — returns error key on failure.
        """
        ...

    def _build_nmap_args(self) -> list[str]:
        """Returns list of nmap CLI arguments based on profile."""
        ...

    def _parse_xml(self, xml_path: str) -> dict:
        """Parse nmap XML output → structured dict."""
        ...

    def _extract_interesting_services(self, ports: list[dict]) -> list[str]:
        """Flag services worth deeper investigation."""
        ...
```

**Nmap commands by profile**:
```bash
# quick
nmap -sV -sC -p 1-1000 --open -oX /tmp/aegis_nmap.xml <target>

# full (default)
nmap -sV -sC -O -p- --open -oX /tmp/aegis_nmap.xml <target>

# web
nmap -sV -p 80,443,8080,8443 --open -oX /tmp/aegis_nmap.xml <target>

# stealth (requires root)
nmap -sS -O -p- --open -T2 -oX /tmp/aegis_nmap.xml <target>
```

**XML parsing — key fields extracted**:
```python
# From nmap XML <port> element:
port.attrib["portid"]               → port number
port.find("state").attrib["state"]  → "open"/"filtered"
port.find("service").attrib["name"] → service name
port.find("service").attrib.get("product", "") + " " + 
    port.find("service").attrib.get("version", "")  → version string
port.findall("script")              → NSE script results
```

**Interesting service flags** (automatically marked for further attention):
- `ftp` with vsftpd 2.3.4 → CVE-2011-2523 (backdoor)
- `http` with Apache 2.2.x → outdated web server
- `ssh` with OpenSSH < 7.4 → potential vulnerabilities
- `mysql` (3306) → check default credentials
- `smb` (445) → check null sessions
- `telnet` (23) → cleartext credential risk
- `rlogin` (513) → legacy cleartext auth

---

### 3.3 Web Scanner (`modules/web_scanner.py`)

**Purpose**: Run nikto and gobuster, parse outputs.

```python
class WebScanner:
    def __init__(self, target: str, base_url: str, verbose: bool, wordlist: str): ...

    def run(self) -> dict:
        """Returns web section of ScanResult."""
        ...

    def _run_nikto(self) -> dict: ...
    def _run_gobuster(self) -> dict: ...
    def _parse_nikto_xml(self, xml_path: str) -> list[dict]: ...
    def _parse_gobuster_output(self, output_path: str) -> list[dict]: ...
    def _determine_base_url(self, target: str, open_ports: list[dict]) -> str: ...
```

**nikto command**:
```bash
nikto -h http://<target> -Format xml -o /tmp/aegis_nikto.xml -maxtime 600
```

**gobuster command**:
```bash
gobuster dir \
  -u http://<target> \
  -w /usr/share/wordlists/dirb/common.txt \
  -o /tmp/aegis_gobuster.txt \
  -q \
  -t 20 \
  --timeout 10s
```

**Nikto XML parsing — key fields**:
```python
item.find("namelink").text          → vulnerability name/ID
item.find("uri").text               → affected path
item.find("method").text            → HTTP method
item.find("description").text       → description
item.find("reference").text         → reference URL/CVE
```

**Gobuster output parsing**:
```
# gobuster output format:
/admin                (Status: 200) [Size: 1234]
/phpmyadmin           (Status: 200) [Size: 5678]
/.htaccess            (Status: 403) [Size: 276]

# Parse regex:
r"^(.+?)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]"
```

---

### 3.4 SMB Enumeration (`modules/smb_enum.py`)

**Purpose**: Run enum4linux, parse shares/users/OS info.

```python
class SmbEnum:
    def __init__(self, target: str, verbose: bool): ...

    def run(self) -> dict:
        """Returns smb section of ScanResult."""
        ...

    def _run_enum4linux(self) -> str: ...
    def _parse_shares(self, output: str) -> list[dict]: ...
    def _parse_users(self, output: str) -> list[str]: ...
    def _check_null_session(self, output: str) -> bool: ...
    def _extract_os(self, output: str) -> str | None: ...
```

**enum4linux command**:
```bash
enum4linux -a <target>
```

**Key parsing patterns from enum4linux text output**:
```python
# Shares section:
# Sharename    Type      Comment
# ---------    ----      -------
# IPC$         IPC       IPC Service
SHARES_PATTERN = r"^\s+(\S+)\s+(\S+)\s+(.*?)\s*$"

# Users section:
# user:[username] rid:[xxx]
USERS_PATTERN = r"user:\[(.+?)\]"

# Null session:
NULL_SESSION_PATTERN = r"Session Check Ok|allows sessions"

# OS:
OS_PATTERN = r"OS=\[(.+?)\]"
```

---

### 3.5 FTP Probe (`modules/ftp_probe.py`)

**Purpose**: Test anonymous FTP login using Python `ftplib`.

```python
class FtpProbe:
    def __init__(self, target: str, verbose: bool): ...

    def run(self) -> dict:
        """Returns ftp section of ScanResult."""
        ...

    def _test_anonymous_login(self) -> tuple[bool, list[str]]:
        """Returns (success, file_list)."""
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, 21, timeout=10)
            banner = ftp.getwelcome()
            ftp.login("anonymous", "anonymous@example.com")
            files = ftp.nlst()
            ftp.quit()
            return True, files[:20]  # Cap at 20 files
        except ftplib.error_perm:
            return False, []
        except Exception as e:
            return False, []
```

**vsftpd 2.3.4 backdoor detection**:
```python
# If FTP banner contains "220 (vsFTPd 2.3.4)"
# Flag: CVE-2011-2523 — vsftpd 2.3.4 backdoor
# The backdoor is triggered by logging in with username ending in ":)"
# AEGIS flags this but does NOT exploit it
if "vsFTPd 2.3.4" in banner:
    result["known_cves"].append("CVE-2011-2523")
    result["notes"] = "vsftpd 2.3.4 backdoor detected (CVE-2011-2523). Port 6200 may be open."
```

---

### 3.6 SSH Probe (`modules/ssh_probe.py`)

**Purpose**: Banner grab and version-based CVE flagging.

```python
class SshProbe:
    def __init__(self, target: str, verbose: bool): ...

    def run(self) -> dict:
        """Returns ssh section of ScanResult."""
        ...

    def _grab_banner(self) -> str | None:
        """TCP connect to port 22, read banner line."""
        ...

    def _check_version(self, banner: str) -> tuple[list[str], list[str]]:
        """
        Returns (known_cves, weak_algorithms).
        Compares version against KNOWN_VULNERABLE_SSH dict.
        """
        ...
```

**Known vulnerable SSH versions table**:
```python
KNOWN_VULNERABLE_SSH = {
    # version_string_contains: [CVE IDs]
    "OpenSSH_4.7": ["CVE-2008-0166"],            # Debian weak key generation
    "OpenSSH_5.":  ["CVE-2010-4478"],            # J-PAKE auth bypass
    "OpenSSH_6.":  ["CVE-2014-1692"],            # memory corruption
    "OpenSSH_7.":  ["CVE-2018-15473"],           # user enumeration
    "dropbear_0.": ["CVE-2012-0920"],            # use-after-free
}
```

---

### 3.7 MySQL Probe (`modules/mysql_probe.py`)

**Purpose**: Test default MySQL credentials.

```python
DEFAULT_CREDENTIALS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "mysql"),
    ("admin", "admin"),
    ("admin", ""),
]
```

**Implementation note**: Uses raw TCP socket + MySQL handshake parse OR attempts `mysql -h <target> -u <user> -p<pass>` as subprocess. Prefer `PyMySQL` if available.

```python
def _test_credentials(self) -> tuple[bool, str | None]:
    """
    Returns (accessible, "user:pass" | None).
    """
    try:
        import pymysql
        for user, password in DEFAULT_CREDENTIALS:
            try:
                conn = pymysql.connect(
                    host=self.target,
                    user=user,
                    password=password,
                    connect_timeout=5,
                )
                conn.close()
                return True, f"{user}:{password if password else '(empty)'}"
            except pymysql.err.OperationalError:
                continue
    except ImportError:
        # PyMySQL not available, skip
        return False, None
    return False, None
```

---

## 4. AI Intelligence Engine (`ai/intelligence.py`)

### Together AI API Contract

**Endpoint**: `POST https://api.together.xyz/v1/chat/completions`

**Request**:
```python
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json",
}

payload = {
    "model": "Qwen/Qwen2.5-72B-Instruct",
    "max_tokens": 4096,
    "temperature": 0.1,      # Low temperature for consistent structured output
    "messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ],
}
```

**Response parsing**:
```python
response.json()["choices"][0]["message"]["content"]  # → JSON string
```

### System Prompt (`ai/prompts.py`)

```python
SYSTEM_PROMPT = """
You are AEGIS Intelligence — a cybersecurity vulnerability analysis engine.

You receive structured scan results from a penetration testing pipeline (nmap, nikto, gobuster, enum4linux, FTP/SSH/MySQL probes) and produce a professional vulnerability intelligence report.

CRITICAL RULES:
1. Respond ONLY with valid JSON. No markdown, no code blocks, no preamble.
2. All CVE IDs must be real CVEs that match the service version found.
3. All MITRE ATT&CK TTP IDs must be valid (format: T####.###).
4. Risk level must be: Critical, High, Medium, or Low.
5. Base risk level on the highest severity finding, weighted by exploitability.

OUTPUT FORMAT (exact JSON schema):
{
  "risk_level": "Critical|High|Medium|Low",
  "executive_summary": "2-3 sentence non-technical summary of findings and overall risk",
  "cves": [
    {
      "id": "CVE-YYYY-NNNNN",
      "cvss": "0.0-10.0",
      "service": "service_name:version",
      "description": "Brief description of the vulnerability",
      "recommendation": "Specific remediation action"
    }
  ],
  "ttps": [
    {
      "id": "T####.###",
      "name": "TTP Name",
      "tactic": "MITRE Tactic Name"
    }
  ],
  "findings": [
    {
      "title": "Finding Title",
      "severity": "Critical|High|Medium|Low",
      "description": "Technical description of the finding",
      "recommendation": "Specific remediation step"
    }
  ]
}
"""
```

### User Message Builder

```python
def build_user_message(scan_result: dict) -> str:
    """
    Converts ScanResult dict to a structured text message for the LLM.
    Includes all non-null, non-error sections.
    """
    sections = []
    
    sections.append(f"TARGET: {scan_result['meta']['target']}")
    sections.append(f"OS GUESS: {scan_result['nmap'].get('os_guess', 'Unknown')}")
    
    # Open ports
    ports_text = "\n".join([
        f"  - Port {p['port']}/{p['protocol']}: {p['service']} {p['version']}"
        for p in scan_result['nmap']['open_ports']
    ])
    sections.append(f"OPEN PORTS:\n{ports_text}")
    
    # Web findings
    if scan_result['web']['enabled']:
        nikto_findings = "\n".join([
            f"  - [{f['path']}] {f['description']}"
            for f in scan_result['web']['nikto']['findings']
        ])
        gobuster_paths = ", ".join([
            p['path'] for p in scan_result['web']['gobuster']['paths']
        ])
        sections.append(f"WEB VULNERABILITIES (nikto):\n{nikto_findings}")
        sections.append(f"DISCOVERED PATHS (gobuster): {gobuster_paths}")
    
    # SMB
    if scan_result['smb']['enabled']:
        shares = ", ".join([s['name'] for s in scan_result['smb']['shares']])
        users = ", ".join(scan_result['smb']['users'])
        sections.append(f"SMB SHARES: {shares}")
        sections.append(f"SMB USERS: {users}")
        sections.append(f"SMB NULL SESSION: {scan_result['smb']['null_session']}")
    
    # FTP
    if scan_result['ftp']['enabled']:
        sections.append(f"FTP ANONYMOUS LOGIN: {scan_result['ftp']['anonymous_login']}")
        sections.append(f"FTP BANNER: {scan_result['ftp']['banner']}")
    
    # SSH
    if scan_result['ssh']['enabled']:
        sections.append(f"SSH VERSION: {scan_result['ssh']['version']}")
        sections.append(f"SSH KNOWN CVEs (pre-check): {', '.join(scan_result['ssh']['known_cves'])}")
    
    # MySQL
    if scan_result['mysql']['enabled']:
        sections.append(f"MYSQL DEFAULT CREDS: {scan_result['mysql']['credentials_found'] or 'None found'}")
    
    sections.append("\nAnalyze all findings above and produce the JSON intelligence report.")
    
    return "\n\n".join(sections)
```

### Retry Logic

```python
def call_ai_engine(scan_result: dict, api_key: str, max_retries: int = 3) -> dict | None:
    """
    Calls Together AI API with retry on 429/5xx.
    Returns parsed AI result dict or None on total failure.
    """
    user_message = build_user_message(scan_result)
    
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": os.getenv("AEGIS_MODEL", "Qwen/Qwen2.5-72B-Instruct"),
                    "max_tokens": 4096,
                    "temperature": 0.1,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_message},
                    ],
                },
                timeout=int(os.getenv("AEGIS_API_TIMEOUT", 60)),
            )
            
            if response.status_code == 429:
                wait = 30 * attempt
                print_warning(f"Rate limited. Retrying in {wait}s... (attempt {attempt}/{max_retries})")
                time.sleep(wait)
                continue
                
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return json.loads(content)
            
        except json.JSONDecodeError:
            if attempt < max_retries:
                continue
            return None
        except requests.RequestException as e:
            if attempt < max_retries:
                time.sleep(10)
                continue
            return None
    
    return None
```

---

## 5. Reporting Pipeline

### 5.1 PDF Generator (`reporting/pdf_generator.py`)

**Library**: `fpdf2` v2.7.9

**Report Structure**:
```
Page 1: Cover Page
  - AEGIS logo/title
  - Target: <IP>
  - Assessment Date: <date>
  - Risk Level: <colored badge>
  - Assessor: (from meta)

Page 2: Executive Summary
  - AI executive_summary text (if available)
  - OR: "AI analysis unavailable — see raw scan data in appendix"
  - Finding count breakdown table: Critical | High | Medium | Low

Page 3+: Vulnerability Findings
  - One section per finding (severity ordered: Critical first)
  - Title, Severity badge, Description, Recommendation

Page N: CVE List (if AI enabled)
  - Table: CVE ID | CVSS | Service | Description | Recommendation

Page N+1: MITRE ATT&CK TTPs (if AI enabled)
  - Table: TTP ID | Name | Tactic

Page N+2: Raw Scan Data Appendix
  - nmap open ports table
  - Web findings summary
  - SMB/FTP/SSH/MySQL results
```

```python
class PdfGenerator:
    def __init__(self, scan_result: dict, output_path: str): ...
    def generate(self) -> str:
        """Builds and saves PDF. Returns output_path."""
        ...
    def _build_cover_page(self): ...
    def _build_executive_summary(self): ...
    def _build_findings_section(self): ...
    def _build_cve_table(self): ...
    def _build_ttp_table(self): ...
    def _build_raw_appendix(self): ...
```

**Severity color map for PDF**:
```python
SEVERITY_COLORS = {
    "Critical": (220, 0, 0),      # Red
    "High":     (255, 100, 0),    # Orange
    "Medium":   (255, 180, 0),    # Yellow
    "Low":      (0, 120, 200),    # Blue
}
```

### 5.2 JSON Exporter (`reporting/json_exporter.py`)

```python
def export_json(scan_result: dict, output_path: str) -> str:
    """
    Serializes full ScanResult to JSON file.
    Returns output_path.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)
    return output_path
```

### 5.3 Markdown Generator (`reporting/markdown_gen.py`)

Generates a TryHackMe/writeup-style Markdown report for student use.

```markdown
# AEGIS Scan Report
## Target: {target}
**Date**: {date}  
**Risk Level**: {risk_level}

---

## Executive Summary
{executive_summary}

---

## Findings

### {finding_title} — {severity}
{description}

**Recommendation**: {recommendation}

---

## CVEs

| CVE ID | CVSS | Service | Description |
|--------|------|---------|-------------|
| {id}   | {cvss} | {service} | {desc} |

---

## MITRE ATT&CK TTPs

| TTP ID | Name | Tactic |
|--------|------|--------|
...

---

## Raw Scan Data

### Open Ports (nmap)
| PORT | SERVICE | VERSION |
...
```

---

## 6. Subprocess Utilities (`utils/subprocess_utils.py`)

All tool execution goes through this wrapper. Never use `subprocess.run()` directly in modules.

```python
def run_tool(
    args: list[str],
    timeout: int = 600,
    capture_output: bool = True,
    verbose: bool = False,
) -> tuple[int, str, str]:
    """
    Safe subprocess wrapper.
    
    Args:
        args: Command as list (NEVER as string with shell=True)
        timeout: Max seconds before TimeoutExpired
        capture_output: Capture stdout/stderr
        verbose: Print command before running
    
    Returns:
        (returncode, stdout, stderr)
    
    Never raises — catches all exceptions and returns error in stderr.
    """
    if verbose:
        print_info(f"[CMD] {' '.join(args)}")
    
    try:
        result = subprocess.run(
            args,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            shell=False,    # NEVER True — prevents shell injection
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Command not found: {args[0]}"
    except PermissionError:
        return -3, "", f"Permission denied: {args[0]} may require sudo"
    except Exception as e:
        return -99, "", f"Unexpected error: {str(e)}"
```

---

## 7. Error Handling Strategy

| Error Type | Module | Handling |
|------------|--------|----------|
| Tool not found (`FileNotFoundError`) | All modules | Catch, add to `scan_result['errors']`, skip module |
| Tool timeout (`TimeoutExpired`) | All modules | Catch, log warning, skip module, continue |
| XML parse error | nmap, nikto | Catch, log error, return empty findings |
| API HTTP error (4xx client) | AI engine | Log, do not retry, return None |
| API HTTP error (5xx server) | AI engine | Retry up to 3x with backoff, then return None |
| API timeout | AI engine | Retry once, then return None |
| JSON decode error (LLM response) | AI engine | Retry with simplified prompt, then return None |
| PDF write error | PDF generator | Catch `IOError`, log, attempt markdown fallback |
| `KeyboardInterrupt` | Orchestrator | Catch at top level, save partial results |

**Invariant**: The orchestrator's `run()` method must NEVER propagate an unhandled exception to the CLI layer. All module failures are caught, logged in `scan_result['errors']`, and execution continues.

---

## 8. Logging

```python
import logging

logging.basicConfig(
    filename="aegis.log",
    level=logging.DEBUG if os.getenv("AEGIS_DEBUG") == "true" else logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(module)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("aegis")
```

**Log to file only** (never to console — console output is handled by Rich). Strip Rich markup before writing to log.

---

## 9. Temp File Management

```python
TEMP_FILES = {
    "nmap":      "/tmp/aegis_nmap.xml",
    "nikto":     "/tmp/aegis_nikto.xml",
    "gobuster":  "/tmp/aegis_gobuster.txt",
    "smb":       "/tmp/aegis_smb.txt",
}

def cleanup_temp_files():
    """Called at end of run() regardless of success/failure."""
    for name, path in TEMP_FILES.items():
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            logger.warning(f"Could not delete temp file: {path}")
```

Temp files are always cleaned up via `finally` block in orchestrator `run()`.
