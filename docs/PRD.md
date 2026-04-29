# Product Requirements Document (PRD)
# AEGIS — Adaptive Exploitation & Global Intelligence System

**Version**: 1.0  
**Last Updated**: 2026-04-26  
**Owner**: Shubham  
**Type**: Portfolio / Open-Source Cybersecurity Tool  

---

## 1. Problem Statement

Security professionals and students conducting authorized penetration tests must juggle 10+ individual tools (nmap, nikto, gobuster, searchsploit, etc.), manually correlate their output, and spend hours writing reports — all without intelligent context about what the findings actually mean together.

Junior security engineers especially lack a unified workflow that ties **recon → scanning → vulnerability correlation → AI-powered risk narrative** into a single, repeatable pipeline. AEGIS solves this by orchestrating industry-standard security tools and feeding their combined output into an LLM that produces actionable, human-readable vulnerability intelligence.

---

## 2. Goals & Objectives

### Product Goals
- Build a **Python CLI tool** that automates the full vulnerability assessment pipeline for a target host or web application.
- Use an **LLM (Qwen2.5-72B-Instruct via Together AI)** to intelligently correlate scan results, map findings to CVEs and MITRE ATT&CK TTPs, and generate professional PDF reports.
- Demonstrate both **offensive security competency** and **AI/LLM integration skills** in a single portfolio project.

### User Goals
- Run a single command and receive a comprehensive vulnerability report within minutes.
- Understand what discovered vulnerabilities *mean* — not just that a port is open, but what an attacker could do with it.
- Generate a report that can be shared with a mentor, lab instructor, or included in a portfolio.

### Business/Portfolio Goals
- Ship a working v1.0 within 30 days on a solo developer schedule.
- Publish on GitHub with a complete README, demo GIF, and sample report PDF.
- Demonstrate competency recruiters care about: Python, security tooling, LLM APIs, CLI tooling, report generation.

---

## 3. Success Metrics

| Metric | Target |
|--------|--------|
| End-to-end scan + report time (Metasploitable 2 target) | < 10 minutes |
| Vulnerabilities correctly identified on Metasploitable 2 | ≥ 15 distinct findings |
| CVE mappings generated per scan | ≥ 5 mapped CVEs |
| MITRE ATT&CK TTP tags generated per scan | ≥ 8 TTP IDs |
| PDF report generation success rate | 100% |
| GitHub stars within 30 days of publish | ≥ 10 (stretch: 50) |
| Zero crashes on valid target inputs | 100% stability |

---

## 4. Target Users & Personas

### Primary Persona: Priya — Cybersecurity Student
- **Role**: BSc/BTech Computer Science student, preparing for eJPT or CEH
- **Pain Points**: Has individual tools installed but no unified workflow; writes manual reports in Google Docs; doesn't know how to map findings to CVEs
- **Goals**: Complete TryHackMe/HTB rooms faster, build a portfolio project, learn real pentest workflow
- **Technical Proficiency**: Comfortable with Linux CLI, Python basics, has Kali installed

### Secondary Persona: Arjun — Junior Penetration Tester
- **Role**: 0–2 years experience, works at a small security firm
- **Pain Points**: Report writing is time-consuming; needs to explain findings to non-technical clients; tool output is noisy
- **Goals**: Speed up report generation for authorized engagements, produce professional deliverables quickly
- **Technical Proficiency**: Proficient in Linux, knows Metasploit, scripting experience

---

## 5. Features & Requirements

### P0 — Must-Have Features (MVP)

#### 1. Target Intake & Validation
- **Description**: Accept a target IP address or hostname via CLI argument. Validate that the target is a private/lab IP or user has explicitly confirmed scope authorization.
- **User Story**: As a user, I want to specify a target and have AEGIS validate it, so that I don't accidentally scan unauthorized hosts.
- **Acceptance Criteria**:
  - [ ] Accepts `--target <IP>` and `--target <hostname>` flags
  - [ ] Validates IP format using Python `ipaddress` module
  - [ ] Shows a scope confirmation prompt for any target
  - [ ] Exits cleanly with error message on invalid input

#### 2. Network Reconnaissance Module
- **Description**: Run `nmap` with service/version detection and OS fingerprinting against the target, parse XML output programmatically.
- **User Story**: As a user, I want AEGIS to perform nmap scanning automatically, so that I don't have to remember nmap flags.
- **Acceptance Criteria**:
  - [ ] Executes `nmap -sV -sC -O -oX` against target
  - [ ] Parses XML output into structured Python dict
  - [ ] Extracts: open ports, service names, service versions, OS guess
  - [ ] Completes full port scan within 3 minutes on LAN target
  - [ ] Handles nmap not found with clear installation guidance

#### 3. Web Application Scanning Module
- **Description**: If HTTP/HTTPS ports are detected, run `nikto` for web vulnerability scanning and `gobuster` for directory/file enumeration.
- **User Story**: As a user, I want web-specific scans to trigger automatically when a web server is detected, so I don't miss web vulnerabilities.
- **Acceptance Criteria**:
  - [ ] Triggers only when port 80, 443, 8080, or 8443 is open
  - [ ] Runs `nikto -h <target> -Format xml -output`
  - [ ] Runs `gobuster dir` with a default wordlist (`/usr/share/wordlists/dirb/common.txt`)
  - [ ] Parses nikto findings into structured list
  - [ ] Parses gobuster discovered paths into list

#### 4. Service-Specific Enumeration Module
- **Description**: Run targeted enumeration tools based on discovered services (SMB → enum4linux, FTP → anonymous login check, SSH → version banner grab).
- **User Story**: As a user, I want AEGIS to automatically run the right enumeration tool for each open service, so I don't miss service-specific vulnerabilities.
- **Acceptance Criteria**:
  - [ ] Detects SMB (445) → runs `enum4linux -a`
  - [ ] Detects FTP (21) → tests anonymous login with Python `ftplib`
  - [ ] Detects SSH (22) → grabs banner, checks for weak algorithms
  - [ ] Detects MySQL (3306) → attempts default credential check
  - [ ] All module outputs structured as Python dicts

#### 5. AI Vulnerability Intelligence Engine
- **Description**: Feed all scan outputs into Qwen2.5-72B-Instruct (via Together AI API) to produce: CVE mappings, MITRE ATT&CK TTP tags, risk ratings, and a natural language vulnerability narrative.
- **User Story**: As a user, I want AI to analyze my scan results, so I understand what the findings mean and what an attacker could realistically do.
- **Acceptance Criteria**:
  - [ ] Constructs a structured prompt from all module outputs
  - [ ] LLM returns: list of CVEs with CVSS, list of ATT&CK TTP IDs, risk level (Critical/High/Medium/Low), executive summary paragraph, technical findings paragraphs
  - [ ] Response is parsed from LLM JSON output
  - [ ] Handles API timeout with retry (max 3 attempts)
  - [ ] Falls back to raw output display if API fails

#### 6. PDF Report Generator
- **Description**: Generate a professional PDF report from all scan data and AI analysis using `reportlab` or `fpdf2`.
- **User Story**: As a user, I want a PDF report I can share or add to my portfolio, so my work is documented professionally.
- **Acceptance Criteria**:
  - [ ] PDF includes: cover page (target, date, assessor), executive summary, findings table, CVE list, ATT&CK TTP list, raw scan appendix
  - [ ] Report saved to `./reports/<target>_<timestamp>.pdf`
  - [ ] PDF is human-readable without any additional software
  - [ ] Generates successfully even if AI engine fails (uses raw data only)

#### 7. Rich Terminal UI
- **Description**: Use `rich` library to display real-time progress, colored output, tables, and status panels during scanning.
- **User Story**: As a user, I want clear visual feedback during scanning, so I know what AEGIS is doing at all times.
- **Acceptance Criteria**:
  - [ ] Shows spinner/progress bar for each module
  - [ ] Prints a colored summary table after each module completes
  - [ ] Uses color coding: red = critical, orange = high, yellow = medium, green = info
  - [ ] Final summary panel shows total findings count by severity

---

### P1 — Should-Have Features

#### 8. CVE Database Local Lookup
- **Description**: Cross-reference discovered service versions against a local CVE cache (NVD JSON feed) before calling the LLM, so CVE data is accurate.
- **User Story**: As a user, I want CVE lookups to work offline, so I can use AEGIS in isolated lab environments.

#### 9. Scan Profile Presets
- **Description**: `--profile quick` (top 1000 ports), `--profile full` (all ports), `--profile web` (HTTP-only), `--profile stealth` (slow scan, lower detection risk).
- **User Story**: As a user, I want scan presets, so I don't have to memorize nmap flags for different scenarios.

#### 10. JSON Export
- **Description**: Export all findings as a structured JSON file in addition to PDF, for programmatic consumption.
- **User Story**: As a developer, I want JSON output so I can integrate AEGIS findings into other tools or dashboards.

#### 11. Markdown Report Option
- **Description**: `--format markdown` generates a `.md` report suitable for GitHub or Obsidian notes.
- **User Story**: As a student, I want Markdown output for my TryHackMe writeups.

---

### P2 — Nice-to-Have Features

- Shodan API integration for passive OSINT on public IPs
- Multi-target scanning from a file (`--target-list targets.txt`)
- CVSS score-based prioritization in report
- Slack/webhook notification when scan completes
- Docker container for zero-dependency deployment

---

## 6. Explicitly OUT OF SCOPE (v1.0)

- **No active exploitation** — AEGIS identifies vulnerabilities but does NOT exploit them. No Metasploit integration for payload delivery.
- **No GUI / web interface** — CLI only.
- **No cloud/AWS/GCP scanning** — local network and web targets only.
- **No mobile application scanning** — not in scope.
- **No authenticated web app scanning** — no login form handling or session management.
- **No scheduled/recurring scans** — one-shot execution only.
- **No database persistence** — scan results stored as files only.
- **No multi-user support** — single user local tool.
- **No Windows support** — Linux/Kali only for v1.0.

---

## 7. User Scenarios

### Scenario 1: Student scans Metasploitable 2 for a lab report
- **Context**: User has VirtualBox running Metasploitable 2 at 192.168.1.100
- **Steps**:
  1. User runs: `python aegis.py --target 192.168.1.100 --profile full`
  2. AEGIS shows scope confirmation prompt → user confirms
  3. Nmap module runs, finds 20+ open ports
  4. Web module triggers (port 80 open), nikto and gobuster run
  5. SMB module triggers (port 445), enum4linux runs
  6. FTP module triggers (port 21), anonymous login detected
  7. All results sent to LLM → CVEs and TTPs generated
  8. PDF report saved to `./reports/192.168.1.100_20260426.pdf`
- **Expected Outcome**: 25-minute scan produces professional PDF with 15+ findings, CVE mappings, and a risk narrative
- **Edge Cases**: nmap requires root → AEGIS prompts for sudo; LLM API down → report generated from raw data only

### Scenario 2: User runs quick web-only scan on a HackTheBox machine
- **Context**: User is on HackTheBox VPN, target is 10.10.10.5
- **Steps**:
  1. `python aegis.py --target 10.10.10.5 --profile web`
  2. Only HTTP scanning modules run
  3. Gobuster finds `/admin`, `/config.php`, `/backup.zip`
  4. Nikto identifies outdated Apache version
  5. AI generates narrative about directory traversal and backup file exposure risks
- **Expected Outcome**: Fast scan (< 5 min), focused web findings
- **Edge Cases**: No HTTP ports open → AEGIS exits with "No web services detected on target"

### Scenario 3: Scan fails mid-execution
- **Context**: Tool crashes when nmap is not installed
- **Steps**:
  1. User runs AEGIS on fresh Debian install
  2. Nmap check fails
  3. AEGIS prints: "nmap not found. Install with: sudo apt install nmap"
  4. Exits with code 1
- **Expected Outcome**: Clean error, no crash, actionable guidance

---

## 8. Dependencies & Constraints

### Technical Constraints
- Requires Kali Linux or Debian-based system with: nmap, nikto, gobuster, enum4linux pre-installed
- Requires Python 3.10+
- Requires Together AI API key (free tier available)
- Some nmap scans require root/sudo privileges
- Gobuster requires a wordlist file on disk

### External Dependencies
- **Together AI API** — Qwen2.5-72B-Instruct (free tier: rate limited)
- **nmap** (v7.94+) — network scanner
- **nikto** (v2.1.6+) — web vulnerability scanner
- **gobuster** (v3.6+) — directory brute-forcer
- **enum4linux** — SMB enumeration

### Python Package Dependencies
- `requests`, `rich`, `fpdf2`, `python-nmap`, `xml.etree.ElementTree` (stdlib)

---

## 9. Timeline & Milestones

| Milestone | Target Date | Features |
|-----------|-------------|----------|
| M1: Foundation | Day 5 | Project structure, CLI parser, target validation, Rich UI scaffold |
| M2: Scan Engine | Day 12 | Nmap module, web module, service enum module |
| M3: AI Engine | Day 18 | LLM integration, CVE/TTP parsing, prompt engineering |
| M4: Reports | Day 22 | PDF generator, JSON export |
| M5: MVP Complete | Day 28 | Full integration, error handling, README, demo |
| M6: Polish | Day 30 | GitHub publish, sample report, demo GIF |

---

## 10. Non-Functional Requirements

- **Performance**: Full scan of Metasploitable 2 (all modules) completes in < 10 minutes on LAN
- **Reliability**: No unhandled exceptions on valid inputs; all tool failures caught and reported
- **Security**: API keys loaded from `.env` file only, never hardcoded; no scan results logged to external services
- **Portability**: Single `requirements.txt` install, works on stock Kali Linux 2024+
- **Code Quality**: PEP8 compliant, docstrings on all public functions, modular architecture (one file per module)
