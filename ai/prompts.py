"""
ai/prompts.py — LLM system prompt and prompt utilities for AEGIS

The SYSTEM_PROMPT instructs Qwen2.5-72B-Instruct to act as a cybersecurity
vulnerability analysis engine and respond ONLY with valid JSON.
"""

SYSTEM_PROMPT = """
You are AEGIS Intelligence — a cybersecurity vulnerability analysis engine.

You receive structured scan results from a penetration testing pipeline
(nmap, nikto, gobuster, enum4linux, FTP/SSH/MySQL probes) and produce
a professional vulnerability intelligence report.

CRITICAL RULES:
1. Respond ONLY with valid JSON. No markdown, no code blocks, no preamble, no explanation.
2. All CVE IDs must be real CVEs that match the service version found in the scan data.
3. All MITRE ATT&CK TTP IDs must be valid (format: T####.### — e.g. T1190, T1110.001).
4. Risk level must be exactly one of: Critical, High, Medium, Low.
5. Base risk level on the highest severity finding, weighted by exploitability.
6. If a finding has no matching real CVE, do not invent one — omit it from the CVE list.
7. executive_summary must be 2-4 sentences, non-technical, suitable for a manager.

OUTPUT FORMAT — respond with EXACTLY this JSON schema, no deviations:
{
  "risk_level": "Critical|High|Medium|Low",
  "executive_summary": "2-4 sentence non-technical summary of overall risk",
  "cves": [
    {
      "id": "CVE-YYYY-NNNNN",
      "cvss": "0.0",
      "service": "service_name:version_string",
      "description": "Brief description of this specific vulnerability",
      "recommendation": "Specific remediation action (patch, disable, configure)"
    }
  ],
  "ttps": [
    {
      "id": "T####.###",
      "name": "TTP Name from MITRE ATT&CK",
      "tactic": "MITRE Tactic Name (e.g. Initial Access)"
    }
  ],
  "findings": [
    {
      "title": "Short descriptive title of the finding",
      "severity": "Critical|High|Medium|Low",
      "description": "Technical description of what was found and why it is dangerous",
      "recommendation": "Specific remediation step with version or configuration detail"
    }
  ]
}
"""


def build_user_message(scan_result: dict) -> str:
    """
    Convert a ScanResult dict to a structured text prompt for the LLM.
    Includes all non-null, non-error module sections.

    Args:
        scan_result: The central ScanResult dict accumulated by the Orchestrator.

    Returns:
        Formatted string to use as the LLM user message.
    """
    sections = []

    # ── Target & OS ─────────────────────────────────────
    target = scan_result.get("meta", {}).get("target", "Unknown")
    profile = scan_result.get("meta", {}).get("profile", "full")
    os_guess = scan_result.get("nmap", {}).get("os_guess") or "Unknown"

    sections.append(f"TARGET: {target}")
    sections.append(f"SCAN PROFILE: {profile}")
    sections.append(f"OS GUESS: {os_guess}")

    # ── Open Ports ──────────────────────────────────────
    open_ports = scan_result.get("nmap", {}).get("open_ports", [])
    if open_ports:
        ports_text = "\n".join(
            f"  - Port {p['port']}/{p['protocol']}: {p['service']} {p.get('version', '')}"
            for p in open_ports
        )
        sections.append(f"OPEN PORTS:\n{ports_text}")
    else:
        sections.append("OPEN PORTS: None detected")

    interesting = scan_result.get("nmap", {}).get("interesting_services", [])
    if interesting:
        sections.append(f"FLAGGED SERVICES: {', '.join(interesting)}")

    # ── Web ─────────────────────────────────────────────
    web = scan_result.get("web", {})
    if web.get("enabled"):
        nikto_findings = web.get("nikto", {}).get("findings", [])
        gobuster_paths = web.get("gobuster", {}).get("paths", [])

        if nikto_findings:
            nikto_text = "\n".join(
                f"  - [{f.get('path', '/')}] {f.get('description', '')}"
                for f in nikto_findings[:30]
            )
            sections.append(f"WEB VULNERABILITIES (nikto):\n{nikto_text}")

        if gobuster_paths:
            paths_str = ", ".join(
                p["path"] for p in gobuster_paths[:30]
            )
            sections.append(f"DISCOVERED PATHS (gobuster): {paths_str}")

    # ── SMB ─────────────────────────────────────────────
    smb = scan_result.get("smb", {})
    if smb.get("enabled"):
        if smb.get("shares"):
            shares_str = ", ".join(s["name"] for s in smb["shares"])
            sections.append(f"SMB SHARES: {shares_str}")
        if smb.get("users"):
            sections.append(f"SMB USERS: {', '.join(smb['users'])}")
        sections.append(f"SMB NULL SESSION: {smb.get('null_session', False)}")
        if smb.get("os_version"):
            sections.append(f"SMB OS VERSION: {smb['os_version']}")

    # ── FTP ─────────────────────────────────────────────
    ftp = scan_result.get("ftp", {})
    if ftp.get("enabled"):
        sections.append(f"FTP ANONYMOUS LOGIN: {ftp.get('anonymous_login', False)}")
        if ftp.get("banner"):
            sections.append(f"FTP BANNER: {ftp['banner']}")
        if ftp.get("known_cves"):
            sections.append(f"FTP KNOWN CVEs (pre-check): {', '.join(ftp['known_cves'])}")
        if ftp.get("notes"):
            sections.append(f"FTP NOTES: {ftp['notes']}")

    # ── SSH ─────────────────────────────────────────────
    ssh = scan_result.get("ssh", {})
    if ssh.get("enabled"):
        if ssh.get("version"):
            sections.append(f"SSH VERSION: {ssh['version']}")
        if ssh.get("known_cves"):
            sections.append(f"SSH KNOWN CVEs (pre-check): {', '.join(ssh['known_cves'])}")
        if ssh.get("weak_algorithms"):
            sections.append(f"SSH WEAK ALGORITHMS: {', '.join(ssh['weak_algorithms'])}")

    # ── MySQL ────────────────────────────────────────────
    mysql = scan_result.get("mysql", {})
    if mysql.get("enabled"):
        sections.append(f"MYSQL ACCESSIBLE: {mysql.get('accessible', False)}")
        if mysql.get("credentials_found"):
            sections.append(f"MYSQL DEFAULT CREDS FOUND: {mysql['credentials_found']}")

    # ── Errors ───────────────────────────────────────────
    errors = scan_result.get("errors", [])
    if errors:
        sections.append(f"SCAN ERRORS (non-fatal): {'; '.join(errors[:5])}")

    sections.append("\nAnalyze ALL findings above and produce the JSON intelligence report.")

    return "\n\n".join(sections)
