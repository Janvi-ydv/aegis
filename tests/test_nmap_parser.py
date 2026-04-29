"""
tests/test_nmap_parser.py — Unit tests for modules/nmap_scanner.py XML parsing

Tests the XML parsing logic using embedded fixture XML (no nmap needed).
"""

import os
import tempfile
import pytest
from modules.nmap_scanner import NmapScanner

# Minimal nmap XML fixture representing a Metasploitable 2-like target
METASPLOITABLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -p- --open -oX /tmp/aegis_nmap.xml 192.168.56.101"
         start="1714000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.56.101" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 2.6.X" accuracy="95" line="66743"/>
    </os>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="4.7p1" extrainfo="Debian 8ubuntu1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.2.8"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open" reason="syn-ack"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.X"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Samba smbd" version="3.X"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="5.0.51a"/>
      </port>
      <port protocol="tcp" portid="8180">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat/Coyote JSP engine" version="1.1"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def nmap_xml_file():
    """Write fixture XML to a temp file and return path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write(METASPLOITABLE_NMAP_XML)
        return f.name


@pytest.fixture
def scanner():
    return NmapScanner("192.168.56.101", "full", verbose=False)


class TestNmapXmlParsing:
    def test_parse_returns_open_ports(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        assert len(result["open_ports"]) == 7

    def test_ftp_port_detected(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        ports = [p["port"] for p in result["open_ports"]]
        assert 21 in ports

    def test_http_port_detected(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        ports = [p["port"] for p in result["open_ports"]]
        assert 80 in ports

    def test_smb_port_detected(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        ports = [p["port"] for p in result["open_ports"]]
        assert 445 in ports

    def test_mysql_port_detected(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        ports = [p["port"] for p in result["open_ports"]]
        assert 3306 in ports

    def test_vsftpd_version_extracted(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        ftp_port = next(p for p in result["open_ports"] if p["port"] == 21)
        assert "vsftpd" in ftp_port["version"].lower() or "vsftpd" in ftp_port["service"].lower() \
               or "2.3.4" in ftp_port["version"]

    def test_os_guess_extracted(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        assert result["os_guess"] is not None
        assert "Linux" in result["os_guess"]

    def test_ports_sorted_ascending(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        port_nums = [p["port"] for p in result["open_ports"]]
        assert port_nums == sorted(port_nums)

    def test_interesting_services_flagged(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        interesting = result["interesting_services"]
        assert len(interesting) > 0
        # ftp should always be flagged
        assert any("ftp" in s.lower() for s in interesting)

    def test_all_ports_are_open(self, scanner, nmap_xml_file):
        result = scanner._parse_xml(nmap_xml_file)
        for port in result["open_ports"]:
            assert port["state"] == "open"


class TestNmapArgBuilder:
    def test_quick_profile_no_p_minus(self, scanner):
        scanner.profile = "quick"
        args = scanner._build_nmap_args()
        assert "1-1000" in " ".join(args)
        assert "-p-" not in args

    def test_full_profile_has_p_minus(self, scanner):
        scanner.profile = "full"
        args = scanner._build_nmap_args()
        assert "-p-" in args

    def test_web_profile_specific_ports(self, scanner):
        scanner.profile = "web"
        args = scanner._build_nmap_args()
        assert "80,443,8080,8443" in args

    def test_output_xml_flag_present(self, scanner):
        args = scanner._build_nmap_args()
        assert "-oX" in args

    def test_target_is_last_arg(self, scanner):
        args = scanner._build_nmap_args()
        assert args[-1] == "192.168.56.101"

    def teardown_method(self, method):
        """Clean up temp file after each test."""
        pass


def teardown_module(module):
    """Cleanup any leftover temp files."""
    import glob
    for f in glob.glob("/tmp/aegis_test_*.xml"):
        try:
            os.remove(f)
        except OSError:
            pass
