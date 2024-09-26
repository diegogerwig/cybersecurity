import os
import sys
import subprocess
import socket
import psutil
import platform
import re
import uuid
import json
import ssl
import OpenSSL
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    import nmap
except ImportError:
    print("python-nmap is not installed. Port scanning will be disabled.")
    nmap = None

try:
    import scapy.all as scapy
except ImportError:
    print("scapy is not installed. Network traffic analysis will be disabled.")
    scapy = None

class SecurityAnalyzer:
    def __init__(self):
        self.os_type = platform.system()
        self.is_admin = self.check_root()
        self.nm = nmap.PortScanner() if nmap else None
        self.results = {}

    # ... [All previous methods remain the same] ...

    def full_analysis(self):
        self.results = {
            "system_info": self.get_system_info(),
            "running_processes": self.analyze_running_processes(),
            "installed_software": self.check_installed_software()
        }

        if self.is_admin:
            self.results["open_ports"] = self.scan_ports("localhost")
            self.results["network_traffic"] = self.analyze_network_traffic("eth0")  # Change interface as needed
            self.results["ssl_vulnerabilities"] = self.check_ssl_vulnerabilities("www.example.com")
            self.results["dns_security"] = self.check_dns_security("example.com")
            self.results["firewall_status"] = self.check_firewall_status()
        else:
            self.results["admin_note"] = "Some checks were skipped due to lack of administrative privileges"

        return self.results

    def generate_report(self):
        report = {
            "OK": [],
            "Failure": []
        }

        # System Info
        report["OK"].append("System information collected successfully")

        # Running Processes
        if len(self.results.get("running_processes", [])) > 0:
            report["OK"].append("Running processes analyzed")
        else:
            report["Failure"].append("Unable to analyze running processes")

        # Installed Software
        if isinstance(self.results.get("installed_software"), list):
            report["OK"].append("Installed software list generated")
        else:
            report["Failure"].append("Unable to retrieve installed software list")

        if self.is_admin:
            # Open Ports
            open_ports = self.results.get("open_ports", [])
            if isinstance(open_ports, list):
                if len(open_ports) > 0:
                    report["Failure"].append(f"Found {len(open_ports)} open ports")
                else:
                    report["OK"].append("No open ports found")
            else:
                report["Failure"].append("Unable to perform port scan")

            # Network Traffic
            if isinstance(self.results.get("network_traffic"), dict):
                report["OK"].append("Network traffic analyzed")
            else:
                report["Failure"].append("Unable to analyze network traffic")

            # SSL Vulnerabilities
            ssl_vulns = self.results.get("ssl_vulnerabilities", [])
            if isinstance(ssl_vulns, list):
                if len(ssl_vulns) == 0:
                    report["OK"].append("No SSL vulnerabilities detected")
                else:
                    report["Failure"].append(f"Detected {len(ssl_vulns)} SSL vulnerabilities")
            else:
                report["Failure"].append("Unable to check SSL vulnerabilities")

            # DNS Security
            dns_sec = self.results.get("dns_security", {})
            if isinstance(dns_sec, dict) and dns_sec.get("DNSSEC") == "Yes":
                report["OK"].append("DNSSEC is enabled")
            else:
                report["Failure"].append("DNSSEC is not enabled or couldn't be checked")

            # Firewall Status
            firewall_status = self.results.get("firewall_status")
            if firewall_status == "Enabled":
                report["OK"].append("Firewall is enabled")
            elif firewall_status == "Disabled":
                report["Failure"].append("Firewall is disabled")
            else:
                report["Failure"].append("Unable to determine firewall status")
        else:
            report["Failure"].append("Some checks were skipped due to lack of administrative privileges")

        return report

    def print_report(self):
        report = self.generate_report()
        print("\n=== Security Analysis Report ===\n")
        
        print("OK:")
        for item in report["OK"]:
            print(f"✓ {item}")
        
        print("\nFailure:")
        for item in report["Failure"]:
            print(f"✗ {item}")

if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    analyzer.full_analysis()
    analyzer.print_report()