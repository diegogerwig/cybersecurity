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

    def check_root(self):
        if self.os_type != "Windows":
            return os.geteuid() == 0
        else:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def run_command(self, command):
        try:
            return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        except subprocess.CalledProcessError:
            return None

    def get_system_info(self):
        return {
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Architecture": platform.machine(),
            "Hostname": socket.gethostname(),
            "IP Address": socket.gethostbyname(socket.gethostname()),
            "MAC Address": ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
        }

    def scan_ports(self, target, ports="1-1024"):
        if not self.nm:
            return "nmap not installed. Port scanning disabled."
        try:
            print(f"Scanning ports on {target}...")
            self.nm.scan(target, ports)
            open_ports = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        open_ports.append((port, self.nm[host][proto][port]['name']))
            return open_ports
        except Exception as e:
            return f"Error scanning ports: {str(e)}"

    def analyze_network_traffic(self, interface, duration=60):
        if not scapy:
            return "scapy not installed. Network traffic analysis disabled."
        try:
            print(f"Analyzing network traffic on {interface} for {duration} seconds...")
            packets = scapy.sniff(iface=interface, timeout=duration)
            traffic_analysis = {
                "total_packets": len(packets),
                "protocols": {},
                "top_talkers": {}
            }
            for packet in packets:
                if scapy.IP in packet:
                    proto = packet[scapy.IP].proto
                    src = packet[scapy.IP].src
                    dst = packet[scapy.IP].dst
                    traffic_analysis["protocols"][proto] = traffic_analysis["protocols"].get(proto, 0) + 1
                    traffic_analysis["top_talkers"][src] = traffic_analysis["top_talkers"].get(src, 0) + 1
                    traffic_analysis["top_talkers"][dst] = traffic_analysis["top_talkers"].get(dst, 0) + 1
            return traffic_analysis
        except Exception as e:
            return f"Error analyzing network traffic: {str(e)}"

    def check_ssl_vulnerabilities(self, target, port=443):
        try:
            print(f"Checking SSL vulnerabilities for {target}...")
            context = ssl.create_default_context()
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    vulnerabilities = []
                    if x509_cert.signature_algorithm_oid._name == "sha1WithRSAEncryption":
                        vulnerabilities.append("Uses weak SHA1 algorithm")
                    if x509_cert.public_key().key_size < 2048:
                        vulnerabilities.append("Uses weak key size (< 2048 bits)")
                    
                    return vulnerabilities if vulnerabilities else "No common vulnerabilities detected"
        except Exception as e:
            return f"Error checking SSL vulnerabilities: {str(e)}"

    def check_dns_security(self, domain):
        if not scapy:
            return "scapy not installed. DNS security check disabled."
        try:
            print(f"Checking DNS security for {domain}...")
            dns_sec = {}
            answers = scapy.sr1(scapy.IP(dst="8.8.8.8")/scapy.UDP(dport=53)/scapy.DNS(rd=1,qd=scapy.DNSQR(qname=domain, qtype="ANY")), verbose=0)
            dns_sec["DNSSEC"] = "Yes" if answers.ar and answers.ar.type == 46 else "No"
            return dns_sec
        except Exception as e:
            return f"Error checking DNS security: {str(e)}"

    def analyze_running_processes(self):
        print("Analyzing running processes...")
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    def check_firewall_status(self):
        if self.os_type == "Windows":
            status = self.run_command('netsh advfirewall show allprofiles state')
            return "Enabled" if status and "ON" in status else "Disabled"
        elif self.os_type == "Linux":
            ufw_status = self.run_command('sudo ufw status')
            return "Enabled" if ufw_status and "active" in ufw_status else "Disabled"
        else:
            return "Unknown"

    def check_installed_software(self):
        if self.os_type == "Windows":
            output = self.run_command('wmic product get name,version')
            if output:
                return [line.split(None, 1) for line in output.splitlines()[1:] if line.strip()]
        elif self.os_type == "Linux":
            output = self.run_command('dpkg-query -W -f="${Package} ${Version}\n"')
            if output:
                return [line.split() for line in output.splitlines()]
        return "Unable to retrieve installed software"

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