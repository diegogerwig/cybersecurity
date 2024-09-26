import socket
import psutil
import platform
import os
import subprocess
import re
import uuid
import requests
import ssl
import OpenSSL
from datetime import datetime

def check_open_ports(host='localhost', start_port=1, end_port=1024):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            open_ports.append((port, service))
        sock.close()
    return open_ports

def check_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'username': proc.info['username']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def check_os_info():
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }

def check_firewall():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True).decode()
            return "Firewall is active" if "ON" in output else "Firewall is inactive"
        except:
            return "Unable to determine firewall status"
    elif platform.system() == "Linux":
        try:
            output = subprocess.check_output("sudo ufw status", shell=True).decode()
            return "Firewall is active" if "active" in output.lower() else "Firewall is inactive"
        except:
            return "Unable to determine firewall status"
    else:
        return "Firewall check not implemented for this OS"

def check_antivirus():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("wmic /node:localhost /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName", shell=True).decode()
            return output.strip().split('\n')[1:] if len(output.strip().split('\n')) > 1 else "No antivirus detected"
        except:
            return "Unable to determine antivirus status"
    else:
        return "Antivirus check not implemented for this OS"

def check_updates():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("wmic qfe list brief /format:table", shell=True).decode()
            updates = len(output.strip().split('\n')) - 2  # Subtract header and separator lines
            return f"{updates} updates installed"
        except:
            return "Unable to check updates"
    elif platform.system() == "Linux":
        try:
            subprocess.check_output("sudo apt-get update", shell=True)
            output = subprocess.check_output("sudo apt-get --just-print upgrade", shell=True).decode()
            updates = len([line for line in output.split('\n') if line.startswith('Inst')])
            return f"{updates} updates available"
        except:
            return "Unable to check updates"
    else:
        return "Update check not implemented for this OS"

def get_mac_address():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])

def check_dns_settings():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("ipconfig /all", shell=True).decode()
            dns_servers = re.findall(r"DNS Servers[^\n]+: (.+)", output)
            return dns_servers if dns_servers else "No DNS servers found"
        except:
            return "Unable to check DNS settings"
    elif platform.system() == "Linux":
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = re.findall(r"nameserver\s+(.+)", f.read())
            return dns_servers if dns_servers else "No DNS servers found"
        except:
            return "Unable to check DNS settings"
    else:
        return "DNS check not implemented for this OS"

def check_ssl_certificates(domains=['www.google.com', 'www.facebook.com', 'www.twitter.com']):
    results = []
    for domain in domains:
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            expiry_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            results.append({
                'domain': domain,
                'expiry_date': expiry_date,
                'days_until_expiry': (expiry_date - datetime.now()).days
            })
        except:
            results.append({
                'domain': domain,
                'error': 'Unable to fetch certificate'
            })
    return results

def main():
    print("Running comprehensive security tests...\n")

    print("System Information:")
    os_info = check_os_info()
    for key, value in os_info.items():
        print(f"{key.capitalize()}: {value}")

    print("\nOpen Ports:")
    open_ports = check_open_ports()
    for port, service in open_ports:
        print(f"Port {port} ({service}) is open")

    print("\nRunning Processes:")
    processes = check_running_processes()
    for proc in processes[:10]:  # Limiting to first 10 for brevity
        print(f"PID: {proc['pid']}, Name: {proc['name']}, User: {proc['username']}")
    print(f"... and {len(processes) - 10} more")

    print(f"\nFirewall Status: {check_firewall()}")
    
    print(f"\nAntivirus Status: {check_antivirus()}")
    
    print(f"\nSystem Updates: {check_updates()}")
    
    print(f"\nMAC Address: {get_mac_address()}")
    
    print("\nDNS Settings:")
    dns_settings = check_dns_settings()
    if isinstance(dns_settings, list):
        for server in dns_settings:
            print(f"DNS Server: {server}")
    else:
        print(dns_settings)

    print("\nSSL Certificate Check:")
    ssl_results = check_ssl_certificates()
    for result in ssl_results:
        if 'error' in result:
            print(f"{result['domain']}: {result['error']}")
        else:
            print(f"{result['domain']}: Expires on {result['expiry_date']} ({result['days_until_expiry']} days)")

if __name__ == "__main__":
    main()
