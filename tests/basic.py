import socket
import psutil
import platform
import os

def check_open_ports(host='localhost', start_port=1, end_port=1024):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_running_processes():
    suspicious_processes = []
    for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
        try:
            # Add names of processes you consider suspicious here
            if proc.name().lower() in ['malware.exe', 'suspiciousapp.exe']:
                suspicious_processes.append(proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
    return suspicious_processes

def check_os_version():
    return platform.platform()

def check_firewall():
    if platform.system() == "Windows":
        firewall_status = os.system("netsh advfirewall show allprofiles state")
        return "Firewall is active" if firewall_status == 0 else "Firewall might be inactive"
    elif platform.system() == "Linux":
        firewall_status = os.system("sudo ufw status")
        return "Firewall is active" if firewall_status == 0 else "Firewall might be inactive"
    else:
        return "Unable to determine firewall status on this operating system"

def main():
    print("Running basic security tests...")
    
    print("\nOpen ports:")
    open_ports = check_open_ports()
    for port in open_ports:
        print(f"Port {port} is open")
    
    print("\nSuspicious running processes:")
    suspicious_procs = check_running_processes()
    for proc in suspicious_procs:
        print(f"Suspicious process detected: {proc}")
    
    print(f"\nOperating System version: {check_os_version()}")
    
    print(f"\nFirewall status: {check_firewall()}")

if __name__ == "__main__":
    main()
