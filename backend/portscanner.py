"""
Port Scanner Module
Scans common ports and detects running services with version information
"""
import socket
import threading
import re

# Common ports to scan with their typical services
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 
    445, 3306, 3389, 5432, 5900, 8080, 8443
]

# Service name mapping
SERVICE_NAMES = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (Secure Web Server)",
    445: "SMB (Server Message Block)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    8080: "HTTP Alternate/Proxy",
    8443: "HTTPS Alternate"
}


def get_service_banner(ip, port):
    """Try to get service banner/version information"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Try to get banner for specific ports
        if port in [21, 22, 25, 110, 143]:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        elif port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            # Extract Server header
            server_match = re.search(r'Server:\s*(.+)', response)
            if server_match:
                return server_match.group(1).strip()
        elif port == 443:
            return "TLS/SSL Service"
        
        sock.close()
        return None
    except:
        return None


def scan_port(ip, port, open_ports):
    """Scan a single port and get version info"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service_short = socket.getservbyport(port)
            except:
                service_short = "unknown"
            
            # Get full service name
            service_name = SERVICE_NAMES.get(port, service_short)
            
            # Try to get version/banner
            version_info = get_service_banner(ip, port)
            
            open_ports.append({
                'port': port,
                'service': service_short,
                'service_name': service_name,
                'version': version_info or "Version detection unavailable",
                'state': 'open'
            })
        sock.close()
    except:
        pass


def scan_ports(ip):
    """Scan multiple ports using threading"""
    open_ports = []
    threads = []
    
    for port in COMMON_PORTS:
        thread = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return sorted(open_ports, key=lambda x: x['port'])
