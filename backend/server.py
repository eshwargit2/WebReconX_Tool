from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
import threading
from datetime import datetime
import re
import requests
from bs4 import BeautifulSoup
import subprocess
from xss_scanner import scan_xss

app = Flask(__name__)
CORS(app)

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

def detect_waf(url):
    """Detect WAF using wafw00f command line tool with deep scanning"""
    waf_info = {
        "detected": False,
        "name": "None detected",
        "full_name": "No Web Application Firewall detected",
        "version": "N/A",
        "method": "wafw00f",
        "confidence": "Low"
    }
    
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            test_url = f'https://{url}'
        else:
            test_url = url
        
        print(f"[WAF] Target: {test_url}")
        
        # Run wafw00f command with verbose flag for deeper scanning
        try:
            result = subprocess.run(
                ['wafw00f', '-a', '-v', test_url], 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode != 0:
                print(f"[WAF] Error: {result.stderr}")
                return waf_info
            
            output = result.stdout
            waf_detected = False
            
            # Parse output for WAF name and version
            if "is behind" in output.lower():
                lines = output.split('\n')
                for line in lines:
                    if "is behind" in line.lower():
                        parts = line.split("is behind")
                        if len(parts) > 1:
                            waf_data = parts[1].strip()
                            if '(' in waf_data:
                                waf_name = waf_data.split('(')[0].strip()
                                version_info = waf_data.split('(')[1].split(')')[0] if ')' in waf_data else "Unknown"
                            else:
                                waf_name = waf_data.strip()
                                version_info = "Unknown"
                            
                            waf_info["detected"] = True
                            waf_info["name"] = waf_name
                            waf_info["full_name"] = waf_data
                            waf_info["version"] = version_info
                            waf_info["method"] = "wafw00f Deep Scan"
                            waf_info["confidence"] = "High"
                            
                            print(f"[WAF] Detected: {waf_name}")
                            print(f"[WAF] Version: {version_info}")
                            waf_detected = True
                            break
            
            # Alternative parsing for different output formats
            if not waf_detected:
                lines = output.split('\n')
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped.startswith('[+]') and 'detected' in line_stripped.lower():
                        if 'behind' in line_stripped:
                            waf_name = line_stripped.split('behind')[-1].strip()
                            waf_info["detected"] = True
                            waf_info["name"] = waf_name
                            waf_info["full_name"] = waf_name
                            waf_info["version"] = "Unknown"
                            waf_info["method"] = "wafw00f Detection"
                            waf_info["confidence"] = "High"
                            print(f"[WAF] Detected: {waf_name}")
                            waf_detected = True
                            break
                    elif line_stripped.startswith('[-]') or 'not behind' in line_stripped.lower() or 'no waf' in line_stripped.lower():
                        print("[WAF] No WAF detected")
                        waf_detected = True
                        break
            
            # Check for multiple WAF detections in verbose mode
            if not waf_detected:
                waf_list = []
                for line in output.split('\n'):
                    if 'detected' in line.lower() and '[+]' in line:
                        waf_name = line.replace('[+]', '').replace('detected', '').strip()
                        if waf_name and waf_name not in waf_list:
                            waf_list.append(waf_name)
                
                if waf_list:
                    # Use the first detected WAF
                    waf_info["detected"] = True
                    waf_info["name"] = waf_list[0]
                    waf_info["full_name"] = waf_list[0]
                    waf_info["version"] = "Unknown"
                    waf_info["method"] = "wafw00f Verbose Scan"
                    waf_info["confidence"] = "High"
                    print(f"[WAF] Detected: {waf_list[0]}")
                    waf_detected = True
            
            # Final check if no detection found
            if not waf_detected:
                if "no waf" in output.lower() or "not behind" in output.lower():
                    print("[WAF] No WAF detected")
                else:
                    print("[WAF] Detection unclear")
                    waf_info["name"] = "Detection unclear"
                    waf_info["full_name"] = "WAF detection unclear"
            
        except subprocess.TimeoutExpired:
            print("[WAF] Error: Scan timeout")
            waf_info["name"] = "Scan timeout"
            waf_info["full_name"] = "WAF scan timeout"
        except FileNotFoundError:
            print("[WAF] Error: wafw00f not found. Install with: pip install wafw00f")
            waf_info["name"] = "wafw00f not installed"
            waf_info["full_name"] = "wafw00f tool not installed"
            waf_info["method"] = "Tool missing"
        
        return waf_info
        
    except Exception as e:
        print(f"[WAF] Error: {e}")
        return waf_info

def detect_technologies(url):
    """Detect technologies used by the website"""
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            test_url = f'https://{url}'
        else:
            test_url = url
        
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(test_url, headers=headers, timeout=10, verify=False)
        html = r.text.lower()
        soup = BeautifulSoup(r.text, "html.parser")

        tech = {
            "Frontend": [],
            "CSS Framework": [],
            "JS Framework": [],
            "Backend": [],
            "Server": []
        }

        # Frontend detection
        if "<html" in html:
            tech["Frontend"].append("HTML")
        if "html5" in html or '<!doctype html>' in html:
            tech["Frontend"].append("HTML5")
        if "<script" in html:
            tech["Frontend"].append("JavaScript")
        if "<style" in html or "css" in html:
            tech["Frontend"].append("CSS")

        # CSS Frameworks
        if "bootstrap" in html:
            match = re.search(r'bootstrap[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["CSS Framework"].append(f"Bootstrap {version}")
        
        if "tailwind" in html:
            match = re.search(r'tailwind[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["CSS Framework"].append(f"Tailwind CSS {version}")

        # JS Frameworks
        if "react" in html or "__react" in html:
            match = re.search(r'react[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"React {version}")
        
        if "angular" in html or "ng-app" in html:
            match = re.search(r'angular[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Angular {version}")
        
        if "vue" in html or "__vue" in html:
            match = re.search(r'vue[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Vue.js {version}")
        
        if "_next" in html:
            match = re.search(r'next[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Next.js {version}")
        
        if "jquery" in html:
            match = re.search(r'jquery[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"jQuery {version}")

        # Backend detection
        headers_lower = str(r.headers).lower()
        
        if "django" in headers_lower or "csrftoken" in headers_lower:
            match = re.search(r'django[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"Django {version}")
        
        if "flask" in headers_lower or "werkzeug" in headers_lower:
            match = re.search(r'flask[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"Flask {version}")
        
        if "express" in headers_lower or "node" in headers_lower:
            tech["Backend"].append("Node.js / Express")
        
        if "php" in headers_lower or ".php" in html:
            match = re.search(r'php[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"PHP {version}")
        
        if "wp-content" in html or "wordpress" in html:
            match = re.search(r'wordpress[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"WordPress {version}")
        
        if "laravel" in headers_lower or "laravel_session" in headers_lower:
            tech["Backend"].append("Laravel")
        
        if "asp.net" in headers_lower or "__viewstate" in html:
            tech["Backend"].append("ASP.NET")

        # Server detection
        if "server" in r.headers:
            server_header = r.headers["Server"]
            match = re.search(r'(nginx|apache|iis|cloudflare)[/\s]?(\d+\.\d+\.?\d*)?', server_header, re.IGNORECASE)
            if match:
                server_name = match.group(1).title()
                version = match.group(2) if match.group(2) else ""
                tech["Server"].append(f"{server_name} {version}".strip())
            else:
                tech["Server"].append(server_header)
        
        if "x-powered-by" in r.headers:
            tech["Server"].append(f"Powered by {r.headers['X-Powered-By']}")

        # Generator meta tag
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            tech["Backend"].append(f"Generator: {generator.get('content')}")

        # Remove duplicates and empty entries
        for key in tech:
            tech[key] = list(set([t for t in tech[key] if t]))
            if not tech[key]:
                tech[key] = ["Not detected"]

        return tech
    
    except Exception as e:
        print(f"Tech detection error: {str(e)}")
        return {
            "Frontend": ["Detection failed"],
            "CSS Framework": ["Detection failed"],
            "JS Framework": ["Detection failed"],
            "Backend": ["Detection failed"],
            "Server": ["Detection failed"]
        }

@app.route('/', methods=['GET'])
def welcome():
    """Welcome API endpoint"""
    return jsonify({
        'message': 'Welcome to Site Guardian AI',
        'status': 'success',
        'version': '1.0.0'
    }), 200


@app.route('/api/analyze', methods=['POST'])
def analyze_website():
    """Analyze website endpoint"""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        # Remove http:// or https:// if present
        url = url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Get IP address
        try:
            ip_address = socket.gethostbyname(url)
        except socket.gaierror:
            return jsonify({
                'status': 'error',
                'message': f'Could not resolve hostname: {url}'
            }), 400
        
        print(f"Scanning {url} ({ip_address})...")
        
        # Scan ports
        open_ports = scan_ports(ip_address)
        
        print(f"Found {len(open_ports)} open ports")
        for port_info in open_ports:
            print(f"  Port {port_info['port']}: {port_info['service']}")
        
        # Detect technologies
        print(f"Detecting technologies for {url}...")
        technologies = detect_technologies(url)
        
        # Detect WAF
        print(f"Detecting WAF for {url}...")
        waf_info = detect_waf(url)
        
        # Scan for XSS vulnerabilities
        print(f"Scanning for XSS vulnerabilities on {url}...")
        from xss_scanner import scan_xss
        
        # Test URL for XSS
        test_url = f"https://{url}" if not url.startswith(('http://', 'https://')) else url
        xss_results = scan_xss(test_url)
        
        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except:
            hostname = url
       
        # Calculate risk score based on findings
        risk_score = 50  # Base score
        if len(open_ports) > 10:
            risk_score += 20
        elif len(open_ports) > 5:
            risk_score += 10
        
        if xss_results.get('total_vulnerabilities', 0) > 0:
            risk_score += 20
        
        if not waf_info['detected']:
            risk_score += 10
        
        risk_score = min(risk_score, 100)
        
        analysis_result = {
            'status': 'success',
            'url': url,
            'ip_address': ip_address,
            'hostname': hostname,
            'open_ports': open_ports,
            'total_open_ports': len(open_ports),
            'technologies': technologies,
            'waf': waf_info,
            'xss_scan': xss_results,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': f'Analysis completed for {url}',
            'data': {
                'risk_score': risk_score,
                'vulnerabilities_found': len(open_ports) + xss_results.get('total_vulnerabilities', 0),
                'scan_date': datetime.now().strftime('%Y-%m-%d')
            }
        }
        
        return jsonify(analysis_result), 200
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/ip', methods=['GET'])
def get_ip():
    """Get IP address endpoint"""
    return jsonify({
        'message': 'Use POST /api/analyze to get IP and port information'
    }), 200


@app.route('/api/scan-xss', methods=['POST'])
def scan_xss_vulnerability():
    """Scan website for XSS vulnerabilities"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        print(f"[XSS] Starting XSS scan for: {url}")
        
        # Run XSS scan
        xss_report = scan_xss(url)
        
        return jsonify({
            'status': 'success',
            'xss_scan': xss_report,
            'message': f'XSS scan completed for {url}'
        }), 200
        
    except Exception as e:
        print(f"Error in XSS scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
