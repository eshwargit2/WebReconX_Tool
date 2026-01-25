import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class SecurityHeadersScanner:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        self.security_headers = {
            "X-Frame-Options": {
                "description": "Clickjacking protection",
                "risk": "High",
                "recommendation": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking attacks",
                "alternatives": ["Frame-Options"]
            },
            "Content-Security-Policy": {
                "description": "XSS and data injection protection",
                "risk": "Critical",
                "recommendation": "Implement strict CSP to prevent XSS and data injection attacks",
                "alternatives": ["Content-Security-Policy-Report-Only"]
            },
            "Strict-Transport-Security": {
                "description": "HTTPS enforcement (HSTS)",
                "risk": "High",
                "recommendation": "Force HTTPS connections with 'max-age=31536000; includeSubDomains; preload'",
                "alternatives": []
            },
            "X-Content-Type-Options": {
                "description": "MIME sniffing protection",
                "risk": "Medium",
                "recommendation": "Set to 'nosniff' to prevent MIME type sniffing",
                "alternatives": []
            },
            "Referrer-Policy": {
                "description": "Referrer information control",
                "risk": "Low",
                "recommendation": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'",
                "alternatives": []
            },
            "Permissions-Policy": {
                "description": "Browser feature access control",
                "risk": "Medium",
                "recommendation": "Restrict access to sensitive browser features",
                "alternatives": ["Feature-Policy"]
            },
            "X-XSS-Protection": {
                "description": "Legacy XSS filter (deprecated but still useful)",
                "risk": "Low",
                "recommendation": "Set to '1; mode=block' for legacy browser protection",
                "alternatives": []
            },
            "Cache-Control": {
                "description": "Caching behavior control",
                "risk": "Low",
                "recommendation": "Use 'no-store, no-cache' for sensitive pages",
                "alternatives": ["Pragma"]
            }
        }
    
    def normalize_url(self, url):
        """Ensure URL has proper protocol"""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url
    
    def extract_meta_policies(self, html):
        """Extract security policies from meta tags"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            meta_results = {}
            
            for meta in soup.find_all('meta'):
                http_equiv = meta.get('http-equiv', '').lower()
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                
                if http_equiv == 'content-security-policy':
                    meta_results['Content-Security-Policy'] = content
                
                if name == 'referrer':
                    meta_results['Referrer-Policy'] = content
            
            return meta_results
        except Exception as e:
            print(f"[!] Error extracting meta policies: {e}")
            return {}
    
    def scan_headers(self, url):
        """Scan website for security headers"""
        url = self.normalize_url(url)
        print(f"\n[*] Scanning security headers for: {url}")
        
        try:
            # First, try to get the actual website (not just domain)
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            
            final_url = response.url
            headers = response.headers
            html = response.text
            
            print(f"[*] Final URL: {final_url}")
            print(f"[*] Status Code: {response.status_code}")
            
            # Debug: Print all headers received
            print(f"[*] Headers received: {list(headers.keys())}")
            
            # Extract meta tag policies
            meta_policies = self.extract_meta_policies(html)
            
            results = {
                'url': final_url,
                'status_code': response.status_code,
                'headers_found': [],
                'headers_missing': [],
                'total_score': 0,
                'max_score': len(self.security_headers) * 10,
                'security_grade': 'F'
            }
            
            # Check each security header
            for header_name, header_info in self.security_headers.items():
                header_found = None
                source = None
                
                # Check HTTP headers (case-insensitive)
                for h in headers:
                    if h.lower() == header_name.lower():
                        header_found = headers[h]
                        source = 'HTTP'
                        print(f"[DEBUG] Found header: {header_name} = {header_found}")
                        break
                
                # Check alternative header names
                if not header_found and 'alternatives' in header_info:
                    for alt_name in header_info['alternatives']:
                        for h in headers:
                            if h.lower() == alt_name.lower():
                                header_found = headers[h]
                                source = f'HTTP ({alt_name})'
                                print(f"[DEBUG] Found alternative header: {alt_name} = {header_found}")
                                break
                        if header_found:
                            break
                
                # Check meta tags if not found in headers
                if not header_found and header_name in meta_policies:
                    header_found = meta_policies[header_name]
                    source = 'META'
                
                if header_found:
                    # Header is present
                    score = 10
                    results['total_score'] += score
                    
                    results['headers_found'].append({
                        'name': header_name,
                        'value': header_found,
                        'source': source,
                        'description': header_info['description'],
                        'status': 'present'
                    })
                    print(f"[✓] {header_name}: PRESENT ({source})")
                    print(f"    Value: {header_found}")
                else:
                    # Header is missing
                    results['headers_missing'].append({
                        'name': header_name,
                        'description': header_info['description'],
                        'risk': header_info['risk'],
                        'recommendation': header_info['recommendation'],
                        'status': 'missing'
                    })
                    print(f"[✗] {header_name}: MISSING")
                    print(f"    Risk: {header_info['risk']} - {header_info['description']}")
            
            # Calculate security grade
            percentage = (results['total_score'] / results['max_score']) * 100
            if percentage >= 90:
                results['security_grade'] = 'A'
            elif percentage >= 80:
                results['security_grade'] = 'B'
            elif percentage >= 70:
                results['security_grade'] = 'C'
            elif percentage >= 60:
                results['security_grade'] = 'D'
            else:
                results['security_grade'] = 'F'
            
            print(f"\n[*] Security Score: {results['total_score']}/{results['max_score']} ({percentage:.1f}%)")
            print(f"[*] Security Grade: {results['security_grade']}")
            
            return results
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed: {e}")
            return {
                'error': True,
                'message': str(e),
                'url': url
            }
        except Exception as e:
            print(f"[!] Scan failed: {e}")
            return {
                'error': True,
                'message': str(e),
                'url': url
            }
    
    def scan_for_api(self, url):
        """Scan method for API integration"""
        return self.scan_headers(url)


# Test function
if __name__ == "__main__":
    scanner = SecurityHeadersScanner()
    
    # Test with a secure site
    print("=" * 80)
    print("Testing with Google (Secure Site)")
    print("=" * 80)
    result = scanner.scan_headers("google.com")
    
    print("\n" + "=" * 80)
    print("Testing with Vulnerable Site")
    print("=" * 80)
    result2 = scanner.scan_headers("testphp.vulnweb.com")
