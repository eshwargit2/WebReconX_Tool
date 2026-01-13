"""
Test script for SQL injection scanner
Tests against a known vulnerable test site
"""
from sqli_scanner import SQLiScanner

def test_scanner():
    print("="*60)
    print("Testing SQL Injection Scanner")
    print("="*60)
    
    # Test with a known vulnerable test site
    test_url = "http://testphp.vulnweb.com/artists.php"
    
    print(f"\n[*] Testing URL: {test_url}")
    print("[*] This is a deliberately vulnerable test site")
    
    scanner = SQLiScanner()
    
    # Scan with 'artist' parameter (known to be vulnerable)
    print("\n[*] Running scan...")
    report = scanner.scan_for_api(test_url, param_name='artist', method='GET')
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Vulnerable Parameters: {report['vulnerable_params']}")
    print(f"Vulnerability Types: {report['vulnerability_types']}")
    
    if report['total_vulnerabilities'] > 0:
        print("\n[✓] Scanner successfully detected vulnerabilities!")
        print("\nSample Vulnerability:")
        if report['vulnerabilities']:
            vuln = report['vulnerabilities'][0]
            print(f"  Type: {vuln['type']}")
            print(f"  Parameter: {vuln['param']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  Evidence: {vuln['evidence']}")
    else:
        print("\n[!] No vulnerabilities detected")
    
    return report

if __name__ == "__main__":
    test_scanner()
