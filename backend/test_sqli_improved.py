"""
Quick test script for SQL Injection Scanner improvements
Tests against testphp.vulnweb.com
"""

import sys
sys.path.append('.')

from sqli_scanner import SQLiScanner

print("="*70)
print("      TESTING IMPROVED SQL INJECTION SCANNER")
print("="*70)

# Test URLs
test_urls = [
    "http://testphp.vulnweb.com/listproducts.php?cat=1",
    "http://testphp.vulnweb.com/artists.php?artist=1",
    "http://testphp.vulnweb.com/showimage.php?file=1"
]

scanner = SQLiScanner()

for test_url in test_urls:
    print(f"\n{'='*70}")
    print(f"Testing: {test_url}")
    print(f"{'='*70}")
    
    try:
        result = scanner.scan_for_api(test_url, method='GET')
        
        print(f"\nResults:")
        print(f"  Total Vulnerabilities: {result['total_vulnerabilities']}")
        print(f"  Vulnerable Parameters: {result['vulnerable_params']}")
        
        if result['vulnerabilities']:
            print(f"\n  Vulnerability Details:")
            for vuln in result['vulnerabilities']:
                print(f"    - Type: {vuln['type']}")
                print(f"      Parameter: {vuln['param']}")
                print(f"      Payload: {vuln['payload']}")
                print(f"      Evidence: {vuln['evidence']}")
                print(f"      Confidence: {vuln.get('confidence', 'N/A')}")
                print()
        else:
            print("  ⚠️  No vulnerabilities detected")
            
    except Exception as e:
        print(f"  ❌ Error testing {test_url}: {e}")

print("\n" + "="*70)
print("Testing Complete!")
print("="*70)
