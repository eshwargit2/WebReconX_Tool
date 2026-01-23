from sqli_scanner import SQLiScanner

print("=" * 80)
print("TESTING SQL INJECTION SCANNER")
print("=" * 80)

url = 'http://testphp.vulnweb.com/listproducts.php?cat=1'
print(f"\nTesting URL: {url}\n")

scanner = SQLiScanner()
result = scanner.scan_for_api(url)

print("\n" + "=" * 80)
print("FINAL RESULT")
print("=" * 80)
print(f"Total vulnerabilities: {result['total_vulnerabilities']}")
print(f"Vulnerable params: {result['vulnerable_params']}")
print(f"\nVulnerabilities found:")
for vuln in result['vulnerabilities']:
    print(f"  - {vuln['type']}: {vuln['param']} with payload '{vuln['payload']}'")
    print(f"    Evidence: {vuln['evidence']}")
