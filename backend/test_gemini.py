from dotenv import load_dotenv
load_dotenv()

from ai_analyzer import AIAnalyzer
import json

print("=" * 50)
print("TESTING GEMINI AI ANALYZER")
print("=" * 50)

# Initialize analyzer
analyzer = AIAnalyzer()
print(f"\n[OK] Client initialized: {analyzer.client is not None}")

# Test data
test_data = {
    'url': 'example.com',
    'open_ports': [{'port': 80, 'service': 'http', 'version': 'Apache 2.4'}],
    'waf': {'detected': False},
    'technologies': ['React', 'Node.js'],
    'xss_scan': {'vulnerable': False},
    'sqli_scan': {'vulnerable': False}
}

print("\n[>] Analyzing security scan results...")
result = analyzer.analyze_security_results(test_data)

print("\n" + "=" * 50)
print("RESULTS")
print("=" * 50)

if result:
    print("\n[OK] Analysis completed successfully!")
    print(f"\nRisk Level: {result.get('risk_level')}")
    print(f"Risk Score: {result.get('risk_score')}")
    print(f"\nRisk Summary:\n{result.get('risk_summary', 'N/A')}")
    
    if 'most_likely_attacks' in result:
        print(f"\nMost Likely Attacks: {len(result['most_likely_attacks'])} found")
    
    print("\n[OK] GEMINI RESPONSE FUNCTIONS WORKING CORRECTLY")
else:
    print("\n[FAIL] Analysis failed - result is None")
    print("[FAIL] GEMINI RESPONSE FUNCTIONS NOT WORKING")
