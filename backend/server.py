#server side code


from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import security scanning modules
from portscanner import scan_ports
from waf_detector import detect_waf
from tech_detector import detect_technologies
from xss_scanner import scan_xss
from sqli_scanner import SQLiScanner
from whois_lookup import perform_whois_lookup
from ai_analyzer import AIAnalyzer
from csrf_scanner import scan_csrf

app = Flask(__name__)
CORS(app)

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
    """Analyze website endpoint with selective test execution"""
    try:
        data = request.get_json()
        url = data.get('url')
        selected_tests = data.get('tests', {
            'ports': True,
            'waf': True,
            'tech': True,
            'xss': True,
            'sqli': False, 
            'whois': True
        })
        
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
        print(f"Selected tests: {selected_tests}")
        
        # Initialize results
        open_ports = []
        technologies = {}
        waf_info = {'detected': False}
        xss_results = {}
        sqli_results = {}
        whois_info = {}
        csrf_results = {}
        
        # WHOIS Lookup (if selected)
        if selected_tests.get('whois', True):
            print(f"[*] Performing WHOIS lookup for {url}...")
            whois_info = perform_whois_lookup(url)
        else:
            print("[*] WHOIS lookup skipped")
        
        # Scan ports (if selected)
        if selected_tests.get('ports', True):
            print(f"[*] Scanning ports...")
            open_ports = scan_ports(ip_address)
            print(f"Found {len(open_ports)} open ports")
            for port_info in open_ports:
                print(f"  Port {port_info['port']}: {port_info['service']}")
        else:
            print("[*] Port scanning skipped")
        
        # Detect technologies (if selected)
        if selected_tests.get('tech', True):
            print(f"[*] Detecting technologies for {url}...")
            technologies = detect_technologies(url)
        else:
            print("[*] Technology detection skipped")
        
        # Detect WAF (if selected)
        if selected_tests.get('waf', True):
            print(f"[*] Detecting WAF for {url}...")
            waf_info = detect_waf(url)
        else:
            print("[*] WAF detection skipped")
        
        # Scan for XSS vulnerabilities (if selected)
        if selected_tests.get('xss', True):
            print(f"[*] Scanning for XSS vulnerabilities on {url}...")
            
            # Test URL for XSS - try HTTP first, then HTTPS
            if not url.startswith(('http://', 'https://')):
                test_url = f"http://{url}"  # Default to HTTP instead of HTTPS
            else:
                test_url = url
            xss_results = scan_xss(test_url)
        else:
            print("[*] XSS scanning skipped")
            xss_results = {'total_vulnerabilities': 0, 'tested_payloads': 0}
        
        # Scan for CSRF vulnerabilities (if selected)
        if selected_tests.get('csrf', False):
            print(f"[*] Scanning for CSRF vulnerabilities on {url}...")
            
            # Test URL for CSRF - try HTTP first, then HTTPS
            if not url.startswith(('http://', 'https://')):
                test_url = f"http://{url}"
            else:
                test_url = url
            csrf_results = scan_csrf(test_url)
        else:
            print("[*] CSRF scanning skipped")
            csrf_results = {'total_forms': 0, 'vulnerable_forms_count': 0, 'is_vulnerable': False}
        
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
            'whois': whois_info,
            'xss_scan': xss_results,
            'sqli_scan': sqli_results,
            'csrf_scan': csrf_results,  # Include CSRF scan results
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': f'Analysis completed for {url}',
            'data': {
                'risk_score': risk_score,
                'vulnerabilities_found': len(open_ports) + xss_results.get('total_vulnerabilities', 0) + csrf_results.get('vulnerable_forms_count', 0),
                'scan_date': datetime.now().strftime('%Y-%m-%d')
            }
        }
        
        # Generate AI analysis (if selected)
        gemini_api_key = data.get('gemini_api_key') or os.getenv('GEMINI_API_KEY')
        if selected_tests.get('ai_analysis', True) and gemini_api_key:
            print(f"[*] Generating AI security analysis...")
            try:
                ai_analyzer = AIAnalyzer(api_key=gemini_api_key)
                ai_analysis = ai_analyzer.analyze_security_results(analysis_result)
                if ai_analysis:
                    analysis_result['ai_analysis'] = ai_analysis
                    print("[*] AI analysis completed")
                else:
                    print("[!] AI analysis failed, using fallback")
                    ai_analyzer_fallback = AIAnalyzer(api_key=None)
                    analysis_result['ai_analysis'] = ai_analyzer_fallback.analyze_security_results(analysis_result)
            except Exception as ai_error:
                print(f"[!] AI analysis error: {ai_error}")
                # Use fallback analysis
                ai_analyzer_fallback = AIAnalyzer(api_key=None)
                analysis_result['ai_analysis'] = ai_analyzer_fallback.analyze_security_results(analysis_result)
        else:
            print("[*] AI analysis skipped or no API key provided")
            # Always provide fallback analysis
            ai_analyzer_fallback = AIAnalyzer(api_key=None)
            analysis_result['ai_analysis'] = ai_analyzer_fallback.analyze_security_results(analysis_result)
        
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


@app.route('/api/scan-sqli', methods=['POST'])
def scan_sql_injection():
    """Scan website for SQL injection vulnerabilities"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        param_name = data.get('param', None)
        method = data.get('method', 'GET').upper()
        
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        print(f"[SQLi] Starting SQL injection scan for: {url}")
        print(f"[SQLi] Parameter: {param_name or 'Auto-detect'}")
        print(f"[SQLi] Method: {method}")
        
        # Initialize SQL injection scanner
        scanner = SQLiScanner()
        
        # Run SQL injection scan
        sqli_report = scanner.scan_for_api(url, param_name, method)
        
        return jsonify({
            'status': 'success',
            'sqli_scan': sqli_report,
            'message': f'SQL injection scan completed for {url}'
        }), 200
        
    except Exception as e:
        print(f"Error in SQL injection scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
