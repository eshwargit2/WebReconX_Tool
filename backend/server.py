#server side code


from flask import Flask, jsonify, request
from flask_cors import CORS
import socket
from datetime import datetime
import os
from dotenv import load_dotenv
from flask import send_file

# Load environment variables from .env file (override existing values)
load_dotenv(override=True)

# Debug: Print API key status on startup
api_key_present = bool(os.getenv('GEMINI_API_KEY'))
api_key_preview = os.getenv('GEMINI_API_KEY', '')[:20] + '...' if os.getenv('GEMINI_API_KEY') else 'NOT FOUND'
print(f"[SERVER] Gemini API Key loaded: {api_key_present} ({api_key_preview})")

# Import security scanning modules
from portscanner import scan_ports
from waf_detector import detect_waf
from tech_detector import detect_technologies
from xss_scanner import scan_xss
from sqli_scanner import SQLiScanner
from whois_lookup import perform_whois_lookup
from ai_analyzer import AIAnalyzer
from directory_scanner import DirectoryScanner
from security_headers import SecurityHeadersScanner

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
        
        if not data:
            print("[ERROR] No JSON data received")
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        
        print(f"[DEBUG] Received data: {data}")
        
        url = data.get('url', '').strip()  # Strip whitespace from URL
        selected_tests = data.get('tests', {
            'ports': True,
            'waf': True,
            'tech': True,
            'xss': True,
            'sqli': False,
            'whois': True,
            'directory': False,
            'security_headers': False
        })
        
        if not url:
            print("[ERROR] URL is missing from request")
            return jsonify({
                'status': 'error',
                'message': 'URL is required'
            }), 400
        
        print(f"[DEBUG] Cleaned URL: '{url}'")
        
        # Store the full URL for scanning
        full_url = url
        
        # Extract hostname for IP resolution (remove protocol and path)
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]
        
        # Get IP address from hostname
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            return jsonify({
                'status': 'error',
                'message': f'Could not resolve hostname: {hostname}'
            }), 400
        
        print(f"Scanning {full_url} ({ip_address})...")
        print(f"Selected tests: {selected_tests}")
        
        # Initialize results
        open_ports = []
        technologies = {}
        waf_info = {'detected': False}
        xss_results = {}
        sqli_results = {}
        whois_info = {}
        directory_results = {}
        security_headers_results = {}
        
        # WHOIS Lookup (if selected)
        if selected_tests.get('whois', True):
            print(f"[*] Performing WHOIS lookup for {hostname}...")
            whois_info = perform_whois_lookup(hostname)
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
            print(f"[*] Detecting technologies for {hostname}...")
            technologies = detect_technologies(hostname)
        else:
            print("[*] Technology detection skipped")
        
        # Detect WAF (if selected)
        if selected_tests.get('waf', True):
            print(f"[*] Detecting WAF for {hostname}...")
            waf_info = detect_waf(hostname)
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
        
        # Scan for SQL injection vulnerabilities (if selected) - BEFORE AI analysis
        if selected_tests.get('sqli', False):
            print(f"[*] Scanning for SQL injection on {full_url}...")
            
            # Ensure URL has proper protocol
            if not full_url.startswith(('http://', 'https://')):
                test_url = f"http://{full_url}"
            else:
                test_url = full_url
            
            # Initialize and run SQLi scanner
            sqli_scanner = SQLiScanner()
            sqli_results = sqli_scanner.scan_for_api(test_url, param_name=None, method='GET')
            print(f"[*] SQLi scan completed: {sqli_results.get('total_vulnerabilities', 0)} vulnerabilities found")
        else:
            print("[*] SQL injection scanning skipped")
            sqli_results = {'total_vulnerabilities': 0, 'vulnerabilities': [], 'vulnerable_params': []}
        
        # Scan for hidden directories (if selected)
        if selected_tests.get('directory', False):
            print(f"[*] Scanning for hidden directories on {full_url}...")
            
            # Ensure URL has proper protocol
            if not full_url.startswith(('http://', 'https://')):
                test_url = f"http://{full_url}"
            else:
                test_url = full_url
            
            # Initialize and run directory scanner
            dir_scanner = DirectoryScanner()
            directory_results = dir_scanner.scan_for_api(test_url)
            print(f"[*] Directory scan completed: {directory_results.get('total_directories', 0)} directories found")
        else:
            print("[*] Directory scanning skipped")
            directory_results = {'total_directories': 0, 'directories': [], 'categories': {}}
        
        # Scan security headers (if selected)
        if selected_tests.get('security_headers', False):
            print(f"[*] Scanning security headers for {full_url}...")
            
            # Ensure URL has proper protocol
            if not full_url.startswith(('http://', 'https://')):
                test_url = f"http://{full_url}"
            else:
                test_url = full_url
            
            # Initialize and run security headers scanner
            headers_scanner = SecurityHeadersScanner()
            security_headers_results = headers_scanner.scan_for_api(test_url)
            
            if security_headers_results.get('error'):
                print(f"[!] Security headers scan failed: {security_headers_results.get('message')}")
            else:
                print(f"[*] Security headers scan completed: Grade {security_headers_results.get('security_grade')} ({security_headers_results.get('total_score')}/{security_headers_results.get('max_score')})")
        else:
            print("[*] Security headers scanning skipped")
            security_headers_results = {}
        
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
            risk_score += 15
        
        if sqli_results.get('total_vulnerabilities', 0) > 0:
            risk_score += 25  # SQLi is more critical
        
        if directory_results.get('total_directories', 0) > 0:
            # Add risk based on sensitive directories found
            admin_dirs = len(directory_results.get('categories', {}).get('admin', []))
            config_dirs = len(directory_results.get('categories', {}).get('config', []))
            if admin_dirs > 0 or config_dirs > 0:
                risk_score += 20  # Exposed admin/config directories are critical
            elif directory_results.get('total_directories', 0) > 5:
                risk_score += 10  # Many exposed directories increase attack surface
        
        if not waf_info['detected']:
            risk_score += 10
        
        risk_score = min(risk_score, 100)
        
        analysis_result = {
            'status': 'success',
            'url': full_url,
            'ip_address': ip_address,
            'hostname': hostname,
            'open_ports': open_ports,
            'total_open_ports': len(open_ports),
            'technologies': technologies,
            'waf': waf_info,
            'whois': whois_info,
            'xss_scan': xss_results,
            'sqli_scan': sqli_results,
            'directory_scan': directory_results,
            'security_headers': security_headers_results,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': f'Analysis completed for {full_url}',
            'data': {
                'risk_score': risk_score,
                'vulnerabilities_found': len(open_ports) + xss_results.get('total_vulnerabilities', 0) + sqli_results.get('total_vulnerabilities', 0) + directory_results.get('total_directories', 0),
                'scan_date': datetime.now().strftime('%Y-%m-%d')
            }
        }
        
        # Generate AI analysis (REQUIRED - AI-based project)
        gemini_api_key = data.get('gemini_api_key') or os.getenv('GEMINI_API_KEY')
        print(f"[SERVER] Using API Key: {bool(gemini_api_key)} - First 20: {gemini_api_key[:20] if gemini_api_key else 'NONE'}...")
        if selected_tests.get('ai_analysis', True):
            if not gemini_api_key:
                print("[!] No Gemini API key provided - AI analysis disabled")
                analysis_result['ai_analysis'] = {
                    "risk_level": "Unknown",
                    "risk_score": 0,
                    "risk_summary": "AI analysis requires Gemini API key. Please provide API key to enable intelligent security analysis.",
                    "most_likely_attacks": [],
                    "vulnerabilities": [],
                    "security_recommendations": [{
                        "category": "Configuration",
                        "priority": "High",
                        "recommendation": "Configure Gemini API key for AI-powered security analysis",
                        "implementation": "This project uses AI (Gemini) for intelligent vulnerability analysis. Get your free API key from https://makersuite.google.com/app/apikey"
                    }],
                    "compliance_notes": "AI analysis disabled - API key required"
                }
            else:
                print(f"[*] Generating AI security analysis with Gemini API...")
                try:
                    ai_analyzer = AIAnalyzer(api_key=gemini_api_key)
                    ai_analysis = ai_analyzer.analyze_security_results(analysis_result)
                    if ai_analysis:
                        # Check if it's a quota error
                        if ai_analysis.get('error') == 'quota_exceeded':
                            print("[!] Gemini API quota exceeded (20 requests/day limit)")
                            analysis_result['ai_analysis'] = ai_analysis
                        else:
                            analysis_result['ai_analysis'] = ai_analysis
                            
                            # Map AI port analysis to open_ports
                            if 'port_analysis' in ai_analysis and 'open_ports' in analysis_result:
                                port_analysis_map = {pa['port']: pa for pa in ai_analysis.get('port_analysis', [])}
                                for port_info in analysis_result['open_ports']:
                                    port_num = port_info.get('port')
                                    if port_num in port_analysis_map:
                                        pa = port_analysis_map[port_num]
                                        port_info['ai_analysis'] = pa.get('explanation', '')
                                        port_info['security_status'] = pa.get('security_status', '')
                                        port_info['ai_recommendation'] = pa.get('recommendation', '')
                            
                            print("[*] AI analysis completed successfully")
                    else:
                        print("[!] AI analysis failed - no response from Gemini")
                        analysis_result['ai_analysis'] = {
                            "risk_level": "Unknown",
                            "risk_score": 0,
                            "risk_summary": "AI analysis failed. Please check your Gemini API key and try again.",
                            "most_likely_attacks": [],
                            "vulnerabilities": [],
                            "security_recommendations": [],
                            "compliance_notes": "AI analysis failed - please retry"
                        }
                except Exception as ai_error:
                    print(f"[!] AI analysis error: {ai_error}")
                    analysis_result['ai_analysis'] = {
                        "risk_level": "Unknown",
                        "risk_score": 0,
                        "risk_summary": f"AI analysis error: {str(ai_error)}. Please verify your Gemini API key.",
                        "most_likely_attacks": [],
                        "vulnerabilities": [],
                        "security_recommendations": [],
                        "compliance_notes": f"Error: {str(ai_error)}"
                    }
        else:
            print("[*] AI analysis disabled by user")
            analysis_result['ai_analysis'] = {
                "risk_level": "Unknown",
                "risk_score": 0,
                "risk_summary": "AI analysis disabled",
                "most_likely_attacks": [],
                "vulnerabilities": [],
                "security_recommendations": [],
                "compliance_notes": "AI analysis was not selected"
            }
        
        return jsonify(analysis_result), 200
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"[ERROR] Exception in analyze_website:")
        print(error_trace)
        return jsonify({
            'status': 'error',
            'message': str(e),
            'trace': error_trace
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


@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf_endpoint():
    """Generate PDF report from analysis data"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        analysis_data = data.get('analysisData', {})
        selected_tests = data.get('selectedTests', {})
        
        if not analysis_data:
            return jsonify({
                'status': 'error',
                'message': 'No analysis data provided'
            }), 400
        
        # Import PDF generator
        from pdf_generator import generate_pdf_report
        
        # Generate PDF
        pdf_path = generate_pdf_report(analysis_data, selected_tests)
        
        # Generate filename
        url = analysis_data.get('url', 'report').replace('://', '-').replace('/', '-').replace('.', '-')
        filename = f'security-report-{url}-{datetime.now().strftime("%Y%m%d-%H%M%S")}.pdf'
        
        # Send file and cleanup
        response = send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
        # Schedule cleanup after sending
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(pdf_path)
            except:
                pass
        
        return response
        
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Failed to generate PDF: {str(e)}'
        }), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
