import google.generativeai as genai
import json
import os

class AIAnalyzer:
    def __init__(self, api_key=None):
        """Initialize Gemini AI analyzer"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if self.api_key:
            genai.configure(api_key=self.api_key)
            # Configure generation settings with timeout
            self.generation_config = {
                'temperature': 0.7,
                'top_p': 0.8,
                'top_k': 40,
                'max_output_tokens': 2048,
            }
            self.model = genai.GenerativeModel(
                'gemini-pro',
                generation_config=self.generation_config
            )
        else:
            self.model = None
            print("[AI] Warning: No Gemini API key provided")
    
    def analyze_security_results(self, scan_data):
        """Analyze scan results and generate AI recommendations"""
        if not self.model:
            return self._get_fallback_analysis(scan_data)
        
        try:
            # Prepare scan summary for AI
            prompt = self._build_analysis_prompt(scan_data)
            
            # Get AI response with timeout handling
            print("[AI] Sending request to Gemini API...")
            response = self.model.generate_content(
                prompt,
                request_options={'timeout': 180}  # 180 second timeout for API call
            )
            print("[AI] Received response from Gemini API")
            
            # Parse AI response
            ai_analysis = self._parse_ai_response(response.text)
            
            return ai_analysis
            
        except Exception as e:
            print(f"[AI] Error during analysis: {e}")
            return self._get_fallback_analysis(scan_data)
    
    def _build_analysis_prompt(self, scan_data):
        """Build comprehensive prompt for AI analysis based on actual scan data"""
        
        # Extract key information
        url = scan_data.get('url', 'Unknown')
        open_ports = scan_data.get('open_ports', [])
        waf = scan_data.get('waf', {})
        technologies = scan_data.get('technologies', [])
        xss_scan = scan_data.get('xss_scan', {})
        sqli_scan = scan_data.get('sqli_scan', {})
        whois_data = scan_data.get('whois_info', {})
        
        # Build detailed port information with services and versions
        port_details = []
        for p in open_ports:
            port_info = f"Port {p.get('port')}: {p.get('service', 'unknown')}"
            if p.get('version'):
                port_info += f" (v{p.get('version')})"
            port_details.append(port_info)
        
        # Build technology details with versions
        tech_details = []
        for t in technologies:
            tech_info = t.get('name', 'Unknown')
            if t.get('version'):
                tech_info += f" v{t.get('version')}"
            tech_details.append(tech_info)
        
        # Build vulnerability details
        xss_details = []
        if xss_scan.get('vulnerable') and xss_scan.get('vulnerabilities'):
            for vuln in xss_scan.get('vulnerabilities', [])[:3]:  # Top 3 XSS issues
                xss_details.append(f"{vuln.get('parameter', 'unknown')} - {vuln.get('payload', '')[:50]}")
        
        sqli_details = []
        if sqli_scan.get('vulnerable') and sqli_scan.get('vulnerabilities'):
            for vuln in sqli_scan.get('vulnerabilities', [])[:3]:  # Top 3 SQLi issues
                sqli_details.append(f"{vuln.get('parameter', 'unknown')} - {vuln.get('error_type', 'unknown')}")
        
        prompt = f"""You are a cybersecurity expert analyzing a web security scan. Provide a detailed security analysis in JSON format based ONLY on the actual scan results below.

Website: {url}

DETAILED SCAN RESULTS:

1. OPEN PORTS ({len(open_ports)} found):
{chr(10).join(['   - ' + pd for pd in port_details[:10]]) if port_details else '   No open ports detected'}

2. WEB APPLICATION FIREWALL:
   {'✓ DETECTED - ' + waf.get('name', 'Unknown') + (f" v{waf.get('version')}" if waf.get('version') else '') if waf.get('detected') else '✗ NOT DETECTED - No WAF protection found'}

3. TECHNOLOGIES DETECTED ({len(technologies)} found):
{chr(10).join(['   - ' + td for td in tech_details[:8]]) if tech_details else '   No technologies detected'}

4. XSS VULNERABILITIES:
   {'✓ VULNERABLE - ' + str(xss_scan.get('total_vulnerabilities', 0)) + ' vulnerabilities found' if xss_scan.get('vulnerable') else '✗ NO XSS FOUND'}
{chr(10).join(['   - ' + xd for xd in xss_details]) if xss_details else ''}

5. SQL INJECTION VULNERABILITIES:
   {'✓ VULNERABLE - ' + str(sqli_scan.get('total_vulnerabilities', 0)) + ' vulnerabilities found' if sqli_scan.get('vulnerable') else '✗ NO SQLi FOUND'}
{chr(10).join(['   - ' + sd for sd in sqli_details]) if sqli_details else ''}

IMPORTANT INSTRUCTIONS:
- Base ALL recommendations on the ACTUAL vulnerabilities and configurations found above
- If WAF is DETECTED (✓), DO NOT recommend adding WAF or report it as missing
- For each open port, recommend specific security measures based on the service and version
- If outdated software versions are detected, recommend updating them specifically
- Prioritize recommendations based on actual vulnerabilities found (XSS, SQLi, etc.)
- Make recommendations specific and actionable, not generic

Please provide a JSON response with the following structure:
{{
  "risk_level": "Low|Medium|High|Critical",
  "risk_score": 0-100,
  "risk_summary": "Brief summary based on actual findings above",
  "most_likely_attacks": [
    {{
      "attack_type": "Specific attack based on vulnerabilities found",
      "probability": "Low|Medium|High",
      "reason": "Based on specific findings (port numbers, services, vulnerabilities)"
    }}
  ],
  "vulnerabilities": [
    {{
      "title": "Specific vulnerability from scan results",
      "severity": "Low|Medium|High|Critical",
      "description": "Specific details from the scan (e.g., 'Port 22 SSH v7.4 exposed')",
      "impact": "Realistic impact based on the specific vulnerability",
      "fix": "Specific actionable fix (e.g., 'Update SSH to v8.0+, disable password auth')"
    }}
  ],
  "security_recommendations": [
    {{
      "category": "Specific category based on findings",
      "priority": "Low|Medium|High|Critical",
      "recommendation": "Specific recommendation based on actual vulnerabilities (reference port numbers, services, versions)",
      "implementation": "Detailed implementation steps for the specific issue found"
    }}
  ],
  "compliance_notes": "Compliance notes based on actual scan findings"
}}

Provide ONLY valid JSON, no markdown formatting or explanations."""

        return prompt
    
    def _parse_ai_response(self, response_text):
        """Parse AI response and ensure valid structure"""
        try:
            # Remove markdown code blocks if present
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
            
            # Parse JSON
            analysis = json.loads(response_text.strip())
            
            # Validate structure
            if not isinstance(analysis, dict):
                raise ValueError("Invalid response structure")
            
            return analysis
            
        except Exception as e:
            print(f"[AI] Error parsing response: {e}")
            return None
    
    def _get_fallback_analysis(self, scan_data):
        """Generate basic analysis without AI"""
        
        # Calculate risk based on vulnerabilities
        xss_vuln = scan_data.get('xss_scan', {}).get('vulnerable', False)
        sqli_vuln = scan_data.get('sqli_scan', {}).get('vulnerable', False)
        waf_detected = scan_data.get('waf', {}).get('detected', False)  # Fixed: changed from 'waf_detected' to 'waf'
        open_ports_count = len(scan_data.get('open_ports', []))
        
        # Calculate risk score
        risk_score = 0
        if xss_vuln:
            risk_score += 30
        if sqli_vuln:
            risk_score += 40
        if not waf_detected:
            risk_score += 20
        if open_ports_count > 3:
            risk_score += 10
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Build fallback analysis
        analysis = {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_summary": f"Basic security analysis shows {risk_level.lower()} risk level. AI analysis unavailable.",
            "most_likely_attacks": [],
            "vulnerabilities": [],
            "security_recommendations": [],
            "compliance_notes": "Enable AI analysis for detailed recommendations."
        }
        
        # Add likely attacks
        if xss_vuln:
            analysis["most_likely_attacks"].append({
                "attack_type": "Cross-Site Scripting (XSS)",
                "probability": "High",
                "reason": "XSS vulnerabilities detected during scan"
            })
        
        if sqli_vuln:
            analysis["most_likely_attacks"].append({
                "attack_type": "SQL Injection",
                "probability": "High",
                "reason": "SQL injection vulnerabilities detected during scan"
            })
        
        if not waf_detected:
            analysis["most_likely_attacks"].append({
                "attack_type": "Automated Attacks",
                "probability": "Medium",
                "reason": "No WAF protection detected"
            })
        
        # Add vulnerabilities
        if xss_vuln:
            xss_count = scan_data.get('xss_scan', {}).get('total_vulnerabilities', 0)
            analysis["vulnerabilities"].append({
                "title": "Cross-Site Scripting Vulnerabilities",
                "severity": "High",
                "description": f"Found {xss_count} XSS vulnerability points in the application",
                "impact": "Attackers can inject malicious scripts, steal user data, or hijack sessions",
                "fix": "Implement input validation, output encoding, and Content Security Policy (CSP) headers"
            })
        
        if sqli_vuln:
            sqli_count = scan_data.get('sqli_scan', {}).get('total_vulnerabilities', 0)
            analysis["vulnerabilities"].append({
                "title": "SQL Injection Vulnerabilities",
                "severity": "Critical",
                "description": f"Found {sqli_count} SQL injection vulnerability points",
                "impact": "Attackers can access, modify, or delete database contents, potentially compromising all data",
                "fix": "Use parameterized queries, prepared statements, and ORM frameworks. Validate all user inputs"
            })
        
        if not waf_detected:
            analysis["vulnerabilities"].append({
                "title": "No Web Application Firewall",
                "severity": "Medium",
                "description": "No WAF detected protecting the application",
                "impact": "Application is more vulnerable to automated attacks and exploitation attempts",
                "fix": "Implement a WAF solution like Cloudflare, AWS WAF, or ModSecurity"
            })
        
        # Add specific recommendations based on vulnerabilities
        if xss_vuln or sqli_vuln:
            analysis["security_recommendations"].append({
                "category": "Input Validation",
                "priority": "Critical",
                "recommendation": f"Fix {'XSS and SQL injection' if (xss_vuln and sqli_vuln) else 'XSS' if xss_vuln else 'SQL injection'} vulnerabilities immediately",
                "implementation": "Use parameterized queries for database operations. Implement output encoding for all user-generated content. Enable Content Security Policy headers"
            })
        
        if not waf_detected:
            analysis["security_recommendations"].append({
                "category": "Infrastructure Protection",
                "priority": "High",
                "recommendation": "Deploy Web Application Firewall",
                "implementation": "Implement Cloudflare WAF, AWS WAF, or ModSecurity to protect against automated attacks and common vulnerabilities"
            })
        
        # Add port-specific recommendations
        open_ports_list = scan_data.get('open_ports', [])
        if len(open_ports_list) > 5:
            port_nums = [str(p.get('port')) for p in open_ports_list[:5]]
            analysis["security_recommendations"].append({
                "category": "Network Security",
                "priority": "High",
                "recommendation": f"Review and restrict open ports (found {len(open_ports_list)}): {', '.join(port_nums)}...",
                "implementation": "Close unnecessary ports, implement firewall rules, and ensure only required services are exposed to the internet"
            })
        
        analysis["security_recommendations"].append({
            "category": "Security Headers",
            "priority": "Medium",
            "recommendation": "Implement comprehensive security headers",
            "implementation": "Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and X-XSS-Protection headers"
        })
        
        return analysis
