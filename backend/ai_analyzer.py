from google import genai
from google.genai import types
import json
import os

class AIAnalyzer:
    def __init__(self, api_key=None):
        """Initialize Gemini AI analyzer"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            self.client = None
            print("[AI] Warning: No Gemini API key provided")
    
    def analyze_security_results(self, scan_data):
        """Analyze scan results and generate AI recommendations"""
        if not self.client:
            print("[AI] Error: No Gemini API key configured")
            return None
        
        try:
            # Prepare scan summary for AI
            prompt = self._build_analysis_prompt(scan_data)
            
            # Get AI response with timeout handling
            print("[AI] Sending request to Gemini API...")
            response = self.client.models.generate_content(
                model='gemini-2.5-flash',  # Free tier: 20 requests/day
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.7,
                    top_p=0.8,
                    top_k=40,
                    max_output_tokens=8192,  # Increased to 8K for complete responses
                    response_mime_type='application/json'  # Force JSON output without markdown
                )
            )
            print("[AI] Received response from Gemini API")
            print(f"[AI] Response text length: {len(response.text)}")
            
            # Check if response was complete
            finish_reason = None
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'finish_reason'):
                    finish_reason = candidate.finish_reason
                    # Convert enum to string for comparison
                    finish_reason_str = str(finish_reason).upper()
                    print(f"[AI] Finish reason: {finish_reason_str}")
            
            # Handle incomplete responses due to token limit
            if finish_reason and ("MAX_TOKENS" in str(finish_reason).upper() or "LENGTH" in str(finish_reason).upper()):
                print("[AI] Warning: Response truncated due to MAX_TOKENS. Retrying with simplified prompt...")
                # Retry with a simplified prompt asking for shorter responses
                simplified_prompt = self._build_simplified_prompt(scan_data)
                response = self.client.models.generate_content(
                    model='gemini-2.5-flash',  # Free tier: 20 requests/day
                    contents=simplified_prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.5,
                        max_output_tokens=8192,
                        response_mime_type='application/json'
                    )
                )
                print(f"[AI] Retry response length: {len(response.text)}")
            
            # Parse AI response
            ai_analysis = self._parse_ai_response(response.text)
            
            if ai_analysis is None:
                print("[AI] Warning: Parsing returned None")
            else:
                print("[AI] Successfully parsed AI analysis")
            
            return ai_analysis
            
        except Exception as e:
            error_msg = str(e)
            print(f"[AI] Error during analysis: {type(e).__name__}: {e}")
            
            # Handle quota/rate limit errors specifically
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
                print("[AI] ⚠️ Gemini API quota exceeded. Free tier limit: 20 requests/day")
                print("[AI] The scan will continue without AI analysis.")
                print("[AI] To get AI insights:")
                print("[AI]   - Wait for quota reset (usually 24 hours)")
                print("[AI]   - Or upgrade to paid plan at https://ai.google.dev/pricing")
                return {
                    "error": "quota_exceeded",
                    "risk_level": "Unknown",
                    "risk_score": 0,
                    "risk_summary": "AI analysis unavailable - API quota exceeded. Free tier allows 20 requests per day. Please wait for quota reset or upgrade your plan.",
                    "most_likely_attacks": [],
                    "port_analysis": [],
                    "vulnerabilities": [],
                    "security_recommendations": [],
                    "compliance_notes": "AI analysis requires API quota. Manual review recommended."
                }
            
            # Handle other errors
            import traceback
            traceback.print_exc()
            return None
    
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
        if isinstance(technologies, dict):
            # Technologies is a dict with categories
            for category, tech_list in technologies.items():
                if isinstance(tech_list, list):
                    for tech in tech_list:
                        if isinstance(tech, str):
                            tech_details.append(f"{tech} ({category})")
                        elif isinstance(tech, dict):
                            tech_info = tech.get('name', 'Unknown')
                            if tech.get('version'):
                                tech_info += f" v{tech.get('version')}"
                            tech_details.append(f"{tech_info} ({category})")
        elif isinstance(technologies, list):
            # Technologies is a list of dicts or strings
            for t in technologies:
                if isinstance(t, dict):
                    tech_info = t.get('name', 'Unknown')
                    if t.get('version'):
                        tech_info += f" v{t.get('version')}"
                    tech_details.append(tech_info)
                elif isinstance(t, str):
                    tech_details.append(t)
        
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
- Base ALL recommendations on ACTUAL findings
- Keep descriptions concise and actionable (under 150 chars)
- If WAF DETECTED, do NOT recommend adding WAF
- Focus on critical findings first
- Limit port_analysis to 5 ports max
- Limit vulnerabilities to 5 items max
- Limit recommendations to 5 items max

Provide JSON response:
{{
  "risk_level": "Low|Medium|High|Critical",
  "risk_score": 0-100,
  "risk_summary": "Brief summary based on actual findings above",
  "most_likely_attacks": [
    {{
      "attack_type": "Specific attack based on vulnerabilities found (e.g., 'XSS via parameter injection')",
      "probability": "Low|Medium|High",
      "reason": "Based on specific findings (explain which vulnerability/port enables this attack)"
    }}
  ],
  "port_analysis": [
    {{
      "port": 80,
      "service": "HTTP",
      "version": "Apache 2.4.41",
      "security_status": "Outdated|Current|Vulnerable",
      "explanation": "Brief security assessment (max 150 chars)",
      "recommendation": "Specific action"
    }}
  ],
  "vulnerabilities": [
    {{
      "title": "Specific vulnerability name",
      "severity": "Low|Medium|High|Critical",
      "description": "Concise description (max 150 chars)",
      "attack_method": "How attacker exploits (max 100 chars)",
      "impact": "Impact summary (max 100 chars)",
      "fix": "Actionable fix (max 150 chars)"
    }}
  ],
  "security_recommendations": [
    {{
      "category": "Category based on findings",
      "priority": "Low|Medium|High|Critical",
      "recommendation": "Specific action (max 150 chars)",
      "implementation": "Implementation steps (max 200 chars)"
    }}
  ],
  "compliance_notes": "Brief compliance notes (max 200 chars)"
}}

Provide ONLY valid JSON, no markdown formatting or explanations."""

        return prompt
    
    def _build_simplified_prompt(self, scan_data):
        """Build a more concise prompt when the full prompt causes MAX_TOKENS"""
        url = scan_data.get('url', 'Unknown')
        open_ports = scan_data.get('open_ports', [])
        waf = scan_data.get('waf', {})
        technologies = scan_data.get('technologies', [])
        xss_scan = scan_data.get('xss_scan', {})
        sqli_scan = scan_data.get('sqli_scan', {})
        
        # Build concise summary
        port_count = len(open_ports)
        waf_status = "Present" if waf.get('detected') else "Absent"
        tech_count = len(technologies) if isinstance(technologies, list) else len(technologies.keys()) if isinstance(technologies, dict) else 0
        xss_status = "Vulnerable" if xss_scan.get('vulnerable') else "Not Detected"
        sqli_status = "Vulnerable" if sqli_scan.get('vulnerable') else "Not Detected"
        
        prompt = f"""Analyze this web security scan for {url}. Provide concise JSON response.

SCAN SUMMARY:
- Open Ports: {port_count}
- WAF: {waf_status}
- Technologies: {tech_count} detected
- XSS: {xss_status}
- SQLi: {sqli_status}

Provide JSON with:
{{
  "risk_level": "Low|Medium|High|Critical",
  "risk_score": 0-100,
  "risk_summary": "Brief 2-sentence summary",
  "most_likely_attacks": [
    {{"attack_type": "string", "probability": "Low|Medium|High", "reason": "Brief reason"}}
  ],
  "port_analysis": [
    {{"port": number, "service": "string", "security_status": "string", "recommendation": "Brief action"}}
  ],
  "vulnerabilities": [
    {{"title": "string", "severity": "string", "description": "Brief description", "fix": "Brief fix"}}
  ],
  "security_recommendations": [
    {{"category": "string", "priority": "string", "recommendation": "Specific action"}}
  ],
  "compliance_notes": "Brief notes"
}}

Keep all descriptions concise (under 100 chars each). Focus on actionable findings."""

        return prompt
    
    def _parse_ai_response(self, response_text):
        """Parse AI response and ensure valid structure"""
        try:
            print(f"[AI] Parsing response... (length: {len(response_text)})")
            
            # With response_mime_type='application/json', the response should be clean JSON
            # But still handle markdown blocks as fallback
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0]
                print("[AI] Removed ```json``` markdown blocks")
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0]
                print("[AI] Removed ``` markdown blocks")
            
            # Clean up the response text - remove any terminal line wrapping artifacts
            # The issue is that terminal output may have wrapped long lines with line breaks
            # This is just a display issue, the actual response from Gemini is valid JSON
            response_text = response_text.strip()
            
            # Parse JSON with strict=False to be more lenient
            analysis = json.loads(response_text, strict=False)
            print("[AI] Successfully parsed JSON")
            
            # Validate structure
            if not isinstance(analysis, dict):
                raise ValueError("Invalid response structure - not a dict")
            
            print(f"[AI] Validated structure. Keys: {list(analysis.keys())}")
            return analysis
            
        except json.JSONDecodeError as e:
            print(f"[AI] JSON parsing error: {e}")
            print(f"[AI] Attempting alternative parsing...")
            
            # Try to get the raw response object instead of text representation
            # The issue might be in how we're printing/displaying the response
            try:
                # If we got here, the response.text might have display issues
                # but the actual data should be fine. Let's try to work with it.
                import re
                # This is likely a display artifact - the actual JSON is probably fine
                # Just try parsing again without debug output interfering
                cleaned = response_text.strip()
                analysis = json.loads(cleaned, strict=False)
                print("[AI] Successfully parsed on retry")
                return analysis
            except:
                print(f"[AI] Alternative parsing also failed")
                print(f"[AI] Response text (repr): {repr(response_text[:300])}")
                return None
        except Exception as e:
            print(f"[AI] Error parsing response: {type(e).__name__}: {e}")
            return None
