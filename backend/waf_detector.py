"""
WAF Detector Module
Detects Web Application Firewalls using wafw00f tool with deep scanning
"""
import subprocess


def detect_waf(url):
    """Detect WAF using wafw00f command line tool with deep scanning"""
    waf_info = {
        "detected": False,
        "name": "None detected",
        "full_name": "No Web Application Firewall detected",
        "version": "N/A",
        "method": "wafw00f",
        "confidence": "Low"
    }
    
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            test_url = f'https://{url}'
        else:
            test_url = url
        
        print(f"[WAF] Target: {test_url}")
        
        # Run wafw00f command with verbose flag for deeper scanning
        try:
            result = subprocess.run(
                ['wafw00f', '-a', '-v', test_url], 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            if result.returncode != 0:
                print(f"[WAF] Error: {result.stderr}")
                return waf_info
            
            output = result.stdout
            waf_detected = False
            
            # Parse output for WAF name and version
            if "is behind" in output.lower():
                lines = output.split('\n')
                for line in lines:
                    if "is behind" in line.lower():
                        parts = line.split("is behind")
                        if len(parts) > 1:
                            waf_data = parts[1].strip()
                            if '(' in waf_data:
                                waf_name = waf_data.split('(')[0].strip()
                                version_info = waf_data.split('(')[1].split(')')[0] if ')' in waf_data else "Unknown"
                            else:
                                waf_name = waf_data.strip()
                                version_info = "Unknown"
                            
                            waf_info["detected"] = True
                            waf_info["name"] = waf_name
                            waf_info["full_name"] = waf_data
                            waf_info["version"] = version_info
                            waf_info["method"] = "wafw00f Deep Scan"
                            waf_info["confidence"] = "High"
                            
                            print(f"[WAF] Detected: {waf_name}")
                            print(f"[WAF] Version: {version_info}")
                            waf_detected = True
                            break
            
            # Alternative parsing for different output formats
            if not waf_detected:
                lines = output.split('\n')
                for line in lines:
                    line_stripped = line.strip()
                    if line_stripped.startswith('[+]') and 'detected' in line_stripped.lower():
                        if 'behind' in line_stripped:
                            waf_name = line_stripped.split('behind')[-1].strip()
                            waf_info["detected"] = True
                            waf_info["name"] = waf_name
                            waf_info["full_name"] = waf_name
                            waf_info["version"] = "Unknown"
                            waf_info["method"] = "wafw00f Detection"
                            waf_info["confidence"] = "High"
                            print(f"[WAF] Detected: {waf_name}")
                            waf_detected = True
                            break
                    elif line_stripped.startswith('[-]') or 'not behind' in line_stripped.lower() or 'no waf' in line_stripped.lower():
                        print("[WAF] No WAF detected")
                        waf_detected = True
                        break
            
            # Check for multiple WAF detections in verbose mode
            if not waf_detected:
                waf_list = []
                for line in output.split('\n'):
                    if 'detected' in line.lower() and '[+]' in line:
                        waf_name = line.replace('[+]', '').replace('detected', '').strip()
                        if waf_name and waf_name not in waf_list:
                            waf_list.append(waf_name)
                
                if waf_list:
                    # Use the first detected WAF
                    waf_info["detected"] = True
                    waf_info["name"] = waf_list[0]
                    waf_info["full_name"] = waf_list[0]
                    waf_info["version"] = "Unknown"
                    waf_info["method"] = "wafw00f Verbose Scan"
                    waf_info["confidence"] = "High"
                    print(f"[WAF] Detected: {waf_list[0]}")
                    waf_detected = True
            
            # Final check if no detection found
            if not waf_detected:
                if "no waf" in output.lower() or "not behind" in output.lower():
                    print("[WAF] No WAF detected")
                else:
                    print("[WAF] Detection unclear")
                    waf_info["name"] = "Detection unclear"
                    waf_info["full_name"] = "WAF detection unclear"
            
        except subprocess.TimeoutExpired:
            print("[WAF] Error: Scan timeout")
            waf_info["name"] = "Scan timeout"
            waf_info["full_name"] = "WAF scan timeout"
        except FileNotFoundError:
            print("[WAF] Error: wafw00f not found. Install with: pip install wafw00f")
            waf_info["name"] = "wafw00f not installed"
            waf_info["full_name"] = "wafw00f tool not installed"
            waf_info["method"] = "Tool missing"
        
        return waf_info
        
    except Exception as e:
        print(f"[WAF] Error: {e}")
        return waf_info
