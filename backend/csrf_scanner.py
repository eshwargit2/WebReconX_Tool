"""
CSRF (Cross-Site Request Forgery) Vulnerability Scanner
Detects missing CSRF tokens in forms
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_csrf(url):
    """
    Scan website for CSRF vulnerabilities
    Checks forms for CSRF protection tokens
    """
    try:
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        
        print(f"[CSRF] Scanning {url} for CSRF vulnerabilities...")
        
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all forms on the page
        forms = soup.find_all('form')
        total_forms = len(forms)
        
        print(f"[CSRF] Found {total_forms} forms on the page")
        
        vulnerable_forms = []
        protected_forms = []
        
        # Common CSRF token field names
        csrf_token_names = [
            'csrf_token', 'csrfmiddlewaretoken', '_csrf', '_token', 
            'authenticity_token', '__RequestVerificationToken', 
            'csrf', 'token', '_csrf_token', 'xsrf_token'
        ]
        
        for idx, form in enumerate(forms, 1):
            form_action = form.get('action', 'N/A')
            form_method = form.get('method', 'GET').upper()
            form_id = form.get('id', f'form_{idx}')
            
            # Check if form has CSRF token
            has_csrf_token = False
            csrf_field_name = None
            
            # Look for CSRF token in input fields
            for token_name in csrf_token_names:
                csrf_input = form.find('input', {'name': token_name})
                if csrf_input:
                    has_csrf_token = True
                    csrf_field_name = token_name
                    break
            
            # Check meta tags for CSRF tokens (some frameworks use this)
            if not has_csrf_token:
                csrf_meta = soup.find('meta', {'name': lambda x: x and 'csrf' in x.lower()})
                if csrf_meta:
                    has_csrf_token = True
                    csrf_field_name = csrf_meta.get('name', 'meta-csrf')
            
            form_info = {
                'form_id': form_id,
                'action': form_action if form_action else '(current page)',
                'method': form_method,
                'absolute_action': urljoin(url, form_action) if form_action else url,
                'has_csrf_token': has_csrf_token,
                'csrf_field': csrf_field_name,
                'input_count': len(form.find_all('input'))
            }
            
            # Only consider POST/PUT/DELETE forms as potentially vulnerable
            # GET forms don't need CSRF protection
            if form_method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not has_csrf_token:
                    vulnerable_forms.append(form_info)
                    print(f"[CSRF] ⚠️  Vulnerable form found: {form_id} ({form_method} {form_action})")
                else:
                    protected_forms.append(form_info)
                    print(f"[CSRF] ✓ Protected form: {form_id} ({form_method} {form_action})")
            else:
                # GET forms are safe, consider them protected
                form_info['note'] = 'GET method - no CSRF protection needed'
                protected_forms.append(form_info)
        
        # Calculate statistics
        vulnerable_count = len(vulnerable_forms)
        protected_count = len(protected_forms)
        is_vulnerable = vulnerable_count > 0
        
        # Determine risk level
        if vulnerable_count == 0:
            risk_level = 'Low'
        elif vulnerable_count <= 2:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
        
        result = {
            'total_forms': total_forms,
            'vulnerable_forms_count': vulnerable_count,
            'protected_forms_count': protected_count,
            'vulnerable_forms': vulnerable_forms,
            'protected_forms': protected_forms,
            'is_vulnerable': is_vulnerable,
            'risk_level': risk_level,
            'scan_status': 'completed',
            'recommendations': generate_csrf_recommendations(is_vulnerable, vulnerable_count)
        }
        
        print(f"[CSRF] Scan completed: {vulnerable_count} vulnerable, {protected_count} protected")
        return result
        
    except requests.exceptions.Timeout:
        print(f"[CSRF] Timeout while scanning {url}")
        return {
            'total_forms': 0,
            'vulnerable_forms_count': 0,
            'protected_forms_count': 0,
            'vulnerable_forms': [],
            'protected_forms': [],
            'is_vulnerable': False,
            'risk_level': 'Unknown',
            'scan_status': 'timeout',
            'error': 'Request timeout'
        }
    except requests.exceptions.RequestException as e:
        print(f"[CSRF] Error scanning {url}: {str(e)}")
        return {
            'total_forms': 0,
            'vulnerable_forms_count': 0,
            'protected_forms_count': 0,
            'vulnerable_forms': [],
            'protected_forms': [],
            'is_vulnerable': False,
            'risk_level': 'Unknown',
            'scan_status': 'error',
            'error': str(e)
        }
    except Exception as e:
        print(f"[CSRF] Unexpected error: {str(e)}")
        return {
            'total_forms': 0,
            'vulnerable_forms_count': 0,
            'protected_forms_count': 0,
            'vulnerable_forms': [],
            'protected_forms': [],
            'is_vulnerable': False,
            'risk_level': 'Unknown',
            'scan_status': 'error',
            'error': str(e)
        }


def generate_csrf_recommendations(is_vulnerable, vulnerable_count):
    """Generate security recommendations based on CSRF scan results"""
    
    recommendations = []
    
    if is_vulnerable:
        recommendations.append({
            'severity': 'high',
            'title': 'CSRF Protection Missing',
            'description': f'{vulnerable_count} form(s) lack CSRF protection tokens',
            'remediation': 'Implement CSRF tokens in all state-changing forms'
        })
        
        recommendations.append({
            'severity': 'medium',
            'title': 'Add CSRF Middleware',
            'description': 'Enable CSRF protection at the framework level',
            'remediation': 'Use built-in CSRF protection (Django, Flask-WTF, etc.)'
        })
        
        recommendations.append({
            'severity': 'medium',
            'title': 'Use SameSite Cookies',
            'description': 'Set SameSite=Strict or Lax on session cookies',
            'remediation': 'Configure cookie settings to prevent cross-site requests'
        })
    else:
        recommendations.append({
            'severity': 'info',
            'title': 'CSRF Protection Active',
            'description': 'All forms appear to have CSRF protection',
            'remediation': 'Maintain current security practices'
        })
    
    return recommendations


if __name__ == '__main__':
    # Test the scanner
    test_url = input("Enter URL to scan for CSRF vulnerabilities: ")
    results = scan_csrf(test_url)
    
    print("\n" + "="*60)
    print("CSRF Scan Results")
    print("="*60)
    print(f"Total Forms: {results['total_forms']}")
    print(f"Vulnerable: {results['vulnerable_forms_count']}")
    print(f"Protected: {results['protected_forms_count']}")
    print(f"Risk Level: {results['risk_level']}")
    
    if results['vulnerable_forms']:
        print("\nVulnerable Forms:")
        for form in results['vulnerable_forms']:
            print(f"  - {form['form_id']}: {form['method']} {form['action']}")
