import socket
import re
from urllib.parse import urlparse

class WhoisLookup:
    def __init__(self):
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
            'us': 'whois.nic.us',
            'uk': 'whois.nic.uk',
            'co': 'whois.nic.co',
            'io': 'whois.nic.io',
            'me': 'whois.nic.me',
            'default': 'whois.iana.org'
        }
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except Exception as e:
            print(f"[WHOIS] Error extracting domain: {e}")
            return None
    
    def get_whois_server(self, domain):
        """Get appropriate WHOIS server for domain TLD"""
        try:
            tld = domain.split('.')[-1].lower()
            return self.whois_servers.get(tld, self.whois_servers['default'])
        except:
            return self.whois_servers['default']
    
    def query_whois(self, domain, server, port=43, timeout=10):
        """Query WHOIS server for domain information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            print(f"[WHOIS] Timeout querying {server}")
            return None
        except Exception as e:
            print(f"[WHOIS] Error querying {server}: {e}")
            return None
    
    def parse_whois_data(self, whois_text):
        """Parse WHOIS response and extract key information"""
        if not whois_text:
            return {}
        
        data = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant_org': None,
            'registrant_country': None,
            'admin_email': None,
            'dnssec': None,
            'raw_data': whois_text
        }
        
        lines = whois_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Registrar
            if re.search(r'registrar:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'registrar:\s*(.+)', line, re.IGNORECASE)
                if match and not data['registrar']:
                    data['registrar'] = match.group(1).strip()
            
            # Creation Date
            if re.search(r'creation date:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'creation date:\s*(.+)', line, re.IGNORECASE)
                if match and not data['creation_date']:
                    data['creation_date'] = match.group(1).strip()
            elif re.search(r'created:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'created:\s*(.+)', line, re.IGNORECASE)
                if match and not data['creation_date']:
                    data['creation_date'] = match.group(1).strip()
            
            # Expiration Date
            if re.search(r'expir(?:y|ation) date:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'expir(?:y|ation) date:\s*(.+)', line, re.IGNORECASE)
                if match and not data['expiration_date']:
                    data['expiration_date'] = match.group(1).strip()
            elif re.search(r'expir(?:es|y):\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'expir(?:es|y):\s*(.+)', line, re.IGNORECASE)
                if match and not data['expiration_date']:
                    data['expiration_date'] = match.group(1).strip()
            
            # Updated Date
            if re.search(r'updated date:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'updated date:\s*(.+)', line, re.IGNORECASE)
                if match and not data['updated_date']:
                    data['updated_date'] = match.group(1).strip()
            elif re.search(r'last updated:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'last updated:\s*(.+)', line, re.IGNORECASE)
                if match and not data['updated_date']:
                    data['updated_date'] = match.group(1).strip()
            
            # Name Servers
            if re.search(r'name server:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'name server:\s*(.+)', line, re.IGNORECASE)
                if match:
                    ns = match.group(1).strip().lower()
                    if ns not in data['name_servers']:
                        data['name_servers'].append(ns)
            
            # Domain Status
            if re.search(r'(?:domain )?status:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'(?:domain )?status:\s*(.+)', line, re.IGNORECASE)
                if match:
                    status = match.group(1).strip()
                    if status not in data['status']:
                        data['status'].append(status)
            
            # Registrant Organization
            if re.search(r'registrant organization:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'registrant organization:\s*(.+)', line, re.IGNORECASE)
                if match and not data['registrant_org']:
                    data['registrant_org'] = match.group(1).strip()
            
            # Registrant Country
            if re.search(r'registrant country:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'registrant country:\s*(.+)', line, re.IGNORECASE)
                if match and not data['registrant_country']:
                    data['registrant_country'] = match.group(1).strip()
            
            # Admin Email
            if re.search(r'admin email:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'admin email:\s*(.+)', line, re.IGNORECASE)
                if match and not data['admin_email']:
                    data['admin_email'] = match.group(1).strip()
            
            # DNSSEC
            if re.search(r'dnssec:\s*(.+)', line, re.IGNORECASE):
                match = re.search(r'dnssec:\s*(.+)', line, re.IGNORECASE)
                if match and not data['dnssec']:
                    data['dnssec'] = match.group(1).strip()
        
        return data
    
    def lookup(self, url):
        """Perform WHOIS lookup for a given URL/domain"""
        try:
            domain = self.extract_domain(url)
            if not domain:
                return {
                    'success': False,
                    'error': 'Could not extract domain from URL',
                    'domain': None
                }
            
            print(f"[WHOIS] Looking up domain: {domain}")
            
            # Get appropriate WHOIS server
            whois_server = self.get_whois_server(domain)
            print(f"[WHOIS] Using server: {whois_server}")
            
            # Query WHOIS server
            whois_response = self.query_whois(domain, whois_server)
            
            if not whois_response:
                return {
                    'success': False,
                    'error': 'WHOIS server timeout or connection error',
                    'domain': domain
                }
            
            # Check if we need to query a different server (referral)
            referral_match = re.search(r'refer:\s*(.+)', whois_response, re.IGNORECASE)
            if referral_match:
                referral_server = referral_match.group(1).strip()
                print(f"[WHOIS] Following referral to: {referral_server}")
                referral_response = self.query_whois(domain, referral_server)
                if referral_response:
                    whois_response = referral_response
            
            # Parse the WHOIS data
            parsed_data = self.parse_whois_data(whois_response)
            
            result = {
                'success': True,
                'domain': domain,
                'registrar': parsed_data.get('registrar', 'Not available'),
                'creation_date': parsed_data.get('creation_date', 'Not available'),
                'expiration_date': parsed_data.get('expiration_date', 'Not available'),
                'updated_date': parsed_data.get('updated_date', 'Not available'),
                'name_servers': parsed_data.get('name_servers', []),
                'status': parsed_data.get('status', []),
                'registrant_org': parsed_data.get('registrant_org'),
                'registrant_country': parsed_data.get('registrant_country'),
                'dnssec': parsed_data.get('dnssec', 'Not available'),
                'raw_whois': parsed_data.get('raw_data', '')[:2000]  # Limit raw data
            }
            
            print(f"[WHOIS] Lookup complete for {domain}")
            return result
            
        except Exception as e:
            print(f"[WHOIS] Error during lookup: {e}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain if 'domain' in locals() else None
            }

def perform_whois_lookup(url):
    """Main function to perform WHOIS lookup"""
    whois = WhoisLookup()
    return whois.lookup(url)
