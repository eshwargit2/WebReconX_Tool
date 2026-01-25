import requests
import threading
from queue import Queue
from urllib.parse import urljoin, urlparse, parse_qs
import os
import urllib3
import re
from bs4 import BeautifulSoup
import subprocess
import json

# Disable SSL warnings when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DirectoryScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.timeout = 2  # Reduced from 5 to 2 seconds for faster scanning
        self.found_directories = []
        self.lock = threading.Lock()
        
        # Enhanced directory wordlist inspired by dirsearch
        self.directories = [
            # Admin panels
            'admin', 'admin/', 'administrator', 'administrator/', 'admin/login', 'admin/admin',
            'admin/index', 'admin/dashboard', 'admin/home', 'admincp', 'admins',
            'wp-admin', 'wp-admin/', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes',
            'phpmyadmin', 'phpMyAdmin', 'pma', 'myadmin', 'mysql',
            'controlpanel', 'cpanel', 'panel', 'webadmin', 'sysadmin',
            'moderator', 'webmaster', 'master', 'backend', 'backoffice',
            
            # Authentication
            'login', 'login/', 'login.php', 'login.html', 'login.asp', 'signin', 'signin/',
            'auth', 'authenticate', 'authentication', 'account', 'user', 'users',
            'profile', 'dashboard', 'portal', 'member', 'members', 'contact-us' ,
            
            # Configuration & sensitive files
            'config', 'config/', 'configuration', 'settings', 'setup', 'install',
            'config.php', 'config.json', 'config.xml', 'web.config', 'application.properties',
            '.env', '.env.local', '.env.production', '.git', '.git/', '.svn', '.htaccess',
            'composer.json', 'package.json', 'package-lock.json', 'yarn.lock',
            
            # Backup & temp files
            'backup', 'backups', 'backup/', 'bak', 'old', 'old/', 'new', 'tmp', 'temp',
            'archive', 'archives', 'dump', 'sql', 'database', 'db', 'data',
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'dump.sql',
            
            # API endpoints
            'api', 'api/', 'api/v1', 'api/v2', 'api/v3', 'rest', 'rest/', 'graphql',
            'restapi', 'webservice', 'ws', 'service', 'services',
            'json', 'xml', 'swagger', 'api-docs', 'docs/api',
            
            # Content & uploads
            'uploads', 'upload', 'upload/', 'files', 'file', 'images', 'img', 'image',
            'media', 'assets', 'static', 'content', 'download', 'downloads',
            'attachments', 'documents', 'docs', 'public', 'resources',
            
            # Application structure
            'app', 'application', 'apps', 'src', 'source', 'lib', 'library',
            'includes', 'include', 'inc', 'common', 'core', 'system',
            'vendor', 'node_modules', 'packages', 'plugins', 'modules',
            'components', 'views', 'templates', 'layouts',
            
            # Scripts & styles
            'js', 'javascript', 'scripts', 'script', 'css', 'style', 'styles',
            'fonts', 'font', 'icons',
            
            # Testing & development
            'test', 'tests', 'testing', 'dev', 'development', 'demo', 'sandbox',
            'staging', 'beta', 'alpha', 'debug', 'trace',
            
            # Logs & monitoring
            'logs', 'log', 'log/', 'access.log', 'error.log', 'debug.log',
            'errors', 'error', 'console', 'monitor', 'monitoring',
            
            # Security & private
            'private', 'secret', 'hidden', 'secure', 'internal', 'restricted',
            'confidential', 'protected',
            
            # Documentation
            'docs', 'documentation', 'doc', 'help', 'readme', 'changelog',
            'manual', 'guide', 'wiki',
            
            # Common CMS/Framework paths
            'wordpress', 'joomla', 'drupal', 'magento', 'prestashop',
            'opencart', 'laravel', 'symfony', 'codeigniter', 'cakephp',
            
            # Error pages
            '404', '403', '500', '401', 'error', 'errors',
            
            # Miscellaneous
            'sitemap', 'sitemap.xml', 'robots.txt', 'crossdomain.xml',
            'favicon.ico', 'index.php', 'index.html', 'home',
            'about', 'contact', 'search', 'cart', 'checkout',
            
            # Common website pages
            'about', 'about/', 'about.php', 'about.html', 'aboutus', 'about-us',
            'contact', 'contact/', 'contact.php', 'contact.html', 'contactus', 'contact-us',
            'services', 'service', 'products', 'product', 'portfolio',
            'team', 'careers', 'jobs', 'pricing', 'plans', 'features',
            'blog', 'blog/', 'news', 'articles', 'posts',
            'faq', 'faqs', 'support', 'help', 'helpdesk',
            'terms', 'terms-of-service', 'tos', 'privacy', 'privacy-policy',
            'legal', 'disclaimer', 'policy', 'policies',
            'partners', 'clients', 'testimonials', 'reviews',
            'gallery', 'photos', 'videos', 'events',
            'newsletter', 'subscribe', 'unsubscribe',
            'feedback', 'sitemap.html', 'map',
            
            # E-commerce specific
            'shop', 'store', 'catalog', 'category', 'categories',
            'checkout', 'cart', 'basket', 'wishlist', 'compare',
            'order', 'orders', 'invoice', 'payment', 'shipping',
            'account', 'my-account', 'myaccount', 'register', 'signup',
            
            # Social & community
            'forum', 'forums', 'community', 'board', 'discussion',
            'comments', 'feedback', 'chat', 'message', 'messages',
            
            # Media & resources
            'video', 'videos', 'audio', 'podcast', 'podcasts',
            'ebook', 'ebooks', 'pdf', 'whitepaper', 'whitepapers',
            'case-study', 'case-studies', 'webinar', 'webinars'
        ]
        
        self.crawled_urls = set()  # Track crawled URLs to avoid duplicates
        self.discovered_endpoints = set()  # Store discovered endpoints
    
    def katana_crawl(self, url):
        """Katana-style intelligent web crawling to discover endpoints"""
        print(f"\n[*] Starting Katana-style intelligent crawl...")
        discovered = set()
        
        # 1. Check robots.txt
        robots_urls = self.check_robots_txt(url)
        discovered.update(robots_urls)
        
        # 2. Check sitemap.xml
        sitemap_urls = self.check_sitemap(url)
        discovered.update(sitemap_urls)
        
        # 3. Crawl homepage and extract links
        crawled_urls = self.crawl_and_extract_links(url, max_depth=2)
        discovered.update(crawled_urls)
        
        # 4. Extract JavaScript endpoints
        js_endpoints = self.extract_js_endpoints(url)
        discovered.update(js_endpoints)
        
        # 5. Check common API endpoints
        api_endpoints = self.check_api_endpoints(url)
        discovered.update(api_endpoints)
        
        print(f"[*] Katana crawl completed: {len(discovered)} unique endpoints discovered")
        return list(discovered)
    
    def check_robots_txt(self, url):
        """Parse robots.txt for disallowed paths (often interesting directories)"""
        discovered = set()
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=3, verify=False)
            if response.status_code == 200:
                print(f"[+] Found robots.txt")
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(base_url, path)
                            discovered.add(full_url)
                            print(f"    [robots.txt] {full_url}")
        except:
            pass
        
        return discovered
    
    def check_sitemap(self, url):
        """Parse sitemap.xml for URLs"""
        discovered = set()
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        sitemap_urls = [
            '/sitemap.xml', '/sitemap_index.xml', '/sitemap-index.xml',
            '/sitemap1.xml', '/sitemap.php', '/sitemap/'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(base_url, sitemap_path)
                response = self.session.get(sitemap_url, timeout=3, verify=False)
                if response.status_code == 200:
                    print(f"[+] Found sitemap: {sitemap_url}")
                    # Extract URLs from XML
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for found_url in urls[:50]:  # Limit to 50 URLs
                        discovered.add(found_url)
                        print(f"    [sitemap] {found_url}")
                    break
            except:
                pass
        
        return discovered
    
    def crawl_and_extract_links(self, url, max_depth=2):
        """Crawl website and extract links (Katana-style)"""
        discovered = set()
        to_crawl = [(url, 0)]
        crawled = set()
        
        while to_crawl and len(crawled) < 20:  # Limit crawling
            current_url, depth = to_crawl.pop(0)
            
            if current_url in crawled or depth > max_depth:
                continue
            
            crawled.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=3, verify=False)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all(['a', 'link'], href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Only same domain
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            discovered.add(full_url)
                            if depth < max_depth:
                                to_crawl.append((full_url, depth + 1))
                    
                    # Extract form actions
                    for form in soup.find_all('form', action=True):
                        action = form['action']
                        full_url = urljoin(current_url, action)
                        discovered.add(full_url)
                        print(f"    [form] {full_url}")
            except:
                pass
        
        return discovered
    
    def extract_js_endpoints(self, url):
        """Extract API endpoints from JavaScript files"""
        discovered = set()
        
        try:
            response = self.session.get(url, timeout=3, verify=False)
            if response.status_code == 200:
                # Find JS file URLs
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
                
                for js_url in js_urls[:10]:  # Limit to 10 JS files
                    full_js_url = urljoin(url, js_url)
                    try:
                        js_response = self.session.get(full_js_url, timeout=2, verify=False)
                        if js_response.status_code == 200:
                            # Extract API endpoints from JS
                            api_patterns = [
                                r'["\']/(api|v\d+|graphql|rest)[^"\']*["\']',
                                r'["\']https?://[^"\']+/api[^"\']*["\']',
                                r'endpoint["\']?\s*:\s*["\']([^"\']+)["\']',
                                r'url["\']?\s*:\s*["\']([^"\']+)["\']'
                            ]
                            
                            for pattern in api_patterns:
                                matches = re.findall(pattern, js_response.text)
                                for match in matches[:5]:
                                    endpoint = match if match.startswith('http') else urljoin(url, match)
                                    discovered.add(endpoint)
                                    print(f"    [js-endpoint] {endpoint}")
                    except:
                        pass
        except:
            pass
        
        return discovered
    
    def check_api_endpoints(self, url):
        """Check common API endpoint patterns"""
        discovered = set()
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        api_patterns = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/graphql',
            '/rest', '/api/users', '/api/auth', '/api/login',
            '/api/data', '/api/posts', '/api/products', '/swagger',
            '/api-docs', '/docs', '/openapi.json', '/api.json'
        ]
        
        for pattern in api_patterns:
            try:
                endpoint = urljoin(base_url, pattern)
                response = self.session.head(endpoint, timeout=2, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 401, 403]:
                    discovered.add(endpoint)
                    print(f"    [api] {endpoint} [{response.status_code}]")
            except:
                pass
        
        return discovered
    
    def check_directory(self, base_url, directory, results_queue):
        """Check if a directory exists and returns 200 OK"""
        try:
            url = urljoin(base_url, directory)
            
            try:
                # Use HEAD request first (faster), fallback to GET if needed
                response = self.session.head(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=False,
                    verify=False  # Skip SSL verification for testing
                )
                
                # Only collect directories with 200 OK status
                if response.status_code == 200:
                    # For HEAD requests, size might be in Content-Length header
                    size = int(response.headers.get('Content-Length', 0))
                    
                    with self.lock:
                        # Avoid duplicates
                        if not any(d['url'] == url for d in self.found_directories):
                            dir_info = {
                                'path': directory,
                                'url': url,
                                'status_code': 200,
                                'size': size,
                                'content_type': response.headers.get('Content-Type', 'Unknown')
                            }
                            self.found_directories.append(dir_info)
                            print(f"[+] Found: {url} [{response.status_code}] (Size: {size} bytes)")
                    
            except requests.exceptions.RequestException:
                pass  # Silently ignore connection errors
                
        except Exception as e:
            pass  # Silently ignore other errors
    
    def scan_directories(self, url, max_threads=30):
        """Scan for hidden directories using multiple threads (dirsearch-style)"""
        print(f"\n[*] Starting directory brute-force scan on {url}")
        
        # Respect user's protocol choice - only auto-detect if no protocol provided
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first (modern websites), fallback to HTTP
            try:
                test_url = f"https://{url}"
                response = requests.head(test_url, timeout=3, verify=False, allow_redirects=True)
                url = test_url
                print(f"[*] Auto-detected: Using HTTPS")
            except:
                url = f"http://{url}"
                print(f"[*] Auto-detected: HTTPS failed, using HTTP")
        else:
            # User explicitly provided protocol - use it
            protocol = url.split('://')[0].upper()
            print(f"[*] Using {protocol} as specified by user")
        
        # Parse URL to get base and path
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        
        # Determine if we should scan subdirectories based on URL path
        scan_paths = [base_url]  # Always scan root
        
        # If URL has a path, also scan that directory
        if parsed.path and parsed.path != '/':
            # Extract directory from path (remove filename if present)
            path_parts = parsed.path.rstrip('/').split('/')
            
            # Add intermediate paths
            for i in range(1, len(path_parts) + 1):
                intermediate_path = '/'.join(path_parts[:i])
                if intermediate_path:
                    scan_url = f"{parsed.scheme}://{parsed.netloc}/{intermediate_path}/"
                    if scan_url not in scan_paths:
                        scan_paths.append(scan_url)
        
        print(f"[*] Base URLs to scan: {len(scan_paths)}")
        for sp in scan_paths:
            print(f"    - {sp}")
        
        # File extensions to test
        extensions = [
            '', '/', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', 
            '.js', '.txt', '.xml', '.json', '.bak', '.old', '.backup',
            '.conf', '.config', '.inc', '.log', '.sql', '.zip', '.tar.gz'
        ]
        
        # Build comprehensive test list (directories + extensions)
        test_paths = []
        for scan_base in scan_paths:
            for directory in self.directories:
                # Add base directory
                test_paths.append((scan_base, directory))
                
                # Add with common extensions (only for certain paths)
                if not any(directory.endswith(ext) for ext in ['.php', '.html', '.xml', '.txt', '.json', '.log']):
                    for ext in ['.php', '.html', '.asp', '.jsp', '.txt']:
                        if not directory.endswith('/'):
                            test_paths.append((scan_base, f"{directory}{ext}"))
        
        print(f"[*] Wordlist size: {len(test_paths)} total paths (base + extensions across all scan paths)")
        print(f"[*] Threads: {max_threads}")
        print(f"[*] Timeout: {self.timeout}s")
        print(f"[*] Status: Scanning for 200 OK responses only")
        
        # Reset found directories
        self.found_directories = []
        
        # Create queue and threads
        queue = Queue()
        results_queue = Queue()
        
        # Add paths to queue
        for scan_base, path in test_paths:
            queue.put((scan_base, path))
        
        # Create worker threads
        def worker():
            while not queue.empty():
                try:
                    scan_base, directory = queue.get_nowait()
                    self.check_directory(scan_base, directory, results_queue)
                    queue.task_done()
                except:
                    break
        
        # Start threads
        threads = []
        for _ in range(min(max_threads, len(test_paths))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for completion
        queue.join()
        
        # Wait for all threads to finish
        for t in threads:
            t.join(timeout=1)
        
        print(f"\n[*] Scan completed!")
        print(f"[*] Directories found: {len(self.found_directories)}")
        
        # Sort results by URL
        self.found_directories.sort(key=lambda x: x['url'])
        
        return self.found_directories
    
    def scan_for_api(self, url):
        """Simplified scan method for API usage with Katana-style crawling"""
        print(f"\n[*] Starting comprehensive endpoint discovery...")
        print(f"[*] Phase 1: Katana-style intelligent crawl")
        
        # Phase 1: Katana-style intelligent crawl
        katana_endpoints = self.katana_crawl(url)
        
        # Phase 2: Traditional directory brute-force
        print(f"\n[*] Phase 2: Directory brute-force scan")
        directories = self.scan_directories(url)
        
        # Combine results and remove duplicates
        all_endpoints = set()
        for endpoint in katana_endpoints:
            all_endpoints.add(endpoint)
        for dir_info in directories:
            all_endpoints.add(dir_info['url'])
        
        # Convert Katana endpoints to directory format
        for endpoint in katana_endpoints:
            if not any(d['url'] == endpoint for d in directories):
                parsed = urlparse(endpoint)
                directories.append({
                    'path': parsed.path or '/',
                    'url': endpoint,
                    'status_code': 200,
                    'size': 0,
                    'content_type': 'discovered',
                    'source': 'katana'
                })
        
        print(f"\n[*] Total unique endpoints discovered: {len(all_endpoints)}")
        
        # Create summary report
        report = {
            'total_directories': len(directories),
            'directories': directories,
            'katana_discovered': len(katana_endpoints),
            'categories': {
                'admin': [],
                'config': [],
                'backup': [],
                'api': [],
                'content': [],
                'other': []
            }
        }
        
        # Categorize directories
        for dir_info in directories:
            path = dir_info['path'].lower()
            categorized = False
            
            if any(keyword in path for keyword in ['admin', 'dashboard', 'panel', 'control', 'login']):
                report['categories']['admin'].append(dir_info)
                categorized = True
            elif any(keyword in path for keyword in ['config', 'setup', 'settings', '.env', '.git']):
                report['categories']['config'].append(dir_info)
                categorized = True
            elif any(keyword in path for keyword in ['backup', 'old', 'tmp', 'temp']):
                report['categories']['backup'].append(dir_info)
                categorized = True
            elif any(keyword in path for keyword in ['api', 'rest', 'graphql', 'v1', 'v2']):
                report['categories']['api'].append(dir_info)
                categorized = True
            elif any(keyword in path for keyword in ['upload', 'content', 'media', 'files', 'images']):
                report['categories']['content'].append(dir_info)
                categorized = True
            
            if not categorized:
                report['categories']['other'].append(dir_info)
        
        return report


# Test function
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    scanner = DirectoryScanner()
    
    print("=" * 80)
    print("DIRECTORY SCANNER - Inspired by dirsearch")
    print("=" * 80)
    
    result = scanner.scan_for_api("testphp.vulnweb.com")
    
    print(f"\n{'='*80}")
    print("SCAN RESULTS")
    print(f"{'='*80}")
    print(f"Total directories found: {result['total_directories']}")
    
    if result['total_directories'] > 0:
        print(f"\n{'='*80}")
        print("CATEGORIZED RESULTS")
        print(f"{'='*80}")
        
        for category, dirs in result['categories'].items():
            if dirs:
                print(f"\n[{category.upper()}] ({len(dirs)} found):")
                for d in dirs:
                    print(f"  [200] {d['url']:<60} ({d['size']} bytes)")
    else:
        print("\n[*] No accessible directories found with 200 OK status")
