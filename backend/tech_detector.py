"""
Technology Detector Module
Detects web technologies including frontend frameworks, backend systems, and servers
"""
import re
import requests
from bs4 import BeautifulSoup


def detect_technologies(url):
    """Detect technologies used by the website"""
    try:
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            test_url = f'https://{url}'
        else:
            test_url = url
        
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(test_url, headers=headers, timeout=10, verify=False)
        html = r.text.lower()
        soup = BeautifulSoup(r.text, "html.parser")

        tech = {
            "Frontend": [],
            "CSS Framework": [],
            "JS Framework": [],
            "Backend": [],
            "Server": []
        }

        # Frontend detection
        if "<html" in html:
            tech["Frontend"].append("HTML")
        if "html5" in html or '<!doctype html>' in html:
            tech["Frontend"].append("HTML5")
        if "<script" in html:
            tech["Frontend"].append("JavaScript")
        if "<style" in html or "css" in html:
            tech["Frontend"].append("CSS")

        # CSS Frameworks
        if "bootstrap" in html:
            match = re.search(r'bootstrap[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["CSS Framework"].append(f"Bootstrap {version}")
        
        if "tailwind" in html:
            match = re.search(r'tailwind[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["CSS Framework"].append(f"Tailwind CSS {version}")

        # JS Frameworks
        if "react" in html or "__react" in html:
            match = re.search(r'react[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"React {version}")
        
        if "angular" in html or "ng-app" in html:
            match = re.search(r'angular[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Angular {version}")
        
        if "vue" in html or "__vue" in html:
            match = re.search(r'vue[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Vue.js {version}")
        
        if "_next" in html:
            match = re.search(r'next[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"Next.js {version}")
        
        if "jquery" in html:
            match = re.search(r'jquery[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["JS Framework"].append(f"jQuery {version}")

        # Backend detection
        headers_lower = str(r.headers).lower()
        
        if "django" in headers_lower or "csrftoken" in headers_lower:
            match = re.search(r'django[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"Django {version}")
        
        if "flask" in headers_lower or "werkzeug" in headers_lower:
            match = re.search(r'flask[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"Flask {version}")
        
        if "express" in headers_lower or "node" in headers_lower:
            tech["Backend"].append("Node.js / Express")
        
        if "php" in headers_lower or ".php" in html:
            match = re.search(r'php[/@\-]?(\d+\.\d+\.?\d*)', headers_lower)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"PHP {version}")
        
        if "wp-content" in html or "wordpress" in html:
            match = re.search(r'wordpress[/@\-]?(\d+\.\d+\.?\d*)', html)
            version = match.group(1) if match else "Unknown"
            tech["Backend"].append(f"WordPress {version}")
        
        if "laravel" in headers_lower or "laravel_session" in headers_lower:
            tech["Backend"].append("Laravel")
        
        if "asp.net" in headers_lower or "__viewstate" in html:
            tech["Backend"].append("ASP.NET")

        # Server detection
        if "server" in r.headers:
            server_header = r.headers["Server"]
            match = re.search(r'(nginx|apache|iis|cloudflare)[/\s]?(\d+\.\d+\.?\d*)?', server_header, re.IGNORECASE)
            if match:
                server_name = match.group(1).title()
                version = match.group(2) if match.group(2) else ""
                tech["Server"].append(f"{server_name} {version}".strip())
            else:
                tech["Server"].append(server_header)
        
        if "x-powered-by" in r.headers:
            tech["Server"].append(f"Powered by {r.headers['X-Powered-By']}")

        # Generator meta tag
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            tech["Backend"].append(f"Generator: {generator.get('content')}")

        # Remove duplicates and empty entries
        for key in tech:
            tech[key] = list(set([t for t in tech[key] if t]))
            if not tech[key]:
                tech[key] = ["Not detected"]

        return tech
    
    except Exception as e:
        print(f"Tech detection error: {str(e)}")
        return {
            "Frontend": ["Detection failed"],
            "CSS Framework": ["Detection failed"],
            "JS Framework": ["Detection failed"],
            "Backend": ["Detection failed"],
            "Server": ["Detection failed"]
        }
