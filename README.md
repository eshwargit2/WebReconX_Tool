# WebReconX
![License](https://img.shields.io/github/license/eshwargit2/WebReconX_Tool) <br>
A comprehensive web security analysis tool that performs automated reconnaissance and vulnerability scanning on websites. WebReconX provides real-time insights into web technologies, security configurations, and potential vulnerabilities.

## 🚀 Features

- **Technology Detection**: Automatically identifies frontend frameworks (React, Angular, Vue), backend technologies (Django, Node.js, WordPress), CSS frameworks, and server software with version detection
- **Web Application Firewall (WAF) Detection**: Detects 15+ WAF types including AWS WAF, Cloudflare, Akamai, Imperva, and more with confidence levels
- **Port Scanning**: Multi-threaded scanning of common ports (21, 22, 80, 443, 3306, etc.) with service version detection
- **XSS Vulnerability Scanning**: Tests for Cross-Site Scripting vulnerabilities using 10 optimized payloads across forms and URL parameters
- **Real-time Progress Tracking**: Live updates showing which security operation is currently executing
- **Comprehensive Dashboard**: Visual representation of scan results with color-coded risk indicators

## 🛠️ Tech Stack

### Backend
- **Python 3.x** with Flask 3.1.0
- **Flask-CORS** 6.0.2 for cross-origin requests
- **Requests** 2.31.0 for HTTP operations
- **BeautifulSoup4** 4.12.3 for HTML parsing
- **wafw00f** for WAF detection
- **Modular Architecture**: Separate modules for port scanning, WAF detection, technology detection, and XSS scanning

### Frontend
- **React 18** with Vite build tool
- **Tailwind CSS** for styling
- **Lucide React** for icons
- Modern component-based architecture

## 📋 Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher
- npm or pnpm package manager
- wafw00f (for WAF detection)

## 🔧 Installation

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install wafw00f:
```bash
pip install wafw00f
```

4. Start the Flask server:
```bash
python server.py
```

The backend server will start on `http://localhost:5000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd Frontend
```

2. Install dependencies:
```bash
npm install
# or
pnpm install
```

3. Start the development server:
```bash
npm run dev
# or
pnpm dev
```

The frontend will start on `http://localhost:5173` (or another available port)

## 💻 Usage

1. Open your browser and navigate to the frontend URL (default: `http://localhost:5173`)

2. Enter a target website URL in the search field (e.g., `https://example.com`)

3. Click the **"Analyze Security"** button

4. Watch real-time progress as WebReconX performs:
   - Hostname resolution
   - Port scanning
   - WAF detection
   - Technology stack identification
   - XSS vulnerability testing

5. View comprehensive results in the dashboard:
   - Website overview (IP, hostname, open ports)
   - WAF protection status
   - Detected technologies by category
   - XSS vulnerability status with attack details
   - Risk assessment and recommendations

## 🔌 API Endpoints

### POST /api/analyze

Performs comprehensive security analysis on a target URL.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "ip_address": "93.184.216.34",
  "hostname": "example.com",
  "open_ports": [
    {
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0"
    }
  ],
  "waf_detected": {
    "detected": true,
    "name": "Cloudflare",
    "full_name": "Cloudflare Web Application Firewall",
    "version": "Unknown",
    "method": "header_analysis",
    "confidence": 90
  },
  "technologies": [
    {
      "name": "React",
      "version": "18.2.0",
      "category": "Frontend Framework"
    }
  ],
  "xss_vulnerable": true,
  "xss_details": {
    "total_tests": 45,
    "vulnerable_params": ["search", "q"],
    "vulnerable_forms": 2,
    "successful_payloads": 3
  }
}
```

## 📁 Project Structure

```
.
├── backend/
│   ├── server.py              # Main Flask application & API routes
│   ├── portscanner.py         # Port scanning module with multi-threading
│   ├── waf_detector.py        # WAF detection using wafw00f
│   ├── tech_detector.py       # Technology fingerprinting module
│   ├── xss_scanner.py         # XSS vulnerability scanner
│   └── requirements.txt       # Python dependencies
│
├── site-guardian-ai-ui/
│   ├── src/
│   │   ├── App.jsx           # Main application component
│   │   ├── components/
│   │   │   ├── Dashboard.jsx           # Main dashboard layout
│   │   │   ├── Header.jsx              # Navigation header
│   │   │   ├── SearchSection.jsx       # URL input and analyze button
│   │   │   ├── LoadingSection.jsx      # Real-time progress display
│   │   │   ├── WebsiteOverview.jsx     # Basic site info display
│   │   │   ├── TechnologyStack.jsx     # Detected technologies
│   │   │   ├── RiskAssessment.jsx      # Security risk summary
│   │   │   ├── IssuesRecommendations.jsx
│   │   │   └── XSSVulnerability.jsx    # XSS scan results
│   │   └── services/
│   │       └── api.js                  # API client
│   ├── package.json
│   └── vite.config.js
│
└── README.md
```

## 🔒 Security Features

### Technology Detection
Identifies 15+ frameworks and technologies including:
- Frontend: React, Angular, Vue.js, Svelte
- Backend: Django, Flask, Laravel, WordPress, Node.js
- CSS Frameworks: Bootstrap, Tailwind CSS, Foundation
- Servers: Nginx, Apache, IIS, Cloudflare

### WAF Detection
Detects major Web Application Firewalls:
- AWS WAF
- Cloudflare
- Akamai Kona Site Defender
- Imperva SecureSphere
- F5 BIG-IP ASM
- ModSecurity
- And 10+ more

### XSS Scanning
Tests for XSS vulnerabilities using:
- 10 optimized injection payloads
- Form-based testing
- URL parameter testing
- GET and POST method support
- Timeout protection (3s per request)
- Smart payload limiting for performance

## ⚠️ Performance Optimizations

- **Multi-threaded port scanning** for faster results
- **Request timeouts** (3s per request) to prevent hangs
- **Payload limiting** (max 5 per parameter) for efficiency
- **Form limiting** (max 3 forms with 5 inputs each)
- **Total timeout** of 60 seconds for comprehensive scans

## 🎯 Use Cases

- Security auditing and reconnaissance
- Identifying outdated or vulnerable technology stacks
- Detecting security misconfigurations
- Compliance checking (WAF requirements)
- Pre-deployment security validation
- Educational purposes and penetration testing practice

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is designed for ethical security testing and educational purposes only. Users must:

- Only scan websites they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Not use this tool for malicious purposes or unauthorized access
- Understand that unauthorized scanning may be illegal in many jurisdictions

The developers assume no liability for misuse of this software.

## 🐛 Known Issues

- XSS scanner may timeout on extremely large or slow websites
- WAF detection confidence varies based on response patterns
- Some technologies may not be detected if heavily obfuscated

## 🏗️ Architecture

WebReconX follows a modular architecture for better maintainability and scalability:

### Backend Modules

1. **server.py**: Main Flask application orchestrating all security operations
2. **portscanner.py**: Multi-threaded port scanning with banner grabbing
3. **waf_detector.py**: WAF detection using wafw00f with deep analysis
4. **tech_detector.py**: Technology stack fingerprinting
5. **xss_scanner.py**: XSS vulnerability testing with optimized payloads

Each module is self-contained and can be tested independently, making the codebase easier to maintain and extend.

## 🚧 Future Enhancements

- SQL injection vulnerability testing
- SSL/TLS configuration analysis
- CORS misconfiguration detection
- Subdomain enumeration
- DNS record analysis
- Report export (PDF/JSON)
- Historical scan comparison
- Scheduled automated scans

## 📝 License

This project is intended for educational purposes. Please use responsibly.

## 👥 Contributing

Contributions are welcome! Please ensure any security-related features follow ethical hacking guidelines.

## 📧 Support

For issues, questions, or suggestions, please create an issue in the project repository.

---

**Built with ❤️ for cybersecurity enthusiasts and developers**
