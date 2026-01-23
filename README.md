# WebReconX
![License](https://img.shields.io/github/license/eshwargit2/WebReconX_Tool)  <br>
A comprehensive web security analysis tool that performs automated reconnaissance and vulnerability scanning on websites. WebReconX provides real-time insights into web technologies, security configurations, and potential vulnerabilities with AI-powered security recommendations and selective test execution for optimized scanning.

## 🚀 Features

- **AI-Powered Security Analysis**: Uses Google Gemini AI to generate contextual security recommendations based on detected vulnerabilities, open ports with versions, and technology stack
- **Selective Test Execution**: Interactive modal allows you to choose which security tests to run (XSS, SQL Injection, Port Scanning, WAF Detection, Technology Detection, WHOIS Lookup, AI Analysis)
- **SQL Injection Scanning**: Advanced testing with 13 optimized payloads detecting Error-based, Boolean-based, Union-based, and Time-based SQL injection vulnerabilities
- **XSS Vulnerability Scanning**: Tests for Cross-Site Scripting vulnerabilities using optimized payloads across forms and URL parameters
- **Technology Detection**: Automatically identifies frontend frameworks (React, Angular, Vue), backend technologies (Django, Node.js, WordPress), CSS frameworks, and server software with version detection
- **Web Application Firewall (WAF) Detection**: Detects 15+ WAF types including AWS WAF, Cloudflare, Akamai, Imperva, and more with confidence levels
- **Port Scanning**: Multi-threaded scanning of common ports (21, 22, 80, 443, 3306, etc.) with service version detection
- **WHOIS Lookup**: Retrieves domain registration information including registrar, creation date, expiration date, and nameservers
- **Smart Loading Animation**: Dynamic progress indicator showing only the selected tests being executed, including AI analysis progress
- **Real-time Progress Tracking**: Live updates showing which security operation is currently executing
- **Comprehensive Dashboard**: Visual representation of scan results with color-coded risk indicators and conditional rendering based on selected tests

## 🛠️ Tech Stack

### Backend
- **Python 3.x** with Flask 3.1.0
- **Flask-CORS** 6.0.2 for cross-origin requests
- **Requests** 2.31.0 for HTTP operations
- **BeautifulSoup4** 4.12.3 for HTML parsing
- **wafw00f** for WAF detection
- **python-whois** for domain registration lookups 
- **python-dotenv** for environment variable management
- **Google Generative AI (Gemini)** for AI-powered security analysis
- **Modular Architecture**: Separate modules for port scanning, WAF detection, technology detection, XSS scanning, SQL injection scanning, WHOIS lookup, and AI analysis

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
- Google Gemini API key (for AI-powered analysis)

## 🔧 Installation

### Backend Setup

1. Navigate to the backend directory:
```bash
cd Backend
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install wafw00f:
```bash
pip install wafw00f
```

4. Create a `.env` file in the Backend directory with your API keys:
```env
# Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Server Configuration
FLASK_ENV=development
FLASK_DEBUG=True
PORT=5000
BACKEND_URL=http://localhost:5000
```

5. Start the Flask server:
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

2. **Enter a target website URL** in the search field:
   - **For XSS testing**: Enter just the domain (e.g., `testphp.vulnweb.com`)
   - **For SQL Injection testing**: Enter the COMPLETE URL with parameters
     - ✅ Correct: `http://testphp.vulnweb.com/listproducts.php?cat=1`
     - ❌ Wrong: `testphp.vulnweb.com` (will not detect SQLi - no parameters!)

3. Click the **"Analyze Security"** button

4. **Select Your Tests**: A modal will appear allowing you to choose which security tests to run:
   - ✅ **Port Scanning** - Scan for open ports and services
   - ✅ **WAF Detection** - Check for Web Application Firewall
   - ✅ **Technology Detection** - Identify web technologies and frameworks
   - ✅ **XSS Vulnerability Test** - Test for Cross-Site Scripting attacks
   - ✅ **SQL Injection Test** - Test for SQL injection vulnerabilities (REQUIRES URL with parameters!)
   - ✅ **WHOIS Lookup** - Get domain registration information
   - ✅ **AI Analysis** - Generate AI-powered security recommendations (requires Gemini API key)
   
   Simply click on any test to toggle it on/off. The scan will only execute the selected tests.

5. Click **"Start Scan"** to begin the analysis

6. Watch real-time progress as WebReconX performs only your selected tests:
   - Hostname resolution
   - Port scanning (if selected)
   - WAF detection (if selected)
   - Technology stack identification (if selected)
   - XSS vulnerability testing (if selected)
   - SQL injection testing (if selected) - scans URL parameters for vulnerabilities
   - WHOIS lookup (if selected)
   - AI-powered analysis (if selected - runs after all scans complete)

7. View comprehensive results in the dashboard:
   - Website overview (IP, hostname, open ports if scanned)
   - WAF protection status (if scanned)
   - Detected technologies by category (if scanned)
   - XSS vulnerability status with attack details (if scanned)
   - SQL injection vulnerability status with detailed payload evidence (if scanned)
   - WHOIS information (if scanned)
   - AI-generated risk assessment and recommendations (if AI analysis selected)

## 🔌 API Endpoints

### POST /api/analyze

Performs comprehensive security analysis on a target URL with optional selective test execution.

**Request Body:**
```json
{
  "url": "https://example.com",
  "tests": {
    "xss": true,
    "sqli": true,
    "ports": true,
    "waf": true,
    "tech": true,
    "whois": true,
    "ai_analysis": true
  }
}
```

**Note**: The `tests` parameter is optional. If not provided, all tests will be executed by default.

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
  "xss_scan": {
    "vulnerable": true,
    "total_vulnerabilities": 3,
    "vulnerabilities": [...]
  },
  "sqli_scan": {
    "vulnerable": true,
    "total_vulnerabilities": 2,
    "vulnerabilities": [...]
  },
  "whois": {
    "domain_name": "example.com",
    "registrar": "Example Registrar Inc.",
    "creation_date": "1995-08-14",
    "expiration_date": "2026-08-13",
    "nameservers": ["ns1.example.com", "ns2.example.com"]
  },
  "ai_analysis": {
    "risk_level": "HIGH",
    "vulnerabilities": [...],
    "recommendations": [...]
  }
}
```

### POST /api/scan-sqli

Performs SQL injection vulnerability scan on a target URL.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "sqli_scan": {
    "url": "https://example.com",
    "vulnerable": true,
    "total_vulnerabilities": 2,
    "vulnerabilities": [
      {
        "url": "https://example.com?id='",
        "method": "GET",
        "parameter": "id",
        "payload": "'",
        "evidence": "SQL syntax error detected"
      }
    ],
    "scan_time": "2.34s"
  }
}
```

## 📁 Project Structure

```
.
├── Backend/
│   ├── server.py              # Main Flask application & API routes
│   ├── portscanner.py         # Port scanning module with multi-threading
│   ├── waf_detector.py        # WAF detection using wafw00f
│   ├── tech_detector.py       # Technology fingerprinting module
│   ├── xss_scanner.py         # XSS vulnerability scanner
│   ├── sqli_scanner.py        # SQL injection vulnerability scanner
│   ├── whois_lookup.py        # WHOIS domain information retrieval
│   ├── ai_analyzer.py         # AI-powered security analysis using Gemini
│   ├── requirements.txt       # Python dependencies
│   └── .env                   # Environment variables (API keys)
│
├── Frontend/
│   ├── src/
│   │   ├── App.jsx           # Main application component
│   │   ├── components/
│   │   │   ├── Dashboard.jsx              # Main dashboard layout
│   │   │   ├── Header.jsx                 # Navigation header
│   │   │   ├── SearchSection.jsx          # URL input and analyze button
│   │   │   ├── LoadingSection.jsx         # Dynamic progress display
│   │   │   ├── ScanOptionsModal.jsx       # Test selection modal
│   │   │   ├── WebsiteOverview.jsx        # Basic site info display
│   │   │   ├── WhoisInfo.jsx              # WHOIS information display
│   │   │   ├── TechnologyStack.jsx        # Detected technologies
│   │   │   ├── RiskAssessment.jsx         # Security risk summary
│   │   │   ├── IssuesRecommendations.jsx  # Security recommendations
│   │   │   ├── XSSVulnerability.jsx       # XSS scan results
│   │   │   └── SQLInjection.jsx           # SQL injection scan results
│   │   └── services/
│   │       └── api.js                     # API client
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
- Optimized injection payloads
- Form-based testing
- URL parameter testing
- GET and POST method support
- Timeout protection (3s per request)
- Smart payload limiting for performance

### SQL Injection Scanning
Tests for SQL injection vulnerabilities using:
- 5 basic SQL injection payloads targeting common vulnerabilities
- GET and POST method support
- Parameter-based testing
- Form input testing
- Error-based detection
- Optimized for speed and accuracy

## ⚠️ Performance Optimizations

- **Selective Test Execution**: Run only the security tests you need, saving time and resources
- **Smart Loading Animation**: Shows progress only for selected tests, including AI analysis phase
- **Optimized SQL Injection Payloads**: Reduced to 5 most effective payloads for faster scanning
- **Multi-threaded Port Scanning**: Parallel execution for faster results
- **Request Timeouts**: 3s per request to prevent hangs; 180s for AI analysis
- **Conditional Rendering**: Frontend displays only the results of executed tests
- **Modular Backend**: Tests are skipped entirely when not selected, reducing server load
- **AI Analysis on Demand**: AI recommendations only generated when enabled, runs after all scans complete
- **Increased Timeout Handling**: Frontend timeout increased to 300s to accommodate AI analysis
- **Efficient Token Management**: AI prompt optimized to stay within token limits while providing comprehensive analysis

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
- SQL injection tests use basic payloads and may not detect advanced protection mechanisms

## 🏗️ Architecture

WebReconX follows a modular architecture for better maintainability and scalability:

### Backend Modules

1. **server.py**: Main Flask application orchestrating all security operations with selective test execution
2. **portscanner.py**: Multi-threaded port scanning with banner grabbing
3. **waf_detector.py**: WAF detection using wafw00f with deep analysis
4. **tech_detector.py**: Technology stack fingerprinting
5. **xss_scanner.py**: XSS vulnerability testing with optimized payloads
6. **sqli_scanner.py**: SQL injection vulnerability testing with 5 basic payloads
7. **whois_lookup.py**: Domain registration information retrieval
8. **ai_analyzer.py**: AI-powered security analysis using Google Gemini - generates contextual recommendations based on actual scan results (open ports with versions, detected technologies, XSS/SQLi findings, WAF status)

Each module is self-contained and can be tested independently, making the codebase easier to maintain and extend.

### AI Analysis Features

The AI analyzer uses Google Gemini to provide:
- **Context-aware recommendations**: Based on specific vulnerabilities found, not generic advice
- **Version-specific guidance**: Considers detected software versions when suggesting fixes
- **Prioritized action items**: Focuses on the most critical issues first
- **Technology-specific advice**: Tailored to the detected tech stack (React, Node.js, etc.)
- **Attack scenario analysis**: Explains potential attack vectors based on findings
- **Smart timeout handling**: 180-second timeout with fallback to rule-based analysis if AI is unavailable

## 🚧 Future Enhancements

- ~~SQL injection vulnerability testing~~ ✅ **Completed**
- ~~AI-powered security recommendations~~ ✅ **Completed**
- ~~WHOIS domain information lookup~~ ✅ **Completed**
- Advanced SQL injection techniques (Union-based, Time-based, Boolean-based)
- SSL/TLS configuration analysis
- CORS misconfiguration detection
- Subdomain enumeration
- DNS record analysis
- Report export (PDF/JSON)
- Historical scan comparison
- Scheduled automated scans
- API rate limiting and authentication
- Enhanced AI analysis with custom security policies
- Multi-language support for AI recommendations

## 📝 License

This project is intended for educational purposes. Please use responsibly.

## 👥 Contributing

Contributions are welcome! Please ensure any security-related features follow ethical hacking guidelines.

## 📧 Support

For issues, questions, or suggestions, please create an issue in the project repository.

---

**Built with ❤️ for cybersecurity enthusiasts and developers**
