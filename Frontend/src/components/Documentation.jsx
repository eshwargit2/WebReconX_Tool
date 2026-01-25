import React, { useState } from 'react';
import { Book, ChevronDown, ChevronRight, AlertTriangle, CheckCircle, Shield, Search, Database, Globe, FolderOpen, Info } from 'lucide-react';

const Documentation = () => {
  const [expandedSections, setExpandedSections] = useState({});

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <Book className="w-10 h-10 text-cyan-400" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Documentation
            </h1>
          </div>
          <p className="text-slate-400 text-lg">
            Complete guide to using WebReconX - Web Security Analysis Tool
          </p>
        </div>

        {/* Quick Start */}
        <Section 
          title="Quick Start Guide" 
          icon={<Info className="w-5 h-5" />}
          expanded={expandedSections['quickstart']}
          onToggle={() => toggleSection('quickstart')}
        >
          <div className="space-y-4">
            <h3 className="text-xl font-semibold text-cyan-400">Getting Started</h3>
            <ol className="space-y-3 list-decimal list-inside text-slate-300">
              <li>Enter a website URL in the search box</li>
              <li>Click "Scan Options" to select tests to run</li>
              <li>Click "Start Scan" to begin analysis</li>
              <li>Review results in different sections</li>
            </ol>
            
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 mt-4">
              <h4 className="font-semibold text-blue-400 mb-2">💡 Pro Tip</h4>
              <p className="text-slate-300">
                For SQL Injection testing, always include the full URL with parameters:<br/>
                <code className="text-cyan-400">http://testphp.vulnweb.com/listproducts.php?cat=1</code>
              </p>
            </div>
          </div>
        </Section>

        {/* Features Overview */}
        <Section 
          title="Features & Capabilities" 
          icon={<Shield className="w-5 h-5" />}
          expanded={expandedSections['features']}
          onToggle={() => toggleSection('features')}
        >
          <div className="space-y-6">
            <FeatureCard
              icon={<Search className="w-6 h-6 text-yellow-400" />}
              title="XSS Detection"
              description="Tests for Cross-Site Scripting vulnerabilities in forms and URL parameters"
              details={[
                "Reflected XSS detection",
                "Stored XSS detection",
                "DOM-based XSS analysis",
                "Multiple payload variations"
              ]}
            />
            
            <FeatureCard
              icon={<Database className="w-6 h-6 text-red-400" />}
              title="SQL Injection Scanner"
              description="Detects SQL injection vulnerabilities with multiple techniques"
              details={[
                "Error-based SQL injection",
                "Time-based blind SQLi",
                "Boolean-based blind SQLi",
                "13+ different test payloads"
              ]}
            />
            
            <FeatureCard
              icon={<FolderOpen className="w-6 h-6 text-orange-400" />}
              title="Directory Enumeration"
              description="Intelligent endpoint discovery using multiple techniques"
              details={[
                "robots.txt parsing",
                "sitemap.xml crawling",
                "Intelligent web crawling",
                "JavaScript endpoint extraction",
                "200+ common path testing",
                "API endpoint detection"
              ]}
            />
            
            <FeatureCard
              icon={<Globe className="w-6 h-6 text-blue-400" />}
              title="Port Scanning"
              description="Scans common ports to identify open services"
              details={[
                "80 ports tested",
                "Service identification",
                "Risk assessment per port",
                "Common vulnerabilities highlighted"
              ]}
            />
            
            <FeatureCard
              icon={<Shield className="w-6 h-6 text-green-400" />}
              title="WAF Detection"
              description="Identifies Web Application Firewalls and security measures"
              details={[
                "Detects 30+ WAF types",
                "Cloudflare, AWS, Akamai, etc.",
                "Security header analysis",
                "Protection level assessment"
              ]}
            />
            
            <FeatureCard
              icon={<Info className="w-6 h-6 text-purple-400" />}
              title="Technology Detection"
              description="Identifies technologies and frameworks used"
              details={[
                "Server detection",
                "Framework identification",
                "CMS detection",
                "Programming language analysis"
              ]}
            />
            
            <FeatureCard
              icon={<Globe className="w-6 h-6 text-indigo-400" />}
              title="WHOIS Lookup"
              description="Domain registration and ownership information"
              details={[
                "Domain registrar",
                "Registration dates",
                "Nameservers",
                "Contact information"
              ]}
            />
          </div>
        </Section>

        {/* Test Websites */}
        <Section 
          title="Recommended Test Websites" 
          icon={<Globe className="w-5 h-5" />}
          expanded={expandedSections['websites']}
          onToggle={() => toggleSection('websites')}
        >
          <div className="space-y-6">
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 mt-1" />
                <div>
                  <h4 className="font-semibold text-red-400 mb-2">Legal Notice</h4>
                  <p className="text-slate-300">
                    Only scan websites you own or have explicit permission to test. 
                    The websites listed below are intentionally vulnerable for educational purposes.
                  </p>
                </div>
              </div>
            </div>

            <TestWebsiteCard
              category="XSS Testing"
              icon={<Search className="w-5 h-5 text-yellow-400" />}
              websites={[
                {
                  url: "http://testphp.vulnweb.com",
                  description: "Reflected XSS vulnerabilities in search parameters",
                  verified: true
                },
                {
                  url: "http://testphp.vulnweb.com/comment.php",
                  description: "Comment form with XSS vulnerabilities",
                  verified: true
                },
                {
                  url: "https://xss-game.appspot.com",
                  description: "Google's XSS challenge game for practice",
                  verified: true
                }
              ]}
            />

            <TestWebsiteCard
              category="SQL Injection Testing"
              icon={<Database className="w-5 h-5 text-red-400" />}
              websites={[
                {
                  url: "http://testphp.vulnweb.com/listproducts.php?cat=1",
                  description: "SQL injection in category parameter (13+ vulnerabilities)",
                  verified: true,
                  important: "Must include full URL with parameters!"
                },
                {
                  url: "http://testphp.vulnweb.com/artists.php?artist=1",
                  description: "Integer-based SQL injection (12+ vulnerabilities)",
                  verified: true
                }
              ]}
            />

            <TestWebsiteCard
              category="Directory Enumeration Testing"
              icon={<FolderOpen className="w-5 h-5 text-orange-400" />}
              websites={[
                {
                  url: "http://testphp.vulnweb.com",
                  description: "Multiple exposed directories (/admin, /images, /css, /js)",
                  verified: true
                },
                {
                  url: "http://demo.testfire.net",
                  description: "Altoro Mutual demo site with accessible directories",
                  verified: true
                },
                {
                  url: "http://zero.webappsecurity.com",
                  description: "Zero Bank application with multiple directories",
                  verified: true
                }
              ]}
            />

            <TestWebsiteCard
              category="Secure Sites (For Comparison)"
              icon={<CheckCircle className="w-5 h-5 text-green-400" />}
              websites={[
                {
                  url: "https://google.com",
                  description: "Strong CSRF protection, security headers, WAF detection",
                  verified: true
                },
                {
                  url: "https://github.com",
                  description: "Modern security practices, strong protection",
                  verified: true
                }
              ]}
            />
          </div>
        </Section>

        {/* Usage Instructions */}
        <Section 
          title="How to Use" 
          icon={<Book className="w-5 h-5" />}
          expanded={expandedSections['usage']}
          onToggle={() => toggleSection('usage')}
        >
          <div className="space-y-6">
            <UsageCard
              title="1. XSS Vulnerability Testing"
              steps={[
                "Enter URL: testphp.vulnweb.com",
                "Select: ✓ XSS Vulnerability",
                "Click 'Start Scan'",
                "Review detected XSS vulnerabilities in results"
              ]}
            />

            <UsageCard
              title="2. SQL Injection Testing"
              steps={[
                "Enter COMPLETE URL: http://testphp.vulnweb.com/listproducts.php?cat=1",
                "Select: ✓ SQL Injection",
                "Click 'Start Scan'",
                "Should find 13+ SQL injection vulnerabilities"
              ]}
              important="⚠️ Must include full path and parameters!"
            />

            <UsageCard
              title="3. Directory Enumeration"
              steps={[
                "Enter domain: testphp.vulnweb.com",
                "Select: ✓ Directory Enumeration",
                "Click 'Start Scan'",
                "Scanner tests 200+ common paths",
                "Results show accessible directories with 200 OK status"
              ]}
            />

            <UsageCard
              title="4. Comprehensive Scan"
              steps={[
                "Enter website URL",
                "Select all desired tests",
                "Enable AI Analysis for intelligent insights",
                "Review all sections: Overview, Reconnaissance, Vulnerabilities"
              ]}
            />
          </div>
        </Section>

        {/* Troubleshooting */}
        <Section 
          title="Troubleshooting" 
          icon={<AlertTriangle className="w-5 h-5" />}
          expanded={expandedSections['troubleshooting']}
          onToggle={() => toggleSection('troubleshooting')}
        >
          <div className="space-y-4">
            <TroubleshootCard
              issue="Scan Timeout"
              solutions={[
                "Website may be slow or blocking scanning tools",
                "Try adding http:// or https:// prefix",
                "Check if website is online in browser first"
              ]}
            />

            <TroubleshootCard
              issue="SQLi Not Detected"
              solutions={[
                "Ensure you're using FULL URL with parameters",
                "Example: http://testphp.vulnweb.com/listproducts.php?cat=1",
                "NOT just: testphp.vulnweb.com",
                "Some pages may be protected - this is normal"
              ]}
            />

            <TroubleshootCard
              issue="Directory Scan Takes Too Long"
              solutions={[
                "Scanner tests 200+ paths - this is normal",
                "Uses 30 concurrent threads for speed",
                "HTTPS-only sites (like Netlify) scan faster",
                "Wait for completion - results will show progressively"
              ]}
            />

            <TroubleshootCard
              issue="No Results or Empty Response"
              solutions={[
                "Check backend server is running (port 5000)",
                "Verify internet connection",
                "Site may have WAF blocking requests",
                "Check browser console for errors"
              ]}
            />
          </div>
        </Section>

        {/* API & Integration */}
        <Section 
          title="Technical Details" 
          icon={<Info className="w-5 h-5" />}
          expanded={expandedSections['technical']}
          onToggle={() => toggleSection('technical')}
        >
          <div className="space-y-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
              <h4 className="font-semibold text-cyan-400 mb-3">Technology Stack</h4>
              <ul className="space-y-2 text-slate-300">
                <li><strong>Frontend:</strong> React + Vite</li>
                <li><strong>Backend:</strong> Python Flask</li>
                <li><strong>AI Analysis:</strong> Google Gemini API (gemini-2.5-flash)</li>
                <li><strong>Scanning Techniques:</strong> Multi-threaded (30+ threads)</li>
              </ul>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
              <h4 className="font-semibold text-cyan-400 mb-3">API Endpoints</h4>
              <ul className="space-y-2 text-slate-300 font-mono text-sm">
                <li><code className="text-green-400">POST</code> /api/analyze - Main scanning endpoint</li>
                <li><code className="text-blue-400">GET</code> /api/ip - Get IP address</li>
              </ul>
            </div>

            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
              <h4 className="font-semibold text-cyan-400 mb-3">Performance</h4>
              <ul className="space-y-2 text-slate-300">
                <li><strong>Port Scanning:</strong> 80 common ports in parallel</li>
                <li><strong>Directory Enumeration:</strong> 30 threads, 2s timeout per request</li>
                <li><strong>XSS Testing:</strong> Multiple payload variations</li>
                <li><strong>SQLi Testing:</strong> 13+ different injection techniques</li>
              </ul>
            </div>
          </div>
        </Section>

        {/* Footer */}
        <div className="mt-12 pt-6 border-t border-slate-700/50 text-center text-slate-500">
          <p>WebReconX v1.0.0 - Web Security Analysis Tool</p>
          <p className="text-sm mt-2">Last Updated: January 2026</p>
        </div>
      </div>
    </div>
  );
};

// Section Component
const Section = ({ title, icon, children, expanded, onToggle }) => {
  return (
    <div className="mb-6 bg-slate-800/50 border border-slate-700/50 rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 hover:bg-slate-700/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-cyan-400">{icon}</span>
          <h2 className="text-xl font-bold text-slate-100">{title}</h2>
        </div>
        {expanded ? (
          <ChevronDown className="w-5 h-5 text-slate-400" />
        ) : (
          <ChevronRight className="w-5 h-5 text-slate-400" />
        )}
      </button>
      {expanded && (
        <div className="p-6 border-t border-slate-700/50">
          {children}
        </div>
      )}
    </div>
  );
};

// Feature Card Component
const FeatureCard = ({ icon, title, description, details }) => {
  return (
    <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
      <div className="flex items-start gap-3">
        <div className="mt-1">{icon}</div>
        <div className="flex-1">
          <h4 className="font-semibold text-slate-100 mb-1">{title}</h4>
          <p className="text-slate-400 text-sm mb-3">{description}</p>
          <ul className="space-y-1 text-slate-300 text-sm">
            {details.map((detail, index) => (
              <li key={index} className="flex items-start gap-2">
                <span className="text-cyan-400 mt-1">•</span>
                <span>{detail}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

// Test Website Card Component
const TestWebsiteCard = ({ category, icon, websites }) => {
  return (
    <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
      <div className="flex items-center gap-2 mb-4">
        {icon}
        <h4 className="font-semibold text-slate-100">{category}</h4>
      </div>
      <div className="space-y-3">
        {websites.map((site, index) => (
          <div key={index} className="bg-slate-800/50 border border-slate-700/30 rounded p-3">
            <div className="flex items-start justify-between gap-2 mb-1">
              <code className="text-cyan-400 text-sm break-all">{site.url}</code>
              {site.verified && (
                <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded flex-shrink-0">
                  VERIFIED
                </span>
              )}
            </div>
            <p className="text-slate-400 text-sm">{site.description}</p>
            {site.important && (
              <p className="text-orange-400 text-sm mt-2 font-semibold">⚠️ {site.important}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

// Usage Card Component
const UsageCard = ({ title, steps, important }) => {
  return (
    <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
      <h4 className="font-semibold text-slate-100 mb-3">{title}</h4>
      <ol className="space-y-2 list-decimal list-inside text-slate-300">
        {steps.map((step, index) => (
          <li key={index} className="text-sm">{step}</li>
        ))}
      </ol>
      {important && (
        <div className="mt-3 bg-orange-500/10 border border-orange-500/30 rounded p-3">
          <p className="text-orange-400 text-sm font-semibold">{important}</p>
        </div>
      )}
    </div>
  );
};

// Troubleshoot Card Component
const TroubleshootCard = ({ issue, solutions }) => {
  return (
    <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-4">
      <h4 className="font-semibold text-red-400 mb-2">{issue}</h4>
      <ul className="space-y-2">
        {solutions.map((solution, index) => (
          <li key={index} className="flex items-start gap-2 text-slate-300 text-sm">
            <span className="text-cyan-400 mt-1">→</span>
            <span>{solution}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Documentation;
