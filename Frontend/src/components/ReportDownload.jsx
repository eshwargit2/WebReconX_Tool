import { useState } from "react"
import { FileDown, FileText, FileType } from "lucide-react"

export default function ReportDownload({ analysisData, selectedTests }) {
  const [downloading, setDownloading] = useState(false)
  const [pdfProgress, setPdfProgress] = useState('')

  const generateHTMLReport = () => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - ${analysisData.url || 'Unknown'}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f8fafc;
        }
        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        .header .url {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #0f172a;
            border-bottom: 3px solid #06b6d4;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .overview-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .overview-item {
            padding: 15px;
            background: #f1f5f9;
            border-radius: 8px;
            border-left: 4px solid #06b6d4;
        }
        .overview-item .label {
            font-size: 0.85em;
            color: #64748b;
            margin-bottom: 5px;
        }
        .overview-item .value {
            font-size: 1.1em;
            font-weight: 600;
            color: #1e293b;
        }
        .risk-box {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }
        .risk-critical { background: #fee2e2; border: 2px solid #ef4444; }
        .risk-high { background: #fed7aa; border: 2px solid #f97316; }
        .risk-medium { background: #fef3c7; border: 2px solid #eab308; }
        .risk-low { background: #d1fae5; border: 2px solid #10b981; }
        .risk-score {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .tech-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
        }
        .tech-item {
            padding: 12px;
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
        }
        .tech-name {
            font-weight: 600;
            color: #0f172a;
            margin-bottom: 5px;
        }
        .tech-version {
            font-size: 0.9em;
            color: #64748b;
        }
        .vulnerability {
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #ef4444;
            background: #fef2f2;
            border-radius: 4px;
        }
        .vulnerability-title {
            font-weight: 600;
            color: #991b1b;
            margin-bottom: 5px;
        }
        .safe {
            padding: 15px;
            background: #f0fdf4;
            border-left: 4px solid #10b981;
            border-radius: 4px;
            color: #166534;
        }
        .recommendation {
            padding: 15px;
            margin: 10px 0;
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #64748b;
            font-size: 0.9em;
            margin-top: 40px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f8fafc;
            font-weight: 600;
            color: #0f172a;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        code {
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }
        .page-break {
            page-break-after: always;
        }
        @media print {
            .section {
                page-break-inside: avoid;
            }
            body {
                background: white;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Analysis Report</h1>
        <div class="url">${analysisData.url || 'N/A'}</div>
        <p style="margin: 10px 0 0 0; opacity: 0.8;">Generated on ${analysisData.scan_date || new Date().toLocaleDateString()}</p>
    </div>

    <!-- Website Overview -->
    <div class="section">
        <h2>📊 Website Overview</h2>
        <div class="overview-grid">
            <div class="overview-item">
                <div class="label">Website URL</div>
                <div class="value">${analysisData.url || 'N/A'}</div>
            </div>
            <div class="overview-item">
                <div class="label">IP Address</div>
                <div class="value">${analysisData.ip_address || 'N/A'}</div>
            </div>
            <div class="overview-item">
                <div class="label">Hostname</div>
                <div class="value">${analysisData.hostname || analysisData.url || 'N/A'}</div>
            </div>
            <div class="overview-item">
                <div class="label">Organization</div>
                <div class="value">${analysisData.whois?.organization || analysisData.whois?.registrant_organization || analysisData.whois?.org || analysisData.whois?.registrant_org || analysisData.whois?.registrant || analysisData.whois?.admin_organization || analysisData.whois?.tech_organization || 'N/A'}</div>
            </div>
            <div class="overview-item">
                <div class="label">Country</div>
                <div class="value">${analysisData.whois?.country || analysisData.whois?.registrant_country || analysisData.whois?.admin_country || analysisData.whois?.tech_country || 'N/A'}</div>
            </div>
            ${selectedTests?.ports !== false ? `
            <div class="overview-item">
                <div class="label">Open Ports</div>
                <div class="value">${analysisData.total_open_ports || 0}</div>
            </div>
            ` : ''}
            ${selectedTests?.waf !== false ? `
            <div class="overview-item">
                <div class="label">WAF Protection</div>
                <div class="value">${analysisData.waf?.name || 'None detected'}</div>
            </div>
            ` : ''}
        </div>
    </div>

    ${generateRiskAssessmentHTML()}
    ${generateAIVulnerabilitiesHTML()}
    ${generateTechnologyStackHTML()}
    ${generateVulnerabilitiesHTML()}
    ${generateRecommendationsHTML()}
    ${generateDirectoryScanHTML()}
    ${generateWAFDetailsHTML()}
    ${generateWhoisHTML()}
    ${generatePortsHTML()}
    ${generateSecurityHeadersHTML()}

    <div class="footer">
        <p><strong>WebReconX  Security Scanner</strong></p>
        <p>Comprehensive security scan including ports, WAF, technologies, and XSS vulnerabilities , Security headers, and more.</p>
        <p>© ${new Date().getFullYear()} WebReconX. All rights reserved.</p>
    </div>
</body>
</html>`

    return html
  }

  const generateRiskAssessmentHTML = () => {
    const aiAnalysis = analysisData?.ai_analysis
    if (!aiAnalysis) return ''

    const riskScore = aiAnalysis?.risk_score || 0
    const riskLevel = aiAnalysis?.risk_level?.toLowerCase() || 'unknown'
    
    let riskClass = 'risk-low'
    if (riskLevel === 'critical' || riskScore >= 80) riskClass = 'risk-critical'
    else if (riskLevel === 'high' || riskScore >= 60) riskClass = 'risk-high'
    else if (riskLevel === 'medium' || riskScore >= 40) riskClass = 'risk-medium'

    return `
    <div class="section">
        <h2>⚠️ AI Risk Assessment</h2>
        <div class="risk-box ${riskClass}">
            <div style="font-size: 1.2em; font-weight: 600;">Risk Level: ${aiAnalysis.risk_level || 'Unknown'}</div>
            <div class="risk-score">${riskScore}/100</div>
            <p style="margin: 15px 0 0 0; font-size: 1.05em;">${aiAnalysis.risk_summary || 'No summary available'}</p>
        </div>
        
        ${aiAnalysis.most_likely_attacks?.length ? `
        <h3 style="margin-top: 25px; color: #0f172a;">🎯 Most Likely Attack Vectors</h3>
        ${aiAnalysis.most_likely_attacks.map((attack, idx) => `
            <div style="padding: 15px; margin: 10px 0; background: #fef2f2; border-left: 4px solid #ef4444; border-radius: 4px;">
                <div style="font-weight: 600; color: #991b1b; margin-bottom: 5px;">${idx + 1}. ${attack.attack_type || 'Unknown Attack'}</div>
                <div style="color: #7f1d1d; margin-bottom: 8px;">${attack.description || ''}</div>
                ${attack.probability ? `<span class="badge badge-danger">Probability: ${attack.probability}</span>` : ''}
                ${attack.impact ? `<span class="badge badge-warning" style="margin-left: 8px;">Impact: ${attack.impact}</span>` : ''}
            </div>
        `).join('')}
        ` : ''}
        
        ${aiAnalysis.executive_summary ? `
        <div style="margin-top: 20px; padding: 15px; background: #f8fafc; border-left: 4px solid #06b6d4; border-radius: 4px;">
            <h4 style="color: #0f172a; margin: 0 0 10px 0;">📋 Executive Summary</h4>
            <p style="margin: 0; color: #334155; line-height: 1.6;">${aiAnalysis.executive_summary}</p>
        </div>
        ` : ''}
    </div>`
  }
  
  const generateAIVulnerabilitiesHTML = () => {
    const aiAnalysis = analysisData?.ai_analysis
    if (!aiAnalysis) return ''
    
    let content = ''
    
    // AI-Identified Vulnerabilities
    if (aiAnalysis.vulnerabilities?.length || aiAnalysis.identified_vulnerabilities?.length) {
      const vulns = aiAnalysis.vulnerabilities || aiAnalysis.identified_vulnerabilities || []
      content += `
      <div class="section">
          <h2>🤖 AI-Identified Vulnerabilities</h2>
          <p style="color: #64748b; margin-bottom: 20px;">
              AI analysis has identified ${vulns.length} potential security vulnerabilities based on scan results.
          </p>
          ${vulns.map((vuln, idx) => `
              <div class="vulnerability">
                  <div class="vulnerability-title">
                      ${idx + 1}. ${vuln.title || vuln.name || vuln.vulnerability || 'Security Vulnerability'}
                  </div>
                  <p style="color: #7f1d1d; margin: 8px 0;">${vuln.description || vuln.details || ''}</p>
                  
                  ${vuln.severity ? `<span class="badge ${
                      vuln.severity.toLowerCase() === 'critical' ? 'badge-danger' : 
                      vuln.severity.toLowerCase() === 'high' ? 'badge-danger' : 
                      vuln.severity.toLowerCase() === 'medium' ? 'badge-warning' : 'badge-info'
                  }">Severity: ${vuln.severity}</span>` : ''}
                  
                  ${vuln.cvss_score ? `<span class="badge badge-danger" style="margin-left: 8px;">CVSS: ${vuln.cvss_score}</span>` : ''}
                  
                  ${vuln.affected_component ? `
                      <div style="margin-top: 10px;">
                          <strong style="color: #0f172a;">Affected Component:</strong> 
                          <code>${vuln.affected_component}</code>
                      </div>
                  ` : ''}
                  
                  ${vuln.exploitation_difficulty ? `
                      <div style="margin-top: 8px;">
                          <strong style="color: #0f172a;">Exploitation Difficulty:</strong> 
                          <span class="badge badge-info">${vuln.exploitation_difficulty}</span>
                      </div>
                  ` : ''}
                  
                  ${vuln.recommendation || vuln.mitigation ? `
                      <div style="margin-top: 12px; padding: 12px; background: #eff6ff; border-left: 3px solid #3b82f6; border-radius: 4px;">
                          <strong style="color: #1e40af;">💡 Mitigation Strategy:</strong>
                          <p style="margin: 5px 0 0 0; color: #1e3a8a;">${vuln.recommendation || vuln.mitigation}</p>
                      </div>
                  ` : ''}
              </div>
          `).join('')}
      </div>`
    }
    
    return content
  }

  const generateTechnologyStackHTML = () => {
    if (selectedTests?.tech === false || !analysisData?.technologies) return ''
    
    const techs = analysisData.technologies
    if (!techs || Object.keys(techs).length === 0) return ''

    return `
    <div class="section">
        <h2>💻 Technology Stack</h2>
        ${Object.entries(techs).map(([category, items]) => {
          if (!Array.isArray(items)) return ''
          return `
            <h3 style="color: #475569; margin: 20px 0 10px 0;">${category}</h3>
            <div class="tech-list">
                ${items.map(tech => {
                  const name = typeof tech === 'object' ? tech.name : tech
                  const version = typeof tech === 'object' ? tech.version : null
                  const categories = typeof tech === 'object' ? tech.categories : null
                  
                  return `
                    <div class="tech-item">
                        <div class="tech-name">${name || 'Unknown'}</div>
                        ${version ? `<div class="tech-version">Version: ${version}</div>` : ''}
                        ${categories?.length ? `<div class="tech-version" style="font-size: 0.85em; color: #94a3b8;">${categories.join(', ')}</div>` : ''}
                    </div>
                  `
                }).join('')}
            </div>
          `
        }).join('')}
    </div>`
  }

  const generateVulnerabilitiesHTML = () => {
    let content = ''
    
    // XSS Vulnerabilities
    if (selectedTests?.xss !== false && analysisData?.xss_scan) {
      const xss = analysisData.xss_scan
      content += `
        <div class="section">
            <h2>⚡ XSS Vulnerability Assessment</h2>
            ${xss.vulnerable ? `
                <div class="vulnerability">
                    <div class="vulnerability-title">⚠️ XSS Vulnerabilities Detected</div>
                    <p><strong>Tested Payloads:</strong> ${xss.tested_payloads || 0}</p>
                    <p><strong>Successful Payloads:</strong> ${xss.successful_payloads || 0}</p>
                    ${xss.vulnerability_details ? `
                        <p><strong>Details:</strong> ${xss.vulnerability_details}</p>
                    ` : ''}
                    ${xss.vulnerable_params?.length ? `
                        <div style="margin-top: 10px;">
                            <strong>Vulnerable Parameters:</strong>
                            <ul style="margin: 5px 0; padding-left: 25px;">
                                ${xss.vulnerable_params.map(param => `<li>${param}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${xss.attack_vectors?.length ? `
                        <div style="margin-top: 10px;">
                            <strong>Attack Vectors Found:</strong>
                            <ul style="margin: 5px 0; padding-left: 25px;">
                                ${xss.attack_vectors.map(vector => `<li><code>${vector}</code></li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    <div style="margin-top: 15px; padding: 10px; background: #eff6ff; border-left: 3px solid #3b82f6; border-radius: 4px;">
                        <strong style="color: #1e40af;">Recommendation:</strong>
                        <p style="margin: 5px 0 0 0; color: #1e3a8a;">
                            Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers.
                            Sanitize all user inputs before rendering them in the browser.
                        </p>
                    </div>
                </div>
            ` : `
                <div class="safe">
                    ✅ No XSS vulnerabilities detected in the tested parameters
                    <p style="margin: 10px 0 0 0; font-size: 0.95em;">
                        <strong>Tested:</strong> ${xss.tested_payloads || 0} different XSS payloads
                    </p>
                </div>
            `}
        </div>`
    }
    
    // SQL Injection
    if (selectedTests?.sqli !== false && analysisData?.sqli_scan) {
      const sqli = analysisData.sqli_scan
      content += `
        <div class="section">
            <h2>💉 SQL Injection Assessment</h2>
            ${sqli.vulnerable ? `
                <div class="vulnerability">
                    <div class="vulnerability-title">⚠️ SQL Injection Vulnerabilities Detected</div>
                    <p><strong>Tested Payloads:</strong> ${sqli.tested_payloads || 0}</p>
                    <p><strong>Successful Payloads:</strong> ${sqli.successful_payloads || 0}</p>
                    ${sqli.vulnerability_details ? `
                        <p><strong>Details:</strong> ${sqli.vulnerability_details}</p>
                    ` : ''}
                    ${sqli.vulnerable_params?.length ? `
                        <div style="margin-top: 10px;">
                            <strong>Vulnerable Parameters:</strong>
                            <ul style="margin: 5px 0; padding-left: 25px;">
                                ${sqli.vulnerable_params.map(param => `<li>${param}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${sqli.injection_points?.length ? `
                        <div style="margin-top: 10px;">
                            <strong>Injection Points:</strong>
                            <ul style="margin: 5px 0; padding-left: 25px;">
                                ${sqli.injection_points.map(point => `<li><code>${point}</code></li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${sqli.database_type ? `
                        <p style="margin-top: 10px;"><strong>Detected Database:</strong> ${sqli.database_type}</p>
                    ` : ''}
                    <div style="margin-top: 15px; padding: 10px; background: #eff6ff; border-left: 3px solid #3b82f6; border-radius: 4px;">
                        <strong style="color: #1e40af;">Recommendation:</strong>
                        <p style="margin: 5px 0 0 0; color: #1e3a8a;">
                            Use parameterized queries (prepared statements) for all database operations.
                            Implement proper input validation and escaping. Never concatenate user input directly into SQL queries.
                            Apply the principle of least privilege for database accounts.
                        </p>
                    </div>
                </div>
            ` : `
                <div class="safe">
                    ✅ No SQL Injection vulnerabilities detected in the tested parameters
                    <p style="margin: 10px 0 0 0; font-size: 0.95em;">
                        <strong>Tested:</strong> ${sqli.tested_payloads || 0} different SQL injection payloads
                    </p>
                </div>
            `}
        </div>`
    }
    
    return content
  }

  const generateRecommendationsHTML = () => {
    const aiAnalysis = analysisData?.ai_analysis
    if (!aiAnalysis) return ''

    let content = '<div class="section"><h2>💡 AI Security Recommendations</h2>'
    let hasContent = false
    
    // AI Vulnerabilities
    if (aiAnalysis.vulnerabilities?.length) {
      hasContent = true
      content += '<h3 style="color: #dc2626; margin: 15px 0 10px 0;">🔴 AI-Identified Vulnerabilities</h3>'
      content += aiAnalysis.vulnerabilities.map((vuln, idx) => {
        const title = vuln.title || 'Vulnerability'
        const description = vuln.description || ''
        const severity = vuln.severity || 'Unknown'
        const attackMethod = vuln.attack_method || ''
        const impact = vuln.impact || ''
        const fix = vuln.fix || ''
        
        const severityColor = severity.toLowerCase() === 'critical' ? '#dc2626' : 
                              severity.toLowerCase() === 'high' ? '#f97316' : 
                              severity.toLowerCase() === 'medium' ? '#eab308' : '#3b82f6'
        
        return `
        <div class="vulnerability">
            <div class="vulnerability-title" style="color: ${severityColor};">
                ${idx + 1}. ${title}
                <span class="badge" style="background: ${severityColor}20; color: ${severityColor}; border: 1px solid ${severityColor}; margin-left: 10px;">${severity.toUpperCase()}</span>
            </div>
            ${description ? `<p style="margin: 8px 0; color: #334155; line-height: 1.6;">${description}</p>` : ''}
            ${attackMethod ? `
                <div style="background: #fef2f2; border: 1px solid #fca5a5; border-radius: 4px; padding: 10px; margin: 8px 0;">
                    <strong style="color: #dc2626;">Attack Method:</strong>
                    <p style="margin: 5px 0 0 0; color: #991b1b; font-size: 0.9em;">${attackMethod}</p>
                </div>
            ` : ''}
            ${impact ? `
                <div style="background: #f8fafc; border-radius: 4px; padding: 10px; margin: 8px 0;">
                    <strong style="color: #f97316;">Impact:</strong>
                    <p style="margin: 5px 0 0 0; color: #64748b; font-size: 0.9em;">${impact}</p>
                </div>
            ` : ''}
            ${fix ? `
                <div style="background: #ecfeff; border: 1px solid #67e8f9; border-radius: 4px; padding: 10px; margin: 8px 0;">
                    <strong style="color: #0e7490;">Fix:</strong>
                    <p style="margin: 5px 0 0 0; color: #164e63; font-size: 0.9em;">${fix}</p>
                </div>
            ` : ''}
        </div>
      `}).join('')
    }
    
    // AI Recommendations
    if (aiAnalysis.security_recommendations?.length) {
      hasContent = true
      content += '<h3 style="color: #0f172a; margin: 25px 0 10px 0;">🎯 Security Recommendations</h3>'
      content += aiAnalysis.security_recommendations.map((rec, idx) => {
        const category = rec.category || 'General'
        const recommendation = rec.recommendation || rec.title || 'Security Recommendation'
        const implementation = rec.implementation || ''
        const priority = rec.priority || ''
        const priorityColor = priority.toLowerCase() === 'critical' ? '#dc2626' : 
                              priority.toLowerCase() === 'high' ? '#f97316' : 
                              priority.toLowerCase() === 'medium' ? '#eab308' : '#3b82f6'
        
        return `
        <div class="recommendation">
            <div style="margin-bottom: 10px;">
                <span style="font-size: 0.75em; color: #64748b; text-transform: uppercase; font-weight: 600;">${category}</span>
                <div style="font-weight: 600; color: #1e293b; margin-top: 3px;">
                    ${idx + 1}. ${recommendation}
                </div>
            </div>
            ${implementation ? `
                <div style="background: #f1f5f9; border-radius: 4px; padding: 10px; margin: 8px 0;">
                    <strong style="color: #0ea5e9;">Implementation:</strong>
                    <p style="margin: 5px 0 0 0; color: #334155; font-size: 0.9em;">${implementation}</p>
                </div>
            ` : ''}
            ${priority ? `<span class="badge" style="background: ${priorityColor}30; color: ${priorityColor}; border: 1px solid ${priorityColor}; padding: 4px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; text-transform: uppercase;">${priority}</span>` : ''}
        </div>
      `}).join('')
    }
    
    // Detailed Issues
    if (aiAnalysis.detailed_issues?.length) {
      hasContent = true
      content += '<h3 style="color: #0f172a; margin: 25px 0 10px 0;">🔍 Detailed Security Issues</h3>'
      content += aiAnalysis.detailed_issues.map((issue, idx) => {
        const issueTitle = issue.issue || issue.title || issue.name || 'Security Issue'
        const description = issue.description || issue.details || ''
        const severity = issue.severity || issue.priority || ''
        const recommendation = issue.recommendation || issue.solution || issue.fix || ''
        
        return `
        <div class="vulnerability">
            <div class="vulnerability-title">${idx + 1}. ${issueTitle}</div>
            ${description ? `<p style="color: #7f1d1d; margin: 5px 0 8px 0;">${description}</p>` : ''}
            ${severity ? `<span class="badge ${
                severity.toLowerCase() === 'critical' || severity.toLowerCase() === 'high' ? 'badge-danger' : 
                severity.toLowerCase() === 'medium' ? 'badge-warning' : 'badge-info'
            }">Severity: ${severity}</span>` : ''}
            ${recommendation ? `
                <div style="margin-top: 10px; padding: 10px; background: #eff6ff; border-left: 3px solid #3b82f6; border-radius: 4px;">
                    <strong style="color: #1e40af;">Recommendation:</strong>
                    <p style="margin: 5px 0 0 0; color: #1e3a8a;">${recommendation}</p>
                </div>
            ` : ''}
        </div>
      `}).join('')
    }
    
    // Security best practices
    if (aiAnalysis.security_best_practices?.length) {
      hasContent = true
      content += '<h3 style="color: #0f172a; margin: 25px 0 10px 0;">✅ Security Best Practices</h3>'
      content += '<ul style="margin: 10px 0; padding-left: 25px;">'
      content += aiAnalysis.security_best_practices.map(practice => {
        const practiceText = typeof practice === 'string' ? practice : practice.practice || practice.description || ''
        return `<li style="margin: 8px 0; color: #334155; line-height: 1.6;">${practiceText}</li>`
      }).join('')
      content += '</ul>'
    }
    
    // Compliance recommendations
    if (aiAnalysis.compliance_recommendations?.length) {
      hasContent = true
      content += '<h3 style="color: #0f172a; margin: 25px 0 10px 0;">📋 Compliance & Standards</h3>'
      content += '<ul style="margin: 10px 0; padding-left: 25px;">'
      content += aiAnalysis.compliance_recommendations.map(comp => {
        const compText = typeof comp === 'string' ? comp : comp.standard || comp.recommendation || ''
        return `<li style="margin: 8px 0; color: #334155; line-height: 1.6;">${compText}</li>`
      }).join('')
      content += '</ul>'
    }
    
    // Quick wins
    if (aiAnalysis.quick_wins?.length) {
      hasContent = true
      content += '<h3 style="color: #059669; margin: 25px 0 10px 0;">⚡ Quick Wins (Easy Improvements)</h3>'
      content += '<div style="background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 15px;">'
      content += '<ul style="margin: 0; padding-left: 25px;">'
      content += aiAnalysis.quick_wins.map(win => {
        const winText = typeof win === 'string' ? win : win.action || win.description || ''
        return `<li style="margin: 8px 0; color: #166534; line-height: 1.6;">${winText}</li>`
      }).join('')
      content += '</ul></div>'
    }
    
    if (!hasContent) {
      const isQuotaError = aiAnalysis?.error === 'quota_exceeded'
      if (isQuotaError) {
        content += `
        <div style="text-align: center; padding: 30px; background: #fff7ed; border: 1px solid #fed7aa; border-radius: 8px;">
          <div style="font-size: 48px; margin-bottom: 15px;">⚠️</div>
          <h3 style="color: #9a3412; margin: 0 0 10px 0; font-size: 1.1em;">AI Analysis Quota Exceeded</h3>
          <p style="color: #7c2d12; margin: 0 0 10px 0; font-size: 0.9em;">
            Gemini API free tier limit reached (20 requests/day).
          </p>
          <p style="color: #78350f; margin: 0; font-size: 0.85em;">
            The scan completed successfully but detailed AI insights are unavailable. 
            Your quota will reset in 24 hours, or you can upgrade your plan for higher limits.
          </p>
        </div>`
      } else {
        content += `
        <div style="text-align: center; padding: 30px; background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px;">
          <div style="font-size: 48px; margin-bottom: 15px;">✓</div>
          <h3 style="color: #166534; margin: 0 0 10px 0; font-size: 1.1em;">No Major Issues Detected</h3>
          <p style="color: #15803d; margin: 0; font-size: 0.9em;">
            The security scan completed successfully. Enable AI analysis with Gemini API key for detailed recommendations.
          </p>
        </div>`
      }
    }
    
    content += '</div>'
    return content
  }

  const generateDirectoryScanHTML = () => {
    if (selectedTests?.directory === false || !analysisData?.directory_scan) return ''
    
    const dirScan = analysisData.directory_scan
    const totalDirs = dirScan.total_directories || 0
    const directories = dirScan.directories || []
    const categories = dirScan.categories || {}
    
    if (totalDirs === 0) return ''
    
    // Helper functions
    const getCategoryLabel = (category) => {
      const labels = {
        admin: 'Admin & Control',
        config: 'Configuration',
        backup: 'Backup & Temp',
        api: 'API Endpoints',
        content: 'Content & Media',
        other: 'Other'
      }
      return labels[category] || category
    }
    
    const formatFileSize = (bytes) => {
      if (!bytes || bytes === 0) return 'N/A'
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    }
    
    const getCategoryColor = (category) => {
      const colors = {
        admin: '#dc2626',
        config: '#f97316',
        backup: '#eab308',
        api: '#3b82f6',
        content: '#a855f7',
        other: '#64748b'
      }
      return colors[category] || colors.other
    }
    
    // Only show directories with status 200
    const status200Dirs = directories.filter(dir => dir.status_code === 200 || dir.status_code === '200')
    
    // Check for critical exposure
    const hasCriticalExposure = (categories.admin && categories.admin.length > 0) || 
                                (categories.config && categories.config.length > 0)
    
    return `
    <div class="section">
        <h2>🔍 Reconnaissance & Endpoint Discovery</h2>
        <h3 style="color: #475569; margin: 15px 0 10px 0;">Directory Enumeration</h3>
        <p style="color: #0f172a; font-weight: 600; margin-bottom: 15px;">
            ${totalDirs} accessible ${totalDirs === 1 ? 'directory' : 'directories'} found
        </p>
        
        <!-- Category Filter Summary -->
        <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; padding: 15px; background: #f8fafc; border-radius: 6px;">
            <span style="padding: 6px 12px; background: #3b82f6; color: white; border-radius: 4px; font-size: 0.85em; font-weight: 600;">
                All (${totalDirs})
            </span>
            ${Object.entries(categories).map(([category, dirs]) => {
              if (dirs.length === 0) return ''
              const color = getCategoryColor(category)
              return `
              <span style="padding: 6px 12px; background: ${color}20; color: ${color}; border: 1px solid ${color}; border-radius: 4px; font-size: 0.85em; font-weight: 600;">
                  ${getCategoryLabel(category)} (${dirs.length})
              </span>
              `
            }).join('')}
        </div>
        
        ${hasCriticalExposure ? `
        <!-- Critical Warning -->
        <div style="background: #fef2f2; border: 2px solid #ef4444; border-radius: 6px; padding: 15px; margin-bottom: 20px;">
            <div style="display: flex; align-items: start; gap: 10px;">
                <span style="font-size: 20px;">⚠️</span>
                <div>
                    <p style="color: #dc2626; font-weight: 600; margin: 0 0 5px 0;">Critical Exposure Detected</p>
                    <p style="color: #991b1b; margin: 0; font-size: 0.9em;">
                        Sensitive directories (admin/config) are publicly accessible. This may allow unauthorized access.
                    </p>
                </div>
            </div>
        </div>
        ` : ''}
        
        <!-- Directory List (Status 200 Only) -->
        <h4 style="color: #475569; margin: 20px 0 10px 0;">Accessible Endpoints (Status: 200 OK)</h4>
        <table>
            <thead>
                <tr>
                    <th>Path</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                ${status200Dirs.map(dir => {
                  const category = Object.keys(categories).find(cat => 
                    categories[cat].some(d => d.url === dir.url)
                  ) || 'other'
                  const color = getCategoryColor(category)
                  
                  return `
                    <tr>
                        <td><code style="background: #f1f5f9; padding: 4px 8px; border-radius: 3px; font-size: 0.85em; color: #1e40af; word-break: break-all;">${dir.path || '/'}</code></td>
                        <td><span style="background: ${color}20; color: ${color}; border: 1px solid ${color}; padding: 3px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600;">${getCategoryLabel(category)}</span></td>
                        <td><span class="badge badge-success">200 OK</span></td>
                        <td style="color: #475569; font-size: 0.9em;">${formatFileSize(dir.size)}</td>
                        <td style="color: #64748b; font-size: 0.85em;">${dir.content_type && dir.content_type !== 'discovered' ? dir.content_type : 'N/A'}</td>
                    </tr>
                  `
                }).join('')}
            </tbody>
        </table>
        
        <!-- Category Summary -->
        <div style="margin-top: 25px; padding: 15px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;">
            <h4 style="color: #475569; margin: 0 0 15px 0;">Category Summary</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">
                ${Object.entries(categories).map(([category, dirs]) => {
                  if (dirs.length === 0) return ''
                  const color = getCategoryColor(category)
                  return `
                  <div style="text-align: center; padding: 12px; background: white; border: 1px solid ${color}; border-radius: 4px;">
                      <div style="color: ${color}; font-size: 0.75em; font-weight: 600; text-transform: uppercase; margin-bottom: 5px;">${getCategoryLabel(category)}</div>
                      <div style="color: #1e293b; font-size: 1.5em; font-weight: bold;">${dirs.length}</div>
                  </div>
                  `
                }).join('')}
            </div>
        </div>
    </div>`
  }

  const generateWAFDetailsHTML = () => {
    if (selectedTests?.waf === false) return ''
    
    const wafData = analysisData?.waf
    const hasWAF = wafData && wafData.name && wafData.name !== 'None detected'
    
    return `
    <div class="section">
        <h2>🛡️ Web Application Firewall (WAF) Detection</h2>
        
        ${hasWAF ? `
        <div style="padding: 20px; background: #f0fdf4; border-left: 4px solid #10b981; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 15px 0; color: #166534; display: flex; align-items: center; gap: 10px;">
                ✅ WAF Protection Detected
            </h3>
            
            <div style="margin: 15px 0;">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div style="background: white; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 0.85em; color: #64748b; margin-bottom: 5px;">WAF Provider</div>
                        <div style="font-size: 1.1em; font-weight: 600; color: #0f172a;">${wafData.name}</div>
                    </div>
                    ${wafData.confidence ? `
                    <div style="background: white; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 0.85em; color: #64748b; margin-bottom: 5px;">Detection Confidence</div>
                        <div style="font-size: 1.1em; font-weight: 600; color: #0f172a;">${wafData.confidence}%</div>
                    </div>
                    ` : ''}
                    ${wafData.type ? `
                    <div style="background: white; padding: 15px; border-radius: 6px;">
                        <div style="font-size: 0.85em; color: #64748b; margin-bottom: 5px;">Type</div>
                        <div style="font-size: 1.1em; font-weight: 600; color: #0f172a;">${wafData.type}</div>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            ${wafData.indicators?.length ? `
            <div style="margin-top: 20px;">
                <h4 style="color: #166534; margin-bottom: 10px;">🔍 Detection Indicators</h4>
                <ul style="margin: 0; padding-left: 25px;">
                    ${wafData.indicators.map(indicator => 
                        `<li style="margin: 5px 0; color: #166534;">${indicator}</li>`
                    ).join('')}
                </ul>
            </div>
            ` : ''}
            
            <div style="margin-top: 20px; padding: 15px; background: #eff6ff; border-radius: 6px;">
                <h4 style="margin: 0 0 10px 0; color: #1e40af;">🤖 AI Analysis</h4>
                <p style="margin: 0; color: #1e3a8a; line-height: 1.6;">
                    The presence of ${wafData.name} provides an additional layer of security by filtering malicious traffic and blocking common attack patterns. 
                    This helps protect against OWASP Top 10 vulnerabilities including SQL injection, XSS, and other web-based attacks.
                </p>
            </div>
            
            <div style="margin-top: 15px; padding: 15px; background: white; border-radius: 6px; border: 1px solid #d1fae5;">
                <h4 style="margin: 0 0 10px 0; color: #0f172a;">💡 Recommendations</h4>
                <ul style="margin: 0; padding-left: 25px;">
                    <li style="margin: 5px 0; color: #334155;">Ensure WAF rules are regularly updated to protect against emerging threats</li>
                    <li style="margin: 5px 0; color: #334155;">Monitor WAF logs for blocked attacks and false positives</li>
                    <li style="margin: 5px 0; color: #334155;">Configure custom rules based on your application's specific security needs</li>
                    <li style="margin: 5px 0; color: #334155;">Enable rate limiting to prevent DDoS attacks</li>
                    <li style="margin: 5px 0; color: #334155;">Implement geo-blocking if your application serves specific regions only</li>
                    <li style="margin: 5px 0; color: #334155;">Regularly review and test WAF effectiveness with penetration testing</li>
                </ul>
            </div>
        </div>
        ` : `
        <div style="padding: 20px; background: #fef2f2; border-left: 4px solid #ef4444; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="margin: 0 0 15px 0; color: #991b1b; display: flex; align-items: center; gap: 10px;">
                ⚠️ No WAF Protection Detected
            </h3>
            
            <div style="margin: 15px 0; padding: 15px; background: white; border-radius: 6px;">
                <h4 style="margin: 0 0 10px 0; color: #0f172a;">🤖 AI Analysis</h4>
                <p style="margin: 0; color: #7f1d1d; line-height: 1.6;">
                    No Web Application Firewall was detected. This means your application lacks an important security layer that helps protect 
                    against common web attacks such as SQL injection, XSS, DDoS, and bot traffic. Without a WAF, your application is more 
                    vulnerable to automated attacks and exploitation attempts.
                </p>
            </div>
            
            <div style="margin-top: 15px; padding: 15px; background: #eff6ff; border-radius: 6px;">
                <h4 style="margin: 0 0 10px 0; color: #1e40af;">💡 Critical Recommendations</h4>
                <ul style="margin: 0; padding-left: 25px;">
                    <li style="margin: 8px 0; color: #1e3a8a;"><strong>Implement a WAF immediately</strong> - Consider cloud-based solutions like Cloudflare, AWS WAF, Azure WAF, or Akamai</li>
                    <li style="margin: 8px 0; color: #1e3a8a;"><strong>OWASP ModSecurity</strong> - Free, open-source WAF for Apache, Nginx, and IIS</li>
                    <li style="margin: 8px 0; color: #1e3a8a;"><strong>Cloud-native protection</strong> - Use CDN providers with built-in WAF capabilities</li>
                    <li style="margin: 8px 0; color: #1e3a8a;"><strong>Bot protection</strong> - Implement CAPTCHA and rate limiting at minimum</li>
                    <li style="margin: 8px 0; color: #1e3a8a;"><strong>DDoS mitigation</strong> - Essential for public-facing applications</li>
                </ul>
            </div>
            
            <div style="margin-top: 15px; padding: 15px; background: #fef3c7; border-radius: 6px; border: 1px solid #eab308;">
                <h4 style="margin: 0 0 10px 0; color: #92400e;">⚡ Popular WAF Solutions</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-top: 10px;">
                    <div style="background: white; padding: 10px; border-radius: 4px;">
                        <strong style="color: #0f172a;">Cloudflare WAF</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9em; color: #64748b;">Free & Paid tiers</p>
                    </div>
                    <div style="background: white; padding: 10px; border-radius: 4px;">
                        <strong style="color: #0f172a;">AWS WAF</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9em; color: #64748b;">Pay-as-you-go pricing</p>
                    </div>
                    <div style="background: white; padding: 10px; border-radius: 4px;">
                        <strong style="color: #0f172a;">ModSecurity</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9em; color: #64748b;">Free & Open Source</p>
                    </div>
                    <div style="background: white; padding: 10px; border-radius: 4px;">
                        <strong style="color: #0f172a;">Sucuri WAF</strong>
                        <p style="margin: 5px 0 0 0; font-size: 0.9em; color: #64748b;">Website protection</p>
                    </div>
                </div>
            </div>
        </div>
        `}
        
        <div style="margin-top: 20px; padding: 15px; background: #f8fafc; border-radius: 8px;">
            <h4 style="margin: 0 0 10px 0; color: #0f172a;">📚 What is a WAF?</h4>
            <p style="margin: 0 0 10px 0; color: #334155; line-height: 1.6;">
                A Web Application Firewall (WAF) monitors, filters, and blocks HTTP/HTTPS traffic to and from web applications. 
                It protects against attacks such as:
            </p>
            <ul style="margin: 0; padding-left: 25px; color: #334155;">
                <li style="margin: 5px 0;">SQL Injection attacks</li>
                <li style="margin: 5px 0;">Cross-Site Scripting (XSS)</li>
                <li style="margin: 5px 0;">Cross-Site Request Forgery (CSRF)</li>
                <li style="margin: 5px 0;">DDoS attacks and rate limiting</li>
                <li style="margin: 5px 0;">Malicious bot traffic</li>
                <li style="margin: 5px 0;">Zero-day exploits</li>
                <li style="margin: 5px 0;">OWASP Top 10 vulnerabilities</li>
            </ul>
        </div>
    </div>`
  }

  const generateWhoisHTML = () => {
    if (selectedTests?.whois === false || !analysisData?.whois?.success) return ''
    
    const whois = analysisData.whois
    return `
    <div class="section">
        <h2>🌐 Domain Information (WHOIS)</h2>
        
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">📋 Domain Details</h3>
            <table>
                <tr><th style="width: 200px;">Domain Name</th><td><strong>${whois.domain_name || 'N/A'}</strong></td></tr>
                <tr>
                    <th>Organization</th>
                    <td><strong style="color: #0f172a; font-size: 1.05em;">${whois.organization || whois.registrant_organization || whois.org || whois.registrant_org || whois.registrant || whois.admin_organization || whois.tech_organization || 'N/A'}</strong></td>
                </tr>
                <tr>
                    <th>Country</th>
                    <td><strong>${whois.country || whois.registrant_country || whois.admin_country || whois.tech_country || 'N/A'}</strong> ${whois.country || whois.registrant_country ? getCountryFlag(whois.country || whois.registrant_country) : ''}</td>
                </tr>
                <tr><th>Registrar</th><td>${whois.registrar || 'N/A'}</td></tr>
                <tr><th>Registrar URL</th><td>${whois.registrar_url || whois.registrar_website || 'N/A'}</td></tr>
                <tr><th>WHOIS Server</th><td>${whois.whois_server || 'N/A'}</td></tr>
                <tr><th>IANA ID</th><td>${whois.registrar_iana_id || whois.iana_id || 'N/A'}</td></tr>
            </table>
        </div>
        
        ${(whois.registrant_name || whois.name || whois.registrant_email || whois.email || whois.registrant_phone || whois.phone || whois.registrant_street || whois.address || whois.street || whois.registrant_city || whois.city || whois.registrant_state || whois.state_province || whois.state || whois.registrant_postal_code || whois.zipcode || whois.postal_code) ? `
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">👤 Registrant Contact Information</h3>
            <table>
                ${whois.registrant_name || whois.name ? `<tr><th style="width: 200px;">Name</th><td>${whois.registrant_name || whois.name}</td></tr>` : ''}
                ${whois.registrant_email || whois.email ? `<tr><th>Email</th><td>${whois.registrant_email || whois.email}</td></tr>` : ''}
                ${whois.registrant_phone || whois.phone ? `<tr><th>Phone</th><td>${whois.registrant_phone || whois.phone}</td></tr>` : ''}
                ${whois.registrant_street || whois.address || whois.street ? `<tr><th>Street Address</th><td>${whois.registrant_street || whois.address || whois.street}</td></tr>` : ''}
                ${whois.registrant_city || whois.city ? `<tr><th>City</th><td>${whois.registrant_city || whois.city}</td></tr>` : ''}
                ${whois.registrant_state || whois.state_province || whois.state ? `<tr><th>State/Province</th><td>${whois.registrant_state || whois.state_province || whois.state}</td></tr>` : ''}
                ${whois.registrant_postal_code || whois.zipcode || whois.postal_code ? `<tr><th>Postal Code</th><td>${whois.registrant_postal_code || whois.zipcode || whois.postal_code}</td></tr>` : ''}
            </table>
        </div>
        ` : ''}
        
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">📅 Important Dates</h3>
            <table>
                <tr>
                    <th style="width: 200px;">Creation Date</th>
                    <td>${whois.creation_date || whois.created_date || 'N/A'}</td>
                </tr>
                <tr>
                    <th>Last Updated</th>
                    <td>${whois.updated_date || whois.last_updated || 'N/A'}</td>
                </tr>
                <tr>
                    <th>Expiration Date</th>
                    <td><strong>${whois.expiration_date || whois.registry_expiry_date || 'N/A'}</strong></td>
                </tr>
                ${whois.expiration_date || whois.registry_expiry_date ? `
                <tr>
                    <th>Days Until Expiry</th>
                    <td>${getDaysUntilExpiry(whois.expiration_date || whois.registry_expiry_date)}</td>
                </tr>
                ` : ''}
            </table>
        </div>
        
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">🌐 DNS & Name Servers</h3>
            <table>
                <tr>
                    <th style="width: 200px;">Name Servers</th>
                    <td>
                        ${whois.name_servers?.length ? 
                            whois.name_servers.map(ns => `<div style="margin: 3px 0;"><code style="background: #f1f5f9; padding: 2px 6px; border-radius: 3px;">${ns}</code></div>`).join('') 
                            : 'N/A'
                        }
                    </td>
                </tr>
            </table>
        </div>
        
        ${whois.status?.length ? `
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">🔒 Domain Status</h3>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                ${whois.status.map(status => `
                    <span class="badge ${status.toLowerCase().includes('lock') ? 'badge-success' : 
                                        status.toLowerCase().includes('hold') ? 'badge-warning' : 
                                        status.toLowerCase().includes('pending') ? 'badge-info' : 'badge-info'}" 
                          style="font-size: 0.85em;">
                        ${status}
                    </span>
                `).join('')}
            </div>
            <p style="margin: 12px 0 0 0; padding: 12px; background: #f8fafc; border-radius: 6px; font-size: 0.9em; color: #64748b;">
                <strong>Note:</strong> Domain status codes indicate the current state and restrictions on the domain. 
                Locked statuses (e.g., clientTransferProhibited) protect against unauthorized changes.
            </p>
        </div>
        ` : ''}
        
        ${(whois.dnssec || whois.dnssec_status) ? `
        <div style="margin-bottom: 25px;">
            <h3 style="color: #475569; margin: 20px 0 15px 0; font-size: 1.1em;">🔐 Security Features</h3>
            <table>
                <tr>
                    <th style="width: 200px;">DNSSEC</th>
                    <td>
                        <span class="badge ${(whois.dnssec || whois.dnssec_status) === 'signed' || (whois.dnssec || whois.dnssec_status) === 'enabled' ? 'badge-success' : 'badge-warning'}">
                            ${whois.dnssec || whois.dnssec_status || 'Not Configured'}
                        </span>
                    </td>
                </tr>
            </table>
            <p style="margin: 12px 0 0 0; padding: 12px; background: #f8fafc; border-radius: 6px; font-size: 0.9em; color: #64748b;">
                DNSSEC (Domain Name System Security Extensions) adds security to DNS by enabling authentication of DNS data.
            </p>
        </div>
        ` : ''}
        
        <div style="padding: 15px; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 6px;">
            <h4 style="margin: 0 0 10px 0; color: #1e40af;">💡 Domain Security Recommendations</h4>
            <ul style="margin: 0; padding-left: 25px;">
                <li style="margin: 5px 0; color: #1e3a8a;">Keep domain registration information up to date</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Enable domain privacy protection to hide personal information</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Set domain to auto-renew to prevent accidental expiration</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Enable domain locking (transfer lock) to prevent unauthorized transfers</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Consider enabling DNSSEC for additional DNS security</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Use strong, unique passwords for your domain registrar account</li>
                <li style="margin: 5px 0; color: #1e3a8a;">Enable two-factor authentication on your registrar account</li>
            </ul>
        </div>
    </div>`
  }
  
  const getCountryFlag = (countryCode) => {
    const flags = {
      'US': '🇺🇸', 'GB': '🇬🇧', 'CA': '🇨🇦', 'AU': '🇦🇺', 'DE': '🇩🇪', 
      'FR': '🇫🇷', 'JP': '🇯🇵', 'CN': '🇨🇳', 'IN': '🇮🇳', 'BR': '🇧🇷',
      'RU': '🇷🇺', 'IT': '🇮🇹', 'ES': '🇪🇸', 'MX': '🇲🇽', 'NL': '🇳🇱',
      'SE': '🇸🇪', 'CH': '🇨🇭', 'SG': '🇸🇬', 'KR': '🇰🇷', 'PL': '🇵🇱',
      'BE': '🇧🇪', 'AT': '🇦🇹', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮',
      'IE': '🇮🇪', 'NZ': '🇳🇿', 'ZA': '🇿🇦', 'IL': '🇮🇱', 'AE': '🇦🇪'
    }
    if (!countryCode) return ''
    const code = countryCode.toUpperCase().substring(0, 2)
    return flags[code] || '🌍'
  }
  
  const getDaysUntilExpiry = (expirationDate) => {
    if (!expirationDate) return 'N/A'
    try {
      const expiry = new Date(expirationDate)
      const today = new Date()
      const diffTime = expiry - today
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
      
      if (diffDays < 0) {
        return `<span class="badge badge-danger">Expired ${Math.abs(diffDays)} days ago</span>`
      } else if (diffDays <= 30) {
        return `<span class="badge badge-danger">⚠️ ${diffDays} days (Renew urgently!)</span>`
      } else if (diffDays <= 90) {
        return `<span class="badge badge-warning">⚠️ ${diffDays} days (Renew soon)</span>`
      } else {
        return `<span class="badge badge-success">${diffDays} days</span>`
      }
    } catch (e) {
      return 'N/A'
    }
  }

  const getPortAIAnalysis = (port, service, version) => {
    const portNum = typeof port === 'object' ? port.port : port
    const serviceName = (typeof port === 'object' ? port.service : service) || 'Unknown'
    const serviceVersion = (typeof port === 'object' ? port.version : version) || ''
    
    // AI-driven security analysis for common ports
    const portAnalysis = {
      21: {
        risk: 'High',
        analysis: 'FTP (File Transfer Protocol) is inherently insecure as it transmits credentials and data in plaintext, making it vulnerable to packet sniffing and man-in-the-middle attacks. Should be disabled if not critical or replaced with FTPS/SFTP.',
        recommendation: 'Migrate to SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure). If FTP must be used, implement strict firewall rules and use VPN for access.'
      },
      22: {
        risk: 'Medium',
        analysis: 'SSH (Secure Shell) is generally secure but requires proper configuration. Common attack vectors include brute force attacks, weak passwords, and outdated versions with known vulnerabilities.',
        recommendation: 'Use SSH key-based authentication, disable root login, implement fail2ban, keep SSH version updated, and use non-standard port if possible.'
      },
      23: {
        risk: 'Critical',
        analysis: 'Telnet transmits all data including passwords in plaintext. This is extremely dangerous and should never be exposed to the internet. Highly vulnerable to eavesdropping and credential theft.',
        recommendation: 'Immediately disable Telnet and replace with SSH. There is no valid use case for Telnet in modern secure environments.'
      },
      25: {
        risk: 'Medium',
        analysis: 'SMTP (Simple Mail Transfer Protocol) can be exploited for spam relay, email spoofing, and information disclosure if not properly configured. Open relays are frequently abused by spammers.',
        recommendation: 'Ensure SMTP authentication is required, implement SPF/DKIM/DMARC, disable open relay, and use TLS encryption for email transmission.'
      },
      80: {
        risk: 'Medium',
        analysis: 'HTTP traffic is unencrypted, exposing all data transmission to potential interception. Modern web applications should enforce HTTPS to protect user data and session tokens.',
        recommendation: 'Implement HTTPS with valid SSL/TLS certificate, redirect all HTTP traffic to HTTPS, and enable HSTS (HTTP Strict Transport Security) headers.'
      },
      443: {
        risk: 'Low',
        analysis: 'HTTPS (HTTP Secure) provides encrypted communication. Ensure strong TLS configuration, valid certificates, and protection against known SSL/TLS vulnerabilities.',
        recommendation: 'Use TLS 1.2 or higher, disable weak cipher suites, implement certificate pinning, and regularly update SSL/TLS certificates before expiration.'
      },
      445: {
        risk: 'High',
        analysis: 'SMB (Server Message Block) has been exploited in major ransomware attacks (WannaCry, NotPetya). Should not be exposed to the internet. Vulnerable to brute force and known exploits.',
        recommendation: 'Block SMB from internet access, use SMB signing, keep systems patched, implement network segmentation, and use VPN for remote file sharing.'
      },
      3306: {
        risk: 'Critical',
        analysis: 'MySQL database exposed to internet is a critical security risk. Direct database access should never be publicly accessible as it can lead to data breaches, SQL injection at protocol level, and brute force attacks.',
        recommendation: 'Immediately restrict access to localhost or trusted IPs only. Use SSH tunneling or VPN for remote access. Implement strong authentication and monitor for unauthorized access attempts.'
      },
      3389: {
        risk: 'High',
        analysis: 'RDP (Remote Desktop Protocol) exposed to internet is frequently targeted by automated attacks and ransomware. Known for brute force attacks and exploitation of vulnerabilities.',
        recommendation: 'Use VPN or jump server for RDP access, implement Network Level Authentication (NLA), use strong passwords or certificate-based auth, enable account lockout, and keep Windows updated.'
      },
      5432: {
        risk: 'Critical',
        analysis: 'PostgreSQL database should never be directly exposed to the internet. Public exposure can lead to unauthorized data access, brute force attacks, and potential data exfiltration.',
        recommendation: 'Restrict access to localhost or specific trusted IPs, use SSL/TLS for connections, implement strong password policies, and use SSH tunneling for remote administration.'
      },
      8080: {
        risk: 'Medium',
        analysis: 'Alternative HTTP port often used for web applications, proxies, or administrative interfaces. Same security concerns as port 80, with additional risk if admin panels are exposed.',
        recommendation: 'Implement HTTPS, use strong authentication for admin interfaces, apply IP whitelisting for administrative access, and ensure proper input validation.'
      },
      8443: {
        risk: 'Low',
        analysis: 'Alternative HTTPS port. Ensure proper SSL/TLS configuration and certificate management. Often used for administrative interfaces or alternative web services.',
        recommendation: 'Maintain strong TLS configuration, implement proper access controls, use valid certificates, and monitor for unauthorized access attempts.'
      },
      27017: {
        risk: 'Critical',
        analysis: 'MongoDB exposed to internet is extremely dangerous. Historical incidents show many databases publicly accessible without authentication, leading to mass data breaches.',
        recommendation: 'Never expose MongoDB to public internet. Enable authentication, use IP whitelisting, implement SSL/TLS, use VPN for remote access, and regularly audit access logs.'
      },
      6379: {
        risk: 'Critical',
        analysis: 'Redis is often configured without authentication by default. Public exposure can lead to data theft, server compromise through malicious commands, and cryptocurrency mining malware installation.',
        recommendation: 'Bind Redis to localhost only, enable authentication (requirepass), use firewall rules, rename dangerous commands, and implement encryption for data in transit.'
      }
    }
    
    const analysis = portAnalysis[portNum] || {
      risk: serviceName.toLowerCase().includes('http') ? 'Medium' : 'Medium',
      analysis: `Port ${portNum} (${serviceName}) is open. ${serviceName.toLowerCase().includes('unknown') ? 'Unknown service - requires investigation.' : 'Ensure this service is necessary and properly secured with authentication and encryption.'}`,
      recommendation: 'Review if this service is required. Implement firewall rules, use strong authentication, enable encryption if available, keep software updated, and monitor access logs.'
    }
    
    return { ...analysis, service: serviceName, version: serviceVersion }
  }

  const generatePortsHTML = () => {
    if (selectedTests?.ports === false || !analysisData?.open_ports?.length) return ''
    
    const portsWithAnalysis = analysisData.open_ports.map(port => {
      const portNum = typeof port === 'object' ? port.port : port
      const service = typeof port === 'object' ? port.service : 'Unknown'
      const version = typeof port === 'object' ? port.version : ''
      return {
        port: portNum,
        ...getPortAIAnalysis(port, service, version)
      }
    })
    
    return `
    <div class="section">
        <h2>🔌 Open Ports & AI Security Analysis</h2>
        <p style="color: #64748b; margin-bottom: 20px;">
            Detected ${analysisData.open_ports.length} open port${analysisData.open_ports.length !== 1 ? 's' : ''} with AI-powered security recommendations
        </p>
        
        ${portsWithAnalysis.map((portData, idx) => `
            <div style="margin-bottom: 20px; padding: 20px; background: ${
              portData.risk === 'Critical' ? '#fef2f2' : 
              portData.risk === 'High' ? '#fff7ed' : 
              portData.risk === 'Medium' ? '#fefce8' : '#f0fdf4'
            }; border-left: 4px solid ${
              portData.risk === 'Critical' ? '#dc2626' : 
              portData.risk === 'High' ? '#ea580c' : 
              portData.risk === 'Medium' ? '#ca8a04' : '#16a34a'
            }; border-radius: 8px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <div>
                        <h3 style="margin: 0; color: #0f172a; font-size: 1.1em;">
                            Port ${portData.port} - ${portData.service}
                            <span class="badge badge-success" style="margin-left: 10px; font-size: 0.85em;">Open</span>
                        </h3>
                        ${portData.version ? `
                            <p style="margin: 5px 0 0 0; color: #64748b; font-size: 0.9em;">
                                <strong>Version:</strong> ${portData.version}
                            </p>
                        ` : ''}
                    </div>
                    <span class="badge ${
                      portData.risk === 'Critical' ? 'badge-danger' : 
                      portData.risk === 'High' ? 'badge-danger' : 
                      portData.risk === 'Medium' ? 'badge-warning' : 'badge-success'
                    }" style="font-size: 0.9em; padding: 6px 14px;">
                        Risk: ${portData.risk}
                    </span>
                </div>
                
                <div style="margin: 15px 0;">
                    <p style="margin: 0; color: #1e293b; line-height: 1.6;">
                        <strong style="color: #0f172a;">🤖 AI Analysis:</strong> ${portData.analysis}
                    </p>
                </div>
                
                <div style="margin-top: 15px; padding: 12px; background: rgba(255, 255, 255, 0.6); border-radius: 6px;">
                    <p style="margin: 0; color: #1e3a8a; line-height: 1.6;">
                        <strong style="color: #1e40af;">💡 Recommendation:</strong> ${portData.recommendation}
                    </p>
                </div>
            </div>
        `).join('')}
        
        <div style="margin-top: 25px; padding: 15px; background: #f1f5f9; border-radius: 8px;">
            <h4 style="margin: 0 0 10px 0; color: #0f172a;">📊 Port Security Summary</h4>
            <p style="margin: 5px 0; color: #334155;">
                <strong>Critical Risk Ports:</strong> ${portsWithAnalysis.filter(p => p.risk === 'Critical').length} | 
                <strong>High Risk:</strong> ${portsWithAnalysis.filter(p => p.risk === 'High').length} | 
                <strong>Medium Risk:</strong> ${portsWithAnalysis.filter(p => p.risk === 'Medium').length} | 
                <strong>Low Risk:</strong> ${portsWithAnalysis.filter(p => p.risk === 'Low').length}
            </p>
        </div>
    </div>`
  }

  const generateSecurityHeadersHTML = () => {
    if (selectedTests?.security_headers === false || !analysisData?.security_headers) return ''
    
    const headers = analysisData.security_headers
    const headersFound = headers.headers_found || []
    const headersMissing = headers.headers_missing || []
    const totalScore = headers.total_score || 0
    const maxScore = headers.max_score || 0
    const grade = headers.security_grade || 'F'
    const percentage = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0
    
    const gradeColor = grade === 'A' ? '#059669' : grade === 'B' ? '#0ea5e9' : grade === 'C' ? '#eab308' : grade === 'D' ? '#f97316' : '#dc2626'
    
    return `
    <div class="section">
        <h2>🛡️ Security Configuration - Headers Analysis</h2>
        
        <div style="padding: 20px; background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%); border-radius: 8px; margin-bottom: 25px;">
            <h3 style="margin: 0 0 15px 0; color: #1e293b;">Security Grade: <span style="color: ${gradeColor}; font-size: 1.5em;">${grade}</span> <span style="color: #64748b; font-size: 0.9em;">(${totalScore}/${maxScore} points • ${percentage}%)</span></h3>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                <div style="text-align: center; padding: 15px; background: #f0fdf4; border: 1px solid #86efac; border-radius: 6px;">
                    <div style="color: #16a34a; font-size: 0.75em; font-weight: 600; margin-bottom: 5px;">Present</div>
                    <div style="color: #15803d; font-size: 2em; font-weight: bold;">${headersFound.length}</div>
                </div>
                <div style="text-align: center; padding: 15px; background: #fef2f2; border: 1px solid #fca5a5; border-radius: 6px;">
                    <div style="color: #dc2626; font-size: 0.75em; font-weight: 600; margin-bottom: 5px;">Missing</div>
                    <div style="color: #b91c1c; font-size: 2em; font-weight: bold;">${headersMissing.length}</div>
                </div>
                <div style="text-align: center; padding: 15px; background: #eff6ff; border: 1px solid #93c5fd; border-radius: 6px;">
                    <div style="color: #2563eb; font-size: 0.75em; font-weight: 600; margin-bottom: 5px;">Score</div>
                    <div style="color: #1d4ed8; font-size: 2em; font-weight: bold;">${percentage}%</div>
                </div>
                <div style="text-align: center; padding: 15px; background: ${gradeColor}15; border: 1px solid ${gradeColor}50; border-radius: 6px;">
                    <div style="color: ${gradeColor}; font-size: 0.75em; font-weight: 600; margin-bottom: 5px;">Grade</div>
                    <div style="color: ${gradeColor}; font-size: 2em; font-weight: bold;">${grade}</div>
                </div>
            </div>
        </div>
        
        ${headersFound.length > 0 ? `
        <h3 style="color: #059669; margin: 20px 0 15px 0;">✅ Security Headers Present (${headersFound.length})</h3>
        <table>
            <thead>
                <tr>
                    <th>Header Name</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                ${headersFound.map(header => `
                    <tr>
                        <td><strong>${header.name}</strong></td>
                        <td><span class="badge badge-info">${header.source || 'HTTP'}</span></td>
                        <td style="color: #64748b; font-size: 0.9em;">${header.description || ''}</td>
                        <td><code style="background: #f1f5f9; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; word-break: break-all; display: block; max-width: 400px;">${header.value || ''}</code></td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        ` : '<p style="color: #64748b;">No security headers detected</p>'}
        
        ${headersMissing.length > 0 ? `
        <h3 style="color: #dc2626; margin: 25px 0 15px 0;">❌ Missing Critical Headers (${headersMissing.length})</h3>
        <table>
            <thead>
                <tr>
                    <th>Header Name</th>
                    <th>Risk Level</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                ${headersMissing.map(header => {
                    const riskColor = header.risk === 'Critical' ? '#dc2626' : header.risk === 'High' ? '#f97316' : header.risk === 'Medium' ? '#eab308' : '#0ea5e9'
                    return `
                    <tr>
                        <td><strong>${header.name}</strong></td>
                        <td><span class="badge" style="background: ${riskColor}20; color: ${riskColor}; border: 1px solid ${riskColor};">${header.risk} Risk</span></td>
                        <td style="color: #64748b; font-size: 0.9em;">${header.description || ''}</td>
                        <td style="color: #475569; font-size: 0.85em;">💡 ${header.recommendation || ''}</td>
                    </tr>
                    `
                }).join('')}
            </tbody>
        </table>
        ` : '<p style="color: #059669; margin-top: 15px;">✅ All critical security headers are present</p>'}
        
        <div style="margin-top: 25px; padding: 15px; background: #dbeafe; border-left: 4px solid #3b82f6; border-radius: 4px;">
            <h4 style="color: #1e40af; margin: 0 0 10px 0;">About Security Headers</h4>
            <p style="color: #1e3a8a; margin: 0; font-size: 0.9em; line-height: 1.6;">
                Security headers are HTTP response headers that instruct browsers on how to behave when handling your site's content. 
                Implementing proper security headers helps protect against common web vulnerabilities like XSS, clickjacking, and data injection attacks.
            </p>
            <div style="margin-top: 10px; padding: 10px; background: #fef3c7; border-left: 3px solid #eab308; border-radius: 3px;">
                <p style="color: #78350f; margin: 0; font-size: 0.85em;">
                    <strong>⚠️ Note:</strong> Some major sites may show missing headers because they use alternative implementations, 
                    different headers for specific services, or have other security measures in place. Always verify results and consider the 
                    overall security posture, not just individual headers.
                </p>
            </div>
        </div>
    </div>`
  }

  const downloadHTMLReport = () => {
    setDownloading(true)
    try {
      const htmlContent = generateHTMLReport()
      const blob = new Blob([htmlContent], { type: 'text/html' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `security-report-${analysisData.url?.replace(/[^a-z0-9]/gi, '-') || 'report'}-${Date.now()}.html`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Error generating HTML report:', error)
      alert('Failed to generate HTML report')
    } finally {
      setDownloading(false)
    }
  }

  const downloadPDFReport = async () => {
    setDownloading(true)
    setPdfProgress('Preparing report data...')
    
    try {
      // Send data to backend for PDF generation
      setPdfProgress('Sending data to server...')
      await new Promise(resolve => setTimeout(resolve, 300))
      
      const response = await fetch('http://localhost:5000/api/generate-pdf', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          analysisData: analysisData,
          selectedTests: selectedTests
        })
      })
      
      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.message || 'Failed to generate PDF')
      }
      
      setPdfProgress('Generating PDF on server...')
      await new Promise(resolve => setTimeout(resolve, 500))
      
      // Get the PDF blob
      const blob = await response.blob()
      
      setPdfProgress('Downloading PDF...')
      
      // Create download link
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `security-report-${analysisData.url?.replace(/[^a-z0-9]/gi, '-') || 'report'}-${Date.now()}.pdf`
      document.body.appendChild(a)
      a.click()
      
      // Cleanup
      setTimeout(() => {
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      }, 100)
      
      setPdfProgress('Download complete!')
      await new Promise(resolve => setTimeout(resolve, 1000))
      
    } catch (error) {
      console.error('Error generating PDF report:', error)
      setPdfProgress('')
      alert(`Failed to generate PDF report: ${error.message}\n\nPlease ensure the backend server is running or try the HTML format instead.`)
    } finally {
      setDownloading(false)
      setPdfProgress('')
    }
  }

  if (!analysisData) return null

  return (
    <div className="space-y-4">
      {/* Progress indicator */}
      {downloading && pdfProgress && (
        <div className="bg-blue-500/10 border border-blue-500/50 rounded-lg p-4 text-center">
          <div className="flex items-center justify-center gap-3">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-400"></div>
            <span className="text-blue-300 font-medium">{pdfProgress}</span>
          </div>
        </div>
      )}
      
      <div className="flex justify-center gap-4 py-4">
        <button
          onClick={downloadHTMLReport}
          disabled={downloading}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded-lg font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <FileText size={20} />
          {downloading && !pdfProgress ? 'Generating...' : 'Download HTML Report'}
        </button>
        
        <button
          onClick={downloadPDFReport}
          disabled={downloading}
          className="flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white px-6 py-3 rounded-lg font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <FileDown size={20} />
          {downloading && pdfProgress ? 'Processing...' : 'Download PDF Report'}
        </button>
      </div>
      
      <p className="text-center text-slate-400 text-sm">
        {downloading ? 'Please wait while we generate your report...' : 'Choose your preferred format to download the complete security report'}
      </p>
    </div>
  )
}
