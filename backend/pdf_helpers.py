"""Helper functions for PDF generation"""

def safe_get(obj, *keys, default='N/A'):
    """Safely get nested dictionary values"""
    for key in keys:
        try:
            obj = obj[key]
        except (KeyError, TypeError, IndexError):
            return default
    return obj if obj else default

def generate_overview_section(data, selected_tests):
    """Generate website overview section"""
    whois = data.get('whois', {})
    org = safe_get(whois, 'organization') or safe_get(whois, 'registrant_organization') or safe_get(whois, 'org')
    country = safe_get(whois, 'country') or safe_get(whois, 'registrant_country')
    
    return f"""
    <div class="section">
        <h2>📊 Website Overview</h2>
        <div class="overview-grid">
            <div class="overview-item">
                <div class="label">Website URL</div>
                <div class="value">{safe_get(data, 'url')}</div>
            </div>
            <div class="overview-item">
                <div class="label">IP Address</div>
                <div class="value">{safe_get(data, 'ip_address')}</div>
            </div>
            <div class="overview-item">
                <div class="label">Hostname</div>
                <div class="value">{safe_get(data, 'hostname', default=safe_get(data, 'url'))}</div>
            </div>
            <div class="overview-item">
                <div class="label">Organization</div>
                <div class="value">{org}</div>
            </div>
            <div class="overview-item">
                <div class="label">Country</div>
                <div class="value">{country}</div>
            </div>
            <div class="overview-item">
                <div class="label">Open Ports</div>
                <div class="value">{safe_get(data, 'total_open_ports', default=0)}</div>
            </div>
            <div class="overview-item">
                <div class="label">WAF Protection</div>
                <div class="value">{safe_get(data, 'waf', 'name', default='None detected')}</div>
            </div>
            <div class="overview-item">
                <div class="label">Scan Date</div>
                <div class="value">{safe_get(data, 'scan_date')}</div>
            </div>
        </div>
    </div>
    """

def generate_risk_assessment_section(data):
    """Generate AI risk assessment section"""
    ai = data.get('ai_analysis', {})
    if not ai:
        return ''
    
    risk_score = safe_get(ai, 'risk_score', default=0)
    risk_level = safe_get(ai, 'risk_level', default='Unknown').lower()
    
    risk_class = 'risk-low'
    if risk_level == 'critical' or risk_score >= 80:
        risk_class = 'risk-critical'
    elif risk_level == 'high' or risk_score >= 60:
        risk_class = 'risk-high'
    elif risk_level == 'medium' or risk_score >= 40:
        risk_class = 'risk-medium'
    
    attacks_html = ''
    if ai.get('most_likely_attacks'):
        attacks_html = '<h3>🎯 Most Likely Attack Vectors</h3>'
        for idx, attack in enumerate(ai['most_likely_attacks'], 1):
            attacks_html += f"""
            <div style="padding: 12px; margin: 8px 0; background: #fef2f2; border-left: 3px solid #ef4444; border-radius: 4px;">
                <div style="font-weight: 600; color: #991b1b; margin-bottom: 5px;">{idx}. {safe_get(attack, 'attack_type')}</div>
                <div style="color: #7f1d1d; margin-bottom: 5px;">{safe_get(attack, 'description')}</div>
                <span class="badge badge-danger">Probability: {safe_get(attack, 'probability')}</span>
            </div>
            """
    
    return f"""
    <div class="section">
        <h2>⚠️ AI Risk Assessment</h2>
        <div class="risk-box {risk_class}">
            <div style="font-size: 12pt; font-weight: 600;">Risk Level: {safe_get(ai, 'risk_level')}</div>
            <div class="risk-score">{risk_score}/100</div>
            <p style="margin: 12px 0 0 0; font-size: 10pt;">{safe_get(ai, 'risk_summary')}</p>
        </div>
        {attacks_html}
    </div>
    """

def generate_ai_vulnerabilities_section(data):
    """Generate AI-identified vulnerabilities section"""
    ai = data.get('ai_analysis', {})
    vulns = ai.get('vulnerabilities', []) or ai.get('identified_vulnerabilities', [])
    
    if not vulns:
        return ''
    
    vulns_html = ''
    for idx, vuln in enumerate(vulns, 1):
        title = safe_get(vuln, 'title') or safe_get(vuln, 'name') or safe_get(vuln, 'vulnerability')
        desc = safe_get(vuln, 'description') or safe_get(vuln, 'details')
        severity = safe_get(vuln, 'severity')
        rec = safe_get(vuln, 'recommendation') or safe_get(vuln, 'mitigation')
        
        badge_class = 'badge-danger' if severity.lower() in ['critical', 'high'] else 'badge-warning' if severity.lower() == 'medium' else 'badge-info'
        
        vulns_html += f"""
        <div class="vulnerability">
            <div style="font-weight: 600; color: #991b1b; margin-bottom: 5px;">{idx}. {title}</div>
            <p style="margin: 5px 0;">{desc}</p>
            <span class="badge {badge_class}">Severity: {severity}</span>
            {f'<div style="margin-top: 8px; padding: 8px; background: #eff6ff; border-left: 2px solid #3b82f6; border-radius: 3px;"><strong>Mitigation:</strong> {rec}</div>' if rec != 'N/A' else ''}
        </div>
        """
    
    return f"""
    <div class="section">
        <h2>🤖 AI-Identified Vulnerabilities</h2>
        <p style="color: #64748b; margin-bottom: 15px;">AI analysis identified {len(vulns)} potential security vulnerabilities.</p>
        {vulns_html}
    </div>
    """

def generate_technology_section(data, selected_tests):
    """Generate technology stack section"""
    if selected_tests.get('tech') == False:
        return ''
    
    techs = data.get('technologies', {})
    if not techs:
        return ''
    
    tech_html = ''
    for category, items in techs.items():
        if not isinstance(items, list):
            continue
        tech_html += f'<h3>{category}</h3><div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px;">'
        for tech in items:
            name = tech.get('name') if isinstance(tech, dict) else tech
            version = tech.get('version', '') if isinstance(tech, dict) else ''
            description = tech.get('description', '') if isinstance(tech, dict) else ''
            version_html = f'<div style="font-size: 8pt; color: #64748b;">v{version}</div>' if version else ''
            desc_html = f'<div style="font-size: 8pt; color: #64748b; margin-top: 4px;">{description}</div>' if description else ''
            tech_html += f'<div style="padding: 8px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px;"><div style="font-weight: 600;">{name}</div>{version_html}{desc_html}</div>'
        tech_html += '</div>'
    
    return f'<div class="section"><h2>💻 Technology Stack</h2>{tech_html}</div>'

def generate_vulnerabilities_section(data, selected_tests):
    """Generate XSS and SQLi vulnerability sections"""
    sections = ''
    
    # XSS
    if selected_tests.get('xss') != False and data.get('xss_scan'):
        xss = data['xss_scan']
        if xss.get('vulnerable'):
            vuln_params = xss.get('vulnerable_parameters', [])
            attack_vectors = xss.get('attack_vectors', [])
            params_html = '<ul>' + ''.join([f'<li><strong>{p}</strong></li>' for p in vuln_params[:10]]) + '</ul>' if vuln_params else '<p>None specified</p>'
            vectors_html = '<ul>' + ''.join([f'<li style="font-family: monospace; font-size: 8pt; color: #7f1d1d;">{v}</li>' for v in attack_vectors[:5]]) + '</ul>' if attack_vectors else '<p>None specified</p>'
            sections += f"""
            <div class="section">
                <h2>⚡ XSS Vulnerability Assessment</h2>
                <div class="vulnerability">
                    <div style="font-weight: 600; color: #991b1b;">⚠️ XSS Vulnerabilities Detected</div>
                    <p><strong>Tested Payloads:</strong> {safe_get(xss, 'tested_payloads', default=0)}</p>
                    <p><strong>Successful Payloads:</strong> {safe_get(xss, 'successful_payloads', default=0)}</p>
                    <h3>Vulnerable Parameters</h3>
                    {params_html}
                    <h3>Sample Attack Vectors</h3>
                    {vectors_html}
                </div>
            </div>
            """
        else:
            sections += '<div class="section"><h2>⚡ XSS Vulnerability Assessment</h2><div class="safe">✅ No XSS vulnerabilities detected</div></div>'
    
    # SQLi
    if selected_tests.get('sqli') != False and data.get('sqli_scan'):
        sqli = data['sqli_scan']
        if sqli.get('vulnerable'):
            injection_points = sqli.get('injection_points', [])
            db_type = safe_get(sqli, 'database_type', default='Unknown')
            error_based = safe_get(sqli, 'error_based_sqli', default=False)
            points_html = '<ul>' + ''.join([f'<li><strong>{p}</strong></li>' for p in injection_points[:10]]) + '</ul>' if injection_points else '<p>None specified</p>'
            sections += f"""
            <div class="section">
                <h2>💉 SQL Injection Assessment</h2>
                <div class="vulnerability">
                    <div style="font-weight: 600; color: #991b1b;">⚠️ SQL Injection Vulnerabilities Detected</div>
                    <p><strong>Tested Payloads:</strong> {safe_get(sqli, 'tested_payloads', default=0)}</p>
                    <p><strong>Successful Payloads:</strong> {safe_get(sqli, 'successful_payloads', default=0)}</p>
                    <p><strong>Database Type Detected:</strong> {db_type}</p>
                    <p><strong>Error-Based SQLi:</strong> {'Yes' if error_based else 'No'}</p>
                    <h3>Injection Points</h3>
                    {points_html}
                </div>
            </div>
            """
        else:
            sections += '<div class="section"><h2>💉 SQL Injection Assessment</h2><div class="safe">✅ No SQL Injection vulnerabilities detected</div></div>'
    
    return sections

def generate_recommendations_section(data):
    """Generate AI recommendations section"""
    ai = data.get('ai_analysis', {})
    recs = ai.get('recommendations', [])
    
    if not recs:
        return ''
    
    recs_html = ''
    for idx, rec in enumerate(recs, 1):
        title = safe_get(rec, 'title') or safe_get(rec, 'recommendation')
        desc = safe_get(rec, 'description') or safe_get(rec, 'details')
        priority = safe_get(rec, 'priority')
        
        badge_class = 'badge-danger' if priority.lower() in ['high', 'critical'] else 'badge-warning' if priority.lower() == 'medium' else 'badge-info'
        
        recs_html += f"""
        <div class="recommendation">
            <div style="font-weight: 600; color: #1e40af; margin-bottom: 5px;">{idx}. {title}</div>
            <p style="margin: 5px 0;">{desc}</p>
            <span class="badge {badge_class}">Priority: {priority}</span>
        </div>
        """
    
    return f'<div class="section"><h2>💡 AI Security Recommendations</h2>{recs_html}</div>'

def generate_directory_section(data, selected_tests):
    """Generate directory scan section"""
    if selected_tests.get('directory') == False:
        return ''
    
    dir_scan = data.get('directory_scan', {})
    dirs = dir_scan.get('found_directories', [])
    files = dir_scan.get('found_files', [])
    
    if not dirs and not files:
        return ''
    
    dirs_html = ''
    if dirs:
        dirs_html = '<h3>Directories</h3><ul>'
        for d in dirs[:50]:  # Limit to 50 to avoid huge PDFs
            path = d.get('path', d) if isinstance(d, dict) else d
            status = d.get('status_code', '') if isinstance(d, dict) else ''
            status_html = f' <span class="badge badge-success">{status}</span>' if status else ''
            dirs_html += f'<li><strong>{path}</strong>{status_html}</li>'
        dirs_html += '</ul>'
    
    files_html = ''
    if files:
        files_html = '<h3>Files</h3><ul>'
        for f in files[:50]:  # Limit to 50
            path = f.get('path', f) if isinstance(f, dict) else f
            status = f.get('status_code', '') if isinstance(f, dict) else ''
            size = f.get('size', '') if isinstance(f, dict) else ''
            status_html = f' <span class="badge badge-success">{status}</span>' if status else ''
            size_html = f' ({size})' if size else ''
            files_html += f'<li><strong>{path}</strong>{status_html}{size_html}</li>'
        files_html += '</ul>'
    
    return f"""
    <div class="section">
        <h2>🔍 Directory & Endpoint Discovery</h2>
        <p><strong>Summary:</strong> Found {len(dirs)} directories and {len(files)} files</p>
        {dirs_html}
        {files_html}
    </div>
    """

def generate_waf_section(data, selected_tests):
    """Generate WAF section"""
    if selected_tests.get('waf') == False:
        return ''
    
    waf = data.get('waf', {})
    has_waf = waf.get('name') and waf['name'] != 'None detected'
    
    if has_waf:
        confidence = safe_get(waf, 'confidence', default='N/A')
        indicators = waf.get('indicators', [])
        indicators_html = '<ul>' + ''.join([f'<li>{ind}</li>' for ind in indicators[:10]]) + '</ul>' if indicators else '<p>No specific indicators listed</p>'
        ai_rec = safe_get(waf, 'ai_recommendations', default='')
        return f"""
        <div class="section">
            <h2>🛡️ Web Application Firewall</h2>
            <div style="padding: 15px; background: #f0fdf4; border-left: 3px solid #10b981; border-radius: 6px;">
                <h3>✅ WAF Protection Detected</h3>
                <p><strong>Provider:</strong> {safe_get(waf, 'name')}</p>
                <p><strong>Confidence Level:</strong> {confidence}</p>
                <h3>Detection Indicators</h3>
                {indicators_html}
                {f'<h3>AI Recommendations</h3><p>{ai_rec}</p>' if ai_rec else ''}
            </div>
        </div>
        """
    return ''

def generate_whois_section(data, selected_tests):
    """Generate WHOIS section"""
    if selected_tests.get('whois') == False:
        return ''
    
    whois = data.get('whois', {})
    if not whois.get('success'):
        return ''
    
    name_servers = whois.get('name_servers', [])
    status = whois.get('status', [])
    ns_html = ', '.join(name_servers[:5]) if name_servers else 'N/A'
    status_html = '<ul>' + ''.join([f'<li>{s}</li>' for s in status[:10]]) + '</ul>' if status else '<p>N/A</p>'
    
    return f"""
    <div class="section">
        <h2>🌐 Domain Information (WHOIS)</h2>
        <table>
            <tr><th>Domain Name</th><td>{safe_get(whois, 'domain_name')}</td></tr>
            <tr><th>Organization</th><td>{safe_get(whois, 'organization') or safe_get(whois, 'registrant_organization') or safe_get(whois, 'org')}</td></tr>
            <tr><th>Country</th><td>{safe_get(whois, 'country') or safe_get(whois, 'registrant_country')}</td></tr>
            <tr><th>Registrar</th><td>{safe_get(whois, 'registrar')}</td></tr>
            <tr><th>Creation Date</th><td>{safe_get(whois, 'creation_date')}</td></tr>
            <tr><th>Expiration Date</th><td>{safe_get(whois, 'expiration_date')}</td></tr>
            <tr><th>Last Updated</th><td>{safe_get(whois, 'updated_date')}</td></tr>
            <tr><th>DNSSEC</th><td>{safe_get(whois, 'dnssec', default='Unsigned')}</td></tr>
            <tr><th>Name Servers</th><td>{ns_html}</td></tr>
        </table>
        <h3>Domain Status</h3>
        {status_html}
    </div>
    """

def generate_ports_section(data, selected_tests):
    """Generate open ports section"""
    if selected_tests.get('ports') == False:
        return ''
    
    ports = data.get('open_ports', [])
    if not ports:
        return ''
    
    ports_html = '<h3>Open Ports</h3>'
    for port in ports:
        port_num = port.get('port') if isinstance(port, dict) else port
        service = port.get('service', 'Unknown') if isinstance(port, dict) else 'Unknown'
        ai_analysis = port.get('ai_analysis', {}) if isinstance(port, dict) else {}
        risk_level = safe_get(ai_analysis, 'risk_level', default='Unknown')
        description = safe_get(ai_analysis, 'description', default='')
        security_concerns = safe_get(ai_analysis, 'security_concerns', default='')
        
        risk_class = 'badge-danger' if risk_level.lower() == 'high' else 'badge-warning' if risk_level.lower() == 'medium' else 'badge-info'
        
        ports_html += f"""
        <div style="padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 10px;">
            <div style="font-weight: 600; color: #1e293b;">Port {port_num} - {service} <span class="badge {risk_class}">{risk_level} Risk</span></div>
            {f'<p style="margin: 5px 0; font-size: 9pt;">{description}</p>' if description else ''}
            {f'<p style="margin: 5px 0; font-size: 9pt; color: #dc2626;"><strong>Security Concerns:</strong> {security_concerns}</p>' if security_concerns else ''}
        </div>
        """
    
    return f'<div class="section"><h2>🔌 Open Ports</h2>{ports_html}</div>'

def generate_security_headers_section(data, selected_tests):
    """Generate security headers section"""
    if selected_tests.get('security_headers') == False:
        return ''
    
    headers = data.get('security_headers', {})
    if not headers:
        return ''
    
    present = headers.get('headers_present', [])
    missing = headers.get('missing_headers', [])
    
    return f"""
    <div class="section">
        <h2>🛡️ Security Headers</h2>
        <h3>✅ Present Headers ({len(present)})</h3>
        <ul>{''.join([f'<li>{h}</li>' for h in present]) if present else '<li>None</li>'}</ul>
        <h3>❌ Missing Headers ({len(missing)})</h3>
        <ul>{''.join([f'<li>{h}</li>' for h in missing]) if missing else '<li>None</li>'}</ul>
    </div>
    """
