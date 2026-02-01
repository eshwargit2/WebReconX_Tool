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
    vulnerabilities = ai.get('vulnerabilities', [])
    recs = ai.get('security_recommendations', [])
    
    # Start section
    section_html = '<div class="section"><h2>💡 AI Security Recommendations</h2>'
    
    if not vulnerabilities and not recs:
        # Check if it's a quota error
        is_quota_error = ai.get('error') == 'quota_exceeded'
        
        if is_quota_error:
            section_html += """
            <div style="text-align: center; padding: 20px; background: #fff7ed; border: 2px solid #fed7aa; margin: 10px 0;">
                <div style="font-size: 36pt; margin-bottom: 10px;">⚠️</div>
                <h3 style="color: #9a3412; margin: 0 0 8px 0; font-size: 11pt;">AI Analysis Quota Exceeded</h3>
                <p style="color: #7c2d12; margin: 0 0 8px 0; font-size: 8pt;">
                    Gemini API free tier limit reached (20 requests/day).
                </p>
                <p style="color: #78350f; margin: 0; font-size: 7pt; line-height: 1.4;">
                    The scan completed successfully but detailed AI insights are unavailable. 
                    Your quota will reset in 24 hours, or you can upgrade your plan for higher limits.
                </p>
            </div>
            """
        else:
            section_html += """
            <div style="text-align: center; padding: 20px; background: #f0fdf4; border: 2px solid #86efac; margin: 10px 0;">
                <div style="font-size: 36pt; margin-bottom: 10px;">✓</div>
                <h3 style="color: #166534; margin: 0 0 8px 0; font-size: 11pt;">No Major Issues Detected</h3>
                <p style="color: #15803d; margin: 0; font-size: 8pt;">
                    The security scan completed successfully. Enable AI analysis with Gemini API key for detailed recommendations.
                </p>
            </div>
            """
        
        section_html += '</div>'
        return section_html
    
    # Generate vulnerabilities if available
    if vulnerabilities:
        section_html += '<h3 style="color: #dc2626; margin: 15px 0 10px 0;">🔴 AI-Identified Vulnerabilities</h3>'
        for idx, vuln in enumerate(vulnerabilities, 1):
            title = safe_get(vuln, 'title', default='Vulnerability')
            description = safe_get(vuln, 'description')
            severity = safe_get(vuln, 'severity', default='Unknown')
            attack_method = safe_get(vuln, 'attack_method')
            impact = safe_get(vuln, 'impact')
            fix = safe_get(vuln, 'fix')
            
            section_html += f"""
            <div class="vulnerability">
                <div class="vulnerability-title">{idx}. {title} <span class="badge badge-danger">{severity.upper()}</span></div>
                {f'<p style="margin: 5px 0; color: #334155;">{description}</p>' if description else ''}
                {f'<div style="background: #fef2f2; border: 1px solid #fca5a5; padding: 8px; margin: 5px 0;"><strong style="color: #dc2626;">Attack Method:</strong> {attack_method}</div>' if attack_method else ''}
                {f'<div style="background: #f8fafc; padding: 8px; margin: 5px 0;"><strong style="color: #f97316;">Impact:</strong> {impact}</div>' if impact else ''}
                {f'<div class="info-box" style="margin: 5px 0;"><strong style="color: #0e7490;">Fix:</strong> {fix}</div>' if fix else ''}
            </div>
            """
    
    # Generate recommendations if available
    if recs:
        section_html += '<h3 style="color: #0f172a; margin: 20px 0 10px 0;">🎯 Security Recommendations</h3>'
        for idx, rec in enumerate(recs, 1):
            category = safe_get(rec, 'category', default='General')
            recommendation = safe_get(rec, 'recommendation') or safe_get(rec, 'title', default='Security Recommendation')
            implementation = safe_get(rec, 'implementation')
            priority = safe_get(rec, 'priority', default='Medium')
            
            badge_class = 'badge-danger' if priority.lower() in ['high', 'critical'] else 'badge-warning' if priority.lower() == 'medium' else 'badge-info'
            
            section_html += f"""
            <div class="recommendation">
                <div style="font-size: 7pt; color: #64748b; text-transform: uppercase; font-weight: bold; margin-bottom: 3px;">{category}</div>
                <div style="font-weight: 600; color: #1e40af; margin-bottom: 5px;">{idx}. {recommendation}</div>
                {f'<div style="background: #f1f5f9; padding: 8px; margin: 5px 0; font-size: 7pt;"><strong style="color: #0ea5e9;">Implementation:</strong> {implementation}</div>' if implementation else ''}
                <span class="badge {badge_class}">{priority.upper()}</span>
            </div>
            """
    
    section_html += '</div>'
    return section_html

def generate_directory_section(data, selected_tests):
    """Generate directory scan section"""
    if selected_tests.get('directory') == False:
        return ''
    
    dir_scan = data.get('directory_scan', {})
    total_dirs = dir_scan.get('total_directories', 0)
    directories = dir_scan.get('directories', [])
    categories = dir_scan.get('categories', {})
    
    if total_dirs == 0:
        return ''
    
    # Helper function
    def get_category_label(category):
        labels = {
            'admin': 'Admin & Control',
            'config': 'Configuration',
            'backup': 'Backup & Temp',
            'api': 'API Endpoints',
            'content': 'Content & Media',
            'other': 'Other'
        }
        return labels.get(category, category)
    
    def format_file_size(size_bytes):
        if not size_bytes or size_bytes == 0:
            return 'N/A'
        if size_bytes < 1024:
            return f'{size_bytes} B'
        elif size_bytes < 1024 * 1024:
            return f'{size_bytes / 1024:.1f} KB'
        return f'{size_bytes / (1024 * 1024):.1f} MB'
    
    def get_category_for_dir(dir_info):
        for cat, dirs in categories.items():
            if any(d.get('url') == dir_info.get('url') for d in dirs):
                return cat
        return 'other'
    
    # Filter for status 200 only
    status_200_dirs = [d for d in directories if d.get('status_code') in [200, '200']]
    
    # Check for critical exposure
    has_critical = (len(categories.get('admin', [])) > 0) or (len(categories.get('config', [])) > 0)
    
    html = '<div class="section">'
    html += '<h2>🔍 Reconnaissance & Endpoint Discovery</h2>'
    html += '<h3>Directory Enumeration</h3>'
    html += f'<p style="font-weight: bold; margin-bottom: 10px;">{total_dirs} accessible {"directory" if total_dirs == 1 else "directories"} found</p>'
    
    # Category summary boxes
    html += '<div style="margin-bottom: 15px;">'
    html += f'<span class="stat-box" style="background: #3b82f6; color: white; display: inline-block; padding: 5px 10px; margin: 3px; font-size: 7pt; font-weight: bold;">All ({total_dirs})</span>'
    for category, dirs in categories.items():
        if len(dirs) > 0:
            label = get_category_label(category)
            html += f'<span class="stat-box" style="display: inline-block; padding: 5px 10px; margin: 3px; font-size: 7pt; font-weight: bold; border: 1px solid #64748b;">{ label} ({len(dirs)})</span>'
    html += '</div>'
    
    # Critical warning
    if has_critical:
        html += """
        <div class="warning-box" style="margin-bottom: 15px; background: #fef2f2; border: 2px solid #ef4444; padding: 10px;">
            <p style="color: #dc2626; font-weight: bold; margin: 0 0 5px 0;">⚠️ Critical Exposure Detected</p>
            <p style="color: #991b1b; margin: 0; font-size: 8pt;">
                Sensitive directories (admin/config) are publicly accessible. This may allow unauthorized access.
            </p>
        </div>
        """
    
    # Directory table (status 200 only)
    html += '<h4 style="margin: 15px 0 8px 0;">Accessible Endpoints (Status: 200 OK)</h4>'
    html += '<table style="width: 100%; margin-bottom: 15px;"><thead><tr>'
    html += '<th>Path</th><th>Category</th><th>Status</th><th>Size</th>'
    html += '</tr></thead><tbody>'
    
    for dir_info in status_200_dirs:
        path = dir_info.get('path', '/')
        category = get_category_for_dir(dir_info)
        label = get_category_label(category)
        size = format_file_size(dir_info.get('size', 0))
        
        html += f'<tr>'
        html += f'<td><code style="font-size: 7pt; word-break: break-all; color: #1e40af;">{path}</code></td>'
        html += f'<td><span class="badge badge-info" style="font-size: 6pt;">{label}</span></td>'
        html += f'<td><span class="badge badge-success">200 OK</span></td>'
        html += f'<td style="font-size: 7pt;">{size}</td>'
        html += f'</tr>'
    
    html += '</tbody></table>'
    
    # Category summary table
    html += '<div style="margin-top: 15px; padding: 10px; background: #f8fafc; border: 1px solid #e2e8f0;">'
    html += '<h4 style="margin: 0 0 10px 0;">Category Summary</h4>'
    html += '<table style="width: 100%; border: none;"><tr>'
    
    count = 0
    for category, dirs in categories.items():
        if len(dirs) > 0:
            label = get_category_label(category)
            html += f'<td style="text-align: center; padding: 8px; border: 1px solid #cbd5e1;">'
            html += f'<div style="font-size: 6pt; font-weight: bold; text-transform: uppercase; margin-bottom: 3px;">{label}</div>'
            html += f'<div style="font-size: 14pt; font-weight: bold;">{len(dirs)}</div>'
            html += f'</td>'
            count += 1
            if count % 3 == 0:
                html += '</tr><tr>'
    
    html += '</tr></table></div>'
    html += '</div>'
    
    return html

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
    
    headers_found = headers.get('headers_found', [])
    headers_missing = headers.get('headers_missing', [])
    total_score = headers.get('total_score', 0)
    max_score = headers.get('max_score', 0)
    grade = headers.get('security_grade', 'F')
    percentage = round((total_score / max_score) * 100) if max_score > 0 else 0
    
    # Grade color
    if grade == 'A':
        grade_color = '#059669'
    elif grade == 'B':
        grade_color = '#0ea5e9'
    elif grade == 'C':
        grade_color = '#eab308'
    elif grade == 'D':
        grade_color = '#f97316'
    else:
        grade_color = '#dc2626'
    
    # Present headers table
    present_html = ''
    if headers_found:
        present_html = f'<h3 style="color: #059669; margin: 20px 0 10px 0;">✅ Security Headers Present ({len(headers_found)})</h3>'
        present_html += '<table><thead><tr><th>Header</th><th>Source</th><th>Description</th><th>Value</th></tr></thead><tbody>'
        for header in headers_found:
            name = header.get('name', '')
            source = header.get('source', 'HTTP')
            description = header.get('description', '')
            value = header.get('value', '')
            # Truncate long values for PDF
            display_value = value[:100] + '...' if len(value) > 100 else value
            present_html += f'''<tr>
                <td><strong>{name}</strong></td>
                <td><span class="badge badge-info">{source}</span></td>
                <td style="color: #64748b; font-size: 8pt;">{description}</td>
                <td style="font-family: monospace; font-size: 7pt; word-break: break-all;">{display_value}</td>
            </tr>'''
        present_html += '</tbody></table>'
    else:
        present_html = '<p style="color: #64748b;">No security headers detected</p>'
    
    # Missing headers table
    missing_html = ''
    if headers_missing:
        missing_html = f'<h3 style="color: #dc2626; margin: 20px 0 10px 0;">❌ Missing Critical Headers ({len(headers_missing)})</h3>'
        missing_html += '<table><thead><tr><th>Header</th><th>Risk</th><th>Issue</th><th>Recommendation</th></tr></thead><tbody>'
        for header in headers_missing:
            name = header.get('name', '')
            risk = header.get('risk', 'Low')
            description = header.get('description', '')
            recommendation = header.get('recommendation', '')
            
            # Risk badge color
            if risk == 'Critical':
                risk_class = 'badge-danger'
            elif risk == 'High':
                risk_class = 'badge-warning'
            elif risk == 'Medium':
                risk_class = 'badge-warning'
            else:
                risk_class = 'badge-info'
            
            missing_html += f'''<tr>
                <td><strong>{name}</strong></td>
                <td><span class="badge {risk_class}">{risk}</span></td>
                <td style="color: #64748b; font-size: 8pt;">{description}</td>
                <td style="color: #475569; font-size: 8pt;">💡 {recommendation}</td>
            </tr>'''
        missing_html += '</tbody></table>'
    else:
        missing_html = '<p style="color: #059669; margin-top: 15px;">✅ All critical security headers are present</p>'
    
    return f"""
    <div class="section">
        <h2>🛡️ Security Configuration - Headers Analysis</h2>
        
        <div style="padding: 12px; background: #f8fafc; border: 2px solid #e2e8f0; margin-bottom: 15px;">
            <h3 style="margin: 0 0 12px 0; color: #1e293b; text-align: center;">Security Grade: <span style="color: {grade_color}; font-size: 1.4em;">{grade}</span> <span style="color: #64748b; font-size: 0.9em;">({total_score}/{max_score} points • {percentage}%)</span></h3>
            <div style="text-align: center;">
                <div class="stat-box" style="background: #f0fdf4; border-color: #10b981;">
                    <div style="color: #16a34a; font-size: 8pt; font-weight: bold; margin-bottom: 5px;">Present</div>
                    <div style="color: #15803d; font-size: 20pt; font-weight: bold;">{len(headers_found)}</div>
                </div>
                <div class="stat-box" style="background: #fef2f2; border-color: #ef4444;">
                    <div style="color: #dc2626; font-size: 8pt; font-weight: bold; margin-bottom: 5px;">Missing</div>
                    <div style="color: #b91c1c; font-size: 20pt; font-weight: bold;">{len(headers_missing)}</div>
                </div>
                <div class="stat-box" style="background: #eff6ff; border-color: #3b82f6;">
                    <div style="color: #2563eb; font-size: 8pt; font-weight: bold; margin-bottom: 5px;">Score</div>
                    <div style="color: #1d4ed8; font-size: 20pt; font-weight: bold;">{percentage}%</div>
                </div>
                <div class="stat-box" style="background: {grade_color}15; border-color: {grade_color};">
                    <div style="color: {grade_color}; font-size: 8pt; font-weight: bold; margin-bottom: 5px;">Grade</div>
                    <div style="color: {grade_color}; font-size: 20pt; font-weight: bold;">{grade}</div>
                </div>
            </div>
        </div>
        
        {present_html}
        {missing_html}
        
        <div class="info-box">
            <h4 style="color: #1e40af; margin: 0 0 8px 0;">About Security Headers</h4>
            <p style="color: #1e3a8a; margin: 0 0 8px 0; line-height: 1.5;">
                Security headers are HTTP response headers that instruct browsers on how to behave when handling your site's content. 
                Implementing proper security headers helps protect against common web vulnerabilities like XSS, clickjacking, and data injection attacks.
            </p>
            <div class="warning-box" style="margin: 0;">
                <p style="color: #78350f; margin: 0;">
                    <strong>⚠️ Note:</strong> Some major sites may show missing headers because they use alternative implementations. Always verify results.
                </p>
            </div>
        </div>
    </div>
    """
