from flask import jsonify, send_file
from xhtml2pdf import pisa
from datetime import datetime
import tempfile
import os
import json
from io import BytesIO

def generate_pdf_report(data, selected_tests):
    """Generate PDF report from analysis data"""
    try:
        html_content = generate_html_content(data, selected_tests)
        
        # Create temporary file for PDF
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        
        # Generate PDF with xhtml2pdf
        with open(temp_path, 'wb') as pdf_file:
            pisa_status = pisa.CreatePDF(
                html_content,
                dest=pdf_file,
                encoding='utf-8'
            )
        
        if pisa_status.err:
            raise Exception(f"PDF generation failed with errors")
        
        return temp_path
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        raise e

def get_pdf_styles():
    """Return CSS styles for PDF"""
    return """
        @page {
            size: A4;
            margin: 15mm;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            font-size: 10pt;
        }
        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 24pt;
        }
        .section {
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            page-break-inside: avoid;
        }
        .section h2 {
            color: #0f172a;
            border-bottom: 2px solid #06b6d4;
            padding-bottom: 8px;
            margin-bottom: 15px;
            font-size: 14pt;
        }
        .section h3 {
            color: #475569;
            margin: 15px 0 10px 0;
            font-size: 12pt;
        }
        .overview-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-bottom: 15px;
        }
        .overview-item {
            padding: 12px;
            background: #f1f5f9;
            border-radius: 6px;
            border-left: 3px solid #06b6d4;
        }
        .overview-item .label {
            font-size: 8pt;
            color: #64748b;
            margin-bottom: 3px;
        }
        .overview-item .value {
            font-size: 10pt;
            font-weight: 600;
            color: #1e293b;
        }
        .risk-box {
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            text-align: center;
        }
        .risk-critical { background: #fee2e2; border: 2px solid #ef4444; }
        .risk-high { background: #fed7aa; border: 2px solid #f97316; }
        .risk-medium { background: #fef3c7; border: 2px solid #eab308; }
        .risk-low { background: #d1fae5; border: 2px solid #10b981; }
        .risk-score {
            font-size: 32pt;
            font-weight: bold;
            margin: 8px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: 9pt;
        }
        th, td {
            padding: 8px;
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
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 8pt;
            font-weight: 600;
        }
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-info { background: #dbeafe; color: #1e40af; }
        .vulnerability {
            padding: 12px;
            margin: 8px 0;
            border-left: 3px solid #ef4444;
            background: #fef2f2;
            border-radius: 4px;
            font-size: 9pt;
        }
        .safe {
            padding: 12px;
            background: #f0fdf4;
            border-left: 3px solid #10b981;
            border-radius: 4px;
            color: #166534;
            font-size: 9pt;
        }
        .recommendation {
            padding: 12px;
            margin: 8px 0;
            background: #eff6ff;
            border-left: 3px solid #3b82f6;
            border-radius: 4px;
            font-size: 9pt;
        }
        code {
            background: #f1f5f9;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 8pt;
        }
        ul {
            margin: 8px 0;
            padding-left: 20px;
        }
        li {
            margin: 4px 0;
        }
    """

def generate_html_content(data, selected_tests):
    """Generate HTML content for PDF from analysis data"""
    
    def safe_get(obj, *keys, default='N/A'):
        """Safely get nested dictionary values"""
        for key in keys:
            try:
                obj = obj[key]
            except (KeyError, TypeError, IndexError):
                return default
        return obj if obj else default
    
    # Import helper functions
    from pdf_helpers import (
        generate_overview_section,
        generate_risk_assessment_section,
        generate_ai_vulnerabilities_section,
        generate_technology_section,
        generate_vulnerabilities_section,
        generate_recommendations_section,
        generate_directory_section,
        generate_waf_section,
        generate_whois_section,
        generate_ports_section,
        generate_security_headers_section
    )
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Analysis Report</title>
    <style>
        {get_pdf_styles()}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Analysis Report</h1>
        <div style="font-size: 14pt; opacity: 0.9;">{safe_get(data, 'url')}</div>
        <p style="margin: 8px 0 0 0; opacity: 0.8; font-size: 10pt;">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    {generate_overview_section(data, selected_tests)}
    {generate_risk_assessment_section(data)}
    {generate_ai_vulnerabilities_section(data)}
    {generate_technology_section(data, selected_tests)}
    {generate_vulnerabilities_section(data, selected_tests)}
    {generate_recommendations_section(data)}
    {generate_directory_section(data, selected_tests)}
    {generate_waf_section(data, selected_tests)}
    {generate_whois_section(data, selected_tests)}
    {generate_ports_section(data, selected_tests)}
    {generate_security_headers_section(data, selected_tests)}
    
    <div style="text-align: center; padding: 15px; color: #64748b; font-size: 9pt; margin-top: 30px; border-top: 1px solid #e2e8f0;">
        <p><strong>WebReconX Security Scanner</strong></p>
        <p>Comprehensive security scan including ports, WAF, technologies, vulnerabilities, and more.</p>
        <p>© {datetime.now().year} WebReconX. All rights reserved.</p>
    </div>
</body>
</html>"""
    
    return html
