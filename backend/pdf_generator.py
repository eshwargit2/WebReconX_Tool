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
    """Return CSS styles for PDF - xhtml2pdf compatible"""
    return """
        @page {
            size: A4;
            margin: 15mm;
        }
        body {
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.6;
            color: #1e293b;
            font-size: 10pt;
            background: #f8fafc;
        }
        .header {
            background: #1e293b;
            color: white;
            padding: 30px;
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
            border: 1px solid #e2e8f0;
            page-break-inside: avoid;
        }
        .section h2 {
            color: #0f172a;
            border-bottom: 3px solid #06b6d4;
            padding-bottom: 8px;
            margin-bottom: 15px;
            font-size: 14pt;
            font-weight: bold;
        }
        .section h3 {
            color: #475569;
            margin: 15px 0 10px 0;
            font-size: 12pt;
            font-weight: bold;
        }
        .section h4 {
            color: #64748b;
            margin: 12px 0 8px 0;
            font-size: 10pt;
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0 15px 0;
            font-size: 8pt;
        }
        th, td {
            padding: 8px 6px;
            text-align: left;
            border: 1px solid #e2e8f0;
        }
        th {
            background: #f1f5f9;
            font-weight: bold;
            color: #0f172a;
        }
        tr:nth-child(even) {
            background: #f8fafc;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border: 1px solid;
            font-size: 7pt;
            font-weight: bold;
        }
        .badge-success { 
            background: #d1fae5; 
            color: #065f46;
            border-color: #10b981;
        }
        .badge-danger { 
            background: #fee2e2; 
            color: #991b1b;
            border-color: #ef4444;
        }
        .badge-warning { 
            background: #fef3c7; 
            color: #92400e;
            border-color: #eab308;
        }
        .badge-info { 
            background: #dbeafe; 
            color: #1e40af;
            border-color: #3b82f6;
        }
        .stat-box {
            display: inline-block;
            width: 22%;
            padding: 10px;
            margin: 5px 1%;
            text-align: center;
            border: 2px solid;
            vertical-align: top;
        }
        .vulnerability {
            padding: 12px;
            margin: 8px 0;
            border-left: 4px solid #ef4444;
            background: #fef2f2;
            font-size: 9pt;
        }
        .safe {
            padding: 12px;
            background: #f0fdf4;
            border-left: 4px solid #10b981;
            color: #166534;
            font-size: 9pt;
        }
        .info-box {
            padding: 12px;
            margin: 12px 0;
            background: #dbeafe;
            border-left: 4px solid #3b82f6;
            font-size: 8pt;
        }
        .warning-box {
            padding: 12px;
            margin: 12px 0;
            background: #fef3c7;
            border-left: 4px solid #eab308;
            font-size: 8pt;
        }
        .recommendation {
            padding: 12px;
            margin: 8px 0;
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            font-size: 9pt;
        }
        code {
            background: #f1f5f9;
            padding: 2px 4px;
            font-family: Courier, monospace;
            font-size: 7pt;
            word-wrap: break-word;
        }
        ul {
            margin: 8px 0;
            padding-left: 20px;
        }
        li {
            margin: 4px 0;
        }
        p {
            margin: 8px 0;
        }
        strong {
            font-weight: bold;
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
