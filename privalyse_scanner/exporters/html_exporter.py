"""
HTML Report Exporter - Beautiful visual compliance reports
"""
from typing import Dict, List, Any
from datetime import datetime


class HTMLExporter:
    """Export scan results as beautiful HTML reports with charts"""
    
    def __init__(self):
        self.severity_colors = {
            'critical': '#dc2626',  # Red
            'high': '#ea580c',      # Orange
            'medium': '#ca8a04',    # Yellow
            'low': '#16a34a',       # Green
            'info': '#0284c7'       # Blue
        }
        
        self.severity_labels = {
            'critical': '🔴 Critical',
            'high': '🟠 High',
            'medium': '🟡 Medium',
            'low': '🟢 Low',
            'info': 'ℹ️ Info'
        }
    
    def export(self, results: Dict[str, Any], output_path: str) -> None:
        """Export results to HTML file"""
        html = self._generate_html(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_html(self, results: Dict[str, Any]) -> str:
        """Generate complete HTML document"""
        compliance = results.get('compliance', {})
        score = compliance.get('score', 0)
        status = compliance.get('status', 'unknown')
        findings = results.get('findings', [])
        meta = results.get('meta', {})
        
        # Group findings by severity
        grouped = self._group_by_severity(findings)
        
        # Generate sections
        header = self._generate_header()
        styles = self._generate_styles()
        score_section = self._generate_score_section(score, status, compliance, grouped)
        chart_section = self._generate_chart_section(grouped)
        findings_section = self._generate_findings_section(findings, grouped)
        footer = self._generate_footer(meta)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Scan Report - Privalyse</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    {styles}
</head>
<body>
    <div class="container">
        {header}
        {score_section}
        {chart_section}
        {findings_section}
        {footer}
    </div>
    {self._generate_chart_script(grouped)}
</body>
</html>"""
    
    def _generate_header(self) -> str:
        """Generate header section"""
        return """
        <header>
            <div class="logo">
                <span class="logo-icon">🔒</span>
                <h1>Privalyse</h1>
            </div>
            <p class="subtitle">Privacy & GDPR Compliance Report</p>
            <p class="timestamp">Generated: {}</p>
        </header>
        """.format(datetime.now().strftime("%B %d, %Y at %H:%M"))
    
    def _generate_styles(self) -> str:
        """Generate CSS styles"""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 10px;
        }
        
        .logo-icon {
            font-size: 48px;
        }
        
        h1 {
            font-size: 42px;
            font-weight: 700;
        }
        
        .subtitle {
            font-size: 18px;
            opacity: 0.9;
            margin-bottom: 8px;
        }
        
        .timestamp {
            font-size: 14px;
            opacity: 0.8;
        }
        
        .score-section {
            padding: 60px 40px;
            text-align: center;
            background: linear-gradient(to bottom, #f9fafb, white);
        }
        
        .score-display {
            font-size: 120px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 20px;
        }
        
        .score-critical { color: #dc2626; }
        .score-warning { color: #ea580c; }
        .score-compliant { color: #16a34a; }
        
        .status-badge {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 9999px;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 30px;
        }
        
        .status-critical { 
            background: #fee2e2; 
            color: #dc2626; 
        }
        
        .status-warning { 
            background: #fed7aa; 
            color: #ea580c; 
        }
        
        .status-compliant { 
            background: #dcfce7; 
            color: #16a34a; 
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }
        
        .stat-card {
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        .stat-value {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .chart-section {
            padding: 40px;
            background: white;
        }
        
        .chart-container {
            max-width: 400px;
            margin: 0 auto;
        }
        
        .findings-section {
            padding: 40px;
        }
        
        .section-title {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e5e7eb;
        }
        
        .severity-group {
            margin-bottom: 40px;
        }
        
        .severity-header {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .finding-card {
            background: #f9fafb;
            border-left: 4px solid;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 16px;
        }
        
        .finding-card.critical { border-color: #dc2626; }
        .finding-card.high { border-color: #ea580c; }
        .finding-card.medium { border-color: #ca8a04; }
        .finding-card.low { border-color: #16a34a; }
        .finding-card.info { border-color: #0284c7; }
        
        .finding-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #111827;
        }
        
        .finding-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 12px;
            font-size: 14px;
            color: #6b7280;
        }
        
        .finding-code {
            background: #1f2937;
            color: #f3f4f6;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            margin: 12px 0;
        }
        
        .finding-gdpr {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 12px;
            border-radius: 6px;
            margin: 12px 0;
            font-size: 14px;
        }
        
        .finding-gdpr strong {
            color: #1e40af;
        }
        
        footer {
            background: #f9fafb;
            padding: 30px 40px;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }
        
        footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        footer a:hover {
            text-decoration: underline;
        }
        
        .disclaimer {
            margin-top: 20px;
            padding: 15px;
            background: #fef3c7;
            border: 1px solid #fde047;
            border-radius: 6px;
            font-size: 13px;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
            
            .finding-card {
                page-break-inside: avoid;
            }
        }
    </style>
        """
    
    def _generate_score_section(self, score: float, status: str, compliance: Dict, grouped: Dict) -> str:
        """Generate compliance score section"""
        # Determine score class and status badge
        if score >= 90:
            score_class = "score-compliant"
            status_class = "status-compliant"
            status_text = "✅ COMPLIANT"
        elif score >= 70:
            score_class = "score-warning"
            status_class = "status-warning"
            status_text = "⚠️ NEEDS WORK"
        else:
            score_class = "score-critical"
            status_class = "status-critical"
            status_text = "❌ CRITICAL"
        
        # Get finding counts from grouped findings (more accurate than compliance dict)
        critical = len(grouped.get('critical', []))
        high = len(grouped.get('high', []))
        medium = len(grouped.get('medium', []))
        low = len(grouped.get('low', []))
        
        return f"""
        <div class="score-section">
            <div class="score-display {score_class}">
                {score:.0f}<span style="font-size: 60px;">/100</span>
            </div>
            <div class="status-badge {status_class}">
                {status_text}
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc2626;">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ea580c;">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ca8a04;">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #16a34a;">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_chart_section(self, grouped: Dict[str, List]) -> str:
        """Generate chart section"""
        return """
        <div class="chart-section">
            <h2 class="section-title">📊 Findings Distribution</h2>
            <div class="chart-container">
                <canvas id="findingsChart"></canvas>
            </div>
        </div>
        """
    
    def _generate_findings_section(self, findings: List[Dict], grouped: Dict) -> str:
        """Generate findings list section"""
        html = '<div class="findings-section">\n'
        html += '    <h2 class="section-title">🔍 Detailed Findings</h2>\n'
        
        # Sort by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            items = grouped.get(severity, [])
            if not items:
                continue
            
            html += f'    <div class="severity-group">\n'
            html += f'        <div class="severity-header">{self.severity_labels[severity]} ({len(items)})</div>\n'
            
            for i, finding in enumerate(items, 1):
                html += self._generate_finding_card(finding, i, severity)
            
            html += '    </div>\n'
        
        html += '</div>\n'
        return html
    
    def _generate_finding_card(self, finding: Dict, index: int, severity: str) -> str:
        """Generate individual finding card"""
        rule = finding.get('rule', 'UNKNOWN')
        file_path = finding.get('file', 'N/A')
        line = finding.get('line', 'N/A')
        snippet = finding.get('snippet', '')
        classification = finding.get('classification', {})
        article = classification.get('article', 'N/A')
        reasoning = classification.get('reasoning', '')
        
        return f"""
        <div class="finding-card {severity}">
            <div class="finding-title">
                {index}. {rule.replace('_', ' ').title()}
            </div>
            <div class="finding-meta">
                <span>📍 <strong>File:</strong> {file_path}</span>
                <span>📏 <strong>Line:</strong> {line}</span>
            </div>
            {f'<div class="finding-code">{self._escape_html(snippet)}</div>' if snippet else ''}
            {f'<div class="finding-gdpr"><strong>GDPR:</strong> {article}</div>' if article != 'N/A' else ''}
            {f'<p style="margin-top: 12px; color: #4b5563;">{reasoning}</p>' if reasoning else ''}
        </div>
        """
    
    def _generate_chart_script(self, grouped: Dict) -> str:
        """Generate Chart.js script"""
        data = {
            'critical': len(grouped.get('critical', [])),
            'high': len(grouped.get('high', [])),
            'medium': len(grouped.get('medium', [])),
            'low': len(grouped.get('low', [])),
            'info': len(grouped.get('info', []))
        }
        
        return f"""
    <script>
        const ctx = document.getElementById('findingsChart');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['🔴 Critical', '🟠 High', '🟡 Medium', '🟢 Low', 'ℹ️ Info'],
                datasets: [{{
                    data: [{data['critical']}, {data['high']}, {data['medium']}, {data['low']}, {data['info']}],
                    backgroundColor: [
                        '{self.severity_colors["critical"]}',
                        '{self.severity_colors["high"]}',
                        '{self.severity_colors["medium"]}',
                        '{self.severity_colors["low"]}',
                        '{self.severity_colors["info"]}'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            font: {{
                                size: 14
                            }}
                        }}
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ': ' + context.parsed + ' findings';
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
        """
    
    def _generate_footer(self, meta: Dict) -> str:
        """Generate footer section"""
        files_scanned = meta.get('files_scanned', 0)
        # Calculate scan duration from scanner metadata if available
        scan_time = meta.get('scan_duration', 0.0)
        
        return f"""
        <footer>
            <p><strong>Generated by Privalyse v0.1.0</strong></p>
            <p>Files scanned: {files_scanned} | Scan time: {scan_time:.2f}s</p>
            <p style="margin-top: 15px;">
                <a href="https://github.com/yourusername/privalyse-cli" target="_blank">GitHub</a> •
                <a href="https://privalyse.com" target="_blank">Website</a> •
                <a href="https://github.com/yourusername/privalyse-cli/blob/main/DETECTION_RULES.md" target="_blank">Detection Rules</a>
            </p>
            <div class="disclaimer">
                ⚠️ <strong>Disclaimer:</strong> This is a technical report generated by automated code analysis. 
                It should not be considered as legal advice. Please consult with legal experts for compliance verification.
            </div>
        </footer>
        """
    
    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in grouped:
                grouped[severity].append(finding)
        
        return grouped
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))
