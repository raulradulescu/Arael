#!/usr/bin/env python3
"""
HTML Report Generator
Create a comprehensive HTML report from Arael analysis.
"""

import json
import sys
from pathlib import Path
from datetime import datetime


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Binary Analysis Report - {filename}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1e1e1e;
            color: #d4d4d4;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #252526;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #4ec9b0;
            border-bottom: 2px solid #4ec9b0;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #569cd6;
            margin-top: 30px;
        }}
        .metadata {{
            background: #2d2d30;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .metadata dt {{
            color: #9cdcfe;
            font-weight: bold;
            width: 200px;
            display: inline-block;
        }}
        .metadata dd {{
            display: inline;
            margin: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #2d2d30;
        }}
        th {{
            background: #3c3c3c;
            color: #4ec9b0;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #4ec9b0;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #3c3c3c;
        }}
        tr:hover {{
            background: #333333;
        }}
        .code {{
            background: #1e1e1e;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            color: #d4d4d4;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-success {{ background: #0e639c; color: white; }}
        .badge-warning {{ background: #ff8c00; color: white; }}
        .badge-danger {{ background: #f44747; color: white; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #2d2d30;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #4ec9b0;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #4ec9b0;
        }}
        .stat-label {{
            color: #858585;
            margin-top: 5px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #3c3c3c;
            color: #858585;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Binary Analysis Report</h1>
        <p>Generated on {timestamp} by Arael</p>

        <h2>Binary Metadata</h2>
        <dl class="metadata">
            <dt>File Name:</dt><dd>{filename}</dd><br>
            <dt>Format:</dt><dd>{format}</dd><br>
            <dt>Architecture:</dt><dd>{architecture} ({addressSize}-bit)</dd><br>
            <dt>Compiler:</dt><dd>{compiler}</dd><br>
        </dl>

        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{func_count:,}</div>
                <div class="stat-label">Functions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{string_count:,}</div>
                <div class="stat-label">Strings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{import_count:,}</div>
                <div class="stat-label">Imports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{section_count:,}</div>
                <div class="stat-label">Sections</div>
            </div>
        </div>

        <h2>Top 10 Largest Functions</h2>
        <table>
            <thead>
                <tr>
                    <th>Function Name</th>
                    <th>Address</th>
                    <th>Size</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                {top_functions}
            </tbody>
        </table>

        <h2>Memory Sections</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Start</th>
                    <th>End</th>
                    <th>Size</th>
                    <th>Permissions</th>
                </tr>
            </thead>
            <tbody>
                {sections}
            </tbody>
        </table>

        {security_section}

        <div class="footer">
            <p>Generated by <strong>Arael</strong> - Reverse Engineering Assistant</p>
            <p>Analysis powered by Ghidra with PyGhidra</p>
        </div>
    </div>
</body>
</html>
"""


def generate_report(data):
    """Generate HTML report from analysis data."""

    # Top functions
    top_funcs = sorted(data['functions'], key=lambda x: x['size'], reverse=True)[:10]
    top_functions_html = ''
    for func in top_funcs:
        badge = 'badge-success' if not func['isExternal'] else 'badge-warning'
        func_type = 'Internal' if not func['isExternal'] else 'External'
        top_functions_html += f'''
            <tr>
                <td>{func["name"]}</td>
                <td><code>{func["address"]}</code></td>
                <td>{func["size"]:,} bytes</td>
                <td><span class="badge {badge}">{func_type}</span></td>
            </tr>
        '''

    # Sections
    sections_html = ''
    if 'sections' in data:
        for sec in data['sections'][:20]:
            perms = sec['permissions']
            perm_str = ('R' if perms['read'] else '-') + \
                       ('W' if perms['write'] else '-') + \
                       ('X' if perms['execute'] else '-')

            badge = 'badge-danger' if perms['execute'] and perms['write'] else 'badge-success'

            sections_html += f'''
                <tr>
                    <td>{sec["name"]}</td>
                    <td><code>{sec["start"]}</code></td>
                    <td><code>{sec["end"]}</code></td>
                    <td>{sec["size"]:,} bytes</td>
                    <td><span class="badge {badge}">{perm_str}</span></td>
                </tr>
            '''

    # Security findings
    security_keywords = ['password', 'key', 'secret', 'token', 'flag']
    findings = []
    for s in data.get('strings', []):
        if any(kw in s['value'].lower() for kw in security_keywords):
            findings.append(s)

    security_html = ''
    if findings:
        security_html = '<h2>Security Findings</h2><table><thead><tr><th>Address</th><th>String</th></tr></thead><tbody>'
        for s in findings[:20]:
            val = s['value'].replace('<', '&lt;').replace('>', '&gt;')[:100]
            security_html += f'<tr><td><code>{s["address"]}</code></td><td>{val}</td></tr>'
        security_html += '</tbody></table>'

    # Fill template
    return HTML_TEMPLATE.format(
        filename=data.get('filename', 'Unknown'),
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        format=data.get('format', 'Unknown'),
        architecture=data.get('architecture', 'Unknown'),
        addressSize=data.get('addressSize', 0),
        compiler=data.get('compiler', 'Unknown'),
        func_count=len(data.get('functions', [])),
        string_count=len(data.get('strings', [])),
        import_count=len(data.get('imports', [])),
        section_count=len(data.get('sections', [])),
        top_functions=top_functions_html,
        sections=sections_html,
        security_section=security_html
    )


def main():
    if len(sys.argv) < 2:
        print('Usage: generate_report.py <analysis.json> [output.html]')
        print('\nExample:')
        print('  python generate_report.py analysis.json report.html')
        sys.exit(1)

    json_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'report.html'

    if not Path(json_path).exists():
        print(f'Error: File not found: {json_path}')
        sys.exit(1)

    print(f'Loading analysis from {json_path}...')
    with open(json_path, 'r') as f:
        data = json.load(f)

    print('Generating HTML report...')
    html = generate_report(data)

    with open(output_path, 'w') as f:
        f.write(html)

    print(f'\n✓ Report saved to: {output_path}')
    print(f'  Open it in your browser to view the analysis.')


if __name__ == '__main__':
    main()
