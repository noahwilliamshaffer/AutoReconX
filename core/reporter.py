"""
Report Generator Module for AutoReconX
Handles data aggregation and export to CSV, Excel, and JSON formats using pandas.
"""

import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import time

from utils.logger import get_module_logger


class ReportGenerator:
    """Report generator for scan and exploitation results."""
    
    def __init__(self, output_dir, output_formats=['csv', 'xlsx', 'json']):
        """
        Initialize the report generator.
        
        Args:
            output_dir (Path): Directory to save reports
            output_formats (list): List of output formats to generate
        """
        self.output_dir = Path(output_dir)
        self.output_formats = output_formats if isinstance(output_formats, list) else [output_formats]
        self.logger = get_module_logger(__name__)
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_reports(self, scan_results=None, exploit_results=None):
        """
        Generate comprehensive reports from scan and exploitation results.
        
        Args:
            scan_results (dict): Network scan results
            exploit_results (dict): Vulnerability exploitation results
        """
        self.logger.info("Starting report generation")
        
        # Generate individual reports
        if scan_results:
            self._generate_scan_reports(scan_results)
        
        if exploit_results:
            self._generate_exploitation_reports(exploit_results)
        
        # Generate combined summary report
        if scan_results or exploit_results:
            self._generate_summary_report(scan_results, exploit_results)
        
        self.logger.info(f"Reports saved to: {self.output_dir}")
    
    def _generate_scan_reports(self, scan_results):
        """Generate reports for network scan results."""
        self.logger.info("Generating network scan reports")
        
        # Extract scan data for tabular format
        scan_data = []
        
        for ip, result in scan_results.get('scan_results', {}).items():
            if result.get('status') == 'success':
                ports = result.get('ports', [])
                
                if ports:
                    for port_info in ports:
                        scan_data.append({
                            'target_ip': ip,
                            'port': port_info.get('port', ''),
                            'protocol': port_info.get('protocol', ''),
                            'state': port_info.get('state', ''),
                            'service': port_info.get('service', ''),
                            'version': port_info.get('version', ''),
                            'scan_time': datetime.fromtimestamp(result.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')
                        })
                else:
                    # No open ports found
                    scan_data.append({
                        'target_ip': ip,
                        'port': 'N/A',
                        'protocol': 'N/A',
                        'state': 'No open ports',
                        'service': 'N/A',
                        'version': 'N/A',
                        'scan_time': datetime.fromtimestamp(result.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')
                    })
            else:
                # Failed scan
                scan_data.append({
                    'target_ip': ip,
                    'port': 'N/A',
                    'protocol': 'N/A',
                    'state': f"Scan failed: {result.get('status', 'unknown')}",
                    'service': 'N/A',
                    'version': 'N/A',
                    'scan_time': datetime.fromtimestamp(result.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')
                })
        
        if scan_data:
            df_scan = pd.DataFrame(scan_data)
            self._save_dataframe(df_scan, 'network_scan_results')
        
        # Generate scan summary
        summary_data = []
        summary = scan_results.get('summary', {})
        summary_data.append({
            'metric': 'Total Targets',
            'value': summary.get('total_targets', 0),
            'description': 'Number of targets scanned'
        })
        summary_data.append({
            'metric': 'Successful Scans',
            'value': summary.get('successful_scans', 0),
            'description': 'Number of successful scans'
        })
        summary_data.append({
            'metric': 'Failed Scans',
            'value': summary.get('failed_scans', 0),
            'description': 'Number of failed scans'
        })
        summary_data.append({
            'metric': 'Total Open Ports',
            'value': summary.get('open_ports_total', 0),
            'description': 'Total number of open ports found'
        })
        
        df_summary = pd.DataFrame(summary_data)
        self._save_dataframe(df_summary, 'scan_summary')
        
        # Save raw scan results as JSON
        if 'json' in self.output_formats:
            json_file = self.output_dir / 'raw_scan_results.json'
            with open(json_file, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)
    
    def _generate_exploitation_reports(self, exploit_results):
        """Generate reports for exploitation results."""
        self.logger.info("Generating exploitation reports")
        
        # SQL injection results
        sqlmap_results = exploit_results.get('exploitation_results', {}).get('sqlmap', {})
        if sqlmap_results.get('status') == 'completed':
            sql_data = []
            
            for test in sqlmap_results.get('targets_tested', []):
                target = test.get('target', {})
                sql_data.append({
                    'target_ip': target.get('ip', ''),
                    'target_port': target.get('port', ''),
                    'target_url': target.get('url', ''),
                    'service': target.get('service', ''),
                    'test_status': test.get('status', ''),
                    'vulnerable': 'Yes' if test.get('vulnerable', False) else 'No',
                    'error': test.get('error', ''),
                    'command_used': test.get('command', '')
                })
            
            if sql_data:
                df_sql = pd.DataFrame(sql_data)
                self._save_dataframe(df_sql, 'sql_injection_results')
        
        # Brute-force results
        hydra_results = exploit_results.get('exploitation_results', {}).get('hydra', {})
        if hydra_results.get('status') == 'completed':
            bf_data = []
            
            for attack in hydra_results.get('targets_attacked', []):
                target = attack.get('target', {})
                credentials = attack.get('credentials_found', [])
                
                if credentials:
                    for cred in credentials:
                        bf_data.append({
                            'target_ip': target.get('ip', ''),
                            'target_port': target.get('port', ''),
                            'service': target.get('service', ''),
                            'attack_status': attack.get('status', ''),
                            'credentials_found': 'Yes',
                            'username': cred.get('username', ''),
                            'password': cred.get('password', ''),
                            'command_used': attack.get('command', '')
                        })
                else:
                    bf_data.append({
                        'target_ip': target.get('ip', ''),
                        'target_port': target.get('port', ''),
                        'service': target.get('service', ''),
                        'attack_status': attack.get('status', ''),
                        'credentials_found': 'No',
                        'username': '',
                        'password': '',
                        'command_used': attack.get('command', '')
                    })
            
            if bf_data:
                df_bf = pd.DataFrame(bf_data)
                self._save_dataframe(df_bf, 'brute_force_results')
        
        # Exploitation summary
        exploit_summary_data = []
        summary = exploit_results.get('summary', {})
        exploit_summary_data.append({
            'metric': 'Total Vulnerabilities',
            'value': summary.get('total_vulnerabilities', 0),
            'description': 'Total vulnerabilities found'
        })
        exploit_summary_data.append({
            'metric': 'SQL Injection Vulnerabilities',
            'value': summary.get('sql_injection_vulns', 0),
            'description': 'SQL injection vulnerabilities found'
        })
        exploit_summary_data.append({
            'metric': 'Brute-force Successes',
            'value': summary.get('brute_force_successes', 0),
            'description': 'Successful brute-force attacks'
        })
        
        df_exploit_summary = pd.DataFrame(exploit_summary_data)
        self._save_dataframe(df_exploit_summary, 'exploitation_summary')
        
        # Save raw exploitation results as JSON
        if 'json' in self.output_formats:
            json_file = self.output_dir / 'raw_exploitation_results.json'
            with open(json_file, 'w') as f:
                json.dump(exploit_results, f, indent=2, default=str)
    
    def _generate_summary_report(self, scan_results=None, exploit_results=None):
        """Generate comprehensive summary report."""
        self.logger.info("Generating comprehensive summary report")
        
        # Create executive summary
        summary_data = {
            'report_generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': scan_results.get('target', 'Unknown') if scan_results else 'Unknown'
        }
        
        # Scanning statistics
        if scan_results:
            summary_data.update({
                'total_targets_scanned': scan_results.get('summary', {}).get('total_targets', 0),
                'successful_scans': scan_results.get('summary', {}).get('successful_scans', 0),
                'failed_scans': scan_results.get('summary', {}).get('failed_scans', 0),
                'total_open_ports': scan_results.get('summary', {}).get('open_ports_total', 0)
            })
        
        # Exploitation statistics
        if exploit_results:
            summary_data.update({
                'total_vulnerabilities': exploit_results.get('summary', {}).get('total_vulnerabilities', 0),
                'sql_injection_vulns': exploit_results.get('summary', {}).get('sql_injection_vulns', 0),
                'brute_force_successes': exploit_results.get('summary', {}).get('brute_force_successes', 0)
            })
        
        # Convert to DataFrame for consistent formatting
        summary_list = []
        for key, value in summary_data.items():
            summary_list.append({
                'metric': key.replace('_', ' ').title(),
                'value': value
            })
        
        df_executive_summary = pd.DataFrame(summary_list)
        self._save_dataframe(df_executive_summary, 'executive_summary')
        
        # Generate findings summary (combine critical findings)
        findings_data = []
        
        if scan_results:
            # Extract interesting services
            for ip, result in scan_results.get('scan_results', {}).items():
                if result.get('status') == 'success':
                    ports = result.get('ports', [])
                    for port_info in ports:
                        service = port_info.get('service', '').lower()
                        port = port_info.get('port', '')
                        
                        # Flag interesting services
                        if any(keyword in service for keyword in ['ssh', 'ftp', 'telnet', 'mysql', 'postgres', 'mssql', 'http', 'https']):
                            findings_data.append({
                                'finding_type': 'Open Service',
                                'severity': 'Info',
                                'target': ip,
                                'port': port,
                                'service': service,
                                'description': f"{service.upper()} service detected on port {port}",
                                'recommendation': f"Ensure {service.upper()} service is properly secured and configured"
                            })
        
        if exploit_results:
            # SQL injection vulnerabilities
            sqlmap_results = exploit_results.get('exploitation_results', {}).get('sqlmap', {})
            for vuln in sqlmap_results.get('vulnerabilities_found', []):
                target = vuln.get('target', {})
                findings_data.append({
                    'finding_type': 'SQL Injection',
                    'severity': 'High',
                    'target': target.get('ip', ''),
                    'port': target.get('port', ''),
                    'service': target.get('service', ''),
                    'description': f"SQL injection vulnerability found on {target.get('url', '')}",
                    'recommendation': 'Implement input validation and parameterized queries'
                })
            
            # Brute-force successes
            hydra_results = exploit_results.get('exploitation_results', {}).get('hydra', {})
            for success in hydra_results.get('successful_attacks', []):
                target = success.get('target', {})
                credentials = success.get('credentials_found', [])
                cred_count = len(credentials)
                findings_data.append({
                    'finding_type': 'Weak Credentials',
                    'severity': 'High',
                    'target': target.get('ip', ''),
                    'port': target.get('port', ''),
                    'service': target.get('service', ''),
                    'description': f"Weak credentials found for {target.get('service', '')} service ({cred_count} credential(s))",
                    'recommendation': 'Implement strong password policies and consider multi-factor authentication'
                })
        
        if findings_data:
            df_findings = pd.DataFrame(findings_data)
            self._save_dataframe(df_findings, 'security_findings')
    
    def _save_dataframe(self, df, filename):
        """Save DataFrame in specified formats."""
        for format_type in self.output_formats:
            if format_type.lower() == 'csv':
                file_path = self.output_dir / f"{filename}.csv"
                df.to_csv(file_path, index=False)
                self.logger.info(f"Saved CSV report: {file_path}")
            
            elif format_type.lower() == 'xlsx':
                file_path = self.output_dir / f"{filename}.xlsx"
                df.to_excel(file_path, index=False, engine='openpyxl')
                self.logger.info(f"Saved Excel report: {file_path}")
            
            elif format_type.lower() == 'json':
                file_path = self.output_dir / f"{filename}.json"
                df.to_json(file_path, orient='records', indent=2)
                self.logger.info(f"Saved JSON report: {file_path}")
    
    def generate_html_report(self, scan_results=None, exploit_results=None):
        """Generate an HTML report with styled tables."""
        self.logger.info("Generating HTML report")
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AutoReconX Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { text-align: center; color: #2c3e50; }
                .summary { background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
                table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #3498db; color: white; }
                .high-severity { background-color: #e74c3c; color: white; }
                .medium-severity { background-color: #f39c12; color: white; }
                .low-severity { background-color: #27ae60; color: white; }
                .vulnerable { background-color: #e74c3c; color: white; }
                .safe { background-color: #27ae60; color: white; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AutoReconX Security Assessment Report</h1>
                <p>Generated on: {timestamp}</p>
            </div>
        """.format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Add summary section
        if scan_results or exploit_results:
            html_content += '<div class="summary"><h2>Executive Summary</h2>'
            
            if scan_results:
                summary = scan_results.get('summary', {})
                html_content += f"""
                <p><strong>Target:</strong> {scan_results.get('target', 'Unknown')}</p>
                <p><strong>Total Targets Scanned:</strong> {summary.get('total_targets', 0)}</p>
                <p><strong>Open Ports Found:</strong> {summary.get('open_ports_total', 0)}</p>
                """
            
            if exploit_results:
                summary = exploit_results.get('summary', {})
                html_content += f"""
                <p><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</p>
                <p><strong>SQL Injection Vulnerabilities:</strong> {summary.get('sql_injection_vulns', 0)}</p>
                <p><strong>Brute-force Successes:</strong> {summary.get('brute_force_successes', 0)}</p>
                """
            
            html_content += '</div>'
        
        html_content += '</body></html>'
        
        # Save HTML report
        html_file = self.output_dir / 'security_report.html'
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {html_file}")


if __name__ == "__main__":
    # Test the reporter
    from utils.logger import setup_logging
    import tempfile
    
    # Setup logging
    setup_logging(level=10)  # DEBUG level
    
    # Mock data for testing
    mock_scan_results = {
        'target': '192.168.1.1',
        'scan_results': {
            '192.168.1.1': {
                'status': 'success',
                'ports': [
                    {'port': '22', 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.4'},
                    {'port': '80', 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'nginx 1.18'}
                ],
                'timestamp': time.time()
            }
        },
        'summary': {
            'total_targets': 1,
            'successful_scans': 1,
            'failed_scans': 0,
            'open_ports_total': 2
        }
    }
    
    mock_exploit_results = {
        'summary': {
            'total_vulnerabilities': 1,
            'sql_injection_vulns': 1,
            'brute_force_successes': 0
        },
        'exploitation_results': {
            'sqlmap': {
                'status': 'completed',
                'vulnerabilities_found': [
                    {
                        'target': {'ip': '192.168.1.1', 'port': '80', 'url': 'http://192.168.1.1/'},
                        'vulnerable': True
                    }
                ]
            }
        }
    }
    
    # Test report generation
    with tempfile.TemporaryDirectory() as temp_dir:
        reporter = ReportGenerator(temp_dir, ['csv', 'json'])
        reporter.generate_reports(mock_scan_results, mock_exploit_results)
        print(f"Test reports generated in: {temp_dir}") 