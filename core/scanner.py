"""
Network Scanner Module for AutoReconX
Handles port scanning, service detection, and OS fingerprinting using nmap.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from tqdm import tqdm

from utils.logger import get_module_logger, ProgressLogger
from utils.validator import validate_target, extract_ips_from_cidr


class NetworkScanner:
    """Network scanner using nmap for reconnaissance."""
    
    def __init__(self, target, nmap_args="-sS -sV -O -A", max_threads=10):
        """
        Initialize the network scanner.
        
        Args:
            target (str): Target to scan (IP, domain, or CIDR)
            nmap_args (str): Nmap arguments
            max_threads (int): Maximum threads for parallel scanning
        """
        self.target = target
        self.nmap_args = nmap_args
        self.max_threads = max_threads
        self.logger = get_module_logger(__name__)
        self.scan_results = {}
        
        # Validate target
        self.target_info = validate_target(target)
        if not self.target_info['valid']:
            raise ValueError(f"Invalid target: {target}")
    
    def check_nmap_availability(self):
        """Check if nmap is available on the system."""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.info("Nmap is available")
                return True
            else:
                self.logger.error("Nmap is not available or not working properly")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.error("Nmap is not installed or not in PATH")
            return False
    
    def run_nmap_scan(self, target_ip, scan_type="default", output_dir=None):
        """
        Run nmap scan on a specific target.
        
        Args:
            target_ip (str): IP address to scan
            scan_type (str): Type of scan to perform
            output_dir (Path): Directory to save output files
            
        Returns:
            dict: Scan results
        """
        if not self.check_nmap_availability():
            raise RuntimeError("Nmap is not available")
        
        # Prepare nmap command
        cmd = ['nmap'] + self.nmap_args.split() + [target_ip]
        
        # Add XML output for parsing
        if output_dir:
            xml_output = output_dir / f"nmap_{target_ip.replace('.', '_')}.xml"
            cmd.extend(['-oX', str(xml_output)])
        
        self.logger.info(f"Running nmap scan: {' '.join(cmd)}")
        
        try:
            # Run nmap command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                scan_result = {
                    'target': target_ip,
                    'status': 'success',
                    'output': result.stdout,
                    'error': result.stderr,
                    'ports': self._parse_nmap_output(result.stdout),
                    'timestamp': time.time()
                }
                
                # Parse XML if available
                if output_dir and xml_output.exists():
                    scan_result.update(self._parse_nmap_xml(xml_output))
                
                return scan_result
            else:
                self.logger.error(f"Nmap scan failed for {target_ip}: {result.stderr}")
                return {
                    'target': target_ip,
                    'status': 'failed',
                    'error': result.stderr,
                    'timestamp': time.time()
                }
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timeout for {target_ip}")
            return {
                'target': target_ip,
                'status': 'timeout',
                'error': 'Scan timeout after 300 seconds',
                'timestamp': time.time()
            }
        except Exception as e:
            self.logger.error(f"Unexpected error during nmap scan: {str(e)}")
            return {
                'target': target_ip,
                'status': 'error',
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _parse_nmap_output(self, output):
        """Parse nmap text output to extract port information."""
        ports = []
        lines = output.split('\n')
        
        for line in lines:
            # Look for port lines (e.g., "22/tcp   open  ssh     OpenSSH 7.4")
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == 'open':
                    port_info = {
                        'port': parts[0].split('/')[0],
                        'protocol': parts[0].split('/')[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown',
                        'version': ' '.join(parts[3:]) if len(parts) > 3 else ''
                    }
                    ports.append(port_info)
        
        return ports
    
    def _parse_nmap_xml(self, xml_file):
        """Parse nmap XML output for detailed information."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            result = {
                'host_info': {},
                'detailed_ports': [],
                'os_detection': {}
            }
            
            # Parse host information
            host = root.find('host')
            if host is not None:
                # Host status
                status = host.find('status')
                if status is not None:
                    result['host_info']['status'] = status.get('state')
                
                # Host addresses
                addresses = host.findall('address')
                result['host_info']['addresses'] = []
                for addr in addresses:
                    result['host_info']['addresses'].append({
                        'addr': addr.get('addr'),
                        'addrtype': addr.get('addrtype')
                    })
                
                # Parse ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        state_elem = port.find('state')
                        port_info = {
                            'portid': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': state_elem.get('state') if state_elem is not None else 'unknown'
                        }
                        
                        # Service information
                        service = port.find('service')
                        if service is not None:
                            port_info.update({
                                'service': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', '')
                            })
                        
                        result['detailed_ports'].append(port_info)
                
                # Parse OS detection
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        result['os_detection'] = {
                            'name': osmatch.get('name'),
                            'accuracy': osmatch.get('accuracy')
                        }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error parsing XML output: {str(e)}")
            return {}
    
    def run_full_scan(self, output_dir=None):
        """
        Run comprehensive scan on target(s).
        
        Args:
            output_dir (Path): Directory to save scan results
            
        Returns:
            dict: Complete scan results
        """
        self.logger.info(f"Starting full scan of target: {self.target}")
        
        # Determine target IPs
        target_ips = []
        if self.target_info['type'] == 'cidr':
            # Extract IPs from CIDR range
            target_ips = extract_ips_from_cidr(self.target)
            self.logger.info(f"Extracted {len(target_ips)} IPs from CIDR range")
        else:
            # Single target
            if self.target_info['resolved_ip']:
                target_ips = [self.target_info['resolved_ip']]
            else:
                target_ips = [self.target]
        
        if not target_ips:
            raise ValueError("No valid target IPs found")
        
        # Setup progress tracking
        progress = ProgressLogger(f"{__name__}.full_scan", len(target_ips))
        
        # Prepare results structure
        results = {
            'target': self.target,
            'target_info': self.target_info,
            'scan_results': {},
            'summary': {
                'total_targets': len(target_ips),
                'successful_scans': 0,
                'failed_scans': 0,
                'open_ports_total': 0
            },
            'timestamp': time.time()
        }
        
        # Run scans (parallel for multiple targets)
        if len(target_ips) == 1:
            # Single target scan
            ip = target_ips[0]
            progress.info(f"Scanning single target: {ip}")
            scan_result = self.run_nmap_scan(ip, output_dir=output_dir)
            results['scan_results'][ip] = scan_result
            
            if scan_result['status'] == 'success':
                results['summary']['successful_scans'] = 1
                results['summary']['open_ports_total'] = len(scan_result.get('ports', []))
            else:
                results['summary']['failed_scans'] = 1
                
            progress.step(f"Completed scan of {ip}")
        else:
            # Multiple targets - use thread pool
            progress.info(f"Scanning {len(target_ips)} targets with {self.max_threads} threads")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all scan jobs
                future_to_ip = {
                    executor.submit(self.run_nmap_scan, ip, output_dir=output_dir): ip 
                    for ip in target_ips
                }
                
                # Process completed scans
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        scan_result = future.result()
                        results['scan_results'][ip] = scan_result
                        
                        if scan_result['status'] == 'success':
                            results['summary']['successful_scans'] += 1
                            results['summary']['open_ports_total'] += len(scan_result.get('ports', []))
                        else:
                            results['summary']['failed_scans'] += 1
                        
                        progress.step(f"Completed scan of {ip}")
                        
                    except Exception as e:
                        self.logger.error(f"Error processing scan result for {ip}: {str(e)}")
                        results['scan_results'][ip] = {
                            'target': ip,
                            'status': 'error',
                            'error': str(e),
                            'timestamp': time.time()
                        }
                        results['summary']['failed_scans'] += 1
                        progress.step(f"Failed scan of {ip}")
        
        progress.finish(f"Scan completed: {results['summary']['successful_scans']} successful, {results['summary']['failed_scans']} failed")
        
        self.scan_results = results
        return results


if __name__ == "__main__":
    # Test the scanner
    import tempfile
    from utils.logger import setup_logging
    
    # Setup logging
    setup_logging(level=10)  # DEBUG level
    
    # Test with a safe target
    scanner = NetworkScanner("127.0.0.1", "-sS -p 22,80,443")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        results = scanner.run_full_scan(Path(temp_dir))
        print(f"Scan completed: {results['summary']}") 