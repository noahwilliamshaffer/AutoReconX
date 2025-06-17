#!/usr/bin/env python3
"""
AutoReconX - Automated Pentesting Agent
Main CLI entry point for the automated reconnaissance and exploitation toolkit.
"""

import argparse
import sys
import os
import logging
from datetime import datetime
from pathlib import Path

# Import custom modules
from core.scanner import NetworkScanner
from core.exploiter import VulnerabilityExploiter
from core.reporter import ReportGenerator
from utils.logger import setup_logging
from utils.banner import display_banner
from utils.validator import validate_target


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AutoReconX - Automated Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1                    # Full scan
  %(prog)s --target example.com --scan-only        # Reconnaissance only
  %(prog)s --target 192.168.1.0/24 --exploit-only # Exploitation only
  %(prog)s --target 10.0.0.1 --output ./reports   # Custom output directory
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP address, domain, or CIDR range'
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--scan-only',
        action='store_true',
        help='Run reconnaissance only (no exploitation)'
    )
    mode_group.add_argument(
        '--exploit-only',
        action='store_true',
        help='Run exploitation only (assumes previous scan data exists)'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    parser.add_argument(
        '--format',
        choices=['csv', 'xlsx', 'json', 'all'],
        default='all',
        help='Report output format (default: all)'
    )
    
    # Scanning options
    parser.add_argument(
        '--nmap-args',
        default='-sS -sV -O -A',
        help='Additional nmap arguments (default: -sS -sV -O -A)'
    )
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of threads for multi-threaded operations (default: 10)'
    )
    
    # Verbosity
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    return parser.parse_args()


def setup_output_directory(output_path):
    """Create timestamped output directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(output_path) / f"autoreconx_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def main():
    """Main execution function."""
    # Parse arguments
    args = parse_arguments()
    
    # Display banner
    display_banner()
    
    # Setup output directory
    output_dir = setup_output_directory(args.output)
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(output_dir / "autoreconx.log", log_level)
    
    logger = logging.getLogger(__name__)
    logger.info(f"AutoReconX started with target: {args.target}")
    
    try:
        # Validate target
        target_validation = validate_target(args.target)
        if not target_validation['valid']:
            logger.error(f"Invalid target: {args.target}")
            sys.exit(1)
        
        # Initialize components
        scanner = NetworkScanner(args.target, args.nmap_args, args.threads)
        exploiter = VulnerabilityExploiter(args.threads)
        reporter = ReportGenerator(output_dir, args.format)
        
        scan_results = None
        exploit_results = None
        
        # Execute reconnaissance phase
        if not args.exploit_only:
            print(f"\n[+] Starting reconnaissance phase for target: {args.target}")
            scan_results = scanner.run_full_scan()
            logger.info("Reconnaissance phase completed")
        
        # Execute exploitation phase
        if not args.scan_only:
            print(f"\n[+] Starting exploitation phase")
            if scan_results:
                exploit_results = exploiter.run_exploitation(scan_results)
            else:
                # Try to load previous scan results
                logger.info("Loading previous scan results for exploitation")
                # This would be implemented to load from previous runs
                print("[-] No scan results available. Run scan first or use --scan-only.")
                sys.exit(1)
            logger.info("Exploitation phase completed")
        
        # Generate reports
        print(f"\n[+] Generating reports in {output_dir}")
        reporter.generate_reports(scan_results, exploit_results)
        
        print(f"\n[+] AutoReconX completed successfully!")
        print(f"[+] Reports saved to: {output_dir}")
        
    except KeyboardInterrupt:
        print("\n[-] Operation interrupted by user")
        logger.info("Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        print(f"[-] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 