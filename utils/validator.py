"""
Target validation utilities for AutoReconX
Validates IP addresses, domains, and CIDR ranges.
"""

import re
import socket
import ipaddress
import validators
from urllib.parse import urlparse


def is_valid_ip(ip_str):
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_str):
    """Check if string is a valid CIDR range."""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain_str):
    """Check if string is a valid domain name."""
    # Use validators library for comprehensive domain validation
    return validators.domain(domain_str) is True


def is_valid_url(url_str):
    """Check if string is a valid URL."""
    return validators.url(url_str) is True


def resolve_hostname(hostname):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def validate_target(target):
    """
    Validate target input (IP, domain, CIDR, or URL).
    
    Args:
        target (str): Target to validate
        
    Returns:
        dict: Validation result with type and normalized target
    """
    target = target.strip()
    
    # Check if it's a valid IP address
    if is_valid_ip(target):
        return {
            'valid': True,
            'type': 'ip',
            'target': target,
            'resolved_ip': target
        }
    
    # Check if it's a valid CIDR range
    if is_valid_cidr(target):
        return {
            'valid': True,
            'type': 'cidr',
            'target': target,
            'resolved_ip': None
        }
    
    # Check if it's a valid URL
    if is_valid_url(target):
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        resolved_ip = resolve_hostname(hostname) if hostname else None
        return {
            'valid': True,
            'type': 'url',
            'target': target,
            'hostname': hostname,
            'resolved_ip': resolved_ip
        }
    
    # Check if it's a valid domain
    if is_valid_domain(target):
        resolved_ip = resolve_hostname(target)
        return {
            'valid': True,
            'type': 'domain',
            'target': target,
            'resolved_ip': resolved_ip
        }
    
    # If none of the above, it's invalid
    return {
        'valid': False,
        'type': 'unknown',
        'target': target,
        'resolved_ip': None
    }


def extract_ips_from_cidr(cidr_str):
    """Extract all IP addresses from a CIDR range."""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def is_private_ip(ip_str):
    """Check if IP address is in private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def is_local_ip(ip_str):
    """Check if IP address is localhost/loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    # Test the validator
    test_targets = [
        "192.168.1.1",
        "10.0.0.0/24",
        "google.com",
        "https://example.com",
        "invalid..target",
        "127.0.0.1"
    ]
    
    for target in test_targets:
        result = validate_target(target)
        print(f"Target: {target}")
        print(f"  Valid: {result['valid']}")
        print(f"  Type: {result['type']}")
        print(f"  Resolved IP: {result.get('resolved_ip', 'N/A')}")
        print() 