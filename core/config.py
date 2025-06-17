"""
Configuration Module for AutoReconX
Handles settings, tool configurations, and customizable parameters.
"""

import json
import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from utils.logger import get_module_logger


@dataclass
class ScanConfig:
    """Configuration for network scanning."""
    default_nmap_args: str = "-sS -sV -O -A"
    scan_timeout: int = 300
    max_threads: int = 10
    port_ranges: Optional[List[str]] = None
    scan_techniques: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.port_ranges is None:
            self.port_ranges = ["1-1000", "1433", "3306", "5432", "8080", "8443"]
        if self.scan_techniques is None:
            self.scan_techniques = ["tcp_syn", "tcp_connect", "udp"]


@dataclass
class ExploitConfig:
    """Configuration for vulnerability exploitation."""
    sqlmap_timeout: int = 300
    hydra_timeout: int = 600
    max_exploit_threads: int = 5
    brute_force_enabled: bool = True
    sql_injection_enabled: bool = True
    custom_wordlists: Optional[Dict[str, str]] = None
    
    def __post_init__(self):
        if self.custom_wordlists is None:
            self.custom_wordlists = {
                "usernames": "",
                "passwords": "",
                "directories": ""
            }


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    default_formats: List[str] = None
    include_raw_output: bool = True
    generate_html: bool = True
    compress_reports: bool = False
    retention_days: int = 30
    
    def __post_init__(self):
        if self.default_formats is None:
            self.default_formats = ["csv", "xlsx", "json"]


@dataclass
class ToolConfig:
    """Configuration for external tools."""
    nmap_path: str = "nmap"
    sqlmap_path: str = "sqlmap"
    hydra_path: str = "hydra"
    tool_timeout: int = 600
    verify_tools: bool = True
    custom_tool_paths: Dict[str, str] = None
    
    def __post_init__(self):
        if self.custom_tool_paths is None:
            self.custom_tool_paths = {}


@dataclass
class AutoReconXConfig:
    """Main configuration for AutoReconX."""
    scan: ScanConfig = None
    exploit: ExploitConfig = None
    report: ReportConfig = None
    tools: ToolConfig = None
    debug: bool = False
    verbose: bool = False
    log_level: str = "INFO"
    
    def __post_init__(self):
        if self.scan is None:
            self.scan = ScanConfig()
        if self.exploit is None:
            self.exploit = ExploitConfig()
        if self.report is None:
            self.report = ReportConfig()
        if self.tools is None:
            self.tools = ToolConfig()


class ConfigManager:
    """Manages AutoReconX configuration loading and saving."""
    
    def __init__(self, config_path=None):
        self.logger = get_module_logger(__name__)
        self.config_path = Path(config_path) if config_path else Path.home() / ".autoreconx" / "config.json"
        self.config = AutoReconXConfig()
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
    
    def load_config(self, config_file=None):
        """Load configuration from file."""
        if config_file:
            self.config_path = Path(config_file)
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Convert dict to config objects
                scan_config = ScanConfig(**config_data.get('scan', {}))
                exploit_config = ExploitConfig(**config_data.get('exploit', {}))
                report_config = ReportConfig(**config_data.get('report', {}))
                tools_config = ToolConfig(**config_data.get('tools', {}))
                
                self.config = AutoReconXConfig(
                    scan=scan_config,
                    exploit=exploit_config,
                    report=report_config,
                    tools=tools_config,
                    debug=config_data.get('debug', False),
                    verbose=config_data.get('verbose', False),
                    log_level=config_data.get('log_level', 'INFO')
                )
                
                self.logger.info(f"Configuration loaded from: {self.config_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to load configuration: {str(e)}")
                self.logger.warning("Using default configuration")
                self.config = AutoReconXConfig()
        else:
            self.logger.info("No configuration file found, using defaults")
            self.config = AutoReconXConfig()
    
    def save_config(self, config_file=None):
        """Save current configuration to file."""
        if config_file:
            self.config_path = Path(config_file)
        
        try:
            # Convert config to dict
            config_dict = {
                'scan': asdict(self.config.scan),
                'exploit': asdict(self.config.exploit),
                'report': asdict(self.config.report),
                'tools': asdict(self.config.tools),
                'debug': self.config.debug,
                'verbose': self.config.verbose,
                'log_level': self.config.log_level
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            self.logger.info(f"Configuration saved to: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
    
    def get_nmap_command(self, target, custom_args=None):
        """Build nmap command with configuration."""
        args = custom_args or self.config.scan.default_nmap_args
        
        # Use custom nmap path if specified
        nmap_path = self.config.tools.custom_tool_paths.get('nmap', self.config.tools.nmap_path)
        
        return f"{nmap_path} {args} {target}"
    
    def get_sqlmap_command(self, url, custom_args=None):
        """Build SQLmap command with configuration."""
        base_args = custom_args or "--batch --random-agent --level=2 --risk=2"
        
        # Use custom sqlmap path if specified
        sqlmap_path = self.config.tools.custom_tool_paths.get('sqlmap', self.config.tools.sqlmap_path)
        
        return f"{sqlmap_path} -u {url} {base_args}"
    
    def get_hydra_command(self, target, service, userlist, passlist, custom_args=None):
        """Build Hydra command with configuration."""
        base_args = custom_args or "-t 4 -w 30 -f"
        
        # Use custom hydra path if specified
        hydra_path = self.config.tools.custom_tool_paths.get('hydra', self.config.tools.hydra_path)
        
        return f"{hydra_path} -L {userlist} -P {passlist} {base_args} {target} {service}"
    
    def create_default_config(self, output_path=None):
        """Create a default configuration file."""
        if output_path:
            self.config_path = Path(output_path)
        
        self.config = AutoReconXConfig()
        self.save_config()
        
        return self.config_path
    
    def validate_config(self):
        """Validate current configuration."""
        issues = []
        
        # Check tool paths
        tools_to_check = {
            'nmap': self.config.tools.nmap_path,
            'sqlmap': self.config.tools.sqlmap_path if self.config.exploit.sql_injection_enabled else None,
            'hydra': self.config.tools.hydra_path if self.config.exploit.brute_force_enabled else None
        }
        
        for tool, path in tools_to_check.items():
            if path and not self._check_tool_availability(path):
                issues.append(f"Tool '{tool}' not found at path: {path}")
        
        # Check custom wordlists
        for wordlist_type, path in self.config.exploit.custom_wordlists.items():
            if path and not Path(path).exists():
                issues.append(f"Custom {wordlist_type} wordlist not found: {path}")
        
        # Check timeout values
        if self.config.scan.scan_timeout <= 0:
            issues.append("Scan timeout must be positive")
        
        if self.config.exploit.sqlmap_timeout <= 0:
            issues.append("SQLmap timeout must be positive")
        
        if self.config.exploit.hydra_timeout <= 0:
            issues.append("Hydra timeout must be positive")
        
        # Check thread counts
        if self.config.scan.max_threads <= 0:
            issues.append("Max scan threads must be positive")
        
        if self.config.exploit.max_exploit_threads <= 0:
            issues.append("Max exploit threads must be positive")
        
        return issues
    
    def _check_tool_availability(self, tool_path):
        """Check if a tool is available."""
        import subprocess
        try:
            result = subprocess.run([tool_path, '--help'], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def print_config(self):
        """Print current configuration in a readable format."""
        print("AutoReconX Configuration")
        print("=" * 50)
        
        print(f"\n[Scanning]")
        print(f"  Default nmap args: {self.config.scan.default_nmap_args}")
        print(f"  Scan timeout: {self.config.scan.scan_timeout}s")
        print(f"  Max threads: {self.config.scan.max_threads}")
        print(f"  Port ranges: {', '.join(self.config.scan.port_ranges)}")
        
        print(f"\n[Exploitation]")
        print(f"  SQL injection enabled: {self.config.exploit.sql_injection_enabled}")
        print(f"  Brute force enabled: {self.config.exploit.brute_force_enabled}")
        print(f"  SQLmap timeout: {self.config.exploit.sqlmap_timeout}s")
        print(f"  Hydra timeout: {self.config.exploit.hydra_timeout}s")
        print(f"  Max exploit threads: {self.config.exploit.max_exploit_threads}")
        
        print(f"\n[Reporting]")
        print(f"  Default formats: {', '.join(self.config.report.default_formats)}")
        print(f"  Include raw output: {self.config.report.include_raw_output}")
        print(f"  Generate HTML: {self.config.report.generate_html}")
        print(f"  Compress reports: {self.config.report.compress_reports}")
        
        print(f"\n[Tools]")
        print(f"  Nmap path: {self.config.tools.nmap_path}")
        print(f"  SQLmap path: {self.config.tools.sqlmap_path}")
        print(f"  Hydra path: {self.config.tools.hydra_path}")
        print(f"  Verify tools: {self.config.tools.verify_tools}")
        
        print(f"\n[General]")
        print(f"  Debug mode: {self.config.debug}")
        print(f"  Verbose mode: {self.config.verbose}")
        print(f"  Log level: {self.config.log_level}")


# Global configuration instance
config_manager = ConfigManager()


def get_config():
    """Get the global configuration instance."""
    return config_manager.config


def load_config(config_file=None):
    """Load configuration from file."""
    config_manager.load_config(config_file)
    return config_manager.config


def save_config(config_file=None):
    """Save current configuration to file."""
    config_manager.save_config(config_file)


if __name__ == "__main__":
    # Test configuration management
    config_mgr = ConfigManager()
    
    # Load or create default config
    config_mgr.load_config()
    
    # Print current configuration
    config_mgr.print_config()
    
    # Validate configuration
    issues = config_mgr.validate_config()
    if issues:
        print(f"\nConfiguration Issues:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print(f"\n✓ Configuration is valid")
    
    # Save configuration
    config_mgr.save_config()
    print(f"\nConfiguration saved to: {config_mgr.config_path}") 