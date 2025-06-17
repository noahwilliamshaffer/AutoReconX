# AutoReconX — Automated Pentesting Agent

AutoReconX is a comprehensive command-line pentesting toolkit that automates common reconnaissance and exploitation tasks using industry-standard tools like nmap, SQLmap, and Hydra. It provides structured, exportable reports and supports advanced configurations for professional security assessments.

## 🔧 Core Features

- **Target Scanning**: IP/domain input with nmap for open ports, services, and OS detection
- **Vulnerability Probing**: SQLmap for SQL injection tests, Hydra for brute-force attacks
- **Report Generator**: Parse tool outputs and aggregate into clean tables using pandas
- **Modular CLI**: argparse-based interface with options to run specific modules or full workflow
- **Configuration Management**: JSON-based configuration for customizable scanning parameters

## ⚙️ Advanced Features

- **Bash Wrappers**: Linux-compatible scripts for BlackArch/Kali environments
- **Automated Installation**: Tool installation and dependency management scripts
- **Logging System**: Comprehensive logging with timestamped report directories
- **Progress Tracking**: Real-time progress bars with tqdm
- **Multi-threading**: Parallel scanning and exploitation for improved performance
- **Pluggable Architecture**: Extensible design for adding new tools and modules

## 📁 Tech Stack

- **Python**: subprocess, pandas, argparse, threading, dataclasses
- **Bash**: Platform-specific tool wrappers and installation scripts
- **External Tools**: nmap, sqlmap, hydra, dirb, gobuster, nikto
- **Output Formats**: CSV, Excel, JSON, HTML

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/noahwilliamshaffer/AutoReconX.git
cd AutoReconX

# Install Python dependencies
pip install -r requirements.txt

# For Linux/Kali users - install pentesting tools
cd scripts
sudo ./install_tools.sh
```

### Basic Usage

```bash
# Full automated scan with wrapper (Linux)
./scripts/autoreconx_wrapper.sh --target 192.168.1.1

# Direct Python execution
python autoreconx.py --target 192.168.1.1

# Scan only (no exploitation)
python autoreconx.py --target example.com --scan-only

# Exploitation only (requires previous scan)
python autoreconx.py --target example.com --exploit-only

# Custom output directory
python autoreconx.py --target 192.168.1.1 --output /tmp/my-scan

# CIDR range scanning
python autoreconx.py --target 192.168.1.0/24 --threads 20
```

### Advanced Usage

```bash
# Custom nmap arguments
python autoreconx.py --target 10.0.0.1 --nmap-args "-sS -sV -p 1-65535"

# Specific output formats
python autoreconx.py --target example.com --format xlsx

# Verbose output with debugging
python autoreconx.py --target 192.168.1.1 --verbose --debug

# Environment check (Linux wrapper)
./scripts/autoreconx_wrapper.sh --check-env
```

## 🛠️ Requirements

### Core Requirements
- **Python 3.8+**
- **nmap** - Network discovery and security auditing
- **sqlmap** - SQL injection detection and exploitation
- **hydra** - Network login cracker

### Optional Tools
- **dirb** - Web content scanner
- **gobuster** - Directory/file brute-forcer
- **nikto** - Web vulnerability scanner
- **masscan** - Fast port scanner

### Operating System
- **Linux** (Kali Linux/BlackArch recommended)
- **Windows** (limited functionality, Python components only)
- **macOS** (with Homebrew package manager)

## 📊 Report Outputs

AutoReconX generates comprehensive reports in multiple formats:

### Report Files
- **`network_scan_results.csv`** - Detailed port and service information
- **`sql_injection_results.xlsx`** - SQL injection test results
- **`brute_force_results.json`** - Credential brute-force attempts
- **`executive_summary.csv`** - High-level findings summary
- **`security_findings.xlsx`** - Prioritized security issues
- **`security_report.html`** - Interactive HTML report

### Raw Data Files
- **`raw_scan_results.json`** - Complete nmap output
- **`raw_exploitation_results.json`** - Full exploitation data
- **`autoreconx.log`** - Detailed execution logs

## ⚙️ Configuration

AutoReconX supports extensive configuration through JSON files:

### Creating a Configuration
```bash
# Generate default configuration
python -c "from core.config import ConfigManager; ConfigManager().create_default_config('my_config.json')"

# Use custom configuration
python autoreconx.py --config my_config.json --target 192.168.1.1
```

### Sample Configuration
See `examples/sample_config.json` for a complete configuration example with:
- Custom tool paths and arguments
- Timeout and threading settings
- Report format preferences
- Wordlist specifications

## 🏗️ Project Structure

```
AutoReconX/
├── autoreconx.py           # Main CLI entry point
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore patterns
├── core/                  # Core modules
│   ├── scanner.py         # Network scanning module
│   ├── exploiter.py       # Vulnerability exploitation
│   ├── reporter.py        # Report generation
│   └── config.py          # Configuration management
├── utils/                 # Utility modules
│   ├── banner.py          # ASCII art and display
│   ├── logger.py          # Logging utilities
│   └── validator.py       # Input validation
├── scripts/               # Bash scripts (Linux)
│   ├── install_tools.sh   # Tool installation
│   └── autoreconx_wrapper.sh # Execution wrapper
└── examples/              # Configuration examples
    └── sample_config.json # Sample configuration
```

## 🔬 Development & Extensibility

### Adding New Tools
1. Create a new method in `core/exploiter.py`
2. Add tool configuration in `core/config.py`
3. Update the installation script in `scripts/install_tools.sh`

### Custom Report Formats
1. Extend the `ReportGenerator` class in `core/reporter.py`
2. Add format-specific methods
3. Update configuration options

### Integration Examples
```python
# Using AutoReconX as a library
from core.scanner import NetworkScanner
from core.exploiter import VulnerabilityExploiter

scanner = NetworkScanner("192.168.1.1")
results = scanner.run_full_scan()

exploiter = VulnerabilityExploiter()
vulns = exploiter.run_exploitation(results)
```

## 🎯 Use Cases

### Security Professionals
- **Penetration Testing**: Automated reconnaissance phase
- **Vulnerability Assessment**: Systematic security evaluation
- **Red Team Operations**: Initial foothold and enumeration

### Educational Purposes
- **Learning Tool**: Understanding common attack vectors
- **Lab Environments**: Safe testing in controlled settings
- **Security Research**: Analyzing tool effectiveness

### Compliance & Auditing
- **Security Audits**: Documenting system vulnerabilities
- **Compliance Checks**: Verifying security controls
- **Risk Assessment**: Quantifying security posture

## 🚨 Security & Ethics

### Responsible Use
- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Legal Compliance**: Understand and follow local cybersecurity laws
- **Scope Limitation**: Respect testing boundaries and agreements
- **Data Protection**: Handle discovered information responsibly

### Defensive Applications
- **Security Monitoring**: Understanding attacker techniques
- **System Hardening**: Identifying and fixing vulnerabilities
- **Incident Response**: Replicating attack scenarios

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/noahwilliamshaffer/AutoReconX.git
cd AutoReconX
pip install -r requirements.txt
python -m pytest tests/  # Run tests (when available)
```

## 📄 License & Disclaimer

**Educational and Authorized Testing Only**

This tool is intended for:
- Educational purposes
- Authorized penetration testing
- Security research in controlled environments

**The authors and contributors are not responsible for any misuse of this tool. Users are solely responsible for ensuring their use complies with applicable laws and regulations.**

## 🐛 Support & Issues

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check the wiki for detailed guides
- **Security**: Report security issues privately to the maintainers

---

**AutoReconX** - Bridging the gap between offensive security tools and structured data analysis. 