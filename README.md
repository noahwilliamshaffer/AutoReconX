# AutoReconX — Automated Pentesting Agent

AutoReconX is a command-line pentesting toolkit that automates common reconnaissance and exploitation tasks using industry-standard tools like nmap, SQLmap, and Hydra. It wraps the results into structured, exportable reports.

## 🔧 Core Features

- **Target Scanning**: IP/domain input with nmap for open ports, services, and OS detection
- **Vulnerability Probing**: SQLmap for SQL injection tests, Hydra for brute-force attacks
- **Report Generator**: Parse tool outputs and aggregate into clean tables using pandas
- **Modular CLI**: argparse-based interface with options to run specific modules or full workflow

## ⚙️ Advanced Features

- Bash wrappers for Linux-only tools (BlackArch/Kali compatibility)
- Logging with timestamped report directories
- Progress bars with tqdm
- Multi-threaded scanning (where safe)
- Pluggable architecture for new tools

## 📁 Tech Stack

- **Python**: subprocess, pandas, argparse, threading
- **Bash**: Platform-specific tool wrappers
- **External Tools**: nmap, sqlmap, hydra, dirb
- **Output Formats**: CSV, Excel, JSON

## 🚀 Installation

```bash
git clone https://github.com/noahwilliamshaffer/AutoReconX.git
cd AutoReconX
pip install -r requirements.txt
```

## 📖 Usage

```bash
# Full automated scan
python autoreconx.py --target 192.168.1.1

# Specific modules
python autoreconx.py --target example.com --scan-only
python autoreconx.py --target example.com --exploit-only

# Custom output
python autoreconx.py --target 192.168.1.1 --output /path/to/reports
```

## 🛠️ Requirements

- Python 3.8+
- nmap
- sqlmap
- hydra
- Linux environment (Kali/BlackArch recommended)

## 📊 Sample Output

AutoReconX generates structured reports in multiple formats:
- `report.csv` - Main findings summary
- `detailed_report.xlsx` - Comprehensive analysis
- `scan_results.json` - Raw data for further processing

## 🎯 Project Goals

This project simulates real-world red team tooling by:
- Automating tedious recon and reporting steps
- Blending offensive security with Python scripting
- Providing clean data handling and export capabilities

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. 