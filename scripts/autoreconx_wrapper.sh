#!/bin/bash

# AutoReconX Wrapper Script
# Provides environment checks and easier execution

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTORECONX_DIR="$(dirname "$SCRIPT_DIR")"
AUTORECONX_SCRIPT="$AUTORECONX_DIR/autoreconx.py"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
   ___         __        ____                     _  __
  / _ | __ __ / /_ ___  / __ \ ___  ____ ___   ___ | |/ /
 / __ |/ // // __// _ \/ /_/ // _ \/ __// _ \ / _ ||   / 
/_/ |_|\___/ \__/ \___/\____/ \___/\__/ \___/ \___//_/|_|  
                                                         
AutoReconX Wrapper - Automated Pentesting Agent
EOF
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This may be necessary for some scan types."
    else
        print_status "Running as regular user. Some scans may require root privileges."
    fi
}

# Check tool availability
check_tools() {
    local tools=("nmap" "python3")
    local optional_tools=("sqlmap" "hydra")
    local missing_tools=()
    local missing_optional=()
    
    print_status "Checking required tools..."
    
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        else
            print_success "$tool: $(which $tool)"
        fi
    done
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_optional+=($tool)
        else
            print_success "$tool: $(which $tool)"
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_error "Run 'sudo ./install_tools.sh' to install missing tools."
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -ne 0 ]; then
        print_warning "Missing optional tools: ${missing_optional[*]}"
        print_warning "Some functionality may be limited."
    fi
}

# Check Python dependencies
check_python_deps() {
    print_status "Checking Python dependencies..."
    
    local deps=("pandas" "colorama" "tqdm")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! python3 -c "import $dep" 2>/dev/null; then
            missing_deps+=($dep)
        else
            print_success "$dep: available"
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_warning "Missing Python dependencies: ${missing_deps[*]}"
        print_status "Installing missing dependencies..."
        pip3 install "${missing_deps[@]}"
    fi
}

# Check if AutoReconX script exists
check_script() {
    if [ ! -f "$AUTORECONX_SCRIPT" ]; then
        print_error "AutoReconX script not found at: $AUTORECONX_SCRIPT"
        exit 1
    fi
    print_success "AutoReconX script found: $AUTORECONX_SCRIPT"
}

# Create output directory with proper permissions
setup_output_dir() {
    local output_dir="${1:-./reports}"
    
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
        print_status "Created output directory: $output_dir"
    fi
    
    # Ensure proper permissions
    chmod 755 "$output_dir"
}

# Display usage information
show_usage() {
    echo "AutoReconX Wrapper Script"
    echo ""
    echo "Usage: $0 [OPTIONS] --target TARGET"
    echo ""
    echo "This wrapper performs environment checks before running AutoReconX."
    echo ""
    echo "Common Examples:"
    echo "  $0 --target 192.168.1.1                    # Full scan of single IP"
    echo "  $0 --target 192.168.1.0/24 --scan-only    # Network scan only"
    echo "  $0 --target example.com --exploit-only     # Exploitation only"
    echo "  $0 --target 10.0.0.1 --output /tmp/scan    # Custom output directory"
    echo ""
    echo "Environment Commands:"
    echo "  $0 --check-env                             # Check environment only"
    echo "  $0 --install-deps                          # Install Python dependencies"
    echo "  $0 --help                                  # Show this help"
    echo ""
    echo "All other options are passed directly to AutoReconX."
    echo "Run '$0 --target 127.0.0.1 --help' to see AutoReconX options."
}

# Install Python dependencies
install_deps() {
    print_status "Installing Python dependencies..."
    pip3 install -r "$AUTORECONX_DIR/requirements.txt"
    print_success "Dependencies installed"
}

# Main execution function
main() {
    show_banner
    check_root
    
    # Handle special commands
    case "${1:-}" in
        "--help"|"-h")
            show_usage
            exit 0
            ;;
        "--check-env")
            print_status "Performing environment check..."
            check_tools
            check_python_deps
            check_script
            print_success "Environment check completed!"
            exit 0
            ;;
        "--install-deps")
            install_deps
            exit 0
            ;;
        "")
            print_error "No arguments provided."
            show_usage
            exit 1
            ;;
    esac
    
    # Perform environment checks
    check_tools
    check_python_deps
    check_script
    
    # Extract output directory from arguments if present
    local output_dir=""
    local args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        if [[ "${args[i]}" == "--output" || "${args[i]}" == "-o" ]] && [[ $((i+1)) -lt ${#args[@]} ]]; then
            output_dir="${args[$((i+1))]}"
            break
        fi
    done
    
    # Setup output directory
    setup_output_dir "$output_dir"
    
    # Execute AutoReconX with all arguments
    print_status "Starting AutoReconX..."
    print_status "Command: python3 $AUTORECONX_SCRIPT $*"
    echo ""
    
    cd "$AUTORECONX_DIR"
    python3 "$AUTORECONX_SCRIPT" "$@"
    
    local exit_code=$?
    echo ""
    
    if [ $exit_code -eq 0 ]; then
        print_success "AutoReconX completed successfully!"
        if [ -n "$output_dir" ]; then
            print_status "Results saved to: $output_dir"
        fi
    else
        print_error "AutoReconX exited with error code: $exit_code"
    fi
    
    exit $exit_code
}

# Run main function with all arguments
main "$@" 