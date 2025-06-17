#!/bin/bash

# AutoReconX Tool Installation Script
# Installs required pentesting tools for Kali Linux / BlackArch

set -e

echo "======================================"
echo "AutoReconX Tool Installation Script"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is recommended for tool installation."
    else
        print_warning "Not running as root. Some tools may fail to install."
        print_warning "Consider running with sudo for full functionality."
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        DISTRO="unknown"
    fi
    
    print_status "Detected distribution: $DISTRO"
}

# Update package lists
update_packages() {
    print_status "Updating package lists..."
    
    case $DISTRO in
        "kali"|"debian"|"ubuntu")
            apt-get update -y
            ;;
        "arch"|"blackarch")
            pacman -Sy
            ;;
        "fedora"|"centos"|"rhel")
            yum update -y || dnf update -y
            ;;
        *)
            print_warning "Unknown distribution. Skipping package update."
            ;;
    esac
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Check if pip is installed
    if ! command -v pip3 &> /dev/null; then
        print_status "Installing pip3..."
        case $DISTRO in
            "kali"|"debian"|"ubuntu")
                apt-get install -y python3-pip
                ;;
            "arch"|"blackarch")
                pacman -S --noconfirm python-pip
                ;;
            "fedora"|"centos"|"rhel")
                yum install -y python3-pip || dnf install -y python3-pip
                ;;
        esac
    fi
    
    # Install required Python packages
    pip3 install --upgrade pip
    pip3 install -r ../requirements.txt
    print_success "Python dependencies installed"
}

# Install nmap
install_nmap() {
    print_status "Installing nmap..."
    
    if command -v nmap &> /dev/null; then
        print_success "nmap is already installed"
        nmap --version | head -1
        return
    fi
    
    case $DISTRO in
        "kali"|"debian"|"ubuntu")
            apt-get install -y nmap
            ;;
        "arch"|"blackarch")
            pacman -S --noconfirm nmap
            ;;
        "fedora"|"centos"|"rhel")
            yum install -y nmap || dnf install -y nmap
            ;;
        *)
            print_error "Cannot install nmap on unknown distribution"
            return 1
            ;;
    esac
    
    if command -v nmap &> /dev/null; then
        print_success "nmap installed successfully"
        nmap --version | head -1
    else
        print_error "nmap installation failed"
    fi
}

# Install SQLmap
install_sqlmap() {
    print_status "Installing SQLmap..."
    
    if command -v sqlmap &> /dev/null; then
        print_success "SQLmap is already installed"
        sqlmap --version
        return
    fi
    
    case $DISTRO in
        "kali"|"debian"|"ubuntu")
            apt-get install -y sqlmap
            ;;
        "arch"|"blackarch")
            pacman -S --noconfirm sqlmap
            ;;
        "fedora"|"centos"|"rhel")
            # SQLmap might not be in default repos, install via pip
            pip3 install sqlmap
            ;;
        *)
            # Fallback to pip installation
            pip3 install sqlmap
            ;;
    esac
    
    if command -v sqlmap &> /dev/null; then
        print_success "SQLmap installed successfully"
        sqlmap --version
    else
        print_error "SQLmap installation failed"
    fi
}

# Install Hydra
install_hydra() {
    print_status "Installing Hydra..."
    
    if command -v hydra &> /dev/null; then
        print_success "Hydra is already installed"
        hydra -h | head -1
        return
    fi
    
    case $DISTRO in
        "kali"|"debian"|"ubuntu")
            apt-get install -y hydra
            ;;
        "arch"|"blackarch")
            pacman -S --noconfirm hydra
            ;;
        "fedora"|"centos"|"rhel")
            yum install -y hydra || dnf install -y hydra
            ;;
        *)
            print_error "Cannot install Hydra on unknown distribution"
            return 1
            ;;
    esac
    
    if command -v hydra &> /dev/null; then
        print_success "Hydra installed successfully"
    else
        print_error "Hydra installation failed"
    fi
}

# Install additional useful tools
install_additional_tools() {
    print_status "Installing additional pentesting tools..."
    
    local tools=("dirb" "nikto" "gobuster" "masscan" "netcat" "curl" "wget")
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            print_success "$tool is already installed"
            continue
        fi
        
        print_status "Installing $tool..."
        case $DISTRO in
            "kali"|"debian"|"ubuntu")
                apt-get install -y $tool
                ;;
            "arch"|"blackarch")
                pacman -S --noconfirm $tool
                ;;
            "fedora"|"centos"|"rhel")
                yum install -y $tool || dnf install -y $tool
                ;;
        esac
        
        if command -v $tool &> /dev/null; then
            print_success "$tool installed successfully"
        else
            print_warning "$tool installation failed or not available"
        fi
    done
}

# Verify installations
verify_installations() {
    print_status "Verifying tool installations..."
    
    local tools=("nmap" "sqlmap" "hydra" "python3" "pip3")
    local failed_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            print_success "$tool: $(which $tool)"
        else
            print_error "$tool: NOT FOUND"
            failed_tools+=($tool)
        fi
    done
    
    if [ ${#failed_tools[@]} -eq 0 ]; then
        print_success "All core tools are installed and available!"
    else
        print_error "The following tools failed to install: ${failed_tools[*]}"
        print_error "AutoReconX may not function properly without these tools."
        return 1
    fi
}

# Create tool check script
create_tool_check() {
    print_status "Creating tool availability checker..."
    
    cat > check_tools.sh << 'EOF'
#!/bin/bash
# AutoReconX Tool Availability Checker

echo "AutoReconX Tool Availability Check"
echo "=================================="

tools=("nmap" "sqlmap" "hydra" "python3" "pip3")

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool: $(which $tool)"
    else
        echo "✗ $tool: NOT FOUND"
    fi
done

echo ""
echo "Python packages:"
pip3 show pandas colorama tqdm 2>/dev/null | grep "Name:\|Version:" || echo "Some Python packages may be missing"
EOF
    
    chmod +x check_tools.sh
    print_success "Tool checker script created: check_tools.sh"
}

# Main installation process
main() {
    print_status "Starting AutoReconX tool installation..."
    
    check_root
    detect_distro
    
    # Update packages first
    update_packages
    
    # Install tools
    install_python_deps
    install_nmap
    install_sqlmap
    install_hydra
    install_additional_tools
    
    # Verify installations
    verify_installations
    
    # Create helper scripts
    create_tool_check
    
    print_success "AutoReconX tool installation completed!"
    print_status "Run './check_tools.sh' to verify tool availability."
    print_status "You can now use AutoReconX with: python3 ../autoreconx.py --help"
}

# Run main function
main "$@" 