#!/bin/bash
#
# Firefox Forensics Tool - Setup Script
# Installs system dependencies for password decryption
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Supported platforms:
#   - Arch Linux / Manjaro
#   - Ubuntu / Debian / Linux Mint / Pop!_OS
#   - Fedora / RHEL / CentOS / Rocky Linux
#   - openSUSE
#   - macOS (via Homebrew)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║  🔧 Firefox Forensics Tool - Setup Script                            ║"
    echo "║  Installing system dependencies...                                   ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print status messages
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            arch|manjaro|endeavouros|garuda|artix)
                echo "arch"
                ;;
            ubuntu|debian|linuxmint|pop|elementary|zorin|kali)
                echo "debian"
                ;;
            fedora|rhel|centos|rocky|almalinux)
                echo "fedora"
                ;;
            opensuse*|suse)
                echo "opensuse"
                ;;
            *)
                # Try ID_LIKE as fallback
                case "$ID_LIKE" in
                    *arch*)
                        echo "arch"
                        ;;
                    *debian*|*ubuntu*)
                        echo "debian"
                        ;;
                    *fedora*|*rhel*)
                        echo "fedora"
                        ;;
                    *)
                        echo "unknown"
                        ;;
                esac
                ;;
        esac
    else
        echo "unknown"
    fi
}

# Check if running as root
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        SUDO=""
    else
        SUDO="sudo"
        if ! command -v sudo &> /dev/null; then
            error "sudo is not installed and you're not root"
            error "Please run as root or install sudo"
            exit 1
        fi
    fi
}

# Check Python version
check_python() {
    info "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
        PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 9 ]; then
            success "Python $PYTHON_VERSION found"
            return 0
        else
            warn "Python $PYTHON_VERSION found but 3.9+ recommended"
            return 0
        fi
    else
        warn "Python 3 not found"
        return 1
    fi
}

# Install dependencies for Arch Linux
install_arch() {
    info "Detected Arch Linux / Arch-based distro"
    info "Installing NSS library..."
    
    $SUDO pacman -Sy --noconfirm nss
    
    success "NSS library installed"
}

# Install dependencies for Debian/Ubuntu
install_debian() {
    info "Detected Debian / Ubuntu-based distro"
    info "Installing NSS library..."
    
    $SUDO apt-get update
    $SUDO apt-get install -y libnss3
    
    success "NSS library installed"
}

# Install dependencies for Fedora/RHEL
install_fedora() {
    info "Detected Fedora / RHEL-based distro"
    info "Installing NSS library..."
    
    $SUDO dnf install -y nss
    
    success "NSS library installed"
}

# Install dependencies for openSUSE
install_opensuse() {
    info "Detected openSUSE"
    info "Installing NSS library..."
    
    $SUDO zypper install -y mozilla-nss
    
    success "NSS library installed"
}

# Install dependencies for macOS
install_macos() {
    info "Detected macOS"
    
    if ! command -v brew &> /dev/null; then
        warn "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    info "Installing NSS library via Homebrew..."
    brew install nss
    
    success "NSS library installed"
}

# Check for Snap/Flatpak Firefox
check_firefox_installation() {
    echo ""
    info "Checking Firefox installation..."
    
    # Check for Snap Firefox
    if [ -d "$HOME/snap/firefox" ] || [ -d "/snap/firefox" ]; then
        warn "Snap Firefox detected!"
        echo -e "${YELLOW}"
        echo "╔══════════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠️  WARNING: Snap Firefox Detected                                  ║"
        echo "╠══════════════════════════════════════════════════════════════════════╣"
        echo "║  Password decryption will NOT work with Snap Firefox.               ║"
        echo "║  Snap Firefox uses its own bundled NSS library in a sandbox.        ║"
        echo "║                                                                     ║"
        echo "║  To use password decryption, install native Firefox:                ║"
        echo "║    $ sudo snap remove firefox                                       ║"
        echo "║    $ sudo apt install firefox  # or use your package manager        ║"
        echo "╚══════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi
    
    # Check for Flatpak Firefox
    if [ -d "$HOME/.var/app/org.mozilla.firefox" ]; then
        warn "Flatpak Firefox detected!"
        echo -e "${YELLOW}"
        echo "╔══════════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠️  WARNING: Flatpak Firefox Detected                               ║"
        echo "╠══════════════════════════════════════════════════════════════════════╣"
        echo "║  Password decryption will NOT work with Flatpak Firefox.            ║"
        echo "║  Flatpak Firefox uses its own bundled NSS library in a sandbox.     ║"
        echo "║                                                                     ║"
        echo "║  To use password decryption, install native Firefox:                ║"
        echo "║    $ flatpak uninstall org.mozilla.firefox                          ║"
        echo "║    $ sudo pacman -S firefox  # or use your package manager          ║"
        echo "╚══════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    fi
    
    # Check for native Firefox
    if [ -f "/usr/bin/firefox" ] || [ -f "/usr/lib/firefox/firefox" ]; then
        success "Native Firefox installation found"
    fi
}

# Verify NSS installation
verify_nss() {
    echo ""
    info "Verifying NSS library installation..."
    
    NSS_PATHS=(
        "/usr/lib/libnss3.so"
        "/usr/lib64/libnss3.so"
        "/usr/lib/x86_64-linux-gnu/libnss3.so"
        "/usr/lib/i386-linux-gnu/libnss3.so"
        "/opt/homebrew/lib/libnss3.dylib"
        "/usr/local/lib/libnss3.dylib"
    )
    
    for path in "${NSS_PATHS[@]}"; do
        if [ -f "$path" ]; then
            success "NSS library found at: $path"
            return 0
        fi
    done
    
    # Try ldconfig
    if ldconfig -p 2>/dev/null | grep -q libnss3; then
        success "NSS library found in system library cache"
        return 0
    fi
    
    error "NSS library not found after installation"
    return 1
}

# Create virtual environment (optional)
setup_venv() {
    echo ""
    read -p "Would you like to create a Python virtual environment? [y/N] " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Creating virtual environment..."
        python3 -m venv venv
        success "Virtual environment created in ./venv"
        echo ""
        info "To activate the virtual environment:"
        echo "    source venv/bin/activate"
    fi
}

# Run environment check
run_env_check() {
    echo ""
    info "Running environment compatibility check..."
    echo ""
    
    if [ -f "nss_decrypt.py" ]; then
        python3 nss_decrypt.py --check || true
    else
        warn "nss_decrypt.py not found in current directory"
        warn "Run this script from the project root directory"
    fi
}

# Print final instructions
print_final() {
    echo ""
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║  ✅ Setup Complete!                                                   ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BOLD}Usage:${NC}"
    echo "  # Extract Firefox forensic data:"
    echo "  python3 main.py ~/.mozilla/firefox/your-profile/"
    echo ""
    echo "  # Check environment compatibility:"
    echo "  python3 main.py --check-env ~/.mozilla/firefox/your-profile/"
    echo ""
    echo "  # Decrypt passwords only:"
    echo "  python3 nss_decrypt.py ~/.mozilla/firefox/your-profile/"
    echo ""
    echo -e "${BOLD}Documentation:${NC}"
    echo "  README.md           - Quick start guide"
    echo "  SETUP.md            - Detailed setup instructions"
    echo "  FIREFOX_FORENSICS.md - Firefox artifact documentation"
    echo ""
}

# Main execution
main() {
    print_banner
    
    OS=$(detect_os)
    info "Detected OS type: $OS"
    
    check_sudo
    check_python
    
    case "$OS" in
        arch)
            install_arch
            ;;
        debian)
            install_debian
            ;;
        fedora)
            install_fedora
            ;;
        opensuse)
            install_opensuse
            ;;
        macos)
            install_macos
            ;;
        *)
            error "Unsupported operating system"
            echo ""
            echo "Please install NSS library manually:"
            echo "  - Arch Linux:    sudo pacman -S nss"
            echo "  - Ubuntu/Debian: sudo apt install libnss3"
            echo "  - Fedora/RHEL:   sudo dnf install nss"
            echo "  - openSUSE:      sudo zypper install mozilla-nss"
            echo "  - macOS:         brew install nss"
            exit 1
            ;;
    esac
    
    verify_nss
    check_firefox_installation
    run_env_check
    print_final
}

# Run main function
main "$@"
