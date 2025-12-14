# Firefox Forensics Extraction Tool
# Makefile for easy setup and usage

.PHONY: help setup install check run clean venv test

# Default target
help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════════════╗"
	@echo "║  🔍 Firefox Forensics Tool - Makefile Commands                       ║"
	@echo "╚══════════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make setup        - Install all system dependencies (requires sudo)"
	@echo "  make venv         - Create Python virtual environment"
	@echo "  make install      - Setup + create virtual environment"
	@echo ""
	@echo "Usage:"
	@echo "  make check        - Check environment compatibility"
	@echo "  make run          - Run tool with auto-detected profile"
	@echo "  make run-profile  - Run tool (prompts for profile path)"
	@echo "  make decrypt      - Decrypt passwords only (prompts for profile)"
	@echo ""
	@echo "Development:"
	@echo "  make test         - Run environment tests"
	@echo "  make clean        - Remove generated files and __pycache__"
	@echo ""
	@echo "Examples:"
	@echo "  make run PROFILE=~/.mozilla/firefox/abc.default/"
	@echo "  make decrypt PROFILE=~/.mozilla/firefox/abc.default/"
	@echo ""

# Detect OS for package manager
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	# Detect Linux distro
	ifneq ($(wildcard /etc/arch-release),)
		PKG_INSTALL = sudo pacman -Sy --noconfirm nss
	else ifneq ($(wildcard /etc/debian_version),)
		PKG_INSTALL = sudo apt-get update && sudo apt-get install -y libnss3
	else ifneq ($(wildcard /etc/fedora-release),)
		PKG_INSTALL = sudo dnf install -y nss
	else ifneq ($(wildcard /etc/redhat-release),)
		PKG_INSTALL = sudo dnf install -y nss
	else ifneq ($(wildcard /etc/SuSE-release),)
		PKG_INSTALL = sudo zypper install -y mozilla-nss
	else
		PKG_INSTALL = @echo "Unknown Linux distro. Please install libnss3 manually."
	endif
endif
ifeq ($(UNAME_S),Darwin)
	PKG_INSTALL = brew install nss
endif

# Install system dependencies
setup:
	@echo "Installing system dependencies..."
	@chmod +x setup.sh
	@./setup.sh

# Create virtual environment
venv:
	@echo "Creating Python virtual environment..."
	@python3 -m venv venv
	@echo ""
	@echo "Virtual environment created. Activate with:"
	@echo "  source venv/bin/activate"

# Full installation
install: setup venv
	@echo ""
	@echo "Installation complete!"

# Check environment
check:
	@python3 nss_decrypt.py --check $(PROFILE)

# Run the tool
run:
ifdef PROFILE
	@python3 main.py $(PROFILE)
else
	@python3 main.py
endif

# Run with profile prompt
run-profile:
	@echo "Enter Firefox profile path:"
	@read profile && python3 main.py "$$profile"

# Decrypt passwords only
decrypt:
ifdef PROFILE
	@python3 nss_decrypt.py $(PROFILE)
else
	@echo "Enter Firefox profile path:"
	@read profile && python3 nss_decrypt.py "$$profile"
endif

# Run tests
test:
	@echo "Running environment tests..."
	@python3 -c "from nss_decrypt import check_nss_library_available, detect_firefox_installation_type; \
		nss_ok, path, err = check_nss_library_available(); \
		print(f'NSS Library: {\"OK\" if nss_ok else \"MISSING\"} ({path or err})'); \
		ff_type, ff_path = detect_firefox_installation_type(); \
		print(f'Firefox: {ff_type} ({ff_path})')"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -rf __pycache__
	@rm -rf *.pyc
	@rm -rf .pytest_cache
	@rm -rf venv
	@rm -f .env
	@echo "Clean complete."

# Quick install for specific distros
install-arch:
	sudo pacman -Sy --noconfirm nss python

install-debian:
	sudo apt-get update && sudo apt-get install -y libnss3 python3

install-fedora:
	sudo dnf install -y nss python3

install-macos:
	brew install nss python3
