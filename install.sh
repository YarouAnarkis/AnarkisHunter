#!/bin/bash
# AnarkisHunter — install.sh
# Setup script untuk Linux/macOS/WSL2

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${RED}"
echo "  █████╗ ███╗   ██╗ █████╗ ██████╗ ██╗  ██╗██╗███████╗"
echo " ██╔══██╗████╗  ██║██╔══██╗██╔══██╗██║ ██╔╝██║██╔════╝"
echo " ███████║██╔██╗ ██║███████║██████╔╝█████╔╝ ██║███████╗"
echo " ██╔══██║██║╚██╗██║██╔══██║██╔══██╗██╔═██╗ ██║╚════██║"
echo " ██║  ██║██║ ╚████║██║  ██║██║  ██║██║  ██╗██║███████║"
echo " ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${CYAN} AnarkisHunter Penetration Testing Framework${NC}"
echo -e "${YELLOW} FOR AUTHORIZED PENETRATION TESTING ONLY${NC}"
echo ""

# Check Python version
echo -e "${CYAN}[*] Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 not found. Please install Python 3.11+${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"

# Create virtual environment
echo -e "${CYAN}[*] Creating virtual environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate
echo -e "${GREEN}[+] Virtual environment created${NC}"

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip -q

# Install dependencies
echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
pip install -r requirements.txt

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  source .venv/bin/activate"
echo -e "  python webpentest.py --url http://target.local --all"
echo -e "  python webpentest.py --help"
echo ""
echo -e "${YELLOW}[!] LEGAL: Only use on systems you have explicit written authorization to test.${NC}"
