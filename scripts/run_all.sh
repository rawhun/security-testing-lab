#!/bin/bash

###############################################################################
# Security Testing Automation Script
# Runs all security scanners against the vulnerable Flask application
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET_URL="http://127.0.0.1:5000"
REPORT_DIR="reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Security Testing Automation Script                ║"
echo "║         Security Testing Lab                              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if target is running
echo -e "${YELLOW}[*] Checking if target application is running...${NC}"
if curl -s --head --request GET "$TARGET_URL" | grep "200\|302\|301" > /dev/null; then
    echo -e "${GREEN}[✓] Target is accessible at $TARGET_URL${NC}"
else
    echo -e "${RED}[✗] Target is not accessible at $TARGET_URL${NC}"
    echo -e "${YELLOW}[!] Please start the vulnerable app first:${NC}"
    echo -e "    python app/vuln_flask.py"
    exit 1
fi

echo ""

# Run Reconnaissance Scanner
echo -e "${CYAN}[1/5] Running Reconnaissance Scanner...${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python scanners/recon.py "$TARGET_URL"
echo ""

# Run Security Header Checker
echo -e "${CYAN}[2/5] Running Security Header Checker...${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python scanners/header_check.py "$TARGET_URL"
echo ""

# Run Directory Enumeration
echo -e "${CYAN}[3/5] Running Directory Enumeration...${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python scanners/dir_enum.py "$TARGET_URL"
echo ""

# Run SQL Injection Checker
echo -e "${CYAN}[4/5] Running SQL Injection Checker...${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python scanners/sqli_check.py "$TARGET_URL/login"
echo ""

# Generate Comprehensive Report
echo -e "${CYAN}[5/5] Generating Comprehensive Security Report...${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python reports/generate_report.py "$TARGET_URL"
echo ""

# Summary
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Security Scan Complete!                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}[*] Results Summary:${NC}"
echo "    • Reconnaissance: Complete"
echo "    • Header Analysis: Complete"
echo "    • Directory Enumeration: Complete"
echo "    • SQL Injection Testing: Complete"
echo "    • Report Generated: security_report.md"
echo ""

echo -e "${CYAN}[*] View the full report:${NC}"
echo "    cat security_report.md"
echo ""

echo -e "${YELLOW}[*] Individual scanner usage:${NC}"
echo "    python scanners/recon.py <url>"
echo "    python scanners/header_check.py <url>"
echo "    python scanners/dir_enum.py <url>"
echo "    python scanners/sqli_check.py <url>"
echo ""

echo -e "${GREEN}[✓] All scans completed successfully!${NC}"
