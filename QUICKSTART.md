# 🚀 Quick Start Guide

Get up and running with the Security Testing Lab in 5 minutes!

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Terminal/Command line access

## Installation Steps

### 1. Clone or Download the Project

```bash
cd security-testing-lab
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or if you prefer using a virtual environment (recommended):

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Start the Vulnerable Application

Open a terminal and run:

```bash
python app/vuln_flask.py
```

You should see:
```
============================================================
🔒 VULNERABLE FLASK APPLICATION
============================================================
⚠️  WARNING: This application is intentionally vulnerable!
⚠️  FOR EDUCATIONAL PURPOSES ONLY
⚠️  DO NOT expose to the internet!
============================================================

[+] Database initialized with sample users
[+] Starting server on http://127.0.0.1:5000
[+] Press CTRL+C to stop
```

Keep this terminal open!

### 4. Run Security Scans

Open a NEW terminal and run:

```bash
# Run all scanners automatically
bash scripts/run_all.sh
```

Or run individual scanners:

```bash
# Reconnaissance
python scanners/recon.py http://localhost:5000

# Security headers
python scanners/header_check.py http://localhost:5000

# Directory enumeration
python scanners/dir_enum.py http://localhost:5000

# SQL injection testing
python scanners/sqli_check.py http://localhost:5000/login
```

### 5. Generate Security Report

```bash
python reports/generate_report.py http://localhost:5000
```

View the report:
```bash
cat security_report.md
```

## Testing the Vulnerable App

### Manual SQL Injection Test

1. Open browser: http://localhost:5000/login
2. Try these payloads in the username field:
   - `admin' OR '1'='1`
   - `' OR 1=1--`
   - `admin'--`
3. Use any password
4. You should bypass authentication!

### API Testing

```bash
# View exposed user data
curl http://localhost:5000/api/users

# Check robots.txt
curl http://localhost:5000/robots.txt
```

## Docker Setup (Optional)

If you want to test against OWASP Juice Shop:

```bash
# Start Docker containers
docker-compose up -d

# Wait 30 seconds for services to start

# Test against Juice Shop
python scanners/recon.py http://localhost:3000
python scanners/header_check.py http://localhost:3000

# Stop containers
docker-compose down
```

## Troubleshooting

### "Module not found" error
```bash
pip install -r requirements.txt
```

### "Port 5000 already in use"
```bash
# Find and kill the process
# macOS/Linux:
lsof -ti:5000 | xargs kill -9

# Or change the port in app/vuln_flask.py
```

### "Permission denied" on run_all.sh
```bash
chmod +x scripts/run_all.sh
```

### Virtual environment issues
```bash
# Deactivate current environment
deactivate

# Remove and recreate
rm -rf venv
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## What's Next?

1. ✅ Read the full [README.md](README.md)
2. ✅ Check out [SHOWCASE.md](showcase.md) for portfolio tips
3. ✅ Explore the code in `scanners/` directory
4. ✅ Modify and extend the scanners
5. ✅ Add this to your GitHub portfolio!

## Quick Command Reference

```bash
# Start vulnerable app
python app/vuln_flask.py

# Run all scans
bash scripts/run_all.sh

# Individual scanners
python scanners/recon.py <url>
python scanners/header_check.py <url>
python scanners/dir_enum.py <url>
python scanners/sqli_check.py <url>

# Generate report
python reports/generate_report.py <url>

# Docker
docker-compose up -d
docker-compose down
```

## Safety Reminders

⚠️ **IMPORTANT**:
- Only test applications you own or have permission to test
- Never expose the vulnerable app to the internet
- Use `127.0.0.1` or `localhost` only
- This is for educational purposes only

## Getting Help

- Check the [README.md](README.md) for detailed documentation
- Review code comments in each scanner
- Open an issue on GitHub
- Read OWASP documentation

---

**Happy Ethical Hacking! 🔒**
