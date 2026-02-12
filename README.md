# 🔒 Security Testing Lab

A comprehensive, ethical security testing lab demonstrating web application security testing, vulnerability scanning, and automated reporting.

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This project is designed for learning cybersecurity concepts in a controlled, local environment. Only test applications you own or have explicit permission to test. Unauthorized security testing is illegal.

## 🎯 Project Overview

This portfolio project demonstrates:
- Web application security fundamentals
- Ethical hacking workflows
- Automated vulnerability scanning
- Professional security reporting
- Python security tooling

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip
- (Optional) Docker & Docker Compose

### Installation

```bash
# Clone the repository
git clone https://github.com/rawhun/security-testing-lab.git
cd security-testing-lab

# Install dependencies
pip install -r requirements.txt

# Run the vulnerable app (Terminal 1)
python app/vuln_flask.py

# Run all scanners (Terminal 2)
bash scripts/run_all.sh
```

## 📁 Project Structure

```
security-testing-lab/
├── app/                    # Vulnerable demo application
│   └── vuln_flask.py      # Flask app with intentional vulnerabilities
├── scanners/              # Security testing modules
│   ├── recon.py          # Reconnaissance scanner
│   ├── header_check.py   # Security header analyzer
│   ├── dir_enum.py       # Directory enumeration
│   └── sqli_check.py     # SQL injection tester
├── reports/               # Report generation
│   └── generate_report.py
├── scripts/               # Automation scripts
│   └── run_all.sh
└── docker-compose.yml     # Optional Docker setup
```

## 🔧 Features

### 1. Vulnerable Flask Application
- Intentionally vulnerable login system
- SQL injection demonstration
- Missing security headers
- Local-only access

### 2. Security Scanners
- **Recon Scanner**: HTTP headers, server info, page titles
- **Header Checker**: CSP, HSTS, X-Frame-Options analysis
- **Directory Enumerator**: Common path discovery
- **SQLi Checker**: Boolean-based SQL injection detection

### 3. Automated Reporting
- Markdown report generation
- Vulnerability severity ratings
- Remediation recommendations

### 4. Docker Integration (Optional)
- OWASP Juice Shop
- OWASP ZAP proxy
- Pre-configured vulnerable targets

## 📖 Usage Examples

### Run Individual Scanners

```bash
# Reconnaissance
python scanners/recon.py http://localhost:5000

# Header analysis
python scanners/header_check.py http://localhost:5000

# Directory enumeration
python scanners/dir_enum.py http://localhost:5000

# SQL injection testing
python scanners/sqli_check.py http://localhost:5000/login
```

### Generate Security Report

```bash
python reports/generate_report.py http://localhost:5000
```

### Run with Docker

```bash
# Start vulnerable applications
docker-compose up -d

# Test against Juice Shop
python scanners/recon.py http://localhost:3000
```

## 🎓 Learning Objectives

This project teaches:
- OWASP Top 10 vulnerabilities
- HTTP security headers
- SQL injection mechanics
- Ethical hacking methodology
- Security automation with Python
- Professional security reporting

## 🛡️ Security Concepts Covered

- **SQL Injection**: Understanding and detecting database attacks
- **Security Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Information Disclosure**: Server fingerprinting and reconnaissance
- **Directory Traversal**: Path enumeration techniques
- **Secure Development**: Learning from vulnerable code

## 📊 Sample Output

```
[+] Security Scan Report
[+] Target: http://localhost:5000
[+] Timestamp: 2024-02-11 10:30:45

[!] CRITICAL: SQL Injection vulnerability detected
[!] HIGH: Missing Content-Security-Policy header
[!] MEDIUM: Missing X-Frame-Options header
[+] Found 3 accessible directories
```

## 🔨 Development

### Adding New Scanners

1. Create scanner in `scanners/` directory
2. Follow the template pattern
3. Import in `generate_report.py`
4. Update documentation

### Extending the Vulnerable App

Add new vulnerabilities to `app/vuln_flask.py` for testing:
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Authentication bypass
- File upload vulnerabilities

## 📝 Portfolio & Resume

This project demonstrates:
- ✅ Python programming proficiency
- ✅ Cybersecurity knowledge
- ✅ Ethical hacking skills
- ✅ Automation and scripting
- ✅ Technical documentation
- ✅ Professional development practices

See [SHOWCASE.md](showcase.md) for interview talking points.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new scanners
4. Submit a pull request

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## ⚖️ Ethical Use

This tool is for:
- ✅ Learning security concepts
- ✅ Testing your own applications
- ✅ Authorized penetration testing
- ✅ Security research in controlled environments

Never use for:
- ❌ Unauthorized testing
- ❌ Malicious purposes
- ❌ Illegal activities

## 👤 Author

[GitHub](https://github.com/rawhun)

## 🙏 Acknowledgments

- OWASP Foundation
- Flask Security Community
- Python Security Tools Developers

---

**Remember: With great power comes great responsibility. Use these tools ethically.**
