# 🚀 START HERE

## Welcome to Your Security Testing Project!

This file will get you up and running in **5 minutes**.

---

## ⚡ Quick Setup (3 Steps)

### Step 1: Verify Setup
```bash
python verify_setup.py
```

This checks if everything is properly configured.

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

Or with virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Test It!

**Terminal 1** - Start the vulnerable app:
```bash
python app/vuln_flask.py
```

**Terminal 2** - Run the scanners:
```bash
bash scripts/run_all.sh
```

---

## 📖 What to Read Next

1. **[QUICKSTART.md](QUICKSTART.md)** - Detailed setup and usage
2. **[README.md](README.md)** - Complete project documentation
3. **[showcase.md](showcase.md)** - Portfolio and interview tips
4. **[TESTING.md](TESTING.md)** - Testing guide

---

## 🎯 Quick Test Commands

```bash
# Test individual scanners
python scanners/recon.py http://localhost:5000
python scanners/header_check.py http://localhost:5000
python scanners/dir_enum.py http://localhost:5000
python scanners/sqli_check.py http://localhost:5000/login

# Generate security report
python reports/generate_report.py http://localhost:5000

# View the report
cat security_report.md
```

---

## 🔍 Try SQL Injection

1. Open browser: http://localhost:5000/login
2. Username: `admin' OR '1'='1`
3. Password: `anything`
4. Click Login → You're in! 🎉

---

## 🐳 Docker (Optional)

```bash
# Start OWASP Juice Shop
docker-compose up -d juice-shop

# Test it
python scanners/recon.py http://localhost:3000

# Stop it
docker-compose down
```

---

## 📁 Project Structure

```
security-testing-lab/
├── app/                    # Vulnerable Flask app
├── scanners/              # 4 security scanners
├── reports/               # Report generator
├── scripts/               # Automation scripts
└── [docs]                 # Documentation files
```

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Vulnerable app starts (`python app/vuln_flask.py`)
- [ ] Scanners run successfully (`bash scripts/run_all.sh`)
- [ ] Report generated (`python reports/generate_report.py http://localhost:5000`)

---

## 🆘 Troubleshooting

### "Module not found"
```bash
pip install -r requirements.txt
```

### "Port 5000 already in use"
```bash
# macOS/Linux
lsof -ti:5000 | xargs kill -9

# Or edit app/vuln_flask.py and change the port
```

### "Permission denied" on scripts
```bash
chmod +x scripts/run_all.sh
chmod +x verify_setup.py
```

---

## 🎓 What This Project Demonstrates

- ✅ Python programming (Flask, Requests, BeautifulSoup, Rich)
- ✅ Web security (SQL injection, security headers, OWASP Top 10)
- ✅ Ethical hacking (reconnaissance, vulnerability scanning)
- ✅ Automation (shell scripts, report generation)
- ✅ Professional development (documentation, code quality)

---

## 🎯 Next Steps

### For Your Portfolio
1. Push to GitHub
2. Add project to resume
3. Update LinkedIn
4. Prepare demo for interviews

### For Learning
1. Read the scanner code
2. Try modifying payloads
3. Add new vulnerabilities
4. Create new scanners

### For Interviews
1. Review [showcase.md](showcase.md)
2. Practice explaining the project
3. Prepare code walkthrough
4. Know the security concepts

---

## 📚 Key Files

| File | Purpose |
|------|---------|
| `README.md` | Main documentation |
| `QUICKSTART.md` | Detailed setup guide |
| `showcase.md` | Portfolio & interview tips |
| `TESTING.md` | Testing guide |
| `CONTRIBUTING.md` | Contribution guidelines |

---

## 🎉 You're Ready!

Your security testing lab is complete and ready to use.

**Start with:**
```bash
python verify_setup.py
```

**Then run:**
```bash
# Terminal 1
python app/vuln_flask.py

# Terminal 2
bash scripts/run_all.sh
```

---

## 💡 Pro Tips

1. **Read the code** - Every file has detailed comments
2. **Try breaking things** - It's a safe environment
3. **Extend it** - Add your own scanners
4. **Share it** - Great for your portfolio
5. **Learn from it** - Understand both attack and defense

---

## ⚠️ Remember

This is for **educational purposes only**:
- ✅ Test your own applications
- ✅ Learn security concepts
- ✅ Practice ethical hacking
- ❌ Never test without permission
- ❌ Never use maliciously

---

## 🚀 Let's Go!

```bash
python verify_setup.py
```

**Happy Ethical Hacking!** 🔒

---

*Questions? Check the documentation files or open an issue on GitHub.*
