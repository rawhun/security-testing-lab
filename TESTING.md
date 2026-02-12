# 🧪 Testing Guide

Comprehensive guide for testing the security scanners and vulnerable application.

## Test Environment Setup

### 1. Local Testing (Recommended)

```bash
# Terminal 1: Start vulnerable app
python app/vuln_flask.py

# Terminal 2: Run tests
python -m pytest tests/  # If you add tests
```

### 2. Docker Testing

```bash
# Start OWASP Juice Shop
docker-compose up -d juice-shop

# Test against it
python scanners/recon.py http://localhost:3000
```

## Manual Testing Scenarios

### SQL Injection Testing

#### Test Case 1: Classic OR Bypass
```
URL: http://localhost:5000/login
Method: POST
Username: admin' OR '1'='1
Password: anything
Expected: Successful login (authentication bypass)
```

#### Test Case 2: Comment-based Bypass
```
Username: admin'--
Password: anything
Expected: Successful login
```

#### Test Case 3: Union-based Detection
```
Username: ' UNION SELECT NULL--
Password: anything
Expected: SQL error or different response
```

### Security Header Testing

#### Test Case 1: Missing CSP
```bash
curl -I http://localhost:5000
# Expected: No Content-Security-Policy header
```

#### Test Case 2: Information Disclosure
```bash
curl -I http://localhost:5000
# Expected: X-Powered-By and Server headers present
```

### Directory Enumeration Testing

#### Test Case 1: Admin Panel Discovery
```bash
curl http://localhost:5000/admin
# Expected: 403 Forbidden or 200 OK
```

#### Test Case 2: API Endpoint Discovery
```bash
curl http://localhost:5000/api/users
# Expected: 200 OK with user data
```

#### Test Case 3: Hidden Files
```bash
curl http://localhost:5000/robots.txt
# Expected: 200 OK with disallow rules
```

## Scanner Testing

### Recon Scanner Tests

```bash
# Test 1: Basic reconnaissance
python scanners/recon.py http://localhost:5000
# Verify: Status code, headers, page title displayed

# Test 2: Invalid URL handling
python scanners/recon.py http://invalid-url-12345.com
# Verify: Graceful error handling

# Test 3: HTTPS site
python scanners/recon.py https://example.com
# Verify: Successful scan with security headers
```

### Header Check Scanner Tests

```bash
# Test 1: Vulnerable app (should score low)
python scanners/header_check.py http://localhost:5000
# Expected: Low security score, missing headers highlighted

# Test 2: Secure site (should score high)
python scanners/header_check.py https://github.com
# Expected: Higher security score

# Test 3: Information disclosure detection
python scanners/header_check.py http://localhost:5000
# Expected: X-Powered-By and Server headers flagged
```

### Directory Enumeration Tests

```bash
# Test 1: Full scan
python scanners/dir_enum.py http://localhost:5000
# Expected: Multiple paths discovered (admin, api, login, etc.)

# Test 2: Non-existent domain
python scanners/dir_enum.py http://localhost:9999
# Expected: Graceful handling, no paths found

# Test 3: Trailing slash handling
python scanners/dir_enum.py http://localhost:5000/
# Expected: Same results as without trailing slash
```

### SQL Injection Scanner Tests

```bash
# Test 1: Vulnerable endpoint
python scanners/sqli_check.py http://localhost:5000/login
# Expected: Multiple vulnerabilities detected

# Test 2: Non-vulnerable endpoint
python scanners/sqli_check.py https://example.com
# Expected: No vulnerabilities detected

# Test 3: Custom parameter
python scanners/sqli_check.py http://localhost:5000/login --param username
# Expected: Test specific parameter
```

## Report Generation Testing

```bash
# Test 1: Full report generation
python reports/generate_report.py http://localhost:5000
# Expected: security_report.md created with all sections

# Test 2: Report content validation
cat security_report.md | grep "CRITICAL"
# Expected: SQL injection vulnerabilities listed

# Test 3: Risk scoring
cat security_report.md | grep "Risk Level"
# Expected: CRITICAL or HIGH risk level
```

## Automated Testing Script

Create a test script to verify all functionality:

```bash
#!/bin/bash
# test_all.sh

echo "Starting test suite..."

# Start vulnerable app in background
python app/vuln_flask.py &
APP_PID=$!
sleep 3

# Run tests
echo "Testing recon scanner..."
python scanners/recon.py http://localhost:5000 > /dev/null
if [ $? -eq 0 ]; then echo "✓ Recon passed"; else echo "✗ Recon failed"; fi

echo "Testing header scanner..."
python scanners/header_check.py http://localhost:5000 > /dev/null
if [ $? -eq 0 ]; then echo "✓ Headers passed"; else echo "✗ Headers failed"; fi

echo "Testing directory scanner..."
python scanners/dir_enum.py http://localhost:5000 > /dev/null
if [ $? -eq 0 ]; then echo "✓ Directory passed"; else echo "✗ Directory failed"; fi

echo "Testing SQLi scanner..."
python scanners/sqli_check.py http://localhost:5000/login > /dev/null
if [ $? -eq 0 ]; then echo "✓ SQLi passed"; else echo "✗ SQLi failed"; fi

echo "Testing report generation..."
python reports/generate_report.py http://localhost:5000 > /dev/null
if [ $? -eq 0 ]; then echo "✓ Report passed"; else echo "✗ Report failed"; fi

# Cleanup
kill $APP_PID
echo "Test suite complete!"
```

## Performance Testing

### Response Time Testing

```python
import time
import requests

url = "http://localhost:5000"
times = []

for i in range(10):
    start = time.time()
    requests.get(url)
    elapsed = time.time() - start
    times.append(elapsed)

print(f"Average response time: {sum(times)/len(times):.3f}s")
print(f"Min: {min(times):.3f}s, Max: {max(times):.3f}s")
```

### Scanner Performance

```bash
# Time each scanner
time python scanners/recon.py http://localhost:5000
time python scanners/header_check.py http://localhost:5000
time python scanners/dir_enum.py http://localhost:5000
time python scanners/sqli_check.py http://localhost:5000/login
```

## Edge Cases & Error Handling

### Test Invalid Inputs

```bash
# No URL provided
python scanners/recon.py
# Expected: Usage message

# Invalid URL format
python scanners/recon.py not-a-url
# Expected: Graceful error handling

# Timeout scenario
python scanners/recon.py http://httpstat.us/200?sleep=30000
# Expected: Timeout error message

# Non-existent endpoint
python scanners/sqli_check.py http://localhost:5000/nonexistent
# Expected: Graceful handling
```

## Security Testing Best Practices

### 1. Isolated Environment
- Always test in isolated environment
- Use virtual machines or containers
- Never test production systems

### 2. Permission
- Only test systems you own
- Get written permission for any external testing
- Document all testing activities

### 3. Rate Limiting
- Don't overwhelm target systems
- Add delays between requests if needed
- Respect robots.txt

### 4. Data Handling
- Don't store sensitive data from scans
- Sanitize reports before sharing
- Follow responsible disclosure

## Validation Checklist

Before considering the project complete, verify:

- [ ] All scanners run without errors
- [ ] Vulnerable app starts successfully
- [ ] SQL injection is detected
- [ ] Security headers are analyzed correctly
- [ ] Directory enumeration finds expected paths
- [ ] Reports are generated in Markdown format
- [ ] Error handling works for invalid inputs
- [ ] Documentation is clear and accurate
- [ ] Code follows PEP8 style guidelines
- [ ] All dependencies are listed in requirements.txt

## Known Issues & Limitations

### Current Limitations

1. **Single-threaded scanning**: Directory enumeration is sequential
2. **Limited payload set**: SQLi scanner uses basic payloads
3. **No authentication**: Scanners don't handle authenticated endpoints
4. **Basic reporting**: Reports are Markdown only (no HTML/PDF)

### Future Improvements

1. Multi-threaded scanning for better performance
2. Expanded payload databases
3. Authentication support (cookies, tokens)
4. HTML report generation with charts
5. Integration with vulnerability databases
6. Custom wordlist support for directory enumeration

## Debugging Tips

### Enable Verbose Output

Add debug prints to scanners:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Network Traffic

Use a proxy to inspect requests:

```bash
# Start mitmproxy
mitmproxy -p 8888

# Configure scanner to use proxy
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
```

### Database Inspection

```bash
# Check vulnerable app database
sqlite3 vulnerable_app.db
sqlite> .tables
sqlite> SELECT * FROM users;
sqlite> .quit
```

## Contributing Tests

When adding new features, include:

1. Unit tests for new functions
2. Integration tests for scanners
3. Documentation of test cases
4. Expected outputs

Example test structure:

```python
# tests/test_recon.py
import pytest
from scanners import recon

def test_get_http_headers():
    result = recon.get_http_headers('http://example.com')
    assert result is not None
    assert 'status_code' in result
    assert result['status_code'] == 200

def test_invalid_url():
    result = recon.get_http_headers('http://invalid-url-12345.com')
    assert result is None
```

---

**Remember**: Testing is crucial for security tools. Always verify your scanners work correctly before relying on their results!
