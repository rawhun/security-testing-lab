# 🤝 Contributing to Security Testing Lab

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on constructive feedback
- Prioritize security and ethical practices
- Help others learn and grow

### Ethical Guidelines

This project is for educational purposes only. Contributors must:
- Never promote malicious use
- Include appropriate warnings and disclaimers
- Follow responsible disclosure practices
- Respect legal and ethical boundaries

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check existing issues
2. Verify the bug is reproducible
3. Collect relevant information

Bug report should include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Error messages or logs

### Suggesting Enhancements

Enhancement suggestions should include:
- Clear use case
- Expected behavior
- Potential implementation approach
- Security considerations

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Development Guidelines

### Code Style

Follow PEP8 Python style guidelines:

```python
# Good
def scan_target(url, timeout=10):
    """
    Scan target URL for vulnerabilities
    
    Args:
        url: Target URL to scan
        timeout: Request timeout in seconds
        
    Returns:
        dict: Scan results
    """
    pass

# Bad
def scanTarget(url,timeout=10):
    pass
```

### Documentation

- Add docstrings to all functions
- Include inline comments for complex logic
- Update README.md for new features
- Provide usage examples

### Security Considerations

When adding new features:
- Validate all inputs
- Handle errors gracefully
- Avoid information disclosure
- Include security warnings
- Test for false positives/negatives

## Project Structure

```
security-testing-lab/
├── app/                    # Vulnerable applications
│   └── vuln_flask.py
├── scanners/              # Security scanners
│   ├── __init__.py
│   ├── recon.py
│   ├── header_check.py
│   ├── dir_enum.py
│   └── sqli_check.py
├── reports/               # Report generation
│   ├── __init__.py
│   └── generate_report.py
├── scripts/               # Automation scripts
│   └── run_all.sh
├── tests/                 # Test files (add these!)
└── docs/                  # Additional documentation
```

## Adding New Scanners

### Scanner Template

```python
#!/usr/bin/env python3
"""
Scanner Name
Brief description of what this scanner does
"""

import sys
import requests
from rich.console import Console

console = Console()


def banner():
    """Display scanner banner"""
    console.print("\n[bold cyan]🔍 Scanner Name[/bold cyan]")
    console.print("[dim]Description...[/dim]\n")


def scan_target(url):
    """
    Main scanning function
    
    Args:
        url: Target URL
        
    Returns:
        dict: Scan results
    """
    try:
        # Implement scanning logic
        pass
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return None


def display_results(results):
    """
    Display scan results
    
    Args:
        results: Scan results dictionary
    """
    # Format and display results
    pass


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print("[red]Usage: python scanner.py <target_url>[/red]")
        sys.exit(1)
    
    target = sys.argv[1]
    banner()
    results = scan_target(target)
    display_results(results)


if __name__ == '__main__':
    main()
```

### Integration Checklist

When adding a new scanner:
- [ ] Create scanner file in `scanners/`
- [ ] Add to `scanners/__init__.py`
- [ ] Update `reports/generate_report.py`
- [ ] Add to `scripts/run_all.sh`
- [ ] Update README.md
- [ ] Add usage examples
- [ ] Include tests

## Adding New Vulnerabilities

### Vulnerable App Template

```python
@app.route('/new-vuln')
def new_vulnerability():
    """
    VULNERABILITY: Description
    
    This endpoint demonstrates [vulnerability type].
    DO NOT use this pattern in production!
    """
    # Implement vulnerable code with clear comments
    pass
```

### Vulnerability Checklist

- [ ] Clear comments explaining the vulnerability
- [ ] Warning messages in code
- [ ] Corresponding scanner to detect it
- [ ] Documentation in README
- [ ] Remediation examples

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_recon.py

# Run with coverage
python -m pytest --cov=scanners tests/
```

### Writing Tests

```python
# tests/test_scanner.py
import pytest
from scanners import your_scanner

def test_basic_functionality():
    """Test basic scanner functionality"""
    result = your_scanner.scan_target('http://example.com')
    assert result is not None

def test_error_handling():
    """Test error handling"""
    result = your_scanner.scan_target('invalid-url')
    assert result is None or 'error' in result
```

## Documentation

### README Updates

When adding features, update:
- Features section
- Usage examples
- Installation requirements
- Project structure

### Code Comments

```python
# Good: Explains WHY
# Use parameterized queries to prevent SQL injection
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))

# Bad: Explains WHAT (obvious from code)
# Execute SQL query
cursor.execute(query)
```

## Commit Messages

### Format

```
type(scope): brief description

Detailed explanation if needed

Fixes #issue_number
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

### Examples

```
feat(scanner): add XSS detection scanner

Implements basic XSS detection using payload injection
and response analysis. Includes reflected and stored XSS tests.

Fixes #42
```

```
fix(sqli): improve false positive detection

Enhanced baseline comparison to reduce false positives
in SQL injection scanner.
```

## Review Process

### Pull Request Checklist

Before submitting:
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No security issues introduced
- [ ] Commit messages are clear

### Review Criteria

Reviewers will check:
- Code quality and style
- Security implications
- Test coverage
- Documentation completeness
- Ethical considerations

## Community

### Getting Help

- Open an issue for questions
- Check existing documentation
- Review closed issues for similar problems

### Discussions

- Feature requests
- Architecture decisions
- Best practices
- Learning resources

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in relevant documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Additional Resources

### Security Testing Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Python Resources

- [PEP 8 Style Guide](https://pep8.org/)
- [Python Documentation](https://docs.python.org/3/)
- [Real Python Tutorials](https://realpython.com/)

### Git Resources

- [Git Documentation](https://git-scm.com/doc)
- [GitHub Guides](https://guides.github.com/)

## Questions?

Feel free to:
- Open an issue
- Start a discussion
- Contact maintainers

---

**Thank you for contributing to security education! 🔒**
