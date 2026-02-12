#!/usr/bin/env python3
"""
Security Header Checker
Analyzes HTTP security headers and provides recommendations
"""

import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from urllib.parse import urlparse

console = Console()


# Security header definitions with descriptions and recommendations
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'Forces HTTPS connections',
        'severity': 'HIGH',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
    },
    'Content-Security-Policy': {
        'description': 'Prevents XSS and injection attacks',
        'severity': 'HIGH',
        'recommendation': "Add: Content-Security-Policy: default-src 'self'",
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
    },
    'X-Frame-Options': {
        'description': 'Prevents clickjacking attacks',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
    },
    'X-Content-Type-Options': {
        'description': 'Prevents MIME type sniffing',
        'severity': 'MEDIUM',
        'recommendation': 'Add: X-Content-Type-Options: nosniff',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS filter (deprecated but still useful)',
        'severity': 'LOW',
        'recommendation': 'Add: X-XSS-Protection: 1; mode=block',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'
    },
    'Referrer-Policy': {
        'description': 'Controls referrer information',
        'severity': 'LOW',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
    },
    'Permissions-Policy': {
        'description': 'Controls browser features and APIs',
        'severity': 'LOW',
        'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
        'references': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
    }
}


def banner():
    """Display scanner banner"""
    console.print("\n[bold cyan]🛡️  Security Header Checker[/bold cyan]")
    console.print("[dim]Analyzing HTTP security headers...[/dim]\n")


def fetch_headers(url):
    """
    Fetch HTTP headers from target
    
    Args:
        url: Target URL
        
    Returns:
        dict: Response headers or None on error
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return dict(response.headers)
    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Error connecting to {url}: {str(e)}[/red]")
        return None


def analyze_headers(headers):
    """
    Analyze security headers
    
    Args:
        headers: HTTP response headers
        
    Returns:
        dict: Analysis results
    """
    results = {
        'present': [],
        'missing': [],
        'score': 0,
        'max_score': len(SECURITY_HEADERS) * 10
    }
    
    for header, info in SECURITY_HEADERS.items():
        if header in headers:
            results['present'].append({
                'header': header,
                'value': headers[header],
                'info': info
            })
            # Score based on severity
            if info['severity'] == 'HIGH':
                results['score'] += 10
            elif info['severity'] == 'MEDIUM':
                results['score'] += 7
            else:
                results['score'] += 5
        else:
            results['missing'].append({
                'header': header,
                'info': info
            })
    
    return results


def check_insecure_headers(headers):
    """
    Check for headers that may leak information
    
    Args:
        headers: HTTP response headers
        
    Returns:
        list: Potentially insecure headers
    """
    insecure = []
    
    # Headers that may leak information
    info_disclosure_headers = {
        'Server': 'Reveals server software and version',
        'X-Powered-By': 'Reveals application framework',
        'X-AspNet-Version': 'Reveals ASP.NET version',
        'X-AspNetMvc-Version': 'Reveals ASP.NET MVC version',
        'X-Generator': 'Reveals CMS or generator'
    }
    
    for header, description in info_disclosure_headers.items():
        if header in headers:
            insecure.append({
                'header': header,
                'value': headers[header],
                'issue': description
            })
    
    return insecure


def display_results(url, headers, analysis):
    """
    Display analysis results
    
    Args:
        url: Target URL
        headers: Response headers
        analysis: Analysis results
    """
    banner()
    console.print(f"[bold]Target:[/bold] {url}\n")
    
    # Security score
    score_percentage = (analysis['score'] / analysis['max_score']) * 100
    score_color = 'green' if score_percentage >= 70 else 'yellow' if score_percentage >= 40 else 'red'
    
    console.print(Panel(
        f"[bold {score_color}]{analysis['score']}/{analysis['max_score']} ({score_percentage:.1f}%)[/bold {score_color}]",
        title="Security Score",
        border_style=score_color
    ))
    
    # Present headers
    if analysis['present']:
        console.print("\n[bold green]✓ Security Headers Present:[/bold green]")
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="white", max_width=50)
        table.add_column("Severity", style="yellow")
        
        for item in analysis['present']:
            table.add_row(
                item['header'],
                item['value'][:50],
                item['info']['severity']
            )
        
        console.print(table)
    
    # Missing headers
    if analysis['missing']:
        console.print("\n[bold red]✗ Security Headers Missing:[/bold red]")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Header", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Severity", style="yellow")
        
        for item in analysis['missing']:
            table.add_row(
                item['header'],
                item['info']['description'],
                item['info']['severity']
            )
        
        console.print(table)
    
    # Information disclosure
    insecure = check_insecure_headers(headers)
    if insecure:
        console.print("\n[bold yellow]⚠️  Information Disclosure Headers:[/bold yellow]")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="white")
        table.add_column("Issue", style="red")
        
        for item in insecure:
            table.add_row(item['header'], item['value'], item['issue'])
        
        console.print(table)
    
    # Recommendations
    if analysis['missing']:
        console.print("\n[bold cyan]💡 Recommendations:[/bold cyan]")
        for item in analysis['missing']:
            if item['info']['severity'] in ['HIGH', 'MEDIUM']:
                console.print(f"\n[yellow]• {item['header']}[/yellow]")
                console.print(f"  {item['info']['description']}")
                console.print(f"  [dim]{item['info']['recommendation']}[/dim]")
    
    # Summary
    console.print("\n[bold cyan]📊 Summary:[/bold cyan]")
    console.print(f"  • Headers Present: {len(analysis['present'])}/{len(SECURITY_HEADERS)}")
    console.print(f"  • Headers Missing: {len(analysis['missing'])}/{len(SECURITY_HEADERS)}")
    console.print(f"  • Information Disclosure: {len(insecure)} header(s)")
    
    if score_percentage >= 70:
        console.print("\n[green]✓ Good security header configuration![/green]")
    elif score_percentage >= 40:
        console.print("\n[yellow]⚠ Moderate security - improvements recommended[/yellow]")
    else:
        console.print("\n[red]✗ Poor security - immediate action required[/red]")
    
    console.print()


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print("[red]Usage: python header_check.py <target_url>[/red]")
        console.print("[dim]Example: python header_check.py http://localhost:5000[/dim]")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
    
    # Fetch headers
    headers = fetch_headers(target)
    if not headers:
        sys.exit(1)
    
    # Analyze headers
    analysis = analyze_headers(headers)
    
    # Display results
    display_results(target, headers, analysis)


if __name__ == '__main__':
    main()
