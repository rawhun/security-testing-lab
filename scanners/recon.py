#!/usr/bin/env python3
"""
Reconnaissance Scanner
Performs basic information gathering on target web applications
"""

import sys
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse

console = Console()


def banner():
    """Display scanner banner"""
    console.print("\n[bold cyan]🔍 Reconnaissance Scanner[/bold cyan]")
    console.print("[dim]Gathering target information...[/dim]\n")


def get_http_headers(url):
    """
    Fetch and analyze HTTP response headers
    
    Args:
        url: Target URL
        
    Returns:
        dict: Response headers and metadata
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'final_url': response.url,
            'redirected': response.url != url,
            'response_time': response.elapsed.total_seconds()
        }
    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Error connecting to {url}: {str(e)}[/red]")
        return None


def get_page_title(url):
    """
    Extract page title from HTML
    
    Args:
        url: Target URL
        
    Returns:
        str: Page title or None
    """
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.find('title')
        return title.string if title else "No title found"
    except Exception as e:
        return f"Error: {str(e)}"


def detect_technologies(headers):
    """
    Detect web technologies from headers
    
    Args:
        headers: HTTP response headers
        
    Returns:
        list: Detected technologies
    """
    technologies = []
    
    # Server detection
    if 'Server' in headers:
        technologies.append(f"Server: {headers['Server']}")
    
    # Framework detection
    if 'X-Powered-By' in headers:
        technologies.append(f"Powered by: {headers['X-Powered-By']}")
    
    # CMS detection
    if 'X-Generator' in headers:
        technologies.append(f"Generator: {headers['X-Generator']}")
    
    # Check for common frameworks
    framework_headers = {
        'X-AspNet-Version': 'ASP.NET',
        'X-AspNetMvc-Version': 'ASP.NET MVC',
        'X-Drupal-Cache': 'Drupal',
        'X-Powered-CMS': 'CMS'
    }
    
    for header, tech in framework_headers.items():
        if header in headers:
            technologies.append(f"{tech}: {headers[header]}")
    
    return technologies if technologies else ["No specific technologies detected"]


def check_security_indicators(headers):
    """
    Check for security-related headers and indicators
    
    Args:
        headers: HTTP response headers
        
    Returns:
        dict: Security findings
    """
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Permissions Policy'
    }
    
    present = []
    missing = []
    
    for header, description in security_headers.items():
        if header in headers:
            present.append(f"{description} ({header})")
        else:
            missing.append(f"{description} ({header})")
    
    return {'present': present, 'missing': missing}


def scan_target(url):
    """
    Perform reconnaissance scan on target
    
    Args:
        url: Target URL
    """
    banner()
    
    # Validate URL
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
    
    console.print(f"[bold]Target:[/bold] {url}\n")
    
    # Fetch headers
    console.print("[yellow]⏳ Fetching HTTP headers...[/yellow]")
    result = get_http_headers(url)
    
    if not result:
        return
    
    # Display basic info
    console.print(f"[green]✓ Status Code:[/green] {result['status_code']}")
    console.print(f"[green]✓ Response Time:[/green] {result['response_time']:.2f}s")
    
    if result['redirected']:
        console.print(f"[yellow]⚠ Redirected to:[/yellow] {result['final_url']}")
    
    # Get page title
    console.print("\n[yellow]⏳ Extracting page title...[/yellow]")
    title = get_page_title(url)
    console.print(f"[green]✓ Page Title:[/green] {title}")
    
    # Display headers table
    console.print("\n[bold cyan]📋 HTTP Response Headers:[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Header", style="cyan")
    table.add_column("Value", style="white")
    
    for header, value in result['headers'].items():
        table.add_row(header, str(value)[:80])
    
    console.print(table)
    
    # Detect technologies
    console.print("\n[bold cyan]🔧 Detected Technologies:[/bold cyan]")
    technologies = detect_technologies(result['headers'])
    for tech in technologies:
        console.print(f"  • {tech}")
    
    # Security analysis
    console.print("\n[bold cyan]🛡️  Security Headers Analysis:[/bold cyan]")
    security = check_security_indicators(result['headers'])
    
    if security['present']:
        console.print("\n[green]✓ Present:[/green]")
        for header in security['present']:
            console.print(f"  • {header}")
    
    if security['missing']:
        console.print("\n[red]✗ Missing:[/red]")
        for header in security['missing']:
            console.print(f"  • {header}")
    
    # Summary
    console.print("\n[bold cyan]📊 Summary:[/bold cyan]")
    console.print(f"  • Total Headers: {len(result['headers'])}")
    console.print(f"  • Security Headers Present: {len(security['present'])}")
    console.print(f"  • Security Headers Missing: {len(security['missing'])}")
    
    console.print("\n[green]✓ Reconnaissance scan complete![/green]\n")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print("[red]Usage: python recon.py <target_url>[/red]")
        console.print("[dim]Example: python recon.py http://localhost:5000[/dim]")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_target(target)


if __name__ == '__main__':
    main()
