#!/usr/bin/env python3
"""
Directory Enumeration Scanner
Discovers hidden directories and files on web applications
"""

import sys
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from urllib.parse import urlparse, urljoin

console = Console()

# Common directories and files to check
WORDLIST = [
    'admin',
    'administrator',
    'login',
    'logout',
    'dashboard',
    'panel',
    'api',
    'backup',
    'backups',
    'config',
    'configuration',
    'database',
    'db',
    'test',
    'dev',
    'development',
    'staging',
    'prod',
    'production',
    'uploads',
    'upload',
    'files',
    'images',
    'img',
    'css',
    'js',
    'assets',
    'static',
    'public',
    'private',
    'secret',
    'hidden',
    'temp',
    'tmp',
    'logs',
    'log',
    'debug',
    'phpinfo.php',
    'info.php',
    'robots.txt',
    'sitemap.xml',
    '.git',
    '.env',
    '.htaccess',
    'web.config',
    'composer.json',
    'package.json',
    'README.md',
    'CHANGELOG.md',
    'users',
    'user',
    'account',
    'accounts',
    'profile',
    'settings',
    'preferences',
    'help',
    'support',
    'contact',
    'about',
    'search',
    'download',
    'downloads',
    'docs',
    'documentation',
    'api/users',
    'api/admin',
    'api/config',
]


def banner():
    """Display scanner banner"""
    console.print("\n[bold cyan]📁 Directory Enumeration Scanner[/bold cyan]")
    console.print("[dim]Discovering hidden paths and files...[/dim]\n")


def check_path(base_url, path, timeout=5):
    """
    Check if a path exists on the target
    
    Args:
        base_url: Base URL of target
        path: Path to check
        timeout: Request timeout
        
    Returns:
        dict: Result information or None
    """
    url = urljoin(base_url, path)
    
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={'User-Agent': 'SecurityScanner/1.0'}
        )
        
        # Consider these status codes as "found"
        if response.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403]:
            return {
                'path': path,
                'url': url,
                'status': response.status_code,
                'size': len(response.content),
                'redirect': response.headers.get('Location', '')
            }
    
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.RequestException:
        return None
    
    return None


def categorize_status(status_code):
    """
    Categorize HTTP status code
    
    Args:
        status_code: HTTP status code
        
    Returns:
        tuple: (category, color)
    """
    if status_code == 200:
        return ('OK', 'green')
    elif status_code in [301, 302, 307, 308]:
        return ('REDIRECT', 'yellow')
    elif status_code == 401:
        return ('AUTH REQUIRED', 'cyan')
    elif status_code == 403:
        return ('FORBIDDEN', 'magenta')
    elif status_code == 404:
        return ('NOT FOUND', 'red')
    else:
        return (f'CODE {status_code}', 'white')


def scan_directories(base_url, wordlist=None, threads=10):
    """
    Scan for directories and files
    
    Args:
        base_url: Target base URL
        wordlist: List of paths to check
        threads: Number of concurrent requests
        
    Returns:
        list: Found paths
    """
    if wordlist is None:
        wordlist = WORDLIST
    
    found = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(wordlist)} paths...",
            total=len(wordlist)
        )
        
        for path in wordlist:
            result = check_path(base_url, path)
            if result:
                found.append(result)
                category, color = categorize_status(result['status'])
                console.print(
                    f"[{color}]✓ Found:[/{color}] {result['path']} "
                    f"[{color}][{result['status']}][/{color}]"
                )
            
            progress.update(task, advance=1)
    
    return found


def display_results(base_url, found):
    """
    Display scan results
    
    Args:
        base_url: Target URL
        found: List of found paths
    """
    console.print(f"\n[bold]Target:[/bold] {base_url}")
    console.print(f"[bold]Paths Checked:[/bold] {len(WORDLIST)}")
    console.print(f"[bold]Paths Found:[/bold] {len(found)}\n")
    
    if not found:
        console.print("[yellow]No accessible paths discovered[/yellow]\n")
        return
    
    # Create results table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Path", style="white")
    table.add_column("Status", style="yellow", justify="center")
    table.add_column("Size", style="cyan", justify="right")
    table.add_column("Notes", style="dim")
    
    # Sort by status code
    found.sort(key=lambda x: x['status'])
    
    for item in found:
        category, color = categorize_status(item['status'])
        
        # Format size
        size = item['size']
        if size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        
        # Notes
        notes = ""
        if item['redirect']:
            notes = f"→ {item['redirect'][:40]}"
        elif item['status'] == 403:
            notes = "Access denied"
        elif item['status'] == 401:
            notes = "Authentication required"
        
        table.add_row(
            item['path'],
            f"[{color}]{item['status']}[/{color}]",
            size_str,
            notes
        )
    
    console.print(table)
    
    # Summary by status
    console.print("\n[bold cyan]📊 Summary by Status:[/bold cyan]")
    status_counts = {}
    for item in found:
        status = item['status']
        status_counts[status] = status_counts.get(status, 0) + 1
    
    for status, count in sorted(status_counts.items()):
        category, color = categorize_status(status)
        console.print(f"  [{color}]{status} ({category}):[/{color}] {count}")
    
    # Security notes
    console.print("\n[bold yellow]⚠️  Security Notes:[/bold yellow]")
    
    sensitive_paths = [p for p in found if any(
        keyword in p['path'].lower()
        for keyword in ['admin', 'config', 'backup', '.git', '.env', 'api']
    )]
    
    if sensitive_paths:
        console.print("  • Potentially sensitive paths discovered:")
        for path in sensitive_paths[:5]:
            console.print(f"    - {path['path']} [{path['status']}]")
    
    forbidden_paths = [p for p in found if p['status'] == 403]
    if forbidden_paths:
        console.print(f"  • {len(forbidden_paths)} forbidden path(s) - may exist but require authentication")
    
    console.print("\n[green]✓ Directory enumeration complete![/green]\n")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        console.print("[red]Usage: python dir_enum.py <target_url>[/red]")
        console.print("[dim]Example: python dir_enum.py http://localhost:5000[/dim]")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"http://{target}"
    
    # Ensure trailing slash
    if not target.endswith('/'):
        target += '/'
    
    banner()
    
    # Run scan
    found = scan_directories(target)
    
    # Display results
    display_results(target, found)


if __name__ == '__main__':
    main()
