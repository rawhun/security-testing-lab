#!/usr/bin/env python3
"""
Setup Verification Script
Checks if all dependencies and files are properly configured
"""

import sys
import os
from pathlib import Path

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def check_python_version():
    """Check Python version"""
    print("\n[1/6] Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (Need 3.8+)")
        return False

def check_dependencies():
    """Check if required packages are installed"""
    print("\n[2/6] Checking dependencies...")
    
    required = {
        'flask': 'Flask',
        'requests': 'Requests',
        'bs4': 'BeautifulSoup4',
        'rich': 'Rich'
    }
    
    all_installed = True
    for module, name in required.items():
        try:
            __import__(module)
            print(f"✓ {name} installed")
        except ImportError:
            print(f"✗ {name} NOT installed")
            all_installed = False
    
    if not all_installed:
        print("\n  Install missing packages:")
        print("  pip install -r requirements.txt")
    
    return all_installed

def check_project_structure():
    """Check if all required files exist"""
    print("\n[3/6] Checking project structure...")
    
    required_files = [
        'README.md',
        'requirements.txt',
        'LICENSE',
        '.gitignore',
        'docker-compose.yml',
        'app/vuln_flask.py',
        'scanners/__init__.py',
        'scanners/recon.py',
        'scanners/header_check.py',
        'scanners/dir_enum.py',
        'scanners/sqli_check.py',
        'reports/__init__.py',
        'reports/generate_report.py',
        'scripts/run_all.sh'
    ]
    
    all_exist = True
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path} NOT FOUND")
            all_exist = False
    
    return all_exist

def check_script_permissions():
    """Check if scripts are executable"""
    print("\n[4/6] Checking script permissions...")
    
    script = Path('scripts/run_all.sh')
    if script.exists():
        if os.access(script, os.X_OK):
            print(f"✓ {script} is executable")
            return True
        else:
            print(f"⚠ {script} is not executable")
            print("  Run: chmod +x scripts/run_all.sh")
            return False
    else:
        print(f"✗ {script} not found")
        return False

def check_imports():
    """Check if scanner modules can be imported"""
    print("\n[5/6] Checking scanner imports...")
    
    all_imported = True
    scanners = ['recon', 'header_check', 'dir_enum', 'sqli_check']
    
    # Add scanners to path
    sys.path.insert(0, os.path.dirname(__file__))
    
    for scanner in scanners:
        try:
            module = __import__(f'scanners.{scanner}', fromlist=[scanner])
            print(f"✓ scanners.{scanner} imported successfully")
        except Exception as e:
            print(f"✗ scanners.{scanner} import failed: {str(e)}")
            all_imported = False
    
    return all_imported

def check_documentation():
    """Check if documentation files exist"""
    print("\n[6/6] Checking documentation...")
    
    docs = [
        'README.md',
        'QUICKSTART.md',
        'TESTING.md',
        'CONTRIBUTING.md',
        'showcase.md',
        'START_HERE.md'
    ]
    
    all_exist = True
    for doc in docs:
        if Path(doc).exists():
            print(f"✓ {doc}")
        else:
            print(f"✗ {doc} NOT FOUND")
            all_exist = False
    
    return all_exist

def main():
    """Main verification function"""
    print_header("Security Testing Lab - Setup Verification")
    
    results = {
        'Python Version': check_python_version(),
        'Dependencies': check_dependencies(),
        'Project Structure': check_project_structure(),
        'Script Permissions': check_script_permissions(),
        'Scanner Imports': check_imports(),
        'Documentation': check_documentation()
    }
    
    print_header("Verification Summary")
    
    all_passed = True
    for check, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:8} - {check}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    
    if all_passed:
        print("\n🎉 All checks passed! Your setup is ready.")
        print("\nNext steps:")
        print("  1. Start the vulnerable app:")
        print("     python app/vuln_flask.py")
        print("\n  2. Run the scanners:")
        print("     bash scripts/run_all.sh")
        print("\n  3. Read QUICKSTART.md for detailed instructions")
        return 0
    else:
        print("\n⚠️  Some checks failed. Please fix the issues above.")
        print("\nCommon fixes:")
        print("  • Install dependencies: pip install -r requirements.txt")
        print("  • Make scripts executable: chmod +x scripts/run_all.sh")
        print("  • Ensure all files are present")
        return 1

if __name__ == '__main__':
    sys.exit(main())
