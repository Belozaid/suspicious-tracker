# file: install_offline.py
import subprocess
import sys
import os

def install_package(package):
    """تثبيت حزمة واحدة"""
    try:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✓ {package} installed successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to install {package}: {e}")
        return False

def main():
    print("Starting offline-friendly installation...")
    
    # الحزم الأساسية (يجب أن تعمل بدون اتصال بالإنترنت)
    packages = [
        "Flask==2.3.3",
        "Flask-Login==0.6.3",
        "Werkzeug==2.3.7",
        "pandas==1.5.3",
        "numpy==1.24.3",
        "plotly==5.15.0",
        "PyYAML==6.0",
        "psutil==5.9.5",
        "dash==2.11.1",
        "dash-bootstrap-components==1.4.1",
        "dash-core-components==2.0.0",
        "dash-html-components==2.0.0",
        "dash-table==5.0.0"
    ]
    
    successful = 0
    failed = 0
    
    for package in packages:
        if install_package(package):
            successful += 1
        else:
            failed += 1
    
    print(f"\nInstallation complete: {successful} successful, {failed} failed")
    
    if failed == 0:
        print("✅ All packages installed successfully!")
    else:
        print("⚠️ Some packages failed to install. The dashboard may still work.")

if __name__ == "__main__":
    main()