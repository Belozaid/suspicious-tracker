#!/usr/bin/env python3
"""
Install Phase 2 dependencies
Run: python install_phase2.py
"""

import subprocess
import sys

def install_dependencies():
    print("=" * 60)
    print("INSTALLING PHASE 2 DEPENDENCIES")
    print("=" * 60)
    
    dependencies = [
        'numpy>=1.21.0',
        'pandas>=1.3.0',
        'scikit-learn>=1.0.0',
        'dash>=2.0.0',
        'plotly>=5.3.0'
    ]
    
    for dep in dependencies:
        print(f"\nInstalling {dep}...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
            print(f"✅ {dep} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {dep}: {e}")
    
    print("\n" + "=" * 60)
    print("INSTALLATION COMPLETE")
    print("=" * 60)
    
    # Test imports
    print("\nTesting Phase 2 imports:")
    
    modules_to_test = [
        ('numpy', 'import numpy'),
        ('pandas', 'import pandas'),
        ('sklearn', 'import sklearn'),
        ('dash', 'import dash'),
        ('plotly', 'import plotly')
    ]
    
    for name, import_stmt in modules_to_test:
        try:
            exec(import_stmt)
            print(f"✅ {name}: OK")
        except ImportError:
            print(f"❌ {name}: Not installed")
    
    print("\nTo activate Phase 2 features:")
    print("1. Restart the system: python main.py")
    print("2. Check the status in the console")

if __name__ == "__main__":
    install_dependencies()