#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 8: Final Release Pack Builder
Creates a clean, deployable ZIP package for project submission
"""

import os
import sys
import json
import zipfile
import hashlib
import shutil
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('release-builder')

class ReleasePackBuilder:
    def __init__(self, version: str = "1.0.0", output_dir: str = "release"):
        self.version = version
        self.output_dir = output_dir
        self.project_name = f"Enterprise_SOC_v{version}"
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.release_file = os.path.join(output_dir, f"{self.project_name}_{self.timestamp}.zip")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Files and directories to include
        self.include_paths = [
            'main.py',
            'app.py',
            'core/',
            'collectors/',
            'detection/',
            'incidents/',
            'preprocessing/',
            'storage/',
            'monitoring/',
            'dashboard/',
            'tuning/',
            'evaluation/',
            'tools/',
            'requirements.txt',
            'README.md',
            'config.yaml.template'
        ]
        
        # Sensitive files to exclude
        self.sensitive_files = [
            'config.yaml',
            'security.db',
            'users.db',
            '.env',
            '*.log',
            '*.pyc',
            '__pycache__',
            '.DS_Store'
        ]
        
        self.manifest = {
            'project': self.project_name,
            'version': self.version,
            'build_date': datetime.now().isoformat(),
            'files': [],
            'integrity_hashes': {},
            'build_info': {}
        }
    
    def _should_include(self, path: str) -> bool:
        """Check if path should be included"""
        # Skip sensitive files
        for pattern in self.sensitive_files:
            if pattern.endswith('/') and pattern[:-1] in path:
                return False
            if pattern in path:
                return False
            if pattern.startswith('*') and path.endswith(pattern[1:]):
                return False
        
        # Include only specified paths
        for include in self.include_paths:
            if include.endswith('/'):
                if path.startswith(include):
                    return True
            else:
                if path == include or path.startswith(include):
                    return True
        
        return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing {file_path}: {e}")
            return ''
    
    def _create_config_template(self):
        """Create config.yaml.template"""
        config_template_path = 'config.yaml.template'
        
        if os.path.exists(config_template_path):
            return
        
        # Create minimal template
        with open(config_template_path, 'w', encoding='utf-8') as f:
            f.write("""# Enterprise SOC - Configuration Template
# Replace placeholders with your actual values

app:
  name: 'Security Monitor Enterprise'
  version: '2.0.0'
  db_path: 'data/security.db'
  log_path: 'logs/security_monitor.log'

dashboard:
  enabled: true
  host: '0.0.0.0'
  port: 8050
  auth_enabled: true
  auth_user: 'admin'
  auth_password: '${DASH_AUTH_PASSWORD}'
  users:
    - username: 'viewer'
      password: 'viewer123'
      role: 'VIEWER'
    - username: 'analyst'
      password: 'analyst123'
      role: 'ANALYST'
    - username: 'admin'
      password: '${DASH_AUTH_PASSWORD}'
      role: 'ADMIN'

collectors:
  process: true
  network: true
  eventlog: true
  login: true

detection:
  enabled: true
  min_severity: 'MEDIUM'
  auto_create_incidents: true
""")
        logger.info("✅ Created config.yaml.template")
    
    def _create_readme(self):
        """Create README.md"""
        readme_path = 'README.md'
        
        if os.path.exists(readme_path):
            return
        
        readme_content = f"""# Enterprise Security Operations Center (SOC)

## Version {self.version}

A comprehensive security monitoring system with AI-powered anomaly detection, real-time dashboard, and complete incident management workflow.

## Features

- **Real-time Monitoring**: Live system metrics, network traffic, and security events
- **AI Anomaly Detection**: Isolation Forest for behavioral analysis
- **Rule-Based Detection**: YAML-defined detection rules
- **Incident Management**: Full workflow with RBAC
- **Interactive Dashboard**: Light mode, responsive design
- **Integrity Checking**: SHA-256 verification for critical files
- **Audit Trail**: Complete user action logging
- **Report Generation**: Automated security reports with hashes

## Quick Start

### Prerequisites
```bash
python 3.8+
pip install -r requirements.txt