# suspicious-tracker
Security Monitoring System - Enterprise SOC Platform

A comprehensive, AI-powered Security Operations Center (SOC) platform for real-time threat detection, incident response, and security monitoring in Windows   environments.

✨ Features

Core Capabilities

🤖 AI-Powered Detection - Isolation Forest algorithm for behavioral anomaly detection

📊 Real-time Monitoring - Continuous collection of processes, network connections, and system metrics

🎯 Rule-Based Engine - Customizable detection rules with severity levels (LOW/MEDIUM/HIGH/CRITICAL)

🔗 MITRE ATT&CK Mapping - Automatic mapping of threats to MITRE framework techniques

📈 Interactive Dashboard - Real-time visualization with Plotly/Dash

🔐 RBAC Authentication - Role-Based Access Control (VIEWER/ANALYST/ADMIN)

Security Features

🛡️ File Integrity Monitoring - SHA-256 hashing for critical file verification

📋 Complete Audit Trail - Logging of all user actions and security events

🌐 Threat Intelligence - IP reputation checking via VirusTotal, AbuseIPDB, IPinfo

📊 Incident Management - Complete lifecycle with workflow and assignment

📄 Report Generation - Automated security reports with digital signatures

Technical Highlights
⚡ Multi-threaded Architecture - Efficient parallel data collection
💾 Lightweight Database - SQLite with WAL mode for concurrent access
🔄 Crash-Safe Execution - Watchdog protection and automatic recovery
📡 Live Data Collection - Real system metrics and network traffic analysis
📊 Performance Optimized - Minimal CPU and memory overhead (<10% CPU, <300MB RAM)

📋 Requirements
Python 3.8+ (3.10+ recommended)
Windows 10/11 or Windows Server 2016+ (Linux support for development)
Minimum 4GB RAM, 2 CPU cores
Administrative privileges recommended for network connection monitoring

🚀 Installation
# Clone the repository
git clone https://github.com/Belozaid/security-monitoring-system.git

# Navigate to the directory
cd security-monitoring-system

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make scripts executable (Linux/Mac)
chmod +x main.py dashboard/app.py

🔧 Quick Start
1. Configure Authentication
Edit core/config.yaml to set up users:

dashboard:
  auth_user: "admin"
  auth_password: "${DASH_AUTH_PASSWORD}"
  users:
    - username: "viewer"
      password: "viewer123"
      role: "VIEWER"
    - username: "analyst"
      password: "analyst123"
      role: "ANALYST"
    - username: "admin"
      password: "${DASH_AUTH_PASSWORD}"
      role: "ADMIN"

Set environment variable for admin password:

# On Windows (PowerShell)
$env:DASH_AUTH_PASSWORD="your_secure_password"

# On Linux/Mac
export DASH_AUTH_PASSWORD="your_secure_password"

2. Start the Monitoring System
python main.py

3. Start the Dashboard (in separate terminal)
python dashboard/app.py

4. Access the Dashboard
Open your browser and navigate to: http://localhost:8050

Default credentials:
viewer / viewer123 (read-only access)
analyst / analyst123 (full workflow access)
admin / your_secure_password (system administration

📊 Dashboard Pages
Dashboard:	Real-time KPIs, system metrics, threat level monitoring
Alerts:	Live security alerts with severity filtering
Incidents:	Complete incident management workflow
System Health:	CPU, memory, disk, network performance metrics
Integrity:	File integrity verification and hash checking
Audit: Log	Complete audit trail of all actions (ADMIN only)
Network:	Real-time network traffic analysis and monitoring
Reports:	Security report generation and export
AI Analytics:	Anomaly scores and model status visualization
Access Control:	User management and role permissions (ADMIN only)

🧪 Running Tests
# Run unit tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_detection.py -v

# Run with coverage report
python -m pytest --cov=. tests/

🛠️ Technology Stack
Python 3.8+ - Core development language
psutil - System and process monitoring
scikit-learn - Isolation Forest for anomaly detection
Dash/Plotly - Interactive dashboard framework
SQLite3 - Embedded database with WAL mode
PyYAML - Configuration management
hashlib - SHA-256 integrity verification


