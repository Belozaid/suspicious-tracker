# 🚨 Suspicious Tracker - Enterprise SOC Dashboard

<div align="center">

![Version](https://img.shields.io/badge/version-3.0.0-blue)

![Python](https://img.shields.io/badge/python-3.8%2B-green)

![License](https://img.shields.io/badge/license-MIT-orange)

![Security](https://img.shields.io/badge/security-SOC-red)

![RBAC](https://img.shields.io/badge/RBAC-enabled-purple)

**An integrated platform for monitoring and managing cybersecurity | Enterprise Security Operations Center**

[Installation](#-installation) •
[Running](#-quick-start) •

[Features](#-features) •

[Structure](#-project-structure) •

[Documentation](#-documentation)

</div>

---

## 🌟 Overview

**Suspicious Tracker** is an integrated cybersecurity operations management (SOC) system with:

- 🔍 **Advanced Threat Detection** using Machine Learning

- 🚨 **Real-Time Alert and Incident Management**

- 👥 **Advanced Responsibility Control System (RBAC)** with 3 roles

- 📊 **Interactive Dashboard** using Dash/Plotly technology

- 🔐 **Threat Intelligence Integration**

- 📝 **Security Reports with Integrity Verification**

## ✨ Key Features

### 🛡️ **Security and Authentication**
- Integrated RBAC system (Viewer, Analyst, Admin)
- Secure session management with all attempts logged
- Password encryption using Werkzeug

### 📊 **Control Panel**
- Modern interface with Light Mode design
- Live system and network data
- Interactive graphs using Plotly
- Automatic updates every 2-10 seconds

### 🤖 **Artificial Intelligence**
- Anomaly detection using Isolation Forest
- Behavioral analysis of network and user behavior
- Real-time risk assessment

### 📋 **Reporting**
- Daily reports with digital signatures
- Incident analysis with digital proofs
- Export in multiple formats (HTML, JSON, CSV)

## 🚀 Installation

### Prerequisites
- Python 3.8 or later
- 4GB RAM (8GB recommended)
- 10GB storage space

### Steps Installation

```bash
# 1. Clone the repository
`git clone https://github.com/Belozaid/suspicious-tracker.git
`cd suspicious-tracker`

# 2. Create a virtual environment
`python -m venv venv`

# 3. Activate the environment
# Windows:
`venv\Scripts\activate`
# Linux/Mac:
`source venv/bin/activate`

# 4. Install requirements
`pip install -r requirements.txt`

# 5. Configure the database
`python -c "from main import main; main()"

# 6. Start the system
`python main.py`
