#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Monitoring System - Enterprise Edition
Version 2.0: Complete Phase 1 + Phase 2 Integration + Dashboard Support
"""

import sys
import os
import time
import signal
import traceback
import json
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

# Add path for modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import libraries
try:
    import yaml as pyyaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: pyyaml not installed, using default config")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed, some features disabled")

# Import system modules
try:
    from core.logger import setup_logger
    from core.scheduler import TaskScheduler
    from preprocessing.feature_engine import FeatureEngine
    from detection.rules_engine import RulesEngine
    from incidents.incident_manager import IncidentManager

    from detection.correlator import fetch_recent_alerts, fetch_latest_ai, fetch_recent_features, correlate, store_scenario
    from detection.threat_scoring import score_threat
    from detection.mitre_mapping import map_to_mitre
    from incidents.workflow import ensure_workflow_row, add_note

    # Import secure config loader
    from core.config_loader import load_config, get_config_value
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure all required modules are installed")
    sys.exit(1)

class SecurityMonitorEnterprise:
    """Enterprise Security Monitoring System"""
    
    def __init__(self, config_path: str = "core/config.yaml"):
        """Initialize system"""
        self.config_path = config_path
        self.logger: Optional[Any] = None
        self.config = self._load_config()
        self.db: Optional[Any] = None
        self.scheduler: Optional[TaskScheduler] = None
        self.feature_engine: Optional[FeatureEngine] = None
        self.rules_engine: Optional[RulesEngine] = None
        self.incident_manager: Optional[IncidentManager] = None
        self.collectors: Dict[str, Any] = {}
        self.running = False
        self.dashboard_available = False
        self.health_monitor = None
        self.active_alerts = []  # List to track active alerts
        self.active_incidents = []  # List to track active incidents
        
        # Initialize system
        self._initialize_system()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration using ConfigLoader"""
        temp_logger = self._get_temp_logger()
        
        try:
            # Try to use ConfigLoader if available
            try:
                from core.config_loader import ConfigLoader
                loader = ConfigLoader(self.config_path)
                config = loader.load()
                
                temp_logger.info(f"✅ Loaded configuration from {self.config_path}")
                self._validate_critical_config(config, temp_logger)
                
                return config
            except ImportError:
                # Fallback to direct YAML loading
                temp_logger.warning("ConfigLoader not available, using direct YAML loading")
                return self._load_yaml_direct()
            
        except Exception as e:
            temp_logger.error(f"❌ Error loading configuration: {e}")
            return self._get_default_config()

    def _load_tuning_profile(self, config):
        """Load tuning profile from YAML (Phase 8)"""
        try:
            import yaml
            tuning_file = 'tuning/tuning_profiles.yaml'
            
            if os.path.exists(tuning_file):
                with open(tuning_file, 'r', encoding='utf-8') as f:
                    tuning_config = yaml.safe_load(f)
                
                if tuning_config:
                    active_profile = tuning_config.get('active_profile', 'SME_Default')
                    profiles = tuning_config.get('profiles', {})
                    
                    if active_profile in profiles:
                        profile = profiles[active_profile]
                        if self.logger:
                            self.logger.info(f"✅ Phase 8: Loaded tuning profile: {active_profile}")
                        
                        # Apply rule thresholds to config
                        rules = profile.get('rules', {})
                        if 'detection' not in config:
                            config['detection'] = {}
                        
                        for rule, value in rules.items():
                            config['detection'][rule] = value
                        
                        config['phase8'] = config.get('phase8', {})
                        config['phase8']['active_profile'] = active_profile
                        config['phase8']['profile_config'] = profile
                    elif self.logger:
                        self.logger.warning(f"Profile '{active_profile}' not found, using defaults")
                elif self.logger:
                    self.logger.info("No tuning profile found, using default thresholds")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error loading tuning profile: {e}")

    def _validate_critical_config(self, config, logger):
        """Validate sensitive configuration"""
        dash_config = config.get('dashboard', {})
        auth_pass = dash_config.get('auth_password')
        
        if auth_pass and isinstance(auth_pass, str) and auth_pass.startswith('${') and auth_pass.endswith('}'):
            env_var = auth_pass[2:-1]
            if not os.environ.get(env_var):
                logger.warning(f"⚠️ Environment variable {env_var} not set")
                os.environ[env_var] = 'Belo2026'
                logger.info(f"✅ Set temporary default password")
                                
    def _get_temp_logger(self):
        """Create a temporary logger for early initialization phase"""
        logger = logging.getLogger("security-monitor-init")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def _log_config_status(self, logger, config: Dict[str, Any]) -> None:
        """Log configuration status"""
        logger.info("=" * 60)
        logger.info("SECURITY MONITOR CONFIGURATION STATUS")
        logger.info("=" * 60)
        
        app_name = config.get('app', {}).get('name', 'Unknown')
        app_version = config.get('app', {}).get('version', 'Unknown')
        logger.info(f"Application: {app_name} v{app_version}")
        
        db_path = config.get('app', {}).get('db_path', 'data/security.db')
        logger.info(f"Database: {db_path}")
        
        self._log_sensitive_config(logger, config)
        logger.info("=" * 60)

    def _log_sensitive_config(self, logger, config: Dict[str, Any]) -> None:
        """Log sensitive configuration status"""
        if 'alerting' in config:
            alerting = config['alerting']
            email_enabled = alerting.get('email_enabled', False)
            
            if email_enabled:
                logger.info("📧 Alerting: Email notifications ENABLED")
                smtp_pass = alerting.get('smtp_password', '')
                if smtp_pass:
                    if isinstance(smtp_pass, str) and smtp_pass.startswith('${') and smtp_pass.endswith('}'):
                        env_var = smtp_pass[2:-1]
                        env_value = os.getenv(env_var)
                        if env_value:
                            logger.info(f"   SMTP Password: [Loaded from environment] ✅")
                        else:
                            logger.error(f"   SMTP Password: Environment variable {env_var} NOT SET! ❌")
        
        if 'dashboard' in config:
            dashboard = config['dashboard']
            auth_user = dashboard.get('auth_user')
            auth_password = dashboard.get('auth_password')
            
            if auth_user:
                logger.info(f"🔐 Dashboard: Authentication ENABLED for user '{auth_user}'")
                
                if auth_password:
                    if isinstance(auth_password, str):
                        if auth_password.startswith('${') and auth_password.endswith('}'):
                            env_var = auth_password[2:-1]
                            env_value = os.getenv(env_var)
                            if env_value:
                                logger.info(f"   Auth Password: [Loaded from {env_var}] ✅")
                            else:
                                logger.error(f"   Auth Password: Environment variable {env_var} NOT SET! ❌")
                        else:
                            if auth_password != '${DASH_AUTH_PASSWORD}':
                                logger.info(f"   Auth Password: [Loaded from environment] ✅")
                            else:
                                logger.error(f"   Auth Password: NOT LOADED from environment! ❌")
                else:
                    logger.error("   Auth Password: NOT CONFIGURED ❌")
            else:
                logger.info("🔐 Dashboard: Authentication DISABLED")
        
        env_overrides = [k for k in os.environ if k.startswith('SMS__')]
        if env_overrides:
            logger.info(f"🔄 Environment Overrides: {len(env_overrides)} applied")
            for override in sorted(env_overrides)[:5]:
                logger.info(f"   {override} = [SET]")
            if len(env_overrides) > 5:
                logger.info(f"   ... and {len(env_overrides) - 5} more")

    def _load_yaml_direct(self) -> Dict[str, Any]:
        """Direct YAML loading fallback"""
        try:
            import yaml
        except ImportError:
            print("Warning: pyyaml not installed")
            return self._get_default_config()
        
        if not os.path.exists(self.config_path):
            print(f"Warning: Config file not found: {self.config_path}")
            return self._get_default_config()
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
                config = self._simple_env_substitution(config)
                return config
        except Exception as e:
            print(f"Error loading YAML: {e}")
            return self._get_default_config()

    def _simple_env_substitution(self, config: Dict) -> Dict:
        """Simple environment variable substitution"""
        def replace_in_dict(d):
            if isinstance(d, dict):
                return {k: replace_in_dict(v) for k, v in d.items()}
            elif isinstance(d, list):
                return [replace_in_dict(i) for i in d]
            elif isinstance(d, str) and d.startswith('${') and d.endswith('}'):
                env_var = d[2:-1]
                return os.getenv(env_var, d)
            else:
                return d
        
        return replace_in_dict(config)

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'app': {
                'name': 'Security Monitor Enterprise',
                'version': '2.0.0',
                'db_path': 'data/security.db',
                'log_path': 'logs/security_monitor.log',
                'poll_seconds': 10,
                'feature_window_seconds': 60,
                'detection_interval_seconds': 60
            },
            'collectors': {
                'process': PSUTIL_AVAILABLE,
                'network': PSUTIL_AVAILABLE,
                'eventlog': True,
                'login': True
            },
            'detection': {
                'enabled': True,
                'min_severity': 'MEDIUM',
                'auto_create_incidents': True
            },
            'dashboard': {
                'enabled': True,
                'host': '127.0.0.1',
                'port': 8050,
                'language': 'en',
                'auth_user': 'admin',
                'auth_password': '${DASH_AUTH_PASSWORD}'
            },
            'alerting': {
                'email_enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'email_from': 'your_email@gmail.com',
                'email_to': 'admin@example.com',
                'smtp_password': '${SMTP_PASSWORD}',
                'sound_alerts': True
            },
            'incidents': {
                'auto_close_days': 7,
                'max_open_incidents': 100
            },
            'phase6': {
                'metrics_interval_seconds': 30,
                'max_retries': 5,
                'backoff_base': 2,
                'health_thresholds': {
                    'cpu_percent_warn': 15,
                    'ram_mb_warn': 200,
                    'cycle_ms_warn': 800
                }
            }
        }

    def _start_dashboard(self) -> None:
        """Start the enhanced dashboard with authentication"""
        if not self.dashboard_available:
            if self.logger:
                self.logger.warning("Dashboard dependencies not installed")
            return
        
        try:
            from dashboard.app import create_dashboard
            from threading import Thread
            
            app, server, host, port, debug = create_dashboard()
            
            if app and server:
                def run_dashboard():
                    try:
                        server.run(host=host, port=port, debug=debug, use_reloader=False)
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Dashboard error: {e}")
                
                dashboard_thread = Thread(target=run_dashboard, daemon=True)
                dashboard_thread.start()
                
                dashboard_config = self.config.get('dashboard', {})
                auth_enabled = bool(dashboard_config.get('auth_user') and dashboard_config.get('auth_password'))
                
                if self.logger:
                    self.logger.info(f"✅ Dashboard started on http://{host}:{port}")
                    self.logger.info(f"   Authentication: {'ENABLED' if auth_enabled else 'DISABLED'}")
                    if auth_enabled:
                        self.logger.info(f"   Username: {dashboard_config.get('auth_user')}")
                        self.logger.info("   Password: [Set via environment variable]")
                
            elif self.logger:
                self.logger.error("Failed to create dashboard")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error starting dashboard: {e}")
            
    def _initialize_system(self) -> None:
        """Initialize all system components"""
        try:
            self._create_directories()
            
            self.logger = setup_logger(
                name="security-monitor-enterprise",
                log_file=self.config['app'].get('log_path'),
                level="INFO"
            )
            
            self._load_tuning_profile(self.config)
            
            self.logger.info("=" * 60)
            self.logger.info(f"Starting Security Monitor Enterprise - Version {self.config['app'].get('version', '2.0.0')}")
            self.logger.info("=" * 60)
            
            self._check_dashboard_availability()
            self.scheduler = TaskScheduler(self.logger)
            self.logger.info("✅ Task Scheduler initialized")
            
            self._initialize_database()
            self._initialize_phase2_components()
            self._initialize_collectors()
            self._initialize_detection()
            
            self.logger.info("✅ System initialization completed successfully")
            
        except Exception as e:
            print(f"Fatal error initializing system: {e}")
            traceback.print_exc()
            sys.exit(1)

    def _log_final_config_status(self):
        """Log final configuration status"""
        if not self.logger:
            return
            
        self.logger.info("📋 FINAL CONFIGURATION STATUS")
        self.logger.info("-" * 40)
        
        collectors_config = self.config.get('collectors', {})
        active_collectors = [name for name, enabled in collectors_config.items() if enabled]
        self.logger.info(f"Active Collectors: {len(active_collectors)}/{len(collectors_config)}")
        
        detection_config = self.config.get('detection', {})
        detection_enabled = detection_config.get('enabled', True)
        self.logger.info(f"Detection System: {'ENABLED' if detection_enabled else 'DISABLED'}")
        
        dashboard_config = self.config.get('dashboard', {})
        dashboard_enabled = dashboard_config.get('enabled', True)
        if dashboard_enabled and self.dashboard_available:
            port = dashboard_config.get('port', 8050)
            host = dashboard_config.get('host', '127.0.0.1')
            self.logger.info(f"Web Dashboard: http://{host}:{port}")
        
        self.logger.info("-" * 40)
        
    def _create_directories(self) -> None:
        """Create system directories"""
        directories = [
            'data', 'logs', 'reports', 'exports', 'dashboard',
            'dashboard/i18n', 'preprocessing', 'detection',
            'incidents', 'collectors', 'storage', 'tuning'
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                if self.logger:
                    self.logger.debug(f"Created/verified directory: {directory}")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error creating directory {directory}: {e}")
                    
    def _check_dashboard_availability(self) -> None:
        """Check if dashboard components are available"""
        try:
            import dash
            import plotly
            self.dashboard_available = True
            if self.logger:
                self.logger.info("✅ Dashboard dependencies available")
        except ImportError:
            self.dashboard_available = False
            if self.logger:
                self.logger.warning("⚠️ Dashboard dependencies not installed. Run: pip install dash plotly pandas")
            
    def _initialize_database(self) -> None:
        """Initialize database with schema check and fix"""
        try:
            db_path = self.config['app'].get('db_path', 'data/security.db')
            
            # Try to import ThreadSafeDatabase
            try:
                from storage.database import ThreadSafeDatabase
                self.db = ThreadSafeDatabase(db_path)
            except ImportError:
                # Fallback to simple database connection
                if self.logger:
                    self.logger.warning("ThreadSafeDatabase not available, using simple connection")
                self.db = self._create_simple_db(db_path)
            
            self._check_and_fix_schema()
            
            if self.logger:
                self.logger.info(f"✅ Database initialized: {db_path}")

            # Create AI scores table
            conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_utc TEXT NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    model_name TEXT NOT NULL,
                    anomaly_score REAL NOT NULL,
                    is_anomaly INTEGER NOT NULL,
                    threshold REAL NOT NULL,
                    feature_vector_json TEXT NOT NULL,
                    decision_function REAL,
                    confidence REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_scores_ts ON ai_scores(ts_utc)")
            conn.commit()
            if self.logger:
                self.logger.info("✅ AI Scores table verified")
            
            # Create incident_enrichment table for Phase 5
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_enrichment (
                    incident_id INTEGER PRIMARY KEY,
                    threat_score INTEGER,
                    severity TEXT,
                    score_breakdown_json TEXT,
                    scenario_name TEXT,
                    confidence REAL,
                    mitre_tactic TEXT,
                    mitre_technique_id TEXT,
                    mitre_technique_name TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                )
            """)
            conn.commit()
            if self.logger:
                self.logger.info("✅ Incident enrichment table verified")

        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Database initialization failed: {e}")
            raise

    def _create_simple_db(self, db_path):
        """Create simple database connection if ThreadSafeDatabase not available"""
        class SimpleDB:
            def __init__(self, path):
                self.path = path
                self._init_db()
            
            def _init_db(self):
                conn = sqlite3.connect(self.path)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        details TEXT,
                        severity TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        description TEXT,
                        evidence TEXT,
                        incident_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT DEFAULT 'OPEN',
                        description TEXT,
                        start_time TEXT,
                        last_update_time TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
                conn.close()
            
            def _get_connection(self):
                return sqlite3.connect(self.path)
            
            def close(self):
                pass
        
        return SimpleDB(db_path)
            
    def _check_and_fix_schema(self) -> None:
        """Check database schema and fix any issues"""
        try:
            conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
            cursor = conn.cursor()
            
            # Check if incidents table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(incidents)")
                columns = [column[1] for column in cursor.fetchall()]
                
                if self.logger:
                    self.logger.debug(f"Incidents table columns: {columns}")
                
                if 'last_update_time' not in columns:
                    if self.logger:
                        self.logger.warning("Adding missing column 'last_update_time' to incidents table")
                    try:
                        cursor.execute("ALTER TABLE incidents ADD COLUMN last_update_time TEXT")
                        current_time = datetime.now().isoformat()
                        cursor.execute("""
                            UPDATE incidents 
                            SET last_update_time = COALESCE(start_time, ?) 
                            WHERE last_update_time IS NULL
                        """, (current_time,))
                        conn.commit()
                        if self.logger:
                            self.logger.info("✅ Database schema updated successfully")
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Failed to update schema: {e}")
                        conn.rollback()
            
            # Check features table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='features'")
            if not cursor.fetchone():
                if self.logger:
                    self.logger.warning("Features table missing, creating...")
                try:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS features (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            window_seconds INTEGER NOT NULL,
                            feature_name TEXT NOT NULL,
                            value REAL NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_features_timestamp ON features(timestamp)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_features_name ON features(feature_name)")
                    conn.commit()
                    if self.logger:
                        self.logger.info("✅ Features table created")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Failed to create features table: {e}")
                    
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking/fixing schema: {e}")
                            
    def _initialize_phase2_components(self) -> None:
        """Initialize Phase 2 components"""
        if not self.logger:
            return
            
        self.logger.info("Initializing Phase 2 components...")
        
        # Feature Engine
        try:
            from preprocessing.feature_engine import FeatureEngine
            self.feature_engine = FeatureEngine(self.logger)
            self.logger.info("✅ Feature Engine: Initialized")
        except ImportError as e:
            self.logger.error(f"❌ Feature Engine: Import failed - {e}")
            self.feature_engine = None
        except Exception as e:
            self.logger.error(f"❌ Feature Engine: Error - {e}")
            self.feature_engine = None
        
        # Rules Engine
        try:
            from detection.rules_engine import RulesEngine
            self.rules_engine = RulesEngine(self.logger)
            
            try:
                from detection.rules import get_all_rules
                if hasattr(self.rules_engine, 'rules'):
                    self.rules_engine.rules = get_all_rules()
                    rule_count = len(self.rules_engine.rules)
                    self.logger.info(f"✅ Rules Engine: Initialized with {rule_count} rules")
                else:
                    self.logger.info("✅ Rules Engine: Initialized")
            except Exception as e:
                self.logger.warning(f"⚠️ Could not load rules: {e}")
                self.logger.info("✅ Rules Engine: Initialized (without rules)")
                
        except ImportError as e:
            self.logger.error(f"❌ Rules Engine: Import failed - {e}")
            self.rules_engine = None
        except Exception as e:
            self.logger.error(f"❌ Rules Engine: Error - {e}")
            self.rules_engine = None
        
        # Incident Manager  
        try:
            from incidents.incident_manager import IncidentManager
            if self.db:
                self.incident_manager = IncidentManager(self.db, self.logger)
                self.logger.info("✅ Incident Manager: Initialized")
            else:
                self.logger.error("❌ Incident Manager: Database not available")
                self.incident_manager = None
        except ImportError as e:
            self.logger.error(f"❌ Incident Manager: Import failed - {e}")
            self.incident_manager = None
        except Exception as e:
            self.logger.error(f"❌ Incident Manager: Error - {e}")
            self.incident_manager = None
        
        phase2_components = []
        if self.feature_engine:
            phase2_components.append("FeatureEngine")
        if self.rules_engine:
            phase2_components.append("RulesEngine")
        if self.incident_manager:
            phase2_components.append("IncidentManager")
        
        if phase2_components:
            self.logger.info(f"✅ Phase 2 components active: {', '.join(phase2_components)}")
        else:
            self.logger.error("❌ NO Phase 2 components active!")
        
        # Check AI Model Status
        try:
            from detection.isolation_forest import get_model_status
            conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
            model_status = get_model_status(conn)
            
            if model_status.get('trained', False):
                self.logger.info(f"✅ AI Model: Trained ({model_status.get('samples', 0)} samples)")
            else:
                self.logger.warning("🤖 AI model not trained. Run train_baseline.py after collecting data.")
        except Exception as e:
            self.logger.error(f"Error checking AI model status: {e}")
                        
    def _initialize_collectors(self) -> None:
        """Initialize data collectors"""
        if not self.logger:
            return
            
        self.logger.info("Initializing data collectors...")
        
        collectors_config = self.config.get('collectors', {})
        self.logger.debug(f"Collectors config: {collectors_config}")
        
        if not self.scheduler:
            self.logger.error("❌ Scheduler not available, cannot initialize collectors")
            return
        
        collector_count = 0
        
        # Process Collector
        if collectors_config.get('process', True):
            try:
                from collectors.process_collector import ProcessCollector
                self.collectors['process'] = ProcessCollector(self.logger)
                self.scheduler.add_task(
                    name="process_collection",
                    task_func=self._collect_process_data,
                    interval_seconds=30
                )
                collector_count += 1
                self.logger.info("✅ Process Collector: Initialized")
            except ImportError as e:
                self.logger.warning(f"⚠️ Process Collector: Import failed - {e}")
            except Exception as e:
                self.logger.error(f"❌ Process Collector: Error - {e}")
        else:
            self.logger.info("⏸️ Process Collector: Disabled in config")
        
        # Network Collector
        if collectors_config.get('network', True):
            try:
                from collectors.network_collector import NetworkCollector
                self.collectors['network'] = NetworkCollector(self.logger)
                self.scheduler.add_task(
                    name="network_collection",
                    task_func=self._collect_network_data,
                    interval_seconds=45
                )
                collector_count += 1
                self.logger.info("✅ Network Collector: Initialized")
            except ImportError as e:
                self.logger.warning(f"⚠️ Network Collector: Import failed - {e}")
            except Exception as e:
                self.logger.error(f"❌ Network Collector: Error - {e}")
        else:
            self.logger.info("⏸️ Network Collector: Disabled in config")
        
        # EventLog Collector
        if collectors_config.get('eventlog', True):
            try:
                from collectors.eventlog_collector import EventLogCollector
                self.collectors['eventlog'] = EventLogCollector(self.logger)
                self.scheduler.add_task(
                    name="eventlog_collection",
                    task_func=self._collect_eventlog_data,
                    interval_seconds=60
                )
                collector_count += 1
                self.logger.info("✅ EventLog Collector: Initialized")
            except ImportError as e:
                self.logger.warning(f"⚠️ EventLog Collector: Import failed - {e}")
            except Exception as e:
                self.logger.error(f"❌ EventLog Collector: Error - {e}")
        else:
            self.logger.info("⏸️ EventLog Collector: Disabled in config")
        
        # Login Collector
        if collectors_config.get('login', True):
            try:
                from collectors.login_collector import LoginCollector
                self.collectors['login'] = LoginCollector(self.logger)
                self.scheduler.add_task(
                    name="login_collection",
                    task_func=self._collect_login_data,
                    interval_seconds=120
                )
                collector_count += 1
                self.logger.info("✅ Login Collector: Initialized")
            except ImportError as e:
                self.logger.warning(f"⚠️ Login Collector: Import failed - {e}")
            except Exception as e:
                self.logger.error(f"❌ Login Collector: Error - {e}")
        else:
            self.logger.info("⏸️ Login Collector: Disabled in config")
        
        self.logger.info(f"📊 Total collectors initialized: {collector_count}")
        
        if collector_count == 0:
            self.logger.warning("⚠️ No collectors were initialized!")
        else:
            self.logger.info(f"✅ Collectors ready: {', '.join(self.collectors.keys())}")
            
    def _initialize_detection(self) -> None:
        """Initialize detection system"""
        if not self.scheduler:
            return
            
        if not self.config['detection'].get('enabled', True):
            if self.logger:
                self.logger.info("Detection system disabled by configuration")
            return
            
        try:
            detection_interval = self.config['app'].get('detection_interval_seconds', 60)
            
            self.scheduler.add_task(
                name="detection_cycle",
                task_func=self._run_detection_cycle,
                interval_seconds=detection_interval
            )
            
            feature_interval = self.config['app'].get('feature_window_seconds', 60)
            self.scheduler.add_task(
                name="feature_extraction",
                task_func=self._run_feature_extraction,
                interval_seconds=feature_interval
            )
            
            if self.logger:
                self.logger.info(f"✅ Detection System: Active (every {detection_interval}s)")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to initialize detection: {e}")
            
    def _run_feature_extraction(self) -> None:
        """Run feature extraction"""
        if not self.db or not self.feature_engine:
            return
        
        try:
            window_seconds = self.config['app'].get('feature_window_seconds', 60)
            
            time.sleep(0.1)  # Ensure unique timestamp
            
            timestamp, features, evidence = self.feature_engine.extract_window_features(
                self.db, window_seconds
            )
            
            if features and self.logger:
                self.logger.info(f"📊 Extracted {len(features)} features for {timestamp}")
                
                count = 0
                for feature_name, value in features.items():
                    try:
                        if hasattr(self.db, 'insert_feature'):
                            self.db.insert_feature(timestamp, window_seconds, feature_name, value)
                        else:
                            # Direct insert
                            conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                            conn.execute(
                                "INSERT INTO features (timestamp, window_seconds, feature_name, value) VALUES (?, ?, ?, ?)",
                                (timestamp, window_seconds, feature_name, value)
                            )
                            conn.commit()
                        count += 1
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Error inserting feature {feature_name}: {e}")
                
                if self.logger:
                    self.logger.info(f"✅ Stored {count} features in database")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in feature extraction: {e}")
                traceback.print_exc()
            
    def _collect_process_data(self) -> None:
        """Collect process data"""
        try:
            if 'process' in self.collectors and self.db and self.logger:
                process_data = self.collectors['process'].collect_processes()
                
                if hasattr(self.db, 'insert_event'):
                    event_id = self.db.insert_event(
                        source='process',
                        event_type='process_snapshot',
                        details=process_data,
                        severity='INFO'
                    )
                else:
                    # Direct insert
                    conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                    cursor = conn.execute(
                        """INSERT INTO events (timestamp, source, event_type, details, severity) 
                           VALUES (datetime('now'), ?, ?, ?, ?)""",
                        ('process', 'process_snapshot', json.dumps(process_data), 'INFO')
                    )
                    event_id = cursor.lastrowid
                    conn.commit()
                
                system_metrics = self.collectors['process'].get_system_metrics()
                if system_metrics and hasattr(self.db, 'insert_system_stat'):
                    self.db.insert_system_stat('cpu_percent', system_metrics.get('cpu_percent', 0))
                    self.db.insert_system_stat('memory_percent', system_metrics.get('memory_percent', 0))
                    self.db.insert_system_stat('disk_percent', system_metrics.get('disk_percent', 0))
                    
                if event_id > 0:
                    self.logger.debug(f"📊 Collected process data: {process_data.get('total_processes', 0)} processes")
                else:
                    self.logger.warning("Failed to store process data")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting process data: {e}")
            
    def _collect_network_data(self) -> None:
        """Collect network data"""
        try:
            if 'network' in self.collectors and self.db and self.logger:
                network_data = self.collectors['network'].collect_connections()
                
                if hasattr(self.db, 'insert_event'):
                    event_id = self.db.insert_event(
                        source='network',
                        event_type='network_snapshot',
                        details=network_data,
                        severity='INFO'
                    )
                else:
                    conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                    cursor = conn.execute(
                        """INSERT INTO events (timestamp, source, event_type, details, severity) 
                           VALUES (datetime('now'), ?, ?, ?, ?)""",
                        ('network', 'network_snapshot', json.dumps(network_data), 'INFO')
                    )
                    event_id = cursor.lastrowid
                    conn.commit()
                
                network_io = self.collectors['network'].get_network_io()
                if network_io and hasattr(self.db, 'insert_system_stat'):
                    self.db.insert_system_stat('network_bytes_sent', network_io.get('bytes_sent', 0))
                    self.db.insert_system_stat('network_bytes_recv', network_io.get('bytes_recv', 0))
                    
                if event_id > 0:
                    self.logger.debug(f"🌐 Collected network data: {network_data.get('total_connections', 0)} connections")
                else:
                    self.logger.warning("Failed to store network data")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting network data: {e}")
            
    def _collect_eventlog_data(self) -> None:
        """Collect eventlog data"""
        try:
            if 'eventlog' in self.collectors and self.db and self.logger:
                eventlog_data = self.collectors['eventlog'].collect_event_logs(
                    channel='Security',
                    hours=1
                )
                
                if eventlog_data.get('event_count', 0) > 0:
                    if hasattr(self.db, 'insert_event'):
                        event_id = self.db.insert_event(
                            source='eventlog',
                            event_type='security_logs',
                            details=eventlog_data,
                            severity='INFO'
                        )
                    else:
                        conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                        cursor = conn.execute(
                            """INSERT INTO events (timestamp, source, event_type, details, severity) 
                               VALUES (datetime('now'), ?, ?, ?, ?)""",
                            ('eventlog', 'security_logs', json.dumps(eventlog_data), 'INFO')
                        )
                        event_id = cursor.lastrowid
                        conn.commit()
                    
                    if event_id > 0:
                        self.logger.debug(f"📝 Collected eventlog data: {eventlog_data.get('event_count', 0)} events")
                    else:
                        self.logger.warning("Failed to store eventlog data")
                else:
                    self.logger.debug("No new eventlog events found")
                    
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting eventlog data: {e}")
            
    def _collect_login_data(self) -> None:
        """Collect login data"""
        try:
            if 'login' in self.collectors and self.db and self.logger:
                login_data = self.collectors['login'].collect_login_info()
                
                if hasattr(self.db, 'insert_event'):
                    event_id = self.db.insert_event(
                        source='login',
                        event_type='login_info',
                        details=login_data,
                        severity='INFO'
                    )
                else:
                    conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                    cursor = conn.execute(
                        """INSERT INTO events (timestamp, source, event_type, details, severity) 
                           VALUES (datetime('now'), ?, ?, ?, ?)""",
                        ('login', 'login_info', json.dumps(login_data), 'INFO')
                    )
                    event_id = cursor.lastrowid
                    conn.commit()
                
                if event_id > 0:
                    self.logger.debug(f"🔐 Collected login data")
                else:
                    self.logger.warning("Failed to store login data")
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting login data: {e}")

    def enrich_incident_phase5(self, conn, incident_id: int, features: dict, window_seconds: int = 300) -> dict:
        """
        Phase 5: Enrich incident with correlation data, threat score, and MITRE
        """
        try:
            # Check if correlation functions are available
            try:
                from detection.correlator import fetch_recent_alerts, fetch_latest_ai, fetch_recent_features, correlate, store_scenario
                from detection.threat_scoring import score_threat
                from detection.mitre_mapping import map_to_mitre
                from incidents.workflow import ensure_workflow_row, add_note
            except ImportError as e:
                if self.logger:
                    self.logger.error(f"Phase 5 modules not available: {e}")
                return {}
            
            alerts = fetch_recent_alerts(conn, minutes=5)
            ai = fetch_latest_ai(conn)
            recent_features = fetch_recent_features(conn, minutes=5)
            
            all_features = {**recent_features, **features}
            
            scenario_name, confidence, signals = correlate(alerts, ai, all_features, window_seconds=window_seconds)
            
            scenario_id = None
            if scenario_name != "NONE":
                scenario_id = store_scenario(conn, scenario_name, confidence, window_seconds, signals)
                if self.logger:
                    self.logger.info(f"📊 Phase 5: Correlated scenario '{scenario_name}' with confidence {confidence:.2f}")
            
            alert_count = len(alerts)
            threat_score, severity, breakdown = score_threat(all_features, ai, confidence, alert_count)
            
            alert_types = [a.get("alert_type") for a in alerts[:5]]
            primary_alert = alerts[0].get("alert_type") if alerts else None
            tactic, tid, tname = map_to_mitre(scenario_name, primary_alert, alert_types)
            
            conn.execute(
                """INSERT INTO incident_enrichment(
                    incident_id, threat_score, severity, score_breakdown_json,
                    scenario_name, confidence, mitre_tactic, mitre_technique_id, mitre_technique_name
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    threat_score=excluded.threat_score,
                    severity=excluded.severity,
                    score_breakdown_json=excluded.score_breakdown_json,
                    scenario_name=excluded.scenario_name,
                    confidence=excluded.confidence,
                    mitre_tactic=excluded.mitre_tactic,
                    mitre_technique_id=excluded.mitre_technique_id,
                    mitre_technique_name=excluded.mitre_technique_name,
                    updated_at=CURRENT_TIMESTAMP""",
                (
                    incident_id,
                    int(threat_score),
                    severity,
                    json.dumps(breakdown, ensure_ascii=False),
                    scenario_name if scenario_name != "NONE" else None,
                    float(confidence),
                    tactic, tid, tname
                ),
            )
            conn.commit()
            
            ensure_workflow_row(conn, incident_id)
            note = f"Phase 5 Enrichment: Score={threat_score} ({severity}) | Scenario={scenario_name} | MITRE={tid}"
            add_note(conn, incident_id, note, actor="system")
            
            if self.logger:
                self.logger.info(f"✅ Phase 5: Incident #{incident_id} enriched - Score: {threat_score} ({severity})")
            
            return {
                "scenario": scenario_name,
                "confidence": confidence,
                "score": threat_score,
                "severity": severity,
                "mitre": (tactic, tid, tname),
                "scenario_id": scenario_id
            }
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Phase 5 enrichment error: {e}")
                traceback.print_exc()
            return {}

    def _run_detection_cycle(self) -> None:
        """Run complete detection cycle with AI integration"""
        if not self.db or not self.feature_engine or not self.rules_engine or not self.incident_manager:
            if self.logger:
                self.logger.warning("Detection cycle: Required components not available")
            return
        
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                if self.logger:
                    self.logger.info("=" * 60)
                    self.logger.info("Starting detection cycle with AI...")
                
                window_seconds = self.config['app'].get('feature_window_seconds', 60)
                timestamp, features, evidence = self.feature_engine.extract_window_features(
                    self.db, window_seconds
                )
                
                if not features:
                    if self.logger:
                        self.logger.debug("No features extracted, skipping detection cycle")
                    return
                
                if self.logger:
                    self.logger.info(f"✅ Extracted {len(features)} features for {timestamp}")
                
                # AI Anomaly Scoring
                ai_result = None
                try:
                    from detection.isolation_forest import (
                        load_isolation_forest, 
                        score_latest_window, 
                        store_ai_score,
                        get_model_status
                    )
                    
                    conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                    model_status = get_model_status(conn)
                    
                    if model_status.get('trained', False):
                        scored = score_latest_window(conn, window_seconds=window_seconds)
                        
                        if scored:
                            ai_ts, ai_features, ai_result_obj = scored
                            
                            score_id = store_ai_score(
                                conn, 
                                ai_ts, 
                                window_seconds, 
                                ai_features, 
                                ai_result_obj
                            )
                            
                            if score_id > 0 and self.logger:
                                self.logger.info(f"✅ Stored AI score #{score_id}: {ai_result_obj.anomaly_score:.3f}")
                            elif self.logger:
                                self.logger.error("❌ Failed to store AI score")
                            
                            evidence['anomaly_score'] = ai_result_obj.anomaly_score
                            evidence['ai_is_anomaly'] = ai_result_obj.is_anomaly
                            evidence['threshold'] = ai_result_obj.threshold
                            evidence['confidence'] = ai_result_obj.confidence
                            
                            if self.logger:
                                self.logger.info(
                                    f"🤖 AI Score: {ai_result_obj.anomaly_score:.3f} | "
                                    f"Anomaly: {ai_result_obj.is_anomaly} | "
                                    f"Confidence: {ai_result_obj.confidence:.2f}"
                                )
                            
                            ai_result = ai_result_obj
                    elif self.logger:
                        self.logger.warning("🤖 AI model not trained")
                        
                except ImportError as e:
                    if self.logger:
                        self.logger.warning(f"🤖 AI module not available: {e}")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"🤖 AI scoring error: {e}")
                        traceback.print_exc()
                
                triggered_rules = self.rules_engine.evaluate_all_rules(features, evidence)
                
                if not triggered_rules:
                    if self.logger:
                        self.logger.info("No rules triggered")
                    return
                
                min_severity = self.config['detection'].get('min_severity', 'MEDIUM')
                severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                min_severity_value = severity_order.get(min_severity, 2)
                
                alerts_created = 0
                for rule_result in triggered_rules:
                    rule_severity_value = severity_order.get(rule_result.severity, 1)
                    if rule_severity_value < min_severity_value:
                        continue
                    
                    if hasattr(self.db, 'insert_alert'):
                        alert_id = self.db.insert_alert(
                            timestamp=timestamp,
                            alert_type=rule_result.alert_type,
                            severity=rule_result.severity,
                            description=rule_result.description,
                            evidence=rule_result.evidence or {},
                            incident_id=None
                        )
                    else:
                        conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                        cursor = conn.execute(
                            """INSERT INTO alerts (timestamp, alert_type, severity, description, evidence, incident_id) 
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (timestamp, rule_result.alert_type, rule_result.severity, 
                             rule_result.description, json.dumps(rule_result.evidence or {}), None)
                        )
                        alert_id = cursor.lastrowid
                        conn.commit()
                    
                    if alert_id > 0:
                        alerts_created += 1
                        
                        if self.logger:
                            if 'AI_' in rule_result.alert_type:
                                self.logger.warning(f"🤖 AI ALERT #{alert_id}: {rule_result.alert_type} ({rule_result.severity})")
                            else:
                                self.logger.warning(f"🚨 RULE ALERT #{alert_id}: {rule_result.alert_type} ({rule_result.severity})")
                        
                        if self.config['detection'].get('auto_create_incidents', True):
                            incident_id, is_new = self.incident_manager.handle_new_alert(
                                alert_type=rule_result.alert_type,
                                severity=rule_result.severity,
                                description=rule_result.description,
                                evidence=rule_result.evidence or {}
                            )
                            
                            if incident_id:
                                conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                                conn.execute(
                                    'UPDATE alerts SET incident_id = ? WHERE id = ?',
                                    (incident_id, alert_id)
                                )
                                conn.commit()
                                
                                # Phase 5 enrichment
                                try:
                                    enr_result = self.enrich_incident_phase5(
                                        conn, 
                                        incident_id, 
                                        features, 
                                        window_seconds
                                    )
                                    if enr_result and self.logger:
                                        self.logger.info(f"🤖 Phase 5: Incident #{incident_id} enriched")
                                except Exception as e:
                                    if self.logger:
                                        self.logger.error(f"❌ Phase 5 enrichment failed: {e}")
                                
                                # Update active lists
                                if incident_id not in self.active_incidents:
                                    self.active_incidents.append(incident_id)
                                
                                if alert_id not in self.active_alerts:
                                    self.active_alerts.append(alert_id)
                                
                                incident_type = "New" if is_new else "Existing"
                                if self.logger:
                                    self.logger.info(f"  → {incident_type} Incident #{incident_id}")
                
                summary_msg = f"Detection cycle completed: {alerts_created} alerts from {len(triggered_rules)} rules"
                if ai_result:
                    summary_msg += f" | AI Score: {ai_result.anomaly_score:.3f}"
                if self.logger:
                    self.logger.info(summary_msg)
                    self.logger.info("=" * 60)
                return
                
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) or "database is busy" in str(e):
                    delay = base_delay * (2 ** attempt)
                    delay = min(delay, 60)
                    if self.logger:
                        self.logger.warning(f"Database locked, attempt {attempt + 1}/{max_retries}, waiting {delay}s")
                    time.sleep(delay)
                else:
                    if self.logger:
                        self.logger.error(f"SQLite error: {e}")
                    break
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in detection cycle: {e}")
                    self.logger.error(traceback.format_exc())
                break
        
        if self.logger:
            self.logger.error("Detection cycle failed after maximum retries")
        
    def _show_system_dashboard(self) -> None:
        """Display system dashboard in console"""
        try:
            if self.db and self.logger and self.incident_manager:
                if hasattr(self.db, 'get_system_summary'):
                    summary = self.db.get_system_summary(hours=1)
                else:
                    summary = {}
                
                if hasattr(self.incident_manager, 'get_active_incidents_summary'):
                    incidents_summary = self.incident_manager.get_active_incidents_summary()
                else:
                    incidents_summary = {'total_open': 0, 'by_severity': {}}
                
                print("\n" + "=" * 60)
                print("📊 SECURITY MONITOR CONSOLE DASHBOARD (Last 1 Hour)")
                print("=" * 60)
                
                events_by_source = summary.get('events_by_source', {})
                if events_by_source:
                    print("📈 Events by Source:")
                    for source, count in events_by_source.items():
                        print(f"  • {source}: {count}")
                
                alerts_by_severity = summary.get('alerts_by_severity', {})
                if alerts_by_severity:
                    print("\n🚨 Alerts by Severity:")
                    for severity, count in alerts_by_severity.items():
                        icon = "🔴" if severity in ['HIGH', 'CRITICAL'] else "🟡" if severity == 'MEDIUM' else "🟢"
                        print(f"  {icon} {severity}: {count}")
                
                if incidents_summary.get('total_open', 0) > 0:
                    print(f"\n⚠️  Active Incidents: {incidents_summary['total_open']}")
                    for severity, count in incidents_summary.get('by_severity', {}).items():
                        if count > 0:
                            print(f"  • {severity}: {count}")
                
                avg_metrics = summary.get('avg_metrics', {})
                if avg_metrics:
                    print("\n⚙️  System Metrics:")
                    for metric, value in avg_metrics.items():
                        print(f"  • {metric}: {value}%")
                
                print(f"\n🔧 Collectors Active: {len(self.collectors)}/{len(self.config.get('collectors', {}))}")
                print(f"📊 Active Alerts: {len(self.active_alerts)}")
                print(f"⚠️  Active Incidents: {len(self.active_incidents)}")
                
                if self.dashboard_available:
                    dashboard_config = self.config.get('dashboard', {})
                    if dashboard_config.get('enabled', True):
                        print(f"📱 Web Dashboard: http://{dashboard_config.get('host', '127.0.0.1')}:{dashboard_config.get('port', 8050)}")
                    else:
                        print("📱 Web Dashboard: Disabled in config")
                else:
                    print("📱 Web Dashboard: Install dash & plotly to enable")
                
                print("=" * 60)
                
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error displaying console dashboard: {e}")
            
    def start(self) -> None:
        """Start the system"""
        try:
            self.running = True
            if self.logger:
                self.logger.info("Starting Security Monitor Enterprise...")
            
            if self.scheduler:
                self.scheduler.start()
                self.logger.info("✅ Scheduler started")
            
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            self._display_system_status()
            
            self.logger.info("Performing initial data collection...")
            self._run_initial_collection()
            
            # Try to import health monitor
            try:
                from monitoring.health import SystemHealthMonitor
                self.health_monitor = SystemHealthMonitor(self.config['app'].get('db_path', 'data/security.db'))
            except ImportError:
                self.health_monitor = None
                self.logger.warning("Health monitor not available")
            
            health_thresholds = self.config.get('phase6', {}).get('health_thresholds', {
                'cpu_percent_warn': 15,
                'ram_mb_warn': 200,
                'cycle_ms_warn': 800
            })
            
            last_dashboard_time = datetime.now()
            last_health_check_time = datetime.now()
            last_metrics_time = time.time()
            metrics_interval = self.config.get('phase6', {}).get('metrics_interval_seconds', 30)
            max_retries = self.config.get('phase6', {}).get('max_retries', 5)
            backoff_base = self.config.get('phase6', {}).get('backoff_base', 2)
            
            self.logger.info("✅ System is now running with Crash-Safe protection")
            
            while self.running:
                cycle_start = time.time()
                
                try:
                    retry_count = 0
                    delay = 1.0
                    
                    while retry_count < max_retries:
                        try:
                            self._run_detection_cycle()
                            break
                        except sqlite3.OperationalError as e:
                            if "locked" in str(e).lower() or "busy" in str(e).lower():
                                retry_count += 1
                                self.logger.warning(f"Database locked, retry {retry_count}/{max_retries} in {delay:.1f}s")
                                time.sleep(delay)
                                delay = min(delay * backoff_base, 30.0)
                            else:
                                raise
                        except Exception as e:
                            self.logger.error(f"Error in detection cycle: {e}")
                            self.logger.error(traceback.format_exc())
                            break
                    
                    cycle_ms = (time.time() - cycle_start) * 1000
                    
                    current_time = time.time()
                    if current_time - last_metrics_time >= metrics_interval and self.health_monitor:
                        try:
                            import psutil
                            
                            process = psutil.Process(os.getpid())
                            metrics = self.health_monitor.collect_system_metrics(process)
                            
                            metrics['alert_queue_size'] = len(self.active_alerts)
                            metrics['incident_queue_size'] = len(self.active_incidents)
                            metrics['total_latency_ms'] = cycle_ms
                            
                            self.health_monitor.save_metrics_to_db(metrics)
                            
                            warnings = self.health_monitor.check_thresholds(metrics, health_thresholds)
                            if warnings:
                                self.logger.warning(f"⚠️ System Health Warnings: {', '.join(warnings)}")
                            
                            last_metrics_time = current_time
                            
                        except Exception as e:
                            self.logger.error(f"Error collecting system metrics: {e}")
                    
                    current_datetime = datetime.fromtimestamp(current_time)
                    if (current_datetime - last_dashboard_time).seconds >= 30:
                        self._show_system_dashboard()
                        last_dashboard_time = current_datetime
                    
                    if (current_datetime - last_health_check_time).seconds >= 300:
                        self._health_check()
                        last_health_check_time = current_datetime
                    
                    time.sleep(1)
                    
                except KeyboardInterrupt:
                    self.logger.info("Received stop signal from user")
                    self.stop()
                    break
                except Exception as e:
                    self.logger.error(f"Unexpected error in main loop: {e}")
                    self.logger.error(traceback.format_exc())
                    time.sleep(5)
                    
        except KeyboardInterrupt:
            if self.logger:
                self.logger.info("Received stop signal from user")
            self.stop()
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error starting system: {e}")
                traceback.print_exc()
            self.stop()
            
    def _run_initial_collection(self) -> None:
        """Run initial data collection"""
        try:
            self.logger.info("Running initial data collection...")
            
            if 'process' in self.collectors:
                self._collect_process_data()
                time.sleep(1)
                
            if 'network' in self.collectors:
                self._collect_network_data()
                time.sleep(1)
                
            if 'eventlog' in self.collectors:
                self._collect_eventlog_data()
                time.sleep(1)
                
            if 'login' in self.collectors:
                self._collect_login_data()
                
            self.logger.info("✅ Initial data collection completed")
            
        except Exception as e:
            self.logger.error(f"Error in initial collection: {e}")
            
    def _health_check(self) -> None:
        """Perform system health check"""
        try:
            self.logger.info("Performing health check...")
            
            if self.db:
                conn = self.db._get_connection() if hasattr(self.db, '_get_connection') else self.db
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM events")
                event_count = cursor.fetchone()[0]
                self.logger.debug(f"Database health: {event_count} events total")
            
            if self.scheduler:
                status = self.scheduler.get_status()
                active_tasks = sum(1 for task in status if task.get('enabled', False))
                self.logger.debug(f"Scheduler health: {active_tasks} active tasks")
            
            collector_status = {}
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'collect_processes'):
                        data = collector.collect_processes()
                        collector_status[name] = f"OK ({data.get('total_processes', 0)} processes)"
                    elif hasattr(collector, 'collect_connections'):
                        data = collector.collect_connections()
                        collector_status[name] = f"OK ({data.get('total_connections', 0)} connections)"
                    else:
                        collector_status[name] = "OK"
                except Exception as e:
                    collector_status[name] = f"ERROR: {str(e)[:50]}"
            
            for name, status in collector_status.items():
                self.logger.debug(f"Collector {name}: {status}")
                
            self.logger.info("✅ Health check completed")
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            
    def stop(self) -> None:
        """Stop the system"""
        if self.logger:
            self.logger.info("Stopping Security Monitor Enterprise...")
        self.running = False
        
        if self.scheduler:
            self.scheduler.stop()
            self.logger.info("✅ Scheduler stopped")
            
        if self.db and hasattr(self.db, 'close'):
            self.db.close()
            self.logger.info("✅ Database connections closed")
            
        if self.logger:
            self.logger.info("✅ System stopped successfully")
        
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle system signals"""
        if self.logger:
            self.logger.info(f"Received signal {signum}")
        self.stop()
                
    def _display_system_status(self) -> None:
        """Display system status in console"""
        app_version = self.config.get('app', {}).get('version', '2.0.0')
        app_name = self.config.get('app', {}).get('name', 'Security Monitor Enterprise')
        
        centered_name = app_name.center(52)
        
        status_info = f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║{centered_name}║
    ╠══════════════════════════════════════════════════════════════╣
    ║                        Version {app_version:^12}                        ║
    ╠══════════════════════════════════════════════════════════════╣"""
        
        if self.collectors:
            for name in self.collectors.keys():
                status_info += f"\n║  ✓ {name.capitalize()} Collector: Active"
            status_info += f"\n║  • Total active collectors: {len(self.collectors)}"
        else:
            status_info += "\n║  ⚠️  No active collectors"
        
        status_info += """
    ╠══════════════════════════════════════════════════════════════╣
    ║                    PHASE 2: ENTERPRISE                      ║
    ╠══════════════════════════════════════════════════════════════╣"""
        
        if self.feature_engine:
            status_info += "\n║  ✓ Feature Engine: Active"
        else:
            status_info += "\n║  ⚠️  Feature Engine: Not Available"
        
        if self.rules_engine:
            if hasattr(self.rules_engine, 'rules'):
                rule_count = len(self.rules_engine.rules)
                status_info += f"\n║  ✓ Rules Engine: {rule_count} rules loaded"
            else:
                status_info += "\n║  ✓ Rules Engine: Available"
        else:
            status_info += "\n║  ⚠️  Rules Engine: Not Available"
        
        if self.incident_manager:
            status_info += "\n║  ✓ Incident Manager: Active"
        else:
            status_info += "\n║  ⚠️  Incident Manager: Not Available"
        
        status_info += "\n║  ✓ Database: Thread-safe SQLite"
        status_info += f"\n║  • Active Alerts: {len(self.active_alerts)}"
        status_info += f"\n║  • Active Incidents: {len(self.active_incidents)}"
        
        status_info += """
    ╠══════════════════════════════════════════════════════════════╣
    ║                    WEB DASHBOARD                            ║
    ╠══════════════════════════════════════════════════════════════╣"""
        
        if self.dashboard_available:
            dashboard_config = self.config.get('dashboard', {})
            if dashboard_config.get('enabled', True):
                host = dashboard_config.get('host', '0.0.0.0')
                port = dashboard_config.get('port', 8050)
                language = dashboard_config.get('language', 'en').upper()
                status_info += f"\n║  ✓ Dashboard: Available"
                status_info += f"\n║  • URL: http://{host}:{port}"
                status_info += f"\n║  • Language: {language}"
            else:
                status_info += f"\n║  ⚠️  Dashboard: Disabled in configuration"
        else:
            status_info += f"\n║  ⚠️  Dashboard: Install dash & plotly to enable"
        
        status_info += """
    ╠══════════════════════════════════════════════════════════════╣
    ║  • Console dashboard updates every 30 seconds               ║
    ║  • Press Ctrl+C to stop the system                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """
        
        print(status_info)
            
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            'running': self.running,
            'collectors': list(self.collectors.keys()),
            'database': self.db is not None,
            'feature_engine': self.feature_engine is not None,
            'rules_engine': self.rules_engine is not None,
            'incident_manager': self.incident_manager is not None,
            'scheduler': self.scheduler.get_status() if self.scheduler else [],
            'dashboard_available': self.dashboard_available,
            'active_alerts': len(self.active_alerts),
            'active_incidents': len(self.active_incidents),
            'config': {
                'detection_enabled': self.config['detection'].get('enabled', True),
                'dashboard_enabled': self.config.get('dashboard', {}).get('enabled', True)
            }
        }

def main() -> None:
    """Main entry point"""
    try:
        if len(sys.argv) > 1:
            if sys.argv[1] == '--help' or sys.argv[1] == '-h':
                print("""
Security Monitoring System - Enterprise Edition
Usage: python main.py [OPTIONS]

Options:
  --help, -h     Show this help message
  --version, -v  Show version information
  --config PATH  Use custom configuration file
  --no-dashboard Disable web dashboard
  --console-only Run in console-only mode
                """)
                return
            elif sys.argv[1] == '--version' or sys.argv[1] == '-v':
                print("Security Monitoring System Enterprise Edition v2.0")
                return
            elif sys.argv[1] == '--config' and len(sys.argv) > 2:
                config_path = sys.argv[2]
                print(f"Using custom configuration: {config_path}")
                monitor = SecurityMonitorEnterprise(config_path)
            elif sys.argv[1] == '--no-dashboard' or sys.argv[1] == '--console-only':
                print("Running in console-only mode")
                monitor = SecurityMonitorEnterprise()
                monitor.dashboard_available = False
            else:
                print(f"Unknown option: {sys.argv[1]}")
                print("Use --help for usage information")
                return
        else:
            monitor = SecurityMonitorEnterprise()
        
        monitor.start()
        
    except KeyboardInterrupt:
        print("\n✅ System stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)

def main_with_watchdog():
    """Main function with Watchdog"""
    try:
        monitor = SecurityMonitorEnterprise()
        monitor.start()
        
    except KeyboardInterrupt:
        print("\n✅ System stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    if os.environ.get("SMS_WATCHDOG") == "1" and os.environ.get("SMS_WATCHDOG_CHILD") != "1":
        print("🔧 Running with Watchdog protection")
        try:
            from core.watchdog import SystemWatchdog
            watchdog = SystemWatchdog()
            watchdog.start()
        except ImportError:
            print("⚠️ Watchdog module not available, running normally")
            main_with_watchdog()
    else:
        main_with_watchdog()