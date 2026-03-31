# core/config_loader.py
"""
Secure configuration loader with environment variable support
Features:
- Load YAML configuration with safe_load
- Replace ${ENV_VAR} placeholders in values
- Support environment variable overrides with SMS__section__key format
- Type conversion for common data types
"""

import os
import yaml
import logging
from typing import Any, Dict, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Secure configuration loader with environment variable support"""
    
    def __init__(self, config_path: str = "core/config.yaml"):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.loaded = False
        
    def _replace_env_vars(self, value: Any) -> Any:
        """Recursively replace ${ENV_VAR} placeholders in configuration values"""
        if isinstance(value, str):
            # Check for ${ENV_VAR} pattern
            if value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                
                # Handle default value syntax: ${VAR:-default}
                if ':-' in env_var:
                    env_var_name, default_value = env_var.split(':-', 1)
                    env_var_name = env_var_name.strip()
                    default_value = default_value.strip()
                    env_value = os.getenv(env_var_name)
                    if env_value is not None:
                        logger.debug(f"Replaced {value} with environment variable {env_var_name}")
                        return env_value
                    else:
                        logger.info(f"Environment variable {env_var_name} not found, using default")
                        return default_value
                else:
                    env_value = os.getenv(env_var)
                    if env_value is not None:
                        logger.debug(f"Replaced {value} with environment variable {env_var}")
                        return env_value
                    else:
                        logger.warning(f"Environment variable {env_var} not found, keeping placeholder: {value}")
                        return value
            
            # Handle inline environment variables (multiple in one string)
            import re
            pattern = r'\$\{([^}]+)\}'
            matches = re.findall(pattern, value)
            for match in matches:
                # Handle default value in inline
                if ':-' in match:
                    env_var_name, default_value = match.split(':-', 1)
                    env_var_name = env_var_name.strip()
                    default_value = default_value.strip()
                    env_value = os.getenv(env_var_name, default_value)
                else:
                    env_value = os.getenv(match, '')
                
                if env_value:
                    value = value.replace(f'${{{match}}}', env_value)
                    logger.debug(f"Replaced ${{{match}}} in string")
            return value
        
        elif isinstance(value, dict):
            return {k: self._replace_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._replace_env_vars(item) for item in value]
        else:
            return value
    
                    
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides in format: SMS__section__key=value"""
        prefix = "SMS__"
        for env_key, env_value in os.environ.items():
            if env_key.startswith(prefix):
                # Convert SMS__section__key to ['section', 'key']
                path = env_key[len(prefix):].lower().split('__')
                
                # Navigate to the correct location in config
                current = self.config
                for i, part in enumerate(path[:-1]):
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                # Convert string to appropriate type
                final_key = path[-1]
                if env_value.lower() == 'true':
                    current[final_key] = True
                elif env_value.lower() == 'false':
                    current[final_key] = False
                elif env_value.isdigit():
                    current[final_key] = int(env_value)
                elif env_value.replace('.', '', 1).isdigit() and env_value.count('.') == 1:
                    current[final_key] = float(env_value)
                else:
                    current[final_key] = env_value
                
                logger.info(f"Applied environment override: {env_key} = {env_value}")

    def get_users_without_passwords(self) -> list:
        """Get list of users without exposing passwords - for dashboard display"""
        users = []
        try:
            # Try to get from config
            config_dict = self.config
            
            if 'dashboard' in config_dict and 'users' in config_dict['dashboard']:
                raw_users = config_dict['dashboard']['users']
                if isinstance(raw_users, list):
                    for user in raw_users:
                        if isinstance(user, dict):
                            # Create safe copy without password
                            safe_user = {
                                'username': user.get('username', 'unknown'),
                                'role': user.get('role', 'VIEWER'),
                                'full_name': user.get('full_name', user.get('username', 'unknown')),
                                'email': user.get('email', '')
                            }
                            users.append(safe_user)
        except Exception as e:
            logger.error(f"Error getting users without passwords: {e}")
        
        return users
    
    def load(self) -> Dict[str, Any]:
        """Load configuration from YAML file with environment variable support"""
        try:
            config_path = Path(self.config_path)
            if not config_path.exists():
                logger.error(f"Configuration file not found: {config_path}")
                return self._get_default_config()
            
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
            
            # Replace environment variable placeholders
            self.config = self._replace_env_vars(self.config)
            
            # Apply environment variable overrides
            self._apply_env_overrides()
            
            self.loaded = True
            logger.info(f"Configuration loaded successfully from {config_path}")
            
            # Log sensitive configuration status (without values)
            self._log_config_status()
            
            return self.config
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return self._get_default_config()
    
    def _log_config_status(self) -> None:
        """Log configuration status without exposing sensitive values"""
        # Check for sensitive configuration
        if 'alerting' in self.config:
            alerting = self.config['alerting']
            logger.info(f"Alerting: Email enabled = {alerting.get('email_enabled', False)}")
            logger.info(f"Alerting: SMTP server = {alerting.get('smtp_server', 'Not configured')}")
            
            # Check if SMTP password is set (show only if configured, not the value)
            smtp_pass = alerting.get('smtp_password')
            if smtp_pass:
                if smtp_pass.startswith('${') and smtp_pass.endswith('}'):
                    env_var = smtp_pass[2:-1]
                    if os.getenv(env_var):
                        logger.info(f"Alerting: SMTP password = [Set from {env_var}]")
                    else:
                        logger.warning(f"Alerting: SMTP password = [Environment variable {env_var} not set]")
                else:
                    logger.info("Alerting: SMTP password = [Configured]")
            else:
                logger.warning("Alerting: SMTP password = [Not configured]")
        
        if 'dashboard' in self.config:
            dashboard = self.config['dashboard']
            auth_user = dashboard.get('auth_user')
            auth_password = dashboard.get('auth_password')
            
            if auth_user:
                logger.info(f"Dashboard: Authentication user = {auth_user}")
            
            if auth_password:
                if auth_password.startswith('${') and auth_password.endswith('}'):
                    env_var = auth_password[2:-1]
                    if os.getenv(env_var):
                        logger.info(f"Dashboard: Authentication password = [Set from {env_var}]")
                    else:
                        logger.warning(f"Dashboard: Authentication password = [Environment variable {env_var} not set]")
                else:
                    logger.info("Dashboard: Authentication password = [Configured]")
            else:
                logger.warning("Dashboard: Authentication = [Disabled]")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'app.name')"""
        if not self.loaded:
            self.load()
        
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration if file loading fails"""
        return {
            'app': {
                'name': 'Security Monitoring System',
                'version': '1.0.0',
                'db_path': 'data/security.db',
                'log_path': 'logs/security_monitor.log'
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': 8050,
                'debug': False
            }
        }


# Singleton instance for easy import
_config_loader: Optional[ConfigLoader] = None


def load_config(config_path: str = "core/config.yaml") -> Dict[str, Any]:
    """Load configuration (singleton pattern)"""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader(config_path)
    return _config_loader.load()


def get_config_value(key: str, default: Any = None) -> Any:
    """Get configuration value using dot notation"""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader()
    return _config_loader.get(key, default)


def reload_config(config_path: str = None) -> Dict[str, Any]:
    """Reload configuration (useful for testing)"""
    global _config_loader
    if config_path:
        _config_loader = ConfigLoader(config_path)
    elif _config_loader is None:
        _config_loader = ConfigLoader()
    
    return _config_loader.load()

def get_config(config_path: str = "core/config.yaml") -> Dict[str, Any]:
    """Alias for load_config for backward compatibility"""
    return load_config(config_path)