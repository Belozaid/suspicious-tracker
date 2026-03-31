"""
Notification Engine for Alerts and Incidents
محرك الإشعارات للتنبيهات والحوادث
"""

import json
import smtplib
import logging
import os
import sys
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Dict, List, Optional, Any
import warnings

# إعداد التسجيل الموحد
logger = logging.getLogger(__name__)

# محاولة استيراد pygame و numpy بشكل اختياري
try:
    import pygame
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    logger.warning("⚠️ Pygame not available, sound alerts disabled")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("⚠️ NumPy not available, sound alerts disabled")


class NotificationEngine:
    """Notification engine for sending alerts via multiple channels"""
    
    def __init__(self, config: Dict):
        """
        Initialize notification engine
        
        Args:
            config: Configuration dictionary with alerts and email settings
        """
        self.config = config
        
        # Get alert configuration with defaults
        alerts_config = config.get('alerts', {})
        self.sound_enabled = alerts_config.get('enable_sound_alerts', True) and PYGAME_AVAILABLE and NUMPY_AVAILABLE
        self.email_enabled = alerts_config.get('enable_email_alerts', False)
        self.channels = alerts_config.get('channels', ['console'])
        
        # Initialize sound system if enabled
        self.alert_sounds = {}
        if self.sound_enabled:
            self._init_sound_system()
        
        # Email configuration
        self.email_config = config.get('email', {})
        
        # Log configuration
        self.log_path = config.get('monitoring', {}).get('log_path', './logs/security_alerts.log')
        
        # Initialize logging if needed
        if 'log_file' in self.channels:
            self._init_logging()
        
        logger.info("Notification engine initialized")
        logger.info(f"  • Sound alerts: {'Enabled' if self.sound_enabled else 'Disabled'}")
        logger.info(f"  • Email alerts: {'Enabled' if self.email_enabled else 'Disabled'}")
        logger.info(f"  • Channels: {self.channels}")
    
    def _init_sound_system(self):
        """Initialize sound system for alerts with error handling"""
        if not PYGAME_AVAILABLE or not NUMPY_AVAILABLE:
            logger.warning("Sound system unavailable: missing pygame or numpy")
            self.sound_enabled = False
            return
        
        try:
            # Try to initialize pygame mixer
            pygame.mixer.init(frequency=22050, size=-16, channels=1, buffer=512)
            
            # Create simple alert sounds
            self.alert_sounds = {
                'LOW': self._create_beep_sound(440, 200),    # A4
                'MEDIUM': self._create_beep_sound(554, 300), # C#5
                'HIGH': self._create_beep_sound(659, 400),   # E5
                'CRITICAL': self._create_beep_sound(880, 500) # A5
            }
            
            # Remove any failed sounds
            self.alert_sounds = {k: v for k, v in self.alert_sounds.items() if v is not None}
            
            if self.alert_sounds:
                logger.info("✅ Sound system initialized successfully")
            else:
                logger.warning("⚠️ Sound system initialized but no sounds created")
                self.sound_enabled = False
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize sound system: {e}")
            self.sound_enabled = False
    
    def _create_beep_sound(self, frequency: int, duration: int):
        """Create a simple beep sound with error handling"""
        if not PYGAME_AVAILABLE or not NUMPY_AVAILABLE:
            return None
        
        try:
            import numpy as np
            
            sample_rate = 44100
            # Ensure duration is integer
            duration_samples = int(duration * sample_rate / 1000.0)
            if duration_samples <= 0:
                duration_samples = int(sample_rate * 0.1)  # 100ms fallback
            
            samples = np.arange(duration_samples)
            waveform = np.sin(2 * np.pi * frequency * samples / sample_rate)
            
            # Normalize to 16-bit integer range
            waveform = np.int16(waveform * 32767 * 0.5)  # Reduce volume by half
            
            # Ensure waveform is 2D for stereo or mono
            if len(waveform.shape) == 1:
                waveform = waveform.reshape(-1, 1)
            
            return pygame.sndarray.make_sound(waveform)
            
        except Exception as e:
            logger.debug(f"Failed to create beep sound: {e}")
            return None
    
    def _init_logging(self):
        """Initialize file logging for alerts"""
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(self.log_path)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            
            # Create separate logger for alerts
            alert_logger = logging.getLogger('security_alerts')
            
            # Avoid adding multiple handlers
            if not alert_logger.handlers:
                file_handler = logging.FileHandler(self.log_path, encoding='utf-8')
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                file_handler.setFormatter(formatter)
                alert_logger.addHandler(file_handler)
                alert_logger.setLevel(logging.INFO)
                alert_logger.propagate = False
                
            logger.info(f"✅ Logging initialized at: {self.log_path}")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize logging: {e}")
    
    def send_alert_notification(self, alert_data: Dict):
        """
        Send notification for a new alert
        إرسال إشعار لتنبيه جديد
        """
        severity = alert_data.get('severity', 'MEDIUM')
        title = alert_data.get('title', 'Unknown Alert')
        
        logger.info(f"🔔 New Alert: {title} ({severity})")
        
        # Send to configured channels
        for channel in self.channels:
            try:
                if channel == 'console':
                    self._send_console_notification(alert_data)
                elif channel == 'database':
                    self._send_database_notification(alert_data)
                elif channel == 'log_file':
                    self._send_log_notification(alert_data)
                elif channel == 'sound' and self.sound_enabled:
                    self._play_alert_sound(alert_data.get('severity', 'MEDIUM'))
                elif channel == 'email' and self.email_enabled:
                    self._send_email_notification(alert_data)
                else:
                    if channel not in ['console', 'database', 'log_file', 'sound', 'email']:
                        logger.warning(f"Unknown notification channel: {channel}")
                        
            except Exception as e:
                logger.error(f"❌ Error sending notification via {channel}: {e}")
    
    def send_incident_notification(self, incident_data: Dict):
        """
        Send notification for a new incident
        إرسال إشعار لحادثة جديدة
        """
        severity = incident_data.get('severity', 'MEDIUM')
        title = incident_data.get('title', 'Unknown Incident')
        incident_id = incident_data.get('incident_id', 'UNKNOWN')
        
        logger.warning(f"🚨 New Incident: {title} ({severity}) - ID: {incident_id}")
        
        # Send to console
        self._send_console_incident_notification(incident_data)
        
        # Log to file if enabled
        if 'log_file' in self.channels:
            self._send_incident_log_notification(incident_data)
        
        # Play critical sound for high severity incidents
        if severity.upper() in ['HIGH', 'CRITICAL'] and self.sound_enabled:
            self._play_alert_sound('CRITICAL')
        
        # Send email for incidents if enabled
        if self.email_enabled:
            self._send_incident_email_notification(incident_data)
    
    def _send_console_notification(self, alert_data: Dict):
        """Send notification to console with color coding"""
        severity = alert_data.get('severity', 'MEDIUM')
        title = alert_data.get('title', 'Unknown Alert')
        description = alert_data.get('description', 'No description')
        
        # Color coding based on severity (ANSI colors)
        colors = {
            'LOW': '\033[93m',      # Yellow
            'MEDIUM': '\033[33m',   # Orange/Yellow
            'HIGH': '\033[91m',     # Light Red
            'CRITICAL': '\033[31m'  # Dark Red
        }
        
        color = colors.get(severity.upper(), '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}{'='*60}{reset}")
        print(f"{color}⚠️  SECURITY ALERT{reset}")
        print(f"{color}{'='*60}{reset}")
        print(f"{color}Severity: {severity}{reset}")
        print(f"{color}Title: {title}{reset}")
        print(f"{color}Description: {description}{reset}")
        print(f"{color}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        print(f"{color}{'='*60}{reset}\n")
    
    def _send_console_incident_notification(self, incident_data: Dict):
        """Send incident notification to console"""
        severity = incident_data.get('severity', 'MEDIUM')
        title = incident_data.get('title', 'Unknown Incident')
        incident_id = incident_data.get('incident_id', 'UNKNOWN')
        
        colors = {
            'LOW': '\033[93m',      # Yellow
            'MEDIUM': '\033[33m',   # Orange/Yellow
            'HIGH': '\033[91m',     # Light Red
            'CRITICAL': '\033[31m'  # Dark Red
        }
        
        color = colors.get(severity.upper(), '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}{'='*60}{reset}")
        print(f"{color}🚨 SECURITY INCIDENT{reset}")
        print(f"{color}{'='*60}{reset}")
        print(f"{color}Incident ID: {incident_id}{reset}")
        print(f"{color}Severity: {severity}{reset}")
        print(f"{color}Title: {title}{reset}")
        print(f"{color}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        print(f"{color}Status: {incident_data.get('status', 'ACTIVE')}{reset}")
        print(f"{color}{'='*60}{reset}\n")
    
    def _send_database_notification(self, alert_data: Dict):
        """Store notification in database"""
        # Already handled by main detection engine
        # This method exists for interface consistency
        pass
    
    def _send_log_notification(self, alert_data: Dict):
        """Write notification to log file"""
        try:
            alert_logger = logging.getLogger('security_alerts')
            
            severity = alert_data.get('severity', 'MEDIUM')
            title = alert_data.get('title', 'Unknown Alert')
            description = alert_data.get('description', 'No description')
            
            log_message = f"ALERT [{severity}]: {title} - {description}"
            alert_logger.info(log_message)
            
        except Exception as e:
            logger.error(f"Failed to write to log file: {e}")
    
    def _send_incident_log_notification(self, incident_data: Dict):
        """Write incident notification to log file"""
        try:
            alert_logger = logging.getLogger('security_alerts')
            
            severity = incident_data.get('severity', 'MEDIUM')
            title = incident_data.get('title', 'Unknown Incident')
            incident_id = incident_data.get('incident_id', 'UNKNOWN')
            
            log_message = f"INCIDENT [{severity}]: #{incident_id} - {title}"
            alert_logger.warning(log_message)
            
        except Exception as e:
            logger.error(f"Failed to write incident to log file: {e}")
    
    def _play_alert_sound(self, severity: str):
        """Play alert sound based on severity"""
        if not self.sound_enabled or not self.alert_sounds:
            return
        
        sound = self.alert_sounds.get(severity.upper())
        if sound:
            try:
                sound.play()
                # Don't wait for sound to finish to avoid blocking
            except Exception as e:
                logger.debug(f"Failed to play sound: {e}")
    
    def _send_email_notification(self, alert_data: Dict):
        """Send email notification for alert"""
        if not self.email_enabled:
            return
        
        try:
            # Validate email configuration
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            sender_email = self.email_config.get('sender_email')
            sender_password = self.email_config.get('sender_password')
            recipient_email = self.email_config.get('recipient_email')
            sender_name = self.email_config.get('sender_name', 'Security Monitor')
            timeout = self.email_config.get('timeout', 30)
            
            if not all([smtp_server, smtp_port, sender_email, sender_password, recipient_email]):
                logger.warning("⚠️ Email configuration incomplete, skipping email notification")
                return
            
            # Create email
            subject = f"Security Alert: {alert_data.get('title', 'Unknown Alert')}"
            
            # Create HTML email with UTF-8 encoding
            html = self._create_alert_email_html(alert_data)
            plain = self._create_alert_email_plain(alert_data)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = formataddr((sender_name, sender_email))
            msg['To'] = recipient_email
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Attach parts with proper encoding
            msg.attach(MIMEText(plain, 'plain', 'utf-8'))
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            # Send email with timeout
            with smtplib.SMTP(smtp_server, smtp_port, timeout=timeout) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            
            logger.info(f"✅ Email notification sent to {recipient_email}")
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ Email authentication failed: {e}")
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP error sending email: {e}")
        except Exception as e:
            logger.error(f"❌ Error sending email notification: {e}")
    
    def _send_incident_email_notification(self, incident_data: Dict):
        """Send email notification for incident"""
        try:
            # Validate email configuration
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            sender_email = self.email_config.get('sender_email')
            sender_password = self.email_config.get('sender_password')
            recipient_email = self.email_config.get('recipient_email')
            sender_name = self.email_config.get('sender_name', 'Security Monitor')
            timeout = self.email_config.get('timeout', 30)
            
            if not all([smtp_server, smtp_port, sender_email, sender_password, recipient_email]):
                logger.warning("⚠️ Email configuration incomplete, skipping incident email")
                return
            
            # Create email
            severity = incident_data.get('severity', 'MEDIUM')
            incident_id = incident_data.get('incident_id', 'UNKNOWN')
            subject = f"[{severity}] Security Incident #{incident_id}: {incident_data.get('title', 'Unknown Incident')}"
            
            # Create HTML email
            html = self._create_incident_email_html(incident_data)
            plain = self._create_incident_email_plain(incident_data)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = formataddr((sender_name, sender_email))
            msg['To'] = recipient_email
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Attach parts
            msg.attach(MIMEText(plain, 'plain', 'utf-8'))
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port, timeout=timeout) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            
            logger.info(f"✅ Incident email notification sent for #{incident_id}")
            
        except Exception as e:
            logger.error(f"❌ Error sending incident email: {e}")
    
    def _create_alert_email_html(self, alert_data: Dict) -> str:
        """Create HTML email body for alert"""
        severity = alert_data.get('severity', 'MEDIUM')
        title = alert_data.get('title', 'Unknown Alert')
        description = alert_data.get('description', 'No description')
        recommendations = alert_data.get('recommendations', [])
        
        color = '#ff0000' if severity.upper() in ['HIGH', 'CRITICAL'] else '#ff9900'
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .alert {{ border: 2px solid {color}; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .severity {{ color: {color}; font-weight: bold; }}
                .header {{ background-color: {color}; color: white; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <div class="header">
                    <h2>⚠️ Security Alert</h2>
                </div>
                <h3>{self._escape_html(title)}</h3>
                <p><span class="severity">Severity:</span> {self._escape_html(severity)}</p>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Description:</strong><br/>{self._escape_html(description)}</p>
        """
        
        if recommendations:
            html += "<p><strong>Recommendations:</strong></p><ul>"
            for rec in recommendations:
                html += f"<li>{self._escape_html(rec)}</li>"
            html += "</ul>"
        
        html += """
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from Security Monitor System.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_alert_email_plain(self, alert_data: Dict) -> str:
        """Create plain text email body for alert"""
        severity = alert_data.get('severity', 'MEDIUM')
        title = alert_data.get('title', 'Unknown Alert')
        description = alert_data.get('description', 'No description')
        recommendations = alert_data.get('recommendations', [])
        
        text = f"""
SECURITY ALERT
{'=' * 40}

Severity: {severity}
Title: {title}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Description:
{description}

"""
        
        if recommendations:
            text += "Recommendations:\n"
            for rec in recommendations:
                text += f"  - {rec}\n"
        
        text += "\n" + "=" * 40 + "\n"
        text += "This is an automated message from Security Monitor System.\n"
        
        return text
    
    def _create_incident_email_html(self, incident_data: Dict) -> str:
        """Create HTML email body for incident"""
        severity = incident_data.get('severity', 'MEDIUM')
        title = incident_data.get('title', 'Unknown Incident')
        incident_id = incident_data.get('incident_id', 'UNKNOWN')
        description = incident_data.get('description', 'No description')
        
        color = '#ff0000' if severity.upper() in ['HIGH', 'CRITICAL'] else '#ff9900'
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .incident {{ border: 2px solid {color}; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .severity {{ color: {color}; font-weight: bold; }}
                .header {{ background-color: {color}; color: white; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="incident">
                <div class="header">
                    <h2>🚨 Security Incident</h2>
                </div>
                <h3>{self._escape_html(title)}</h3>
                <p><strong>Incident ID:</strong> #{self._escape_html(str(incident_id))}</p>
                <p><span class="severity">Severity:</span> {self._escape_html(severity)}</p>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Status:</strong> {self._escape_html(incident_data.get('status', 'ACTIVE'))}</p>
                <p><strong>Description:</strong><br/>{self._escape_html(description)}</p>
                <p style="color: #666; font-size: 12px;">
                    This is an automated message from Security Monitor System.
                    Please investigate this incident immediately.
                </p>
            </div>
        </body>
        </html>
        """
    
    def _create_incident_email_plain(self, incident_data: Dict) -> str:
        """Create plain text email body for incident"""
        severity = incident_data.get('severity', 'MEDIUM')
        title = incident_data.get('title', 'Unknown Incident')
        incident_id = incident_data.get('incident_id', 'UNKNOWN')
        description = incident_data.get('description', 'No description')
        
        return f"""
SECURITY INCIDENT
{'=' * 40}

Incident ID: #{incident_id}
Severity: {severity}
Title: {title}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: {incident_data.get('status', 'ACTIVE')}

Description:
{description}

{'=' * 40}
This is an automated message from Security Monitor System.
Please investigate this incident immediately.
"""
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if text is None:
            return ""
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    
    def get_status(self) -> Dict[str, Any]:
        """Get current notification engine status"""
        return {
            "sound_enabled": self.sound_enabled,
            "email_enabled": self.email_enabled,
            "channels": self.channels,
            "has_sounds": len(self.alert_sounds) > 0 if self.alert_sounds else False,
            "log_path": self.log_path if 'log_file' in self.channels else None
        }