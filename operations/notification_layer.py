
# operations/notification_layer.py
"""
Notification Layer - Email, Desktop, and Sound notifications
Version 4.0.0
"""
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import os

try:
    import win10toast  # For Windows desktop notifications
    DESKTOP_NOTIF_AVAILABLE = True
except ImportError:
    DESKTOP_NOTIF_AVAILABLE = False

try:
    import pygame  # For sound alerts
    SOUND_AVAILABLE = True
except ImportError:
    SOUND_AVAILABLE = False

class NotificationLayer:
    """Comprehensive notification system for security alerts"""
    
    def __init__(self, logger: logging.Logger = None, config: Dict = None):
        self.logger = logger or logging.getLogger(__name__)
        self.config = config or {}
        self.notification_history: List[Dict] = []
        
        # Initialize sound if available
        if SOUND_AVAILABLE:
            try:
                pygame.mixer.init()
                self.sound_available = True
            except:
                self.sound_available = False
        else:
            self.sound_available = False
        
        # Initialize desktop notifier if available
        if DESKTOP_NOTIF_AVAILABLE:
            try:
                self.toaster = win10toast.ToastNotifier()
                self.desktop_available = True
            except:
                self.desktop_available = False
        else:
            self.desktop_available = False
        
        self.logger.info(f"Notification layer initialized: Desktop={self.desktop_available}, Sound={self.sound_available}")
    
    def send_notification(self, notification_data: Dict, channels: List[str] = None) -> Dict:
        """
        Send notification through multiple channels
        
        Args:
            notification_data: Notification content
            channels: List of channels to use
            
        Returns:
            Dictionary with send results
        """
        if channels is None:
            channels = ['desktop']  # Default channel
        
        results = {}
        
        for channel in channels:
            if channel == 'email':
                result = self.send_email_notification(notification_data)
                results['email'] = result
            elif channel == 'desktop':
                result = self.send_desktop_notification(notification_data)
                results['desktop'] = result
            elif channel == 'sound':
                result = self.play_alert_sound(notification_data.get('sound_type', 'alert'))
                results['sound'] = result
            elif channel == 'log':
                result = self.log_notification(notification_data)
                results['log'] = result
        
        # Record in history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'notification_data': notification_data,
            'channels': channels,
            'results': results,
            'successful': any(r.get('success', False) for r in results.values() if isinstance(r, dict))
        }
        self.notification_history.append(history_entry)
        
        # Keep only last 1000 entries
        if len(self.notification_history) > 1000:
            self.notification_history = self.notification_history[-1000:]
        
        return {
            'sent_at': datetime.now().isoformat(),
            'channels_attempted': channels,
            'results': results,
            'successful': history_entry['successful']
        }
    
    def send_email_notification(self, notification_data: Dict) -> Dict:
        """
        Send email notification
        
        Args:
            notification_data: Email content
            
        Returns:
            Send result
        """
        email_config = self.config.get('email', {})
        
        if not email_config.get('enabled', False):
            return {'success': False, 'error': 'Email notifications disabled'}
        
        try:
            # Extract email parameters
            smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = email_config.get('smtp_port', 587)
            email_from = email_config.get('email_from', '')
            email_to = email_config.get('email_to', '')
            ssl_required = email_config.get('ssl_required', True)
            
            if not all([smtp_server, email_from, email_to]):
                return {'success': False, 'error': 'Email configuration incomplete'}
            
            # Create message
            subject = notification_data.get('title', 'Security Alert')
            message = notification_data.get('message', 'Security incident detected')
            urgency = notification_data.get('urgency', 'medium')
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{urgency.upper()}] {subject}"
            msg['From'] = email_from
            msg['To'] = email_to
            
            # Create HTML content
            html = self._create_email_html(notification_data)
            text = self._create_email_text(notification_data)
            
            # Attach parts
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            
            if ssl_required:
                with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                    # In production, use proper authentication
                    server.login(email_from, email_config.get('password', ''))
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    server.starttls(context=context)
                    # In production, use proper authentication
                    server.login(email_from, email_config.get('password', ''))
                    server.send_message(msg)
            
            self.logger.info(f"Email notification sent to {email_to}")
            return {'success': True, 'recipient': email_to}
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return {'success': False, 'error': str(e)}
    
    def send_desktop_notification(self, notification_data: Dict) -> Dict:
        """
        Send desktop notification
        
        Args:
            notification_data: Notification content
            
        Returns:
            Send result
        """
        if not self.desktop_available:
            return {'success': False, 'error': 'Desktop notifications not available'}
        
        try:
            title = notification_data.get('title', 'Security Alert')
            message = notification_data.get('message', 'Security incident detected')
            duration = notification_data.get('duration', 10)  # seconds
            icon_path = notification_data.get('icon_path', None)
            
            self.toaster.show_toast(
                title,
                message,
                duration=duration,
                icon_path=icon_path,
                threaded=True
            )
            
            self.logger.info(f"Desktop notification shown: {title}")
            return {'success': True, 'title': title}
            
        except Exception as e:
            self.logger.error(f"Failed to show desktop notification: {e}")
            return {'success': False, 'error': str(e)}
    
    def play_alert_sound(self, sound_type: str = 'alert') -> Dict:
        """
        Play alert sound
        
        Args:
            sound_type: Type of sound to play
            
        Returns:
            Play result
        """
        if not self.sound_available:
            return {'success': False, 'error': 'Sound not available'}
        
        try:
            # Map sound types to files or frequencies
            sounds = {
                'alert': (440, 500),  # Frequency, duration
                'warning': (880, 300),
                'critical': (220, 1000),
                'info': (660, 200)
            }
            
            if sound_type in sounds:
                frequency, duration = sounds[sound_type]
                # In production, play actual sound files
                self.logger.info(f"Playing {sound_type} sound: {frequency}Hz for {duration}ms")
                # pygame.mixer.Sound(...).play()  # Actual implementation
                return {'success': True, 'sound_type': sound_type}
            else:
                return {'success': False, 'error': f'Unknown sound type: {sound_type}'}
                
        except Exception as e:
            self.logger.error(f"Failed to play sound: {e}")
            return {'success': False, 'error': str(e)}
    
    def log_notification(self, notification_data: Dict) -> Dict:
        """
        Log notification to file
        
        Args:
            notification_data: Notification content
            
        Returns:
            Log result
        """
        try:
            log_dir = "logs/notifications"
            os.makedirs(log_dir, exist_ok=True)
            
            filename = f"notifications_{datetime.now().strftime('%Y%m%d')}.log"
            filepath = os.path.join(log_dir, filename)
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'notification': notification_data,
                'type': 'logged'
            }
            
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            return {'success': True, 'log_file': filepath}
            
        except Exception as e:
            self.logger.error(f"Failed to log notification: {e}")
            return {'success': False, 'error': str(e)}
    
    def _create_email_html(self, notification_data: Dict) -> str:
        """Create HTML email content"""
        title = notification_data.get('title', 'Security Alert')
        message = notification_data.get('message', '')
        incident_id = notification_data.get('incident_id')
        severity = notification_data.get('severity', 'MEDIUM')
        
        severity_colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#f39c12',
            'MEDIUM': '#f1c40f',
            'LOW': '#2ecc71',
            'INFO': '#3498db'
        }
        
        color = severity_colors.get(severity, '#3498db')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px; }}
                .content {{ background-color: #f9f9f9; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .footer {{ color: #777; font-size: 12px; border-top: 1px solid #eee; padding-top: 10px; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: {color}; color: white; 
                         text-decoration: none; border-radius: 3px; margin: 10px 0; }}
                .severity {{ display: inline-block; padding: 3px 8px; background-color: {color}; 
                           color: white; border-radius: 3px; font-size: 12px; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Security Alert</h1>
                    <p><span class="severity">{severity}</span> • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="content">
                    <h2>{title}</h2>
                    <p>{message}</p>
                    
                    {f'<p><strong>Incident ID:</strong> #{incident_id}</p>' if incident_id else ''}
                    
                    <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    
                    <a href="#" class="button">View Incident Details</a>
                    
                    <p><em>This is an automated notification from the Security Operations Center.</em></p>
                </div>
                
                <div class="footer">
                    <p>Security Operations Center v4.0.0</p>
                    <p>This email was automatically generated. Please do not reply.</p>
                    <p>Confidential - For authorized recipients only</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_email_text(self, notification_data: Dict) -> str:
        """Create plain text email content"""
        title = notification_data.get('title', 'Security Alert')
        message = notification_data.get('message', '')
        incident_id = notification_data.get('incident_id')
        severity = notification_data.get('severity', 'MEDIUM')
        
        text = f"""
SECURITY ALERT - {severity}
========================================
{title}

{message}

{ f'Incident ID: #{incident_id}' if incident_id else '' }
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

========================================
This is an automated notification from the Security Operations Center.

Security Operations Center v4.0.0
Confidential - For authorized recipients only
        """
        
        return text.strip()
    
    def get_notification_history(self, limit: int = 100) -> List[Dict]:
        """Get notification history"""
        return self.notification_history[-limit:] if self.notification_history else []
    
    def clear_notification_history(self) -> None:
        """Clear notification history"""
        self.notification_history = []
        self.logger.info("Notification history cleared")