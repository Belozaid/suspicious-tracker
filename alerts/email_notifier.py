# alerts/email_notifier.py
"""
Email Notification System for Security Alerts
"""

import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from typing import Dict, Any, Optional, List, Union
from datetime import datetime

# إعداد التسجيل
logger = logging.getLogger(__name__)


class EmailNotifier:
    """Handles email notifications for security incidents"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize email notifier with configuration
        
        Args:
            config: Dictionary containing email configuration:
                - enabled: bool
                - smtp_server: str
                - smtp_port: int
                - sender_email: str
                - sender_name: str (optional)
                - sender_password: str
                - recipient_email: str or List[str]
                - use_tls: bool (default: True)
                - timeout: int (default: 30)
                - retry_count: int (default: 3)
        """
        self.config = config
        self.enabled = config.get("enabled", False)
        self.timeout = config.get("timeout", 30)
        self.retry_count = config.get("retry_count", 3)
        self.sender_name = config.get("sender_name", "Security Monitoring System")
        
        if self.enabled:
            self._validate_config()
    
    def _validate_config(self):
        """Validate email configuration"""
        required_fields = [
            "smtp_server",
            "smtp_port",
            "sender_email",
            "sender_password",
            "recipient_email"
        ]
        
        missing = [field for field in required_fields if not self.config.get(field)]
        if missing:
            logger.error(f"Missing email configuration: {missing}")
            raise ValueError(f"Missing email configuration: {missing}")
        
        # تحقق من صحة المنفذ
        try:
            port = int(self.config["smtp_port"])
            if port <= 0 or port > 65535:
                raise ValueError(f"Invalid SMTP port: {port}")
        except (ValueError, TypeError):
            raise ValueError(f"Invalid SMTP port: {self.config.get('smtp_port')}")
        
        # تحقق من صحة البريد الإلكتروني
        if '@' not in self.config["sender_email"]:
            raise ValueError(f"Invalid sender email: {self.config['sender_email']}")
        
        logger.info("Email configuration validated successfully")
    
    def _get_recipient_list(self) -> List[str]:
        """Get list of recipients (supports single string or list)"""
        recipients = self.config["recipient_email"]
        if isinstance(recipients, str):
            return [recipients]
        elif isinstance(recipients, list):
            return recipients
        else:
            raise ValueError(f"Invalid recipient_email type: {type(recipients)}")
    
    def send(self, subject: str, body: str, 
             html_body: Optional[str] = None,
             recipients: Optional[Union[str, List[str]]] = None) -> Dict[str, Any]:
        """
        Send email notification with retry logic
        
        Args:
            subject: Email subject
            body: Plain text email body
            html_body: Optional HTML email body
            recipients: Optional override for recipients
            
        Returns:
            Dictionary with send status and details
        """
        
        if not self.enabled:
            logger.warning("Email notifications disabled")
            return {"sent": False, "error": "Email notifications disabled"}
        
        # تحديد المستلمين
        recipient_list = self._get_recipient_list() if recipients is None else (
            [recipients] if isinstance(recipients, str) else recipients
        )
        
        if not recipient_list:
            logger.error("No recipients specified")
            return {"sent": False, "error": "No recipients specified"}
        
        # محاولة الإرسال مع إعادة المحاولة
        last_error = None
        for attempt in range(self.retry_count):
            try:
                result = self._send_email(subject, body, html_body, recipient_list)
                if result["sent"]:
                    logger.info(f"Email sent successfully to {', '.join(recipient_list)}")
                    return result
                else:
                    last_error = result.get("error", "Unknown error")
                    logger.warning(f"Attempt {attempt + 1}/{self.retry_count} failed: {last_error}")
                    
            except smtplib.SMTPServerDisconnected as e:
                last_error = f"SMTP server disconnected: {e}"
                logger.warning(f"Attempt {attempt + 1}/{self.retry_count}: {last_error}")
                
            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"SMTP authentication failed: {e}")
                return {
                    "sent": False,
                    "error": f"Authentication failed: {e}",
                    "subject": subject,
                    "timestamp": self._get_timestamp()
                }
                
            except smtplib.SMTPException as e:
                last_error = f"SMTP error: {e}"
                logger.warning(f"Attempt {attempt + 1}/{self.retry_count}: {last_error}")
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Attempt {attempt + 1}/{self.retry_count}: {last_error}")
            
            # انتظار قبل إعادة المحاولة (زيادة الوقت مع كل محاولة)
            if attempt < self.retry_count - 1:
                import time
                time.sleep(2 ** attempt)  # 1, 2, 4 ثواني
        
        # فشلت جميع المحاولات
        logger.error(f"Failed to send email after {self.retry_count} attempts: {last_error}")
        return {
            "sent": False,
            "error": last_error,
            "subject": subject,
            "timestamp": self._get_timestamp(),
            "recipients": recipient_list
        }
    
    def _send_email(self, subject: str, body: str, 
                    html_body: Optional[str],
                    recipients: List[str]) -> Dict[str, Any]:
        """Internal method to send email"""
        
        # Create message
        msg = MIMEMultipart("alternative")
        
        # Set subject with proper encoding
        try:
            msg["Subject"] = subject
        except Exception:
            # Fallback for non-ASCII subjects
            msg["Subject"] = subject.encode('utf-8', errors='ignore').decode('ascii', errors='ignore')
        
        # Set sender with name if provided
        sender = formataddr((self.sender_name, self.config["sender_email"]))
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        
        # Add plain text part with UTF-8 encoding
        try:
            text_part = MIMEText(body, "plain", "utf-8")
        except Exception:
            # Fallback for encoding issues
            text_part = MIMEText(body.encode('utf-8', errors='ignore').decode('ascii', errors='ignore'), "plain", "us-ascii")
        msg.attach(text_part)
        
        # Add HTML part if provided
        if html_body:
            try:
                html_part = MIMEText(html_body, "html", "utf-8")
            except Exception:
                # Fallback for encoding issues
                html_part = MIMEText(html_body.encode('utf-8', errors='ignore').decode('ascii', errors='ignore'), "html", "us-ascii")
            msg.attach(html_part)
        
        # Connect to SMTP server
        context = ssl.create_default_context()
        
        # Create connection with timeout
        server = None
        try:
            server = smtplib.SMTP(
                self.config["smtp_server"], 
                self.config["smtp_port"],
                timeout=self.timeout
            )
            
            # Start TLS if configured
            if self.config.get("use_tls", True):
                server.starttls(context=context)
            
            # Login
            server.login(self.config["sender_email"], self.config["sender_password"])
            
            # Send email
            server.send_message(msg)
            
            return {
                "sent": True,
                "subject": subject,
                "recipients": recipients,
                "timestamp": self._get_timestamp(),
                "message_id": msg.get("Message-ID", None)
            }
            
        except smtplib.SMTPHeloError as e:
            raise smtplib.SMTPException(f"Server did not respond to HELO: {e}")
        except smtplib.SMTPAuthenticationError as e:
            raise smtplib.SMTPAuthenticationError(e.smtp_code, e.smtp_error)
        except smtplib.SMTPServerDisconnected as e:
            raise smtplib.SMTPServerDisconnected(f"Server disconnected: {e}")
        except smtplib.SMTPException as e:
            raise smtplib.SMTPException(f"SMTP error: {e}")
        except Exception as e:
            raise Exception(f"Failed to send email: {e}")
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass  # Ignore errors on quit
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def send_incident_notification(self, incident: Dict[str, Any], 
                                   report_path: Optional[str] = None,
                                   additional_recipients: Optional[Union[str, List[str]]] = None) -> Dict[str, Any]:
        """
        Send formatted incident notification email
        
        Args:
            incident: Incident dictionary with incident details
            report_path: Optional path to PDF report
            additional_recipients: Optional additional recipients
        """
        
        # Create email content
        severity = incident.get('max_severity', 'MEDIUM')
        subject = f"[{severity}] Incident #{incident.get('id', 'Unknown')}: {incident.get('title', 'Security Alert')}"
        
        # Create HTML body
        html_body = self._create_incident_html(incident, report_path)
        
        # Create plain text body
        plain_body = self._create_incident_plain(incident, report_path)
        
        # Determine recipients
        recipients = None
        if additional_recipients:
            recipients = additional_recipients
        
        # Send email
        result = self.send(subject, plain_body, html_body, recipients)
        
        # Log incident notification
        if result["sent"]:
            logger.info(f"Incident #{incident.get('id')} notification sent successfully")
        else:
            logger.error(f"Failed to send incident #{incident.get('id')} notification: {result.get('error')}")
        
        return result
    
    def send_test_email(self) -> Dict[str, Any]:
        """Send a test email to verify configuration"""
        test_subject = "Security Monitoring System - Test Email"
        test_body = f"""
        Test Email from Security Monitoring System
        
        This is a test email to verify that email notifications are working correctly.
        
        Time: {self._get_timestamp()}
        Server: {self.config.get('smtp_server')}
        Sender: {self.config.get('sender_email')}
        
        If you received this email, the configuration is correct.
        """
        
        test_html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif;">
            <div style="background-color: #28a745; color: white; padding: 20px; text-align: center;">
                <h1>✅ Security Monitoring System</h1>
                <h2>Test Email</h2>
            </div>
            <div style="padding: 20px;">
                <p>This is a test email to verify that email notifications are working correctly.</p>
                <p><strong>Time:</strong> {self._get_timestamp()}</p>
                <p><strong>Server:</strong> {self.config.get('smtp_server')}</p>
                <p><strong>Sender:</strong> {self.config.get('sender_email')}</p>
                <p>If you received this email, the configuration is correct.</p>
            </div>
        </body>
        </html>
        """
        
        return self.send(test_subject, test_body, test_html)
    
    def _create_incident_html(self, incident: Dict[str, Any], 
                              report_path: Optional[str]) -> str:
        """Create HTML email body for incident with proper encoding"""
        
        severity_color = {
            "CRITICAL": "#dc3545",
            "HIGH": "#dc3545",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "INFO": "#17a2b8"
        }.get(incident.get('max_severity', 'MEDIUM'), '#6c757d')
        
        # Escape any potentially dangerous content
        def escape_html(text):
            if text is None:
                return "N/A"
            return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        
        incident_id = escape_html(incident.get('id', 'Unknown'))
        title = escape_html(incident.get('title', 'Security Alert'))
        severity = escape_html(incident.get('max_severity', 'MEDIUM'))
        status = escape_html(incident.get('status', 'OPEN'))
        start_time = escape_html(incident.get('start_ts_utc', 'N/A'))
        last_update = escape_html(incident.get('last_update_ts_utc', 'N/A'))
        summary = escape_html(incident.get('summary', 'No summary available'))
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {severity_color}; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ padding: 20px; background-color: #f8f9fa; border-radius: 0 0 5px 5px; }}
                .incident-details {{ background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
                .footer {{ text-align: center; padding: 20px; color: #6c757d; font-size: 12px; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: {severity_color}; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }}
                .severity-badge {{ display: inline-block; padding: 5px 10px; background-color: {severity_color}; color: white; border-radius: 3px; font-weight: bold; }}
                hr {{ border: none; border-top: 1px solid #dee2e6; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Security Incident Alert</h1>
                    <h2>Incident #{incident_id}</h2>
                    <span class="severity-badge">{severity} SEVERITY</span>
                </div>
                
                <div class="content">
                    <div class="incident-details">
                        <h3>📋 Incident Details</h3>
                        <p><strong>Title:</strong> {title}</p>
                        <p><strong>Severity:</strong> {severity}</p>
                        <p><strong>Status:</strong> {status}</p>
                        <p><strong>Start Time:</strong> {start_time}</p>
                        <p><strong>Last Updated:</strong> {last_update}</p>
                        <p><strong>Summary:</strong><br/>{summary}</p>
                    </div>
                    
                    <div style="text-align: center; margin: 20px 0;">
                        <a href="http://127.0.0.1:8050" class="button">📊 View in Dashboard</a>
                    </div>
                    
                    {f'<p><strong>📄 Detailed Report:</strong> {escape_html(report_path)}</p>' if report_path else ''}
                    
                    <hr/>
                    
                    <h4>⚡ Required Actions:</h4>
                    <ol>
                        <li>Review incident details in the security dashboard</li>
                        <li>Investigate related alerts and system logs</li>
                        <li>Take appropriate containment measures if needed</li>
                        <li>Update incident status as investigation progresses</li>
                    </ol>
                </div>
                
                <div class="footer">
                    <p>This email was automatically generated by the Security Monitoring System</p>
                    <p>© 2024 Cybersecurity SOC Dashboard - All rights reserved</p>
                    <p><small>Do not reply to this automated email</small></p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _create_incident_plain(self, incident: Dict[str, Any], 
                               report_path: Optional[str]) -> str:
        """Create plain text email body for incident"""
        
        incident_id = incident.get('id', 'Unknown')
        title = incident.get('title', 'Security Alert')
        severity = incident.get('max_severity', 'MEDIUM')
        status = incident.get('status', 'OPEN')
        start_time = incident.get('start_ts_utc', 'N/A')
        last_update = incident.get('last_update_ts_utc', 'N/A')
        summary = incident.get('summary', 'No summary available')
        
        return f"""
SECURITY INCIDENT NOTIFICATION
{'=' * 40}

INCIDENT DETAILS:
- Incident ID: #{incident_id}
- Title: {title}
- Severity: {severity}
- Status: {status}
- Start Time: {start_time}
- Last Updated: {last_update}

SUMMARY:
{summary}

{'=' * 40}

IMMEDIATE ACTIONS REQUIRED:
1. Review incident details in the security dashboard: http://127.0.0.1:8050
2. Investigate all related alerts and system logs
3. Take appropriate containment measures if required
4. Update incident status as investigation progresses

{'REPORT: A detailed PDF report has been generated: ' + report_path if report_path else 'No report generated'}

{'=' * 40}
This notification was automatically generated by the Security Monitoring System.
Time: {self._get_timestamp()}
Do not reply to this automated email.
"""
    
    def get_status(self) -> Dict[str, Any]:
        """Get email notifier status"""
        return {
            "enabled": self.enabled,
            "smtp_server": self.config.get("smtp_server") if self.enabled else None,
            "smtp_port": self.config.get("smtp_port") if self.enabled else None,
            "sender_email": self.config.get("sender_email") if self.enabled else None,
            "recipients": self._get_recipient_list() if self.enabled else None,
            "use_tls": self.config.get("use_tls", True),
            "timeout": self.timeout,
            "retry_count": self.retry_count
        }


# ============================================================
# Example Configuration
# ============================================================

def get_default_config() -> Dict[str, Any]:
    """Get default email configuration"""
    return {
        "enabled": False,  # Set to True to enable
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "your-email@gmail.com",
        "sender_name": "Security Monitoring System",
        "sender_password": "your-app-password",  # Use app password for Gmail
        "recipient_email": "admin@example.com",  # Can be string or list
        "use_tls": True,
        "timeout": 30,
        "retry_count": 3
    }