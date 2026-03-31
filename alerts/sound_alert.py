# alerts/sound_alert.py
"""
Sound Alert System for Critical Security Events
"""

import os
import platform
import subprocess
import logging
import sys
from typing import Dict, Any, Optional

# إعداد التسجيل
logger = logging.getLogger(__name__)


class SoundAlert:
    """Plays sound alerts for critical security incidents"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize sound alert system
        
        Args:
            config: Configuration dictionary with sound settings
        """
        self.config = config or {}
        self.system = platform.system()
        self.enabled = self.config.get("enabled", True)
        self.volume = self.config.get("volume", 0.5)  # 0.0 to 1.0
        self._last_alert_time = None
        self._alert_cooldown = self.config.get("cooldown_seconds", 1)  # Prevent rapid alerts
        
        # Check if sound system is available
        self._check_availability()
        
        logger.info(f"Sound alert system initialized for {self.system}")
        logger.info(f"  • Enabled: {self.enabled}")
        logger.info(f"  • Available: {self.available}")
    
    def _check_availability(self):
        """Check if sound system is available on current platform"""
        self.available = False
        self.availability_reason = None
        
        if not self.enabled:
            self.availability_reason = "Disabled by configuration"
            return
        
        try:
            if self.system == "Windows":
                # Check if winsound is available
                try:
                    import winsound
                    self.available = True
                except ImportError:
                    self.availability_reason = "winsound module not available"
                    
            elif self.system == "Darwin":  # macOS
                # Check if afplay exists
                result = subprocess.run(['which', 'afplay'], 
                                       capture_output=True, 
                                       text=True)
                if result.returncode == 0:
                    # Check if sound files exist
                    sound_files = ['/System/Library/Sounds/Sosumi.aiff',
                                  '/System/Library/Sounds/Basso.aiff',
                                  '/System/Library/Sounds/Ping.aiff']
                    existing_sounds = [f for f in sound_files if os.path.exists(f)]
                    if existing_sounds:
                        self.available = True
                        self._mac_sounds = existing_sounds
                    else:
                        self.availability_reason = "No sound files found in /System/Library/Sounds/"
                else:
                    self.availability_reason = "afplay command not found"
                    
            elif self.system == "Linux":
                # Try multiple methods on Linux
                methods = [
                    self._check_linux_speaker_test,
                    self._check_linux_spd_say,
                    self._check_linux_beep,
                    self._check_linux_aplay
                ]
                
                for method in methods:
                    if method():
                        self.available = True
                        break
                
                if not self.available:
                    self.availability_reason = "No sound method available on Linux"
                    
            else:
                # Fallback to console beep
                self.available = True
                logger.info(f"Using console beep fallback for {self.system}")
                
        except Exception as e:
            self.availability_reason = f"Error checking availability: {e}"
            logger.error(f"Failed to check sound availability: {e}")
    
    def _check_linux_speaker_test(self) -> bool:
        """Check if speaker-test is available on Linux"""
        try:
            result = subprocess.run(['which', 'speaker-test'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_linux_spd_say(self) -> bool:
        """Check if spd-say is available on Linux"""
        try:
            result = subprocess.run(['which', 'spd-say'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_linux_beep(self) -> bool:
        """Check if beep command is available on Linux"""
        try:
            result = subprocess.run(['which', 'beep'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_linux_aplay(self) -> bool:
        """Check if aplay is available on Linux"""
        try:
            result = subprocess.run(['which', 'aplay'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            return result.returncode == 0
        except Exception:
            return False
    
    def play_alert(self, alert_type: str = "HIGH") -> bool:
        """
        Play sound alert based on severity
        
        Args:
            alert_type: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            bool: True if alert played successfully, False otherwise
        """
        if not self.enabled:
            logger.debug("Sound alerts disabled by configuration")
            return False
        
        if not self.available:
            logger.debug(f"Sound system not available: {self.availability_reason}")
            return False
        
        # Prevent rapid successive alerts (cooldown)
        import time
        current_time = time.time()
        if self._last_alert_time:
            if current_time - self._last_alert_time < self._alert_cooldown:
                logger.debug(f"Alert cooldown active, skipping sound")
                return False
        self._last_alert_time = current_time
        
        try:
            # Normalize alert type
            alert_type = alert_type.upper()
            
            if self.system == "Windows":
                return self._play_windows_alert(alert_type)
            elif self.system == "Darwin":  # macOS
                return self._play_mac_alert(alert_type)
            elif self.system == "Linux":
                return self._play_linux_alert(alert_type)
            else:
                return self._play_beep_alert(alert_type)
                
        except Exception as e:
            logger.error(f"Sound alert error: {e}")
            return False
    
    def _play_windows_alert(self, alert_type: str) -> bool:
        """Play alert on Windows with proper error handling"""
        try:
            import winsound
            
            if alert_type in ["CRITICAL", "HIGH"]:
                # Play emergency alert sound with multiple beeps
                frequencies = [1000, 1200, 1400, 1200, 1000]
                duration = 400
                for freq in frequencies:
                    winsound.Beep(freq, duration)
                return True
                
            elif alert_type == "MEDIUM":
                # Play warning sound
                winsound.Beep(800, 400)
                winsound.Beep(600, 400)
                return True
                
            else:  # LOW or others
                # Play notification sound
                winsound.Beep(500, 300)
                return True
                
        except ImportError:
            logger.warning("winsound module not available, using fallback")
            return self._play_beep_alert(alert_type)
        except Exception as e:
            logger.debug(f"Windows sound error: {e}")
            return self._play_beep_alert(alert_type)
    
    def _play_mac_alert(self, alert_type: str) -> bool:
        """Play alert on macOS with fallback options"""
        try:
            # Define sound files for different severities
            sound_files = {
                "CRITICAL": ["/System/Library/Sounds/Sosumi.aiff",
                            "/System/Library/Sounds/Basso.aiff"],
                "HIGH": ["/System/Library/Sounds/Sosumi.aiff"],
                "MEDIUM": ["/System/Library/Sounds/Basso.aiff"],
                "LOW": ["/System/Library/Sounds/Ping.aiff"]
            }
            
            # Get sound files for this severity
            sounds = sound_files.get(alert_type, ["/System/Library/Sounds/Ping.aiff"])
            
            # Try each sound file until one works
            for sound_file in sounds:
                if os.path.exists(sound_file):
                    # Use subprocess with timeout
                    subprocess.run(['afplay', sound_file], 
                                 timeout=2,
                                 capture_output=True)
                    logger.debug(f"Played sound: {sound_file}")
                    return True
            
            # If no sound files found, try fallback
            logger.debug("No sound files found, trying beep fallback")
            return self._play_beep_alert(alert_type)
            
        except subprocess.TimeoutExpired:
            logger.warning("Sound playback timed out")
            return False
        except Exception as e:
            logger.debug(f"macOS sound error: {e}")
            return self._play_beep_alert(alert_type)
    
    def _play_linux_alert(self, alert_type: str) -> bool:
        """Play alert on Linux with multiple method fallbacks"""
        
        # Try different methods in order of preference
        methods = [
            self._play_linux_spd_say,
            self._play_linux_speaker_test,
            self._play_linux_beep,
            self._play_linux_aplay
        ]
        
        for method in methods:
            try:
                if method(alert_type):
                    return True
            except Exception as e:
                logger.debug(f"Linux method {method.__name__} failed: {e}")
                continue
        
        # Final fallback
        return self._play_beep_alert(alert_type)
    
    def _play_linux_spd_say(self, alert_type: str) -> bool:
        """Play speech alert on Linux using spd-say"""
        try:
            # Check if spd-say exists
            result = subprocess.run(['which', 'spd-say'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            if result.returncode != 0:
                return False
            
            # Different messages based on severity
            messages = {
                "CRITICAL": "Critical security alert! Immediate action required!",
                "HIGH": "High severity security alert!",
                "MEDIUM": "Medium severity security alert",
                "LOW": "Security notification"
            }
            
            message = messages.get(alert_type, "Security alert")
            
            # Adjust speech rate based on severity
            if alert_type in ["CRITICAL", "HIGH"]:
                rate = 50  # Slower for critical
            else:
                rate = 0  # Normal
            
            subprocess.run(['spd-say', '-t', 'male1', '-r', str(rate), message],
                         timeout=3,
                         capture_output=True)
            return True
            
        except subprocess.TimeoutExpired:
            logger.debug("spd-say timed out")
            return False
        except Exception:
            return False
    
    def _play_linux_speaker_test(self, alert_type: str) -> bool:
        """Play alert using speaker-test"""
        try:
            # Check if speaker-test exists
            result = subprocess.run(['which', 'speaker-test'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            if result.returncode != 0:
                return False
            
            # speaker-test runs continuously, so we need to run it briefly
            # Use a short duration for the test
            duration = 0.5 if alert_type == "LOW" else 1.0
            
            subprocess.run(['speaker-test', '-t', 'sine', '-f', '1000', 
                          '-l', str(int(duration))],
                         timeout=duration + 1,
                         capture_output=True)
            return True
            
        except subprocess.TimeoutExpired:
            return True  # Timeout is expected for speaker-test
        except Exception:
            return False
    
    def _play_linux_beep(self, alert_type: str) -> bool:
        """Play beep alert on Linux using beep command"""
        try:
            # Check if beep exists
            result = subprocess.run(['which', 'beep'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            if result.returncode != 0:
                return False
            
            if alert_type in ["CRITICAL", "HIGH"]:
                # Multiple beeps
                for _ in range(3):
                    subprocess.run(['beep', '-f', '1000', '-l', '200'],
                                 timeout=1,
                                 capture_output=True)
            else:
                # Single beep
                subprocess.run(['beep', '-f', '800', '-l', '200'],
                             timeout=1,
                             capture_output=True)
            return True
            
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def _play_linux_aplay(self, alert_type: str) -> bool:
        """Play alert using aplay with generated sound"""
        try:
            # Check if aplay exists
            result = subprocess.run(['which', 'aplay'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=2)
            if result.returncode != 0:
                return False
            
            # Generate a simple beep sound using /dev/urandom
            # This is a fallback method
            if alert_type in ["CRITICAL", "HIGH"]:
                # Multiple beeps
                for _ in range(3):
                    subprocess.run(['aplay', '-q', '-f', 'cd', '/dev/urandom'],
                                 timeout=0.2,
                                 capture_output=True)
            else:
                subprocess.run(['aplay', '-q', '-f', 'cd', '/dev/urandom'],
                             timeout=0.1,
                             capture_output=True)
            return True
            
        except subprocess.TimeoutExpired:
            return True  # Timeout is expected
        except Exception:
            return False
    
    def _play_beep_alert(self, alert_type: str) -> bool:
        """Fallback beep alert using console bell"""
        try:
            if alert_type in ["CRITICAL", "HIGH"]:
                # Multiple beeps for critical alerts
                for _ in range(3):
                    print("\a", end='', flush=True)
                    import time
                    time.sleep(0.2)
                return True
            else:
                # Single beep for others
                print("\a", end='', flush=True)
                return True
                
        except Exception as e:
            logger.debug(f"Beep alert failed: {e}")
            return False
    
    def test_sound(self) -> bool:
        """Test sound alert functionality"""
        logger.info("Testing sound alert system...")
        
        if not self.enabled:
            logger.warning("Sound alerts are disabled")
            return False
        
        if not self.available:
            logger.warning(f"Sound system not available: {self.availability_reason}")
            return False
        
        # Test with different severities
        test_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        for severity in test_severities:
            logger.info(f"Testing {severity} alert...")
            success = self.play_alert(severity)
            if success:
                logger.info(f"✅ {severity} alert test successful")
                import time
                time.sleep(0.5)  # Small delay between tests
            else:
                logger.warning(f"❌ {severity} alert test failed")
        
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get current sound alert system status"""
        return {
            "enabled": self.enabled,
            "available": self.available,
            "system": self.system,
            "availability_reason": self.availability_reason,
            "volume": self.volume,
            "cooldown_seconds": self._alert_cooldown
        }
    
    def set_volume(self, volume: float) -> bool:
        """
        Set volume level (where supported)
        
        Args:
            volume: Volume level between 0.0 and 1.0
            
        Returns:
            bool: True if volume set successfully
        """
        if 0.0 <= volume <= 1.0:
            self.volume = volume
            logger.info(f"Volume set to {volume}")
            
            # Note: Actual volume control is OS-dependent and may not be supported
            # This method mainly stores the volume preference
            
            return True
        else:
            logger.warning(f"Invalid volume value: {volume}")
            return False
    
    def set_cooldown(self, seconds: float) -> None:
        """Set cooldown period between alerts"""
        if seconds >= 0:
            self._alert_cooldown = seconds
            logger.info(f"Alert cooldown set to {seconds} seconds")