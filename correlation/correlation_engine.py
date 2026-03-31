# correlation/correlation_engine.py
"""
Correlation Engine for detecting related security events
"""

class CorrelationEngine:
    def __init__(self, time_window_minutes=5):
        self.time_window = time_window_minutes
        self.event_buffer = []
    
    def check_correlation(self, current_event, recent_events):
        """Check if current event correlates with recent events"""
        correlation_score = 0.0
        
        # Check for same source IP
        source_ip_matches = sum(1 for e in recent_events 
                               if e.get('source_ip') == current_event.get('source_ip'))
        if source_ip_matches > 0:
            correlation_score += 0.3
        
        # Check for same target
        target_matches = sum(1 for e in recent_events 
                            if e.get('target') == current_event.get('target'))
        if target_matches > 0:
            correlation_score += 0.3
        
        # Check for similar alert types
        alert_type_matches = sum(1 for e in recent_events 
                                if e.get('alert_type') == current_event.get('alert_type'))
        if alert_type_matches > 0:
            correlation_score += 0.2
        
        # Time proximity
        time_matches = sum(1 for e in recent_events 
                          if self._time_difference(e, current_event) < self.time_window)
        if time_matches > 0:
            correlation_score += 0.2
        
        return min(correlation_score, 1.0)