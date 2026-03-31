"""
Database verification script for Phase 1 completion
سكربت التحقق من قاعدة البيانات لإكمال المرحلة الأولى
"""

import sqlite3
import json
from datetime import datetime
import sys
import os

def verify_phase1_completion(db_path: str = "./data/security_monitor.db") -> dict:
    """
    Verify Phase 1 completion by checking database contents
    التحقق من إكمال المرحلة الأولى عن طريق فحص محتويات قاعدة البيانات
    """
    results = {
        'phase': 'Phase 1 - Data-Driven Foundation',
        'timestamp': datetime.now().isoformat(),
        'checks': {},
        'status': 'PASSED',
        'recommendations': []
    }
    
    if not os.path.exists(db_path):
        results['status'] = 'FAILED'
        results['checks']['database_file'] = 'NOT FOUND'
        results['recommendations'].append(f"Create database at {db_path}")
        return results
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check 1: Database schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in cursor.fetchall()]
        
        required_tables = ['events', 'system_metrics', 'collector_states', 'audit_log']
        for table in required_tables:
            if table in tables:
                results['checks'][f'table_{table}'] = 'EXISTS'
            else:
                results['checks'][f'table_{table}'] = 'MISSING'
                results['status'] = 'FAILED'
        
        # Check 2: Event data
        cursor.execute("SELECT COUNT(*) as count FROM events")
        event_count = cursor.fetchone()['count']
        results['checks']['total_events'] = event_count
        
        if event_count > 0:
            results['checks']['event_data'] = 'PRESENT'
            
            # Check event sources
            cursor.execute('''
                SELECT event_source, COUNT(*) as count 
                FROM events 
                GROUP BY event_source 
                ORDER BY count DESC
            ''')
            event_sources = cursor.fetchall()
            
            sources_found = [row['event_source'] for row in event_sources]
            required_sources = ['process_collector', 'network_collector', 'login_collector']
            
            for source in required_sources:
                if source in sources_found:
                    results['checks'][f'events_{source}'] = 'PRESENT'
                else:
                    results['checks'][f'events_{source}'] = 'MISSING'
                    results['recommendations'].append(f"Run {source} to collect data")
        else:
            results['checks']['event_data'] = 'EMPTY'
            results['status'] = 'FAILED'
            results['recommendations'].append("Run collectors to populate events")
        
        # Check 3: Recent activity
        cursor.execute('''
            SELECT COUNT(*) as count 
            FROM events 
            WHERE timestamp_utc > datetime('now', '-1 hour')
        ''')
        recent_events = cursor.fetchone()['count']
        results['checks']['recent_activity'] = recent_events
        
        if recent_events > 0:
            results['checks']['collection_active'] = 'YES'
        else:
            results['checks']['collection_active'] = 'NO'
            results['recommendations'].append("Check if collectors are running")
        
        # Check 4: Collector states
        cursor.execute("SELECT COUNT(*) as count FROM collector_states")
        collector_count = cursor.fetchone()['count']
        results['checks']['collector_states'] = collector_count
        
        # Check 5: Database size
        db_size = os.path.getsize(db_path) / (1024 * 1024)  # MB
        results['checks']['database_size_mb'] = round(db_size, 2)
        
        # Check 6: Views exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view'")
        views = [row['name'] for row in cursor.fetchall()]
        
        if 'recent_events' in views:
            results['checks']['view_recent_events'] = 'EXISTS'
        else:
            results['checks']['view_recent_events'] = 'MISSING'
        
        # Check 7: Sample data query
        try:
            cursor.execute('''
                SELECT 
                    event_source,
                    event_type,
                    severity,
                    timestamp_utc
                FROM events 
                ORDER BY timestamp_utc DESC 
                LIMIT 5
            ''')
            sample_data = [dict(row) for row in cursor.fetchall()]
            results['sample_data'] = sample_data
            
        except Exception as e:
            results['checks']['sample_query'] = f'ERROR: {str(e)}'
        
        conn.close()
        
    except Exception as e:
        results['status'] = 'ERROR'
        results['error'] = str(e)
    
    return results

def print_verification_report(results: dict):
    """Print verification report in readable format"""
    print("=" * 70)
    print("SECURITY MONITOR - PHASE 1 VERIFICATION REPORT")
    print("=" * 70)
    print(f"Phase: {results.get('phase', 'Unknown')}")
    print(f"Timestamp: {results.get('timestamp', 'Unknown')}")
    print(f"Status: {results.get('status', 'Unknown')}")
    print("-" * 70)
    
    if 'error' in results:
        print(f"ERROR: {results['error']}")
        return
    
    # Print checks
    print("DATABASE CHECKS:")
    for check, status in results.get('checks', {}).items():
        status_symbol = "✅" if status in ['EXISTS', 'PRESENT', 'YES'] else "❌"
        if isinstance(status, (int, float)):
            print(f"  {check}: {status}")
        else:
            print(f"  {status_symbol} {check}: {status}")
    
    print("-" * 70)
    
    # Print sample data
    if 'sample_data' in results and results['sample_data']:
        print("SAMPLE EVENTS (Latest 5):")
        for i, event in enumerate(results['sample_data'], 1):
            print(f"  {i}. {event.get('timestamp_utc')} - "
                  f"{event.get('event_source')}: {event.get('event_type')} "
                  f"(Severity: {event.get('severity')})")
    
    print("-" * 70)
    
    # Print recommendations
    if results.get('recommendations'):
        print("RECOMMENDATIONS:")
        for i, rec in enumerate(results.get('recommendations'), 1):
            print(f"  {i}. {rec}")
    
    print("=" * 70)
    
    # Final verdict
    if results.get('status') == 'PASSED':
        print("🎉 PHASE 1 COMPLETED SUCCESSFULLY!")
        print("The data-driven foundation is ready for Phase 2.")
    else:
        print("⚠️  PHASE 1 VERIFICATION FAILED")
        print("Please address the issues before proceeding to Phase 2.")

if __name__ == '__main__':
    # Default database path
    db_path = "./data/security_monitor.db"
    
    # Allow custom path via command line
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    print(f"Verifying Phase 1 completion for database: {db_path}")
    print()
    
    results = verify_phase1_completion(db_path)
    print_verification_report(results)