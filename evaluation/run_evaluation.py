#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phase 8: Evaluation Harness (Fixed for your database schema)
"""

import os
import sys
import sqlite3
import json
import time
import hashlib
import argparse
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional

# Fix Unicode for Windows
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='ignore')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('evaluation/evaluation.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('evaluation-harness')

class EvaluationHarness:
    def __init__(self, db_path: str = "data/security.db", profile: str = "SME_Default"):
        self.db_path = db_path
        self.profile = profile
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'profile': profile,
            'scenarios': [],
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'overall_detection_rate': 0.0,
                'overall_fp_rate': 0.0,
                'avg_mttr': 0.0,
                'avg_confidence': 0.0
            },
            'confusion_matrix': {
                'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0
            },
            'resource_usage': {},
            'integrity_hash': ''
        }
        
        os.makedirs('evaluation', exist_ok=True)
        os.makedirs('evaluation/reports', exist_ok=True)
    
    def _connect_db(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def _get_table_columns(self, cursor, table_name):
        """Get column names for a table"""
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [row[1] for row in cursor.fetchall()]
    
    def evaluate_brute_force(self) -> Dict[str, Any]:
        """Evaluate brute force detection using your database schema"""
        logger.info("[SEARCH] Evaluating Brute Force Detection...")
        
        conn = self._connect_db()
        cursor = conn.cursor()
        
        # First, check what columns are available in the events table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not cursor.fetchone():
            logger.warning("Events table not found")
            conn.close()
            return {
                'scenario': 'Brute Force Detection',
                'status': 'SKIPPED',
                'reason': 'Events table not found',
                'detection_rate': 0,
                'fp_rate': 0
            }
        
        columns = self._get_table_columns(cursor, 'events')
        logger.info(f"Events table columns: {columns}")
        
        seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
        
        # Try different possible column names for source IP
        possible_ip_columns = ['source_ip', 'ip_address', 'src_ip', 'ip', 'source']
        ip_column = None
        
        for col in possible_ip_columns:
            if col in columns:
                ip_column = col
                break
        
        if not ip_column:
            # If no IP column, use a different approach - count failed logins overall
            logger.warning("No IP column found, using global failed login count")
            cursor.execute("""
                SELECT COUNT(*) as event_count
                FROM events 
                WHERE source = 'login' 
                    AND (details LIKE '%failed%' OR details LIKE '%fail%' OR details LIKE '%invalid%')
                    AND timestamp > ?
            """, (seven_days_ago,))
            
            total_failed = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                'scenario': 'Brute Force Detection',
                'total_failed_logins': total_failed,
                'status': 'PARTIAL',
                'detection_rate': 0,
                'fp_rate': 0,
                'note': 'Using global count (no IP column)'
            }
        
        # Use the found IP column
        cursor.execute(f"""
            SELECT 
                COUNT(*) as event_count,
                {ip_column} as source_ip,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events 
            WHERE source = 'login' 
                AND (details LIKE '%failed%' OR details LIKE '%fail%' OR details LIKE '%invalid%')
                AND timestamp > ?
            GROUP BY {ip_column}
            HAVING event_count >= 3
            ORDER BY event_count DESC
        """, (seven_days_ago,))
        
        brute_force_ips = cursor.fetchall()
        
        # Check alerts table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        alerts_exist = cursor.fetchone() is not None
        
        brute_force_alerts = {}
        
        if alerts_exist:
            alert_columns = self._get_table_columns(cursor, 'alerts')
            alert_ip_column = None
            
            for col in possible_ip_columns:
                if col in alert_columns:
                    alert_ip_column = col
                    break
            
            if alert_ip_column:
                cursor.execute(f"""
                    SELECT 
                        COUNT(*) as alert_count,
                        {alert_ip_column} as source_ip,
                        timestamp
                    FROM alerts 
                    WHERE alert_type LIKE '%BRUTE%' OR alert_type LIKE '%LOGIN%'
                        AND timestamp > ?
                    GROUP BY {alert_ip_column}
                """, (seven_days_ago,))
                
                for row in cursor.fetchall():
                    if row['source_ip']:
                        brute_force_alerts[row['source_ip']] = row['alert_count']
        
        conn.close()
        
        # Calculate metrics
        tp = 0
        fn = 0
        
        for row in brute_force_ips:
            ip = row['source_ip']
            event_count = row['event_count']
            
            if ip and ip in brute_force_alerts:
                tp += 1
                logger.debug(f"TP: {ip} - {event_count} events, alert generated")
            elif ip:
                fn += 1
                logger.warning(f"FN: {ip} - {event_count} events, NO alert")
        
        detection_rate = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        
        result = {
            'scenario': 'Brute Force Detection',
            'tp': tp,
            'fn': fn,
            'detection_rate': round(detection_rate, 2),
            'total_brute_force_ips': len(brute_force_ips),
            'total_alerts': len(brute_force_alerts)
        }
        
        logger.info(f"Brute Force: DR={detection_rate:.1f}%, IPs={len(brute_force_ips)}")
        return result
    
    def evaluate_ai_anomaly_detection(self) -> Dict[str, Any]:
        """Evaluate AI anomaly detection"""
        logger.info("[AI] Evaluating AI Anomaly Detection...")
        
        conn = self._connect_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_scores'")
        if not cursor.fetchone():
            logger.warning("AI scores table not found")
            conn.close()
            return {
                'scenario': 'AI Anomaly Detection',
                'status': 'SKIPPED',
                'reason': 'No AI scores table',
                'detection_rate': 0
            }
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scores,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies_detected,
                AVG(anomaly_score) as avg_score,
                AVG(confidence) as avg_confidence
            FROM ai_scores
            WHERE ts_utc > datetime('now', '-7 days')
        """)
        
        row = cursor.fetchone()
        total_scores = row['total_scores'] or 0
        anomalies_detected = row['anomalies_detected'] or 0
        avg_score = row['avg_score'] or 0
        avg_confidence = row['avg_confidence'] or 0
        
        conn.close()
        
        detection_rate = (anomalies_detected / max(total_scores, 1)) * 100
        
        result = {
            'scenario': 'AI Anomaly Detection',
            'total_scores': total_scores,
            'anomalies_detected': anomalies_detected,
            'avg_anomaly_score': round(avg_score, 3),
            'avg_confidence': round(avg_confidence, 2),
            'detection_rate': round(detection_rate, 2),
            'status': 'COMPLETED'
        }
        
        logger.info(f"[AI] {anomalies_detected} anomalies from {total_scores} scores")
        return result
    
    def evaluate_response_time(self) -> Dict[str, Any]:
        """Calculate Mean Time to Respond"""
        logger.info("[TIME] Evaluating Response Time (MTTR)...")
        
        conn = self._connect_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")
        if not cursor.fetchone():
            logger.warning("Incidents table not found")
            conn.close()
            return {
                'scenario': 'Mean Time to Respond',
                'status': 'SKIPPED',
                'reason': 'No incidents table'
            }
        
        cursor.execute("""
            SELECT 
                id,
                created_at,
                closed_at,
                status,
                severity
            FROM incidents 
            WHERE closed_at IS NOT NULL 
                AND created_at > datetime('now', '-30 days')
            ORDER BY created_at DESC
        """)
        
        incidents = cursor.fetchall()
        
        if not incidents:
            logger.warning("No resolved incidents found")
            conn.close()
            return {
                'scenario': 'Mean Time to Respond',
                'status': 'NO_DATA',
                'avg_mttr_seconds': 0,
                'avg_mttr_minutes': 0,
                'total_resolved': 0
            }
        
        total_response_time = 0
        response_times = []
        
        for inc in incidents:
            try:
                created = datetime.fromisoformat(inc['created_at'])
                if inc['closed_at']:
                    closed = datetime.fromisoformat(inc['closed_at'])
                    response_seconds = (closed - created).total_seconds()
                    response_times.append(response_seconds)
                    total_response_time += response_seconds
                    logger.debug(f"Incident #{inc['id']}: {response_seconds:.0f}s")
            except Exception as e:
                logger.warning(f"Error calculating response time: {e}")
        
        avg_mttr = total_response_time / len(response_times) if response_times else 0
        
        conn.close()
        
        result = {
            'scenario': 'Mean Time to Respond',
            'total_resolved': len(response_times),
            'avg_mttr_seconds': round(avg_mttr, 0),
            'avg_mttr_minutes': round(avg_mttr / 60, 1),
            'min_response': min(response_times) if response_times else 0,
            'max_response': max(response_times) if response_times else 0
        }
        
        logger.info(f"MTTR: {result['avg_mttr_minutes']:.1f} minutes ({len(response_times)} incidents)")
        return result
    
    def evaluate_resource_usage(self) -> Dict[str, Any]:
        """Measure system resource usage"""
        logger.info("[RESOURCE] Evaluating Resource Usage...")
        
        conn = self._connect_db()
        cursor = conn.cursor()
        
        # Check for metrics tables
        for table in ['system_metrics', 'system_metrics_history']:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
            if cursor.fetchone():
                table_name = table
                break
        else:
            logger.warning("No metrics tables found")
            conn.close()
            return {
                'scenario': 'Resource Usage',
                'status': 'NO_DATA'
            }
        
        # Get column names
        columns = self._get_table_columns(cursor, table_name)
        logger.info(f"Metrics table columns: {columns}")
        
        # Build dynamic query based on available columns
        select_parts = []
        
        cpu_cols = [c for c in columns if 'cpu' in c.lower()]
        if cpu_cols:
            select_parts.append(f"AVG({cpu_cols[0]}) as avg_cpu")
            select_parts.append(f"MAX({cpu_cols[0]}) as max_cpu")
        
        mem_cols = [c for c in columns if 'memory' in c.lower() or 'mem' in c.lower()]
        if mem_cols:
            select_parts.append(f"AVG({mem_cols[0]}) as avg_memory")
            select_parts.append(f"MAX({mem_cols[0]}) as max_memory")
        
        disk_cols = [c for c in columns if 'disk' in c.lower()]
        if disk_cols:
            select_parts.append(f"AVG({disk_cols[0]}) as avg_disk")
            select_parts.append(f"MAX({disk_cols[0]}) as max_disk")
        
        latency_cols = [c for c in columns if 'latency' in c.lower() or 'ms' in c.lower()]
        if latency_cols:
            select_parts.append(f"AVG({latency_cols[0]}) as avg_latency")
        
        select_parts.append("COUNT(*) as sample_count")
        
        if not select_parts:
            logger.warning("No usable metrics columns found")
            conn.close()
            return {
                'scenario': 'Resource Usage',
                'status': 'NO_DATA'
            }
        
        query = f"""
            SELECT {', '.join(select_parts)}
            FROM {table_name}
            WHERE timestamp > datetime('now', '-1 day')
        """
        
        cursor.execute(query)
        row = cursor.fetchone()
        conn.close()
        
        if not row or row['sample_count'] == 0:
            logger.warning("No metrics samples in last 24 hours")
            return {
                'scenario': 'Resource Usage',
                'status': 'NO_DATA'
            }
        
        result = {
            'scenario': 'Resource Usage',
            'avg_cpu_percent': round(row['avg_cpu'] or 0, 2) if 'avg_cpu' in row.keys() else 0,
            'max_cpu_percent': round(row['max_cpu'] or 0, 2) if 'max_cpu' in row.keys() else 0,
            'avg_memory_percent': round(row['avg_memory'] or 0, 2) if 'avg_memory' in row.keys() else 0,
            'max_memory_percent': round(row['max_memory'] or 0, 2) if 'max_memory' in row.keys() else 0,
            'avg_disk_percent': round(row['avg_disk'] or 0, 2) if 'avg_disk' in row.keys() else 0,
            'sample_count': row['sample_count'] or 0
        }
        
        logger.info(f"CPU: {result['avg_cpu_percent']}% | Memory: {result['avg_memory_percent']}%")
        return result
    
    def run_evaluation(self) -> Dict[str, Any]:
        """Run complete evaluation suite"""
        logger.info("=" * 70)
        logger.info("PHASE 8: EVALUATION HARNESS - STARTING")
        logger.info(f"Profile: {self.profile}")
        logger.info(f"Database: {self.db_path}")
        logger.info("=" * 70)
        
        start_time = time.time()
        
        scenarios = [
            self.evaluate_brute_force(),
            self.evaluate_ai_anomaly_detection(),
            self.evaluate_response_time(),
            self.evaluate_resource_usage()
        ]
        
        self.results['scenarios'] = scenarios
        self.results['summary']['total_tests'] = len(scenarios)
        
        # Calculate overall metrics
        detection_rates = [s.get('detection_rate', 0) for s in scenarios if 'detection_rate' in s]
        self.results['summary']['overall_detection_rate'] = round(sum(detection_rates) / len(detection_rates), 2) if detection_rates else 0
        
        # MTTR
        mttr_result = next((s for s in scenarios if s.get('scenario') == 'Mean Time to Respond'), {})
        self.results['summary']['avg_mttr'] = mttr_result.get('avg_mttr_seconds', 0)
        
        # Confidence
        ai_result = next((s for s in scenarios if s.get('scenario') == 'AI Anomaly Detection'), {})
        self.results['summary']['avg_confidence'] = ai_result.get('avg_confidence', 0)
        
        self.results['summary']['passed'] = sum(1 for s in scenarios if s.get('detection_rate', 0) >= 50)
        self.results['summary']['failed'] = self.results['summary']['total_tests'] - self.results['summary']['passed']
        
        execution_time = time.time() - start_time
        self.results['execution_time_seconds'] = round(execution_time, 2)
        
        self._generate_integrity_hash()
        self._save_results()
        self._generate_report_markdown()
        
        logger.info("=" * 70)
        logger.info("EVALUATION COMPLETE")
        logger.info(f"   Detection Rate: {self.results['summary']['overall_detection_rate']}%")
        logger.info(f"   MTTR: {self.results['summary']['avg_mttr']:.0f}s")
        logger.info(f"   Execution Time: {execution_time:.2f}s")
        logger.info("=" * 70)
        
        return self.results
    
    def _generate_integrity_hash(self):
        result_str = json.dumps(self.results, sort_keys=True, default=str)
        self.results['integrity_hash'] = hashlib.sha256(result_str.encode()).hexdigest()
    
    def _save_results(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"evaluation/results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        with open('evaluation/results_latest.json', 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"Results saved to {filename}")
    
    def _generate_report_markdown(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"evaluation/reports/report_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# SOC Evaluation Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Profile:** {self.profile}\n")
            f.write(f"**Database:** {self.db_path}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Detection Rate | **{self.results['summary']['overall_detection_rate']}%** |\n")
            f.write(f"| Mean Time to Respond | **{self.results['summary']['avg_mttr']:.0f}s** |\n")
            f.write(f"| Average Confidence | **{self.results['summary']['avg_confidence']}%** |\n\n")
            
            f.write("## Scenarios\n\n")
            for scenario in self.results['scenarios']:
                f.write(f"### {scenario.get('scenario', 'Unknown')}\n\n")
                for key, value in scenario.items():
                    if key != 'scenario':
                        f.write(f"- **{key}**: {value}\n")
                f.write("\n")
            
            f.write("\n## Integrity\n\n")
            f.write(f"**SHA-256 Hash:** `{self.results['integrity_hash']}`\n\n")
        
        logger.info(f"Report generated: {report_file}")
        return report_file


def main():
    parser = argparse.ArgumentParser(description='Phase 8: Evaluation Harness')
    parser.add_argument('--db', default='data/security.db', help='Database path')
    parser.add_argument('--profile', default='SME_Default', help='Tuning profile to use')
    parser.add_argument('--scenario', choices=['brute-force', 'ai', 'mttr', 'resources', 'all'], 
                        default='all', help='Specific scenario to run')
    
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("PHASE 8: EVALUATION HARNESS")
    print("=" * 70)
    
    try:
        evaluator = EvaluationHarness(db_path=args.db, profile=args.profile)
        
        if args.scenario == 'all':
            results = evaluator.run_evaluation()
            print("\n✅ Evaluation Complete!")
            print(f"   Results saved to evaluation/results_latest.json")
            print(f"   Report saved to evaluation/reports/")
        elif args.scenario == 'brute-force':
            results = evaluator.evaluate_brute_force()
            print(json.dumps(results, indent=2, default=str))
        elif args.scenario == 'ai':
            results = evaluator.evaluate_ai_anomaly_detection()
            print(json.dumps(results, indent=2, default=str))
        elif args.scenario == 'mttr':
            results = evaluator.evaluate_response_time()
            print(json.dumps(results, indent=2, default=str))
        elif args.scenario == 'resources':
            results = evaluator.evaluate_resource_usage()
            print(json.dumps(results, indent=2, default=str))
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️ Evaluation interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())