"""
Comprehensive test suite for Phase 1 functionality
مجموعة اختبارات شاملة لوظائف المرحلة الأولى
"""

import unittest
import os
import tempfile
import json
from datetime import datetime, timezone

from storage.database import DatabaseManager
from collectors.process_collector import ProcessCollector, collect_process_data
from collectors.network_collector import NetworkCollector, collect_network_data
from collectors.login_collector import LoginCollector, collect_login_data

class TestPhase1(unittest.TestCase):
    """Test cases for Phase 1 components"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Create temporary database
        cls.test_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        cls.test_db_path = cls.test_db.name
        
        # Initialize database manager
        cls.db_manager = DatabaseManager()
        cls.db_manager.initialize(cls.test_db_path)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        cls.db_manager.close_all()
        if os.path.exists(cls.test_db_path):
            os.unlink(cls.test_db_path)
    
    def test_01_database_initialization(self):
        """Test database initialization"""
        self.assertTrue(os.path.exists(self.test_db_path), 
                       "Database file should be created")
        
        # Check if tables exist
        conn = self.db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row['name'] for row in cursor.fetchall()]
        
        expected_tables = ['events', 'system_metrics', 'collector_states', 'audit_log']
        for table in expected_tables:
            self.assertIn(table, tables, f"Table '{table}' should exist")
    
    def test_02_database_health_check(self):
        """Test database health check"""
        health = self.db_manager.health_check()
        
        self.assertIn('status', health, "Health check should return status")
        self.assertEqual(health['status'], 'healthy', 
                        "Database should be healthy after initialization")
    
    def test_03_process_collector_initialization(self):
        """Test process collector initialization"""
        collector = ProcessCollector(max_processes=50)
        
        self.assertEqual(collector.max_processes, 50,
                        "Process collector should be initialized with correct max processes")
        self.assertIsNotNone(collector.hostname,
                            "Hostname should be set")
    
    def test_04_process_collection(self):
        """Test process data collection"""
        collector = ProcessCollector(max_processes=10)
        process_data = collector.collect()
        
        self.assertIn('statistics', process_data,
                     "Process data should contain statistics")
        self.assertIn('processes', process_data,
                     "Process data should contain processes list")
        self.assertIn('metadata', process_data,
                     "Process data should contain metadata")
        
        # Check statistics
        stats = process_data.get('statistics', {})
        self.assertGreaterEqual(stats.get('total_collected', 0), 0,
                               "Should collect 0 or more processes")
    
    def test_05_network_collector_initialization(self):
        """Test network collector initialization"""
        collector = NetworkCollector(max_connections=50)
        
        self.assertEqual(collector.max_connections, 50,
                        "Network collector should be initialized with correct max connections")
        self.assertIsNotNone(collector.hostname,
                            "Hostname should be set")
    
    def test_06_network_collection(self):
        """Test network data collection"""
        collector = NetworkCollector(max_connections=10)
        network_data = collector.collect()
        
        self.assertIn('statistics', network_data,
                     "Network data should contain statistics")
        self.assertIn('connections', network_data,
                     "Network data should contain connections list")
        self.assertIn('metadata', network_data,
                     "Network data should contain metadata")
        
        # Check statistics
        stats = network_data.get('statistics', {})
        self.assertGreaterEqual(stats.get('total_collected', 0), 0,
                               "Should collect 0 or more connections")
    
    def test_07_login_collector_initialization(self):
        """Test login collector initialization"""
        collector = LoginCollector()
        
        self.assertIsNotNone(collector.hostname,
                            "Hostname should be set")
        self.assertIsNotNone(collector.current_user,
                            "Current user should be set")
    
    def test_08_login_collection(self):
        """Test login data collection"""
        collector = LoginCollector()
        login_data = collector.collect()
        
        self.assertIn('current_sessions', login_data,
                     "Login data should contain current sessions")
        self.assertIn('login_history', login_data,
                     "Login data should contain login history")
        self.assertIn('user_information', login_data,
                     "Login data should contain user information")
        self.assertIn('analysis', login_data,
                     "Login data should contain analysis")
    
    def test_09_database_event_insertion(self):
        """Test inserting events into database"""
        # Create test event
        test_event = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'event_source': 'test',
            'event_type': 'test_event',
            'severity': 1,
            'hostname': 'test-host',
            'username': 'test-user',
            'details': {'message': 'Test event'}
        }
        
        # Insert event
        event_id = self.db_manager.insert_event(test_event)
        
        self.assertIsNotNone(event_id, "Event insertion should return ID")
        self.assertGreater(event_id, 0, "Event ID should be positive")
        
        # Verify event was inserted
        events = self.db_manager.get_recent_events(limit=1)
        self.assertEqual(len(events), 1, "Should retrieve the inserted event")
        
        retrieved_event = events[0]
        self.assertEqual(retrieved_event['event_source'], 'test',
                        "Retrieved event should have correct source")
    
    def test_10_database_statistics(self):
        """Test database statistics retrieval"""
        stats = self.db_manager.get_system_stats()
        
        self.assertIn('total_events', stats,
                     "System stats should contain total events")
        self.assertIn('events_by_source', stats,
                     "System stats should contain events by source")
        self.assertIn('collector_status', stats,
                     "System stats should contain collector status")
    
    def test_11_collector_state_management(self):
        """Test collector state management"""
        # Update collector state
        success = self.db_manager.update_collector_state(
            'test_collector',
            {
                'last_run_utc': datetime.now(timezone.utc).isoformat(),
                'items_collected': 100,
                'status': 'active'
            }
        )
        
        self.assertTrue(success, "Collector state update should succeed")
    
    def test_12_process_collection_integration(self):
        """Test process collection integration with database"""
        process_data = collect_process_data()
        
        self.assertIsNotNone(process_data, "Process collection should return data")
        
        # Check if event was inserted
        events = self.db_manager.get_recent_events(
            limit=10, 
            source='process_collector'
        )
        
        self.assertGreater(len(events), 0,
                          "Should have process events in database")
    
    def test_13_network_collection_integration(self):
        """Test network collection integration with database"""
        network_data = collect_network_data()
        
        self.assertIsNotNone(network_data, "Network collection should return data")
        
        # Check if event was inserted
        events = self.db_manager.get_recent_events(
            limit=10, 
            source='network_collector'
        )
        
        self.assertGreater(len(events), 0,
                          "Should have network events in database")
    
    def test_14_login_collection_integration(self):
        """Test login collection integration with database"""
        login_data = collect_login_data()
        
        self.assertIsNotNone(login_data, "Login collection should return data")
        
        # Check if event was inserted
        events = self.db_manager.get_recent_events(
            limit=10, 
            source='login_collector'
        )
        
        self.assertGreater(len(events), 0,
                          "Should have login events in database")

if __name__ == '__main__':
    unittest.main(verbosity=2)