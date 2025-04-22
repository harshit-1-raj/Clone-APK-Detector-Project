# database.py - Database operations for APK analyzer

import sqlite3
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path):
        """Initialize database connection"""
        self.db_path = db_path
        self._ensure_db_directory()

    def _ensure_db_directory(self):
        """Ensure the directory for the database exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)

    def get_connection(self):
        """Get a database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        return conn

    def init_db(self):
        """Initialize database tables"""
        logger.info("Initializing database")
        conn = self.get_connection()

        try:
            cursor = conn.cursor()

            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TIMESTAMP NOT NULL,
                    original_filename TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    package_name TEXT,
                    safety_score REAL NOT NULL,
                    assessment TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_file_hash ON scans(file_hash)')

            # Create statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    stat_date TIMESTAMP NOT NULL,
                    total_scans INTEGER NOT NULL,
                    safe_count INTEGER NOT NULL,
                    suspicious_count INTEGER NOT NULL,
                    dangerous_count INTEGER NOT NULL,
                    avg_safety_score REAL
                )
            ''')

            conn.commit()
        finally:
            conn.close()


        # Add these methods to your database.py file

    def save_scan_result(self, original_filename, file_hash, package_name, safety_score, assessment, result_json):
        """Save a scan result to the database"""
        logger.info(f"Saving scan result for {original_filename}")
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans 
                (scan_date, original_filename, file_hash, package_name, safety_score, assessment, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                original_filename,
                file_hash,
                package_name,
                safety_score,
                assessment,
                result_json
            ))
            conn.commit()
            scan_id = cursor.lastrowid
            
            # Update statistics
            self._update_statistics()
            
            return scan_id
        finally:
            conn.close()

    def get_recent_scans(self, limit=10, offset=0):
        """Get recent scans with pagination"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    id, scan_date, original_filename, file_hash, 
                    package_name, safety_score, assessment
                FROM scans
                ORDER BY scan_date DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
        finally:
            conn.close()

    def get_scan_by_id(self, scan_id):
        """Get a specific scan by ID"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    id, scan_date, original_filename, file_hash, 
                    package_name, safety_score, assessment, result_json
                FROM scans
                WHERE id = ?
            ''', (scan_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            result = dict(row)
            # Parse JSON result
            if result.get('result_json'):
                result['analysis'] = json.loads(result['result_json'])
                del result['result_json']  # Remove raw JSON
            
            return result
        finally:
            conn.close()

    def get_stats(self):
        """Get overall statistics"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Get total counts
            cursor.execute('SELECT COUNT(*) FROM scans')
            total_scans = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Safe"')
            safe_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Suspicious"')
            suspicious_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Dangerous"')
            dangerous_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(safety_score) FROM scans')
            avg_safety = cursor.fetchone()[0] or 0
            
            # Get recent trend (last 7 days)
            cursor.execute('''
                SELECT 
                    date(scan_date) as day,
                    COUNT(*) as count,
                    AVG(safety_score) as avg_score
                FROM scans
                WHERE scan_date > date('now', '-7 days')
                GROUP BY day
                ORDER BY day
            ''')
            trend_data = [dict(row) for row in cursor.fetchall()]
            
            return {
                'total_scans': total_scans,
                'safe_count': safe_count,
                'suspicious_count': suspicious_count,
                'dangerous_count': dangerous_count,
                'avg_safety_score': avg_safety,
                'trend': trend_data
            }
        finally:
            conn.close()

    def _update_statistics(self):
        """Update statistics table with current data"""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Get current stats
            cursor.execute('SELECT COUNT(*) FROM scans')
            total_scans = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Safe"')
            safe_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Suspicious"')
            suspicious_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM scans WHERE assessment = "Dangerous"')
            dangerous_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(safety_score) FROM scans')
            avg_safety = cursor.fetchone()[0] or 0
            
            # Update stats table
            cursor.execute('''
                INSERT INTO statistics
                (stat_date, total_scans, safe_count, suspicious_count, dangerous_count, avg_safety_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                total_scans,
                safe_count,
                suspicious_count,
                dangerous_count,
                avg_safety
            ))
            conn.commit()
        finally:
            conn.close()
