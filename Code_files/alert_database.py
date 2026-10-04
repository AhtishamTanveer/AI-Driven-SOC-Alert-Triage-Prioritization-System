import sqlite3
import json
from datetime import datetime
import pandas as pd

class AlertDatabase:
    def __init__(self, db_path='alerts.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create alerts table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                asset_type TEXT,
                threat_type TEXT,
                source_ip TEXT,
                destination TEXT,
                is_malicious_ip INTEGER,
                failed_attempts INTEGER,
                description TEXT,
                rule_id TEXT,
                rule_level INTEGER,
                priority TEXT,
                priority_score INTEGER,
                triage_reasons TEXT,
                source TEXT,
                seq_id INTEGER,
                created_at TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database ready")
    
    def save_alert(self, alert):
        """Save alert (prevent duplicates)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if exists
            cursor.execute('SELECT id FROM alerts WHERE id = ?', (alert['id'],))
            if cursor.fetchone():
                conn.close()
                return False
            
            cursor.execute('''
                INSERT INTO alerts 
                (id, timestamp, severity, asset_type, threat_type, source_ip, 
                 destination, is_malicious_ip, failed_attempts, description, 
                 rule_id, rule_level, priority, priority_score, triage_reasons, 
                 source, seq_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['id'],
                alert.get('timestamp'),
                alert.get('severity'),
                alert.get('asset_type'),
                alert.get('threat_type'),
                alert.get('source_ip'),
                alert.get('destination'),
                int(alert.get('is_malicious_ip', False)),
                alert.get('failed_attempts', 0),
                alert.get('description'),
                alert.get('rule_id'),
                alert.get('rule_level', 0),
                alert.get('priority'),
                alert.get('priority_score'),
                json.dumps(alert.get('triage_reasons', [])),
                alert.get('source', 'wazuh'),
                alert.get('seq_id', 0),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            conn.close()
    
    def get_all_alerts(self):
        """Get all alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alerts.append({
                'id': row[0], 'timestamp': row[1], 'severity': row[2],
                'asset_type': row[3], 'threat_type': row[4], 'source_ip': row[5],
                'destination': row[6], 'is_malicious_ip': bool(row[7]),
                'failed_attempts': row[8], 'description': row[9], 'rule_id': row[10],
                'rule_level': row[11], 'priority': row[12], 'priority_score': row[13],
                'triage_reasons': json.loads(row[14]) if row[14] else [],
                'source': row[15], 'seq_id': row[16]
            })
        return alerts
    
    def get_alerts_by_date_range(self, start_date, end_date):
        """Get alerts in date range"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM alerts 
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
        ''', (start_date, end_date))
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alerts.append({
                'id': row[0], 'timestamp': row[1], 'severity': row[2],
                'asset_type': row[3], 'threat_type': row[4], 'source_ip': row[5],
                'destination': row[6], 'is_malicious_ip': bool(row[7]),
                'failed_attempts': row[8], 'description': row[9], 'rule_id': row[10],
                'rule_level': row[11], 'priority': row[12], 'priority_score': row[13],
                'triage_reasons': json.loads(row[14]) if row[14] else [],
                'source': row[15], 'seq_id': row[16]
            })
        return alerts
    
    def get_alert_count(self):
        """Total alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def clear_all_alerts(self):
        """Delete all"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        print("✅ Cleared")
    
    def get_stats(self):
        """Stats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        
        cursor.execute('SELECT priority, COUNT(*) FROM alerts GROUP BY priority')
        priority_stats = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT DATE(timestamp), COUNT(*) 
            FROM alerts 
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp) DESC
            LIMIT 7
        ''')
        date_stats = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total': total,
            'by_priority': priority_stats,
            'by_date': date_stats
        }