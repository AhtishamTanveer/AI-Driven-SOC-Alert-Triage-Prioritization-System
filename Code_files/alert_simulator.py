import random
from datetime import datetime, timedelta
import time

class AlertSimulator:
    """Simulates real-time security alerts"""
    
    def __init__(self):
        self.severities = ['critical', 'high', 'medium', 'low']
        self.asset_types = ['production', 'staging', 'development']
        self.threat_types = [
            'ransomware', 'data_exfiltration', 'malware',
            'brute_force', 'dos_attack', 'suspicious_activity',
            'policy_violation'
        ]
        self.source_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.23',
            '203.0.113.45', '198.51.100.78', '185.220.101.1'
        ]
        self.destinations = [
            'web-server-prod', 'database-prod', 'api-gateway',
            'file-server', 'mail-server', 'backup-server'
        ]
        self.alert_counter = 1000
    
    def generate_alert(self):
        """Generate a single realistic alert"""
        self.alert_counter += 1
        
        severity = random.choices(
            self.severities,
            weights=[10, 25, 40, 25]  # More medium alerts
        )[0]
        
        threat_type = random.choice(self.threat_types)
        
        # Critical threats are more likely to be on production
        if severity == 'critical':
            asset_type = random.choices(
                self.asset_types,
                weights=[70, 20, 10]
            )[0]
        else:
            asset_type = random.choice(self.asset_types)
        
        alert = {
            'id': f"ALT-{self.alert_counter}",
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'asset_type': asset_type,
            'threat_type': threat_type,
            'source_ip': random.choice(self.source_ips),
            'destination': random.choice(self.destinations),
            'is_malicious_ip': random.random() < 0.3,  # 30% chance
            'failed_attempts': random.randint(0, 15) if threat_type == 'brute_force' else 0,
            'description': self.generate_description(threat_type, severity)
        }
        
        return alert
    
    def generate_description(self, threat_type, severity):
        """Generate realistic alert description"""
        descriptions = {
            'ransomware': f"{severity.capitalize()} ransomware activity detected - file encryption attempt",
            'data_exfiltration': f"Suspected data exfiltration - unusual outbound traffic pattern",
            'malware': f"Malware signature detected - {severity} threat level",
            'brute_force': f"Brute force attack detected - multiple failed login attempts",
            'dos_attack': f"Denial of service attack in progress - high traffic volume",
            'suspicious_activity': f"Suspicious user activity - anomalous behavior detected",
            'policy_violation': f"Security policy violation - unauthorized access attempt"
        }
        return descriptions.get(threat_type, "Security event detected")
    
    def generate_batch(self, count=50):
        """Generate multiple alerts"""
        return [self.generate_alert() for _ in range(count)]