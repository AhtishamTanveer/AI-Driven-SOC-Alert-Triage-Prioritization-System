from datetime import datetime

# Rule weights
SEVERITY_WEIGHTS = {
    'critical': 60,
    'high': 25,
    'medium': 15,
    'low': 5
}

ASSET_WEIGHTS = {
    'production': 40,
    'staging': 20,
    'development': 10
}

THREAT_WEIGHTS = {
    'ransomware': 50,
    'data_exfiltration': 45,
    'malware': 35,
    'brute_force': 30,
    'dos_attack': 25,
    'suspicious_activity': 15,
    'policy_violation': 10
}

def calculate_priority(alert):
    """Calculate priority score based on rules"""
    score = 0
    reasons = []
    
    # Rule 1: Severity
    severity = alert.get('severity', 'low').lower()
    severity_score = SEVERITY_WEIGHTS.get(severity, 10)
    score += severity_score
    reasons.append(f"Severity ({severity}): +{severity_score}")
    
    # Rule 2: Asset Criticality
    asset_type = alert.get('asset_type', 'development').lower()
    asset_score = ASSET_WEIGHTS.get(asset_type, 10)
    score += asset_score
    reasons.append(f"Asset type ({asset_type}): +{asset_score}")
    
    # Rule 3: Threat Type
    threat_type = alert.get('threat_type', 'suspicious_activity').lower()
    threat_score = THREAT_WEIGHTS.get(threat_type, 15)
    score += threat_score
    reasons.append(f"Threat type ({threat_type}): +{threat_score}")
    
    # Rule 4: After-hours (6 PM to 6 AM)
    try:
        alert_time = datetime.fromisoformat(alert.get('timestamp', datetime.now().isoformat()))
        if alert_time.hour >= 18 or alert_time.hour <= 6:
            score += 15
            reasons.append("After-hours activity: +15")
    except:
        pass
    
    # Rule 5: Known malicious IP
    if alert.get('is_malicious_ip', False):
        score += 25
        reasons.append("Known malicious IP: +25")
    
    # Rule 6: Multiple failed attempts
    if alert.get('failed_attempts', 0) > 5:
        score += 20
        reasons.append(f"Multiple failed attempts ({alert.get('failed_attempts')}): +20")
    
    # Classify final priority
    priority = classify_priority(score)
    
    return {
        'score': score,
        'priority': priority,
        'reasons': reasons
    }

def classify_priority(score):
    """Convert score to priority level"""
    if score >= 90:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 30:
        return 'MEDIUM'
    else:
        return 'LOW'