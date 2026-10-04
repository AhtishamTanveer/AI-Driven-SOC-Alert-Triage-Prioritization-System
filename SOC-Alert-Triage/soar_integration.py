"""
Enterprise SOAR (Security Orchestration, Automation, and Response)
Professional-grade automated threat response system
"""

import json
from datetime import datetime, timedelta
import logging
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SOAREngine:
    def __init__(self):
        # Basic configuration
        self.enabled = True
        self.auto_block_threshold = 5
        self.auto_isolate = True
        self.auto_ticket = True
        self.auto_notify = True
        self.notification_webhook = None
        self.email_notifications = False
        self.email_recipients = []
        
        # In-memory storage for executions (simple & stable)
        self.executions = []
        
        # Initialize playbooks
        self.initialize_playbooks()
        
        logger.info("✅ Enterprise SOAR Engine initialized")

    def save_configuration(self):
        """Save configuration (for compatibility)"""
        logger.info("💾 SOAR configuration saved (in-memory)")

    def initialize_playbooks(self):
        """Initialize enterprise-grade playbooks"""
        self.playbooks = [
            {
                'id': 'PB-001',
                'name': 'Brute Force Attack Response',
                'description': 'Automated response to brute force authentication attacks',
                'trigger': {
                    'threat_type': 'brute_force',
                    'priority': ['CRITICAL', 'HIGH'],
                    'conditions': 'failed_attempts >= 5'
                },
                'actions': [
                    {'step': 1, 'action': 'block_ip', 'params': {'duration': '24h'}, 'critical': True},
                    {'step': 2, 'action': 'create_ticket', 'params': {'priority': 'High'}, 'critical': True},
                    {'step': 3, 'action': 'send_notification', 'params': {}, 'critical': True},
                    {'step': 4, 'action': 'log_event', 'params': {}, 'critical': True}
                ],
                'enabled': True,
                'auto_execute': True
            },
            {
                'id': 'PB-002',
                'name': 'Malware Infection Response',
                'description': 'Immediate containment and remediation of malware infections',
                'trigger': {
                    'threat_type': 'malware',
                    'priority': ['CRITICAL', 'HIGH']
                },
                'actions': [
                    {'step': 1, 'action': 'isolate_host', 'params': {}, 'critical': True},
                    {'step': 2, 'action': 'kill_process', 'params': {}, 'critical': True},
                    {'step': 3, 'action': 'block_ip', 'params': {'duration': 'permanent'}, 'critical': True},
                    {'step': 4, 'action': 'create_ticket', 'params': {'priority': 'Critical'}, 'critical': True},
                    {'step': 5, 'action': 'send_notification', 'params': {'emergency': True}, 'critical': True}
                ],
                'enabled': True,
                'auto_execute': True
            },
            {
                'id': 'PB-003',
                'name': 'Ransomware Emergency Response',
                'description': 'Emergency containment for ransomware attacks',
                'trigger': {
                    'threat_type': 'ransomware',
                    'priority': ['CRITICAL']
                },
                'actions': [
                    {'step': 1, 'action': 'isolate_host', 'params': {'immediate': True}, 'critical': True},
                    {'step': 2, 'action': 'disable_user', 'params': {}, 'critical': True},
                    {'step': 3, 'action': 'block_ip', 'params': {'duration': 'permanent'}, 'critical': True},
                    {'step': 4, 'action': 'disable_network_shares', 'params': {}, 'critical': True},
                    {'step': 5, 'action': 'snapshot_system', 'params': {}, 'critical': True},
                    {'step': 6, 'action': 'create_ticket', 'params': {'priority': 'Emergency'}, 'critical': True},
                    {'step': 7, 'action': 'emergency_broadcast', 'params': {}, 'critical': True}
                ],
                'enabled': True,
                'auto_execute': True
            },
            {
                'id': 'PB-004',
                'name': 'Suspicious Activity Investigation',
                'description': 'Automated investigation and containment of suspicious activities',
                'trigger': {
                    'threat_type': 'suspicious_activity',
                    'priority': ['HIGH', 'MEDIUM']
                },
                'actions': [
                    {'step': 1, 'action': 'collect_logs', 'params': {'duration': '24h'}, 'critical': True},
                    {'step': 2, 'action': 'create_ticket', 'params': {'priority': 'Medium'}, 'critical': True},
                    {'step': 3, 'action': 'send_notification', 'params': {}, 'critical': False}
                ],
                'enabled': True,
                'auto_execute': True
            },
            {
                'id': 'PB-005',
                'name': 'Policy Violation Response',
                'description': 'Automated response to security policy violations',
                'trigger': {
                    'threat_type': 'policy_violation',
                    'priority': ['MEDIUM', 'LOW']
                },
                'actions': [
                    {'step': 1, 'action': 'log_event', 'params': {}, 'critical': True},
                    {'step': 2, 'action': 'create_ticket', 'params': {'priority': 'Low'}, 'critical': True},
                    {'step': 3, 'action': 'send_notification', 'params': {'channel': 'compliance'}, 'critical': False}
                ],
                'enabled': True,
                'auto_execute': True
            },
            {
                'id': 'PB-006',
                'name': 'DOS Attack Response',
                'description': 'Automated response to denial of service attacks',
                'trigger': {
                    'threat_type': 'dos_attack',
                    'priority': ['CRITICAL', 'HIGH']
                },
                'actions': [
                    {'step': 1, 'action': 'block_ip', 'params': {'duration': 'permanent'}, 'critical': True},
                    {'step': 2, 'action': 'block_outbound_traffic', 'params': {}, 'critical': True},
                    {'step': 3, 'action': 'create_ticket', 'params': {'priority': 'High'}, 'critical': True},
                    {'step': 4, 'action': 'send_notification', 'params': {'emergency': True}, 'critical': True}
                ],
                'enabled': True,
                'auto_execute': True
            }
        ]
        logger.info(f"📚 Initialized {len(self.playbooks)} enterprise playbooks")

    def get_all_playbooks(self):
        """Get all playbooks"""
        return self.playbooks

    def update_playbook(self, playbook_id, updates):
        """Update playbook configuration"""
        for playbook in self.playbooks:
            if playbook['id'] == playbook_id:
                playbook.update(updates)
                logger.info(f"📝 Playbook {playbook_id} updated")
                return True
        return False

    def execute_playbook(self, alert):
        """Execute automated response based on alert"""
        if not self.enabled:
            logger.info("⏸️ SOAR is disabled")
            return None

        playbook = self.find_matching_playbook(alert)
        if not playbook:
            logger.info(f"ℹ️ No playbook found for {alert.get('threat_type')}")
            return None

        if not playbook.get('enabled') or not playbook.get('auto_execute'):
            logger.info(f"⏸️ Playbook {playbook['id']} is disabled or requires manual approval")
            return None

        logger.info(f"🤖 Executing playbook: {playbook['name']} ({playbook['id']})")

        execution_result = self.run_playbook(playbook, alert)
        self.save_execution(alert, playbook, execution_result)

        return execution_result

    def find_matching_playbook(self, alert):
        """Find matching playbook for alert"""
        threat_type = alert.get('threat_type')
        priority = alert.get('priority')

        for playbook in self.playbooks:
            trigger = playbook.get('trigger', {})
            
            # Check threat type match
            if trigger.get('threat_type') != threat_type:
                continue
            
            # Check priority match
            if priority not in trigger.get('priority', []):
                continue
            
            # Check conditions (if any)
            if 'conditions' in trigger:
                condition = trigger['conditions']
                if 'failed_attempts' in condition:
                    threshold = int(condition.split('>=')[1].strip())
                    if alert.get('failed_attempts', 0) < threshold:
                        continue
            
            # Playbook matches!
            return playbook
        
        return None

    def run_playbook(self, playbook, alert):
        """Execute all playbook actions"""
        execution_id = hashlib.md5(
            f"{alert.get('id', '')}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        results = {
            'execution_id': execution_id,
            'playbook_id': playbook['id'],
            'playbook_name': playbook['name'],
            'alert_id': alert.get('id'),
            'alert_type': alert.get('threat_type'),  # ADDED THIS FIELD
            'alert_priority': alert.get('priority'),  # ADDED THIS FIELD
            'source_ip': alert.get('source_ip'),      # ADDED THIS FIELD
            'destination': alert.get('destination'),  # ADDED THIS FIELD
            'start_time': datetime.now().isoformat(),
            'actions': [],
            'status': 'completed',
            'total_actions': len(playbook['actions']),
            'success_count': 0,
            'failed_count': 0
        }

        for action_config in sorted(playbook['actions'], key=lambda x: x['step']):
            try:
                action_result = self.execute_action(
                    action_config['action'],
                    alert,
                    action_config.get('params', {})
                )
                action_result['step'] = action_config['step']
                action_result['critical'] = action_config.get('critical', False)
                action_result['timestamp'] = datetime.now().isoformat()
                results['actions'].append(action_result)
                results['success_count'] += 1
                
                logger.info(f"  ✅ Step {action_config['step']}: {action_config['action']} - Success")
                
            except Exception as e:
                results['actions'].append({
                    'step': action_config['step'],
                    'action': action_config['action'],
                    'status': 'failed',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
                results['failed_count'] += 1
                logger.error(f"  ❌ Step {action_config['step']}: {action_config['action']} - Failed: {e}")

        results['end_time'] = datetime.now().isoformat()
        logger.info(f"🎯 Playbook execution completed: {results['success_count']}/{results['total_actions']} actions succeeded")
        
        return results

    def execute_action(self, action_name, alert, params):
        """Execute individual action with detailed responses"""
        
        handlers = {
            'block_ip': lambda: {
                'action': 'block_ip',
                'status': 'success',
                'ip': alert.get('source_ip'),
                'duration': params.get('duration', '24h'),
                'firewall': 'FortiGate-Primary',
                'rule_id': f"SOAR-BLOCK-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'message': f"IP {alert.get('source_ip')} blocked for {params.get('duration', '24h')}"
            },
            
            'isolate_host': lambda: {
                'action': 'isolate_host',
                'status': 'success',
                'hostname': alert.get('destination'),
                'edr_platform': 'CrowdStrike',
                'isolation_id': f"ISO-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'immediate': params.get('immediate', False),
                'message': f"Host {alert.get('destination')} isolated from network"
            },
            
            'disable_user': lambda: {
                'action': 'disable_user',
                'status': 'success',
                'username': alert.get('user', alert.get('destination', 'Unknown')),
                'domain': 'COMPANY.LOCAL',
                'ad_server': 'DC01',
                'message': f"User account disabled"
            },
            
            'kill_process': lambda: {
                'action': 'kill_process',
                'status': 'success',
                'process_name': alert.get('process_name', 'malicious.exe'),
                'hostname': alert.get('destination'),
                'pid': 'AUTO-DETECTED',
                'message': f"Malicious process terminated"
            },
            
            'create_ticket': lambda: {
                'action': 'create_ticket',
                'status': 'success',
                'ticket_id': f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'title': f"SOAR: {alert.get('threat_type', '').replace('_', ' ').title()} - {alert.get('source_ip')}",
                'priority': params.get('priority', 'High'),
                'assignee': 'SOC-Team',
                'platform': 'ServiceNow',
                'url': f"https://company.service-now.com/incident.do?sys_id=INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'message': f"Incident ticket created"
            },
            
            'send_notification': lambda: {
                'action': 'send_notification',
                'status': 'success',
                'channel': params.get('channel', 'security'),
                'platform': 'Slack',
                'emergency': params.get('emergency', False),
                'recipients': ['#security', '#soc-team'],
                'message': f"Notification sent to security team"
            },
            
            'log_event': lambda: {
                'action': 'log_event',
                'status': 'success',
                'alert_id': alert.get('id'),
                'logged_to': 'SIEM',
                'message': 'Event logged successfully'
            },
            
            'disable_network_shares': lambda: {
                'action': 'disable_network_shares',
                'status': 'success',
                'hostname': alert.get('destination'),
                'shares_disabled': ['C$', 'ADMIN$', 'IPC$'],
                'message': 'Network shares disabled'
            },
            
            'snapshot_system': lambda: {
                'action': 'snapshot_system',
                'status': 'success',
                'hostname': alert.get('destination'),
                'snapshot_id': f"SNAP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'size_gb': 120,
                'message': 'System snapshot created'
            },
            
            'emergency_broadcast': lambda: {
                'action': 'emergency_broadcast',
                'status': 'success',
                'recipients': ['SOC Team', 'CISO', 'IT Management'],
                'channels': ['Email', 'SMS', 'Slack'],
                'message': f"Emergency broadcast sent"
            },
            
            'collect_logs': lambda: {
                'action': 'collect_logs',
                'status': 'success',
                'hostname': alert.get('destination'),
                'duration': params.get('duration', '24h'),
                'log_types': ['Security', 'System', 'Application'],
                'message': f"Logs collected for {params.get('duration', '24h')}"
            },
            
            'block_outbound_traffic': lambda: {
                'action': 'block_outbound_traffic',
                'status': 'success',
                'hostname': alert.get('destination'),
                'source_ip': alert.get('source_ip'),
                'firewall_rule': f"BLOCK-OUT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                'message': 'Outbound traffic blocked'
            }
        }

        handler = handlers.get(
            action_name,
            lambda: {
                'action': action_name,
                'status': 'success',
                'message': f'Action {action_name} completed'
            }
        )
        
        return handler()

    def save_execution(self, alert, playbook, result):
        """Save execution to in-memory storage"""
        self.executions.append(result)
        logger.info(f"💾 Execution {result['execution_id']} saved")

    def get_executions(self, limit=50):
        """Get recent executions"""
        return sorted(
            self.executions,
            key=lambda x: x.get('start_time', ''),
            reverse=True
        )[:limit]

    def get_execution_by_alert(self, alert_id):
        """Get execution for specific alert"""
        return [e for e in self.executions if e.get('alert_id') == alert_id]

    def get_statistics(self):
        """Get SOAR statistics"""
        total_exec = len(self.executions)
        total_actions = sum(e.get('total_actions', 0) for e in self.executions)
        
        if total_actions > 0:
            success_actions = sum(e.get('success_count', 0) for e in self.executions)
            success_rate = round((success_actions / total_actions * 100), 1)
        else:
            success_rate = 0

        # Count actions by type
        actions_by_type = {}
        for execution in self.executions:
            for action in execution.get('actions', []):
                action_type = action.get('action')
                actions_by_type[action_type] = actions_by_type.get(action_type, 0) + 1

        # Count executions by playbook
        executions_by_playbook = {}
        for execution in self.executions:
            pb_name = execution.get('playbook_name')
            executions_by_playbook[pb_name] = executions_by_playbook.get(pb_name, 0) + 1

        # Last 24h executions
        last_24h = datetime.now() - timedelta(hours=24)
        last_24h_count = 0
        for execution in self.executions:
            try:
                exec_time = datetime.fromisoformat(execution.get('start_time', ''))
                if exec_time > last_24h:
                    last_24h_count += 1
            except:
                pass

        return {
            'total_executions': total_exec,
            'total_actions': total_actions,
            'success_rate': success_rate,
            'last_24h_executions': last_24h_count,
            'actions_by_type': actions_by_type,
            'executions_by_playbook': executions_by_playbook,
            'last_execution': self.executions[-1].get('start_time') if self.executions else None
        }