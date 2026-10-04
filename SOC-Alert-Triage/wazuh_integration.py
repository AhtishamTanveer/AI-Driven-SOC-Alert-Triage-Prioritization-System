"""
wazuh_integration.py

Secure Wazuh Indexer integration for the SOC dashboard.

Security features:
  * Credentials come only from environment variables / .env (never hardcoded)
  * HTTPS is mandatory (credentials are never sent over plain HTTP)
  * TLS verification is configurable (full verify, custom CA cert, or lab mode)
  * Password is never printed, logged or shown in repr()
  * Server error bodies are never logged (they can echo sensitive data)
  * Lookback window is validated (no query injection through env values)
  * Source IPs are validated before being passed to the dashboard
  * Request timeout, bounded result size and automatic retry on 502/503/504
"""

import ipaddress
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone

import requests
import urllib3
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

logger = logging.getLogger(__name__)


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default, minimum, maximum):
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


class WazuhIntegration:
    # Hard upper limits so a wrong setting cannot overload the indexer
    MAX_FETCH_SIZE = 1000
    MAX_RETURN_LIMIT = 1000

    # Only allow values like "now-2d", "now-12h", "now-30m"
    _LOOKBACK_PATTERN = re.compile(r"^now-\d{1,3}[mhdw]$")

    def __init__(self):
        # ---- Connection settings (from environment) ----
        self.indexer_url = os.getenv(
            "WAZUH_INDEXER_URL", "https://localhost:9200"
        ).rstrip("/")
        self.username = os.getenv("WAZUH_USER", "admin")
        self._password = os.getenv("WAZUH_PASSWORD")  # private, never printed
        self.agent_name = os.getenv("WAZUH_AGENT_NAME", "Windows-PC")
        self.timeout = _env_int("WAZUH_TIMEOUT", 15, 1, 120)
        self.fetch_size = _env_int("WAZUH_FETCH_SIZE", 500, 1, self.MAX_FETCH_SIZE)

        # ---- Validation ----
        if not self._password:
            raise ValueError(
                "WAZUH_PASSWORD is not set. Add it to your .env file "
                "(see .env.example)."
            )

        if not self.indexer_url.startswith("https://"):
            raise ValueError(
                "WAZUH_INDEXER_URL must start with https:// "
                "(credentials must not travel over plain HTTP)."
            )

        lookback = os.getenv("WAZUH_LOOKBACK", "now-2d").strip()
        if not self._LOOKBACK_PATTERN.match(lookback):
            raise ValueError(
                "WAZUH_LOOKBACK is invalid. Use a value like now-2d, now-12h or now-30m."
            )
        self.lookback = lookback

        # ---- TLS verification ----
        ca_cert = os.getenv("WAZUH_CA_CERT")
        if ca_cert:
            if not os.path.isfile(ca_cert):
                raise ValueError("WAZUH_CA_CERT points to a file that does not exist.")
            self.verify = ca_cert  # trust only this CA (best for Wazuh self-signed certs)
        elif _env_bool("WAZUH_VERIFY_SSL", True):
            self.verify = True  # normal verification
        else:
            self.verify = False  # lab mode only
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning(
                "TLS verification is DISABLED. Use this only for a local lab; "
                "set WAZUH_CA_CERT or WAZUH_VERIFY_SSL=true for real deployments."
            )

        # ---- HTTP session with retry ----
        self.session = requests.Session()
        self.session.auth = (self.username, self._password)
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=(502, 503, 504),
            allowed_methods=("POST",),
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

        logger.info("Wazuh Indexer integration ready")
        print("✅ Wazuh Indexer integration ready")

    # Never leak the password through print(obj) or logs
    def __repr__(self):
        return (
            f"WazuhIntegration(url={self.indexer_url!r}, "
            f"user={self.username!r}, password='***')"
        )

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------
    def _build_query(self):
        return {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": self.lookback, "lte": "now"}}}
                    ],
                    "filter": [{"term": {"agent.name": self.agent_name}}],
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": self.fetch_size,
        }

    def get_recent_alerts(self, limit=100):
        """Get recent SECURITY alerts from Wazuh Indexer with smart deduplication."""
        try:
            limit = max(1, min(int(limit), self.MAX_RETURN_LIMIT))
        except (TypeError, ValueError):
            limit = 100

        try:
            print("🔍 Querying Wazuh Indexer...")
            response = self.session.post(
                f"{self.indexer_url}/wazuh-alerts-*/_search",
                json=self._build_query(),
                verify=self.verify,
                timeout=self.timeout,
            )
            print(f"📡 Response status: {response.status_code}")

            if response.status_code == 401:
                logger.error("Wazuh authentication failed. Check WAZUH_USER / WAZUH_PASSWORD.")
                print("❌ Authentication failed. Check your .env credentials.")
                return []
            if response.status_code == 403:
                logger.error("Wazuh user is not allowed to read alerts (403).")
                print("❌ Access denied (403). This user cannot read wazuh-alerts-*.")
                return []
            if response.status_code != 200:
                # Do not log response.text: it may contain sensitive details
                logger.error("Indexer returned HTTP %s", response.status_code)
                print(f"⚠️ Indexer returned error: {response.status_code}")
                return []

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            total_hits = data.get("hits", {}).get("total", {}).get("value", 0)

            print(f"📊 Total alerts in Wazuh: {total_hits}")
            print(f"📦 Retrieved {len(hits)} alert documents")

            # ---------------- SMART DEDUPLICATION ----------------
            # Group alerts by threat category + 10-minute window
            alert_groups = defaultdict(list)

            for hit in hits:
                source = hit.get("_source", {})
                rule_id = source.get("rule", {}).get("id", "")
                rule_desc = source.get("rule", {}).get("description", "").lower()
                timestamp = source.get("timestamp", "")

                threat_category = self.get_threat_category(rule_desc, rule_id)

                # YYYY-MM-DDTHH:M -> 10-minute window
                time_window = timestamp[:15] if timestamp else ""
                group_key = f"{threat_category}_{time_window}"

                alert_groups[group_key].append({"hit": hit, "source": source})

            alerts = []
            for group_alerts in alert_groups.values():
                if not group_alerts or len(alerts) >= limit:
                    continue

                representative = group_alerts[0]
                formatted = self.format_alert(
                    representative["source"],
                    representative["hit"].get("_id", "unknown"),
                    alert_count=len(group_alerts),
                )

                if formatted:
                    alerts.append(formatted)
                    if len(alerts) <= 3:
                        print(
                            f"  ✓ Alert {len(alerts)}: {formatted['threat_type']} "
                            f"- Consolidated {len(group_alerts)} similar alerts"
                        )

            print(f"✅ Returning {len(alerts)} consolidated alerts (from {len(hits)} raw alerts)")
            return alerts

        except requests.exceptions.SSLError:
            logger.error("TLS/SSL error while connecting to the indexer.")
            print(
                "❌ SSL error. For the Wazuh self-signed cert set WAZUH_CA_CERT "
                "or (lab only) WAZUH_VERIFY_SSL=false in .env"
            )
            return []
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to the indexer at %s", self.indexer_url)
            print("❌ Cannot connect to the Wazuh Indexer. Is Docker running?")
            return []
        except requests.exceptions.Timeout:
            logger.error("Indexer request timed out after %s seconds", self.timeout)
            print("❌ Indexer request timed out.")
            return []
        except Exception as exc:
            # Log only the error type/message, never request details or credentials
            logger.error("Unexpected error querying indexer: %s", type(exc).__name__)
            print(f"❌ Error querying indexer: {type(exc).__name__}")
            return []

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------
    def get_threat_category(self, description, rule_id):
        """Categorize alerts for better deduplication."""
        desc_lower = description.lower()

        # Brute force attacks (group all failed logins together)
        if any(word in desc_lower for word in ["logon", "authentication", "login", "failed"]):
            return "brute_force"
        # File integrity (group file changes together)
        elif any(word in desc_lower for word in ["integrity", "file", "checksum"]):
            return "file_integrity"
        # Process activity (group process events together)
        elif any(word in desc_lower for word in ["process", "started", "terminated", "service"]):
            return "process_activity"
        # Registry changes
        elif any(word in desc_lower for word in ["registry", "regkey"]):
            return "registry_changes"
        # Malware
        elif any(word in desc_lower for word in ["malware", "virus", "trojan"]):
            return "malware"
        # Policy violations
        elif any(word in desc_lower for word in ["policy", "violation", "unauthorized"]):
            return "policy_violation"
        # Use rule_id as fallback
        else:
            return f"rule_{rule_id}"

    @staticmethod
    def _safe_ip(value, default="127.0.0.1"):
        """Return value only if it is a valid IP address."""
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except (ValueError, AttributeError):
            return default

    def format_alert(self, source, alert_id, alert_count=1):
        """Convert Wazuh indexer alert to dashboard format."""
        try:
            rule = source.get("rule", {})
            agent = source.get("agent", {})
            data = source.get("data", {})

            # Map level to severity
            level = rule.get("level", 0)
            if level >= 12:
                severity = "critical"
            elif level >= 7:
                severity = "high"
            elif level >= 4:
                severity = "medium"
            else:
                severity = "low"

            # Determine threat type
            description = rule.get("description", "").lower()
            groups = rule.get("groups", [])
            threat_type = self.map_threat_type(description, groups, level)

            # Extract source IP (validated)
            raw_ip = (
                data.get("srcip")
                or data.get("win", {}).get("eventdata", {}).get("ipAddress")
                or data.get("src_ip")
                or source.get("srcip")
                or "127.0.0.1"
            )
            source_ip = self._safe_ip(raw_ip)

            # Show if it's consolidated
            alert_description = rule.get("description", "Security event")
            if alert_count > 1:
                alert_description = (
                    f"{alert_description} (Consolidated {alert_count} similar events)"
                )

            # Failed attempts
            failed_attempts = (
                alert_count
                if "logon" in description
                or "authentication" in description
                or "login" in description
                else 0
            )

            timestamp = source.get("timestamp", datetime.now(timezone.utc).isoformat())

            return {
                "id": alert_id,
                "timestamp": timestamp,
                "severity": severity,
                "asset_type": self.determine_asset_type(level),
                "threat_type": threat_type,
                "source_ip": source_ip,
                "destination": agent.get("name", self.agent_name),
                "is_malicious_ip": level >= 10,
                "failed_attempts": failed_attempts,
                "description": alert_description,
                "rule_id": rule.get("id", "N/A"),
                "rule_level": level,
                "source": "wazuh",
            }
        except Exception as exc:
            logger.warning("Error formatting alert: %s", type(exc).__name__)
            print(f"⚠️ Error formatting alert: {type(exc).__name__}")
            return None

    def map_threat_type(self, description, groups, level):
        """Map Wazuh alert to threat type."""
        groups_str = " ".join(groups).lower() if groups else ""

        if any(word in description for word in [
            "authentication failed", "login", "logon failed", "failed logon",
            "logon failure", "invalid user", "user logon", "account logon",
        ]):
            return "brute_force"
        elif any(word in groups_str for word in ["malware", "virus", "trojan", "rootkit", "worm"]):
            return "malware"
        elif any(word in description for word in [
            "integrity", "file modified", "file added", "file changed",
            "file deleted", "checksum",
        ]):
            return "suspicious_activity"
        elif any(word in description for word in ["policy", "violation", "compliance", "unauthorized"]):
            return "policy_violation"
        elif any(word in groups_str for word in ["attack", "exploit", "vulnerability", "dos", "ddos"]):
            return "dos_attack"
        elif any(word in description for word in ["ransomware", "encryption", "crypto"]):
            return "ransomware"
        elif any(word in description for word in ["privilege", "escalation", "elevation", "admin"]):
            return "suspicious_activity"
        elif any(word in description for word in ["firewall", "blocked", "denied", "reject"]):
            return "policy_violation"
        elif any(word in description for word in ["process", "started", "terminated", "service"]):
            return "suspicious_activity"
        elif level >= 7:
            return "suspicious_activity"
        else:
            return "policy_violation"

    def determine_asset_type(self, level):
        """Determine asset type based on alert severity."""
        if level >= 10:
            return "production"
        elif level >= 5:
            return "staging"
        else:
            return "development"
