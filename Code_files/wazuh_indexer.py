"""
wazuh_indexer.py

Simple (non-deduplicated) alert query against the Wazuh Indexer.
Credentials are read from the .env file, never hardcoded.
"""

import ipaddress
import logging
import os
import re

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_LOOKBACK_PATTERN = re.compile(r"^now-\d{1,3}[mhdw]$")


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _get_verify_setting():
    """Return the 'verify' value for requests: CA file path, True, or False (lab only)."""
    ca_cert = os.getenv("WAZUH_CA_CERT")
    if ca_cert:
        if not os.path.isfile(ca_cert):
            raise ValueError("WAZUH_CA_CERT points to a file that does not exist.")
        return ca_cert
    if _env_bool("WAZUH_VERIFY_SSL", True):
        return True
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.warning("TLS verification is DISABLED (lab mode).")
    return False


def _safe_ip(value, default="N/A"):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, AttributeError):
        return default


def map_severity(level):
    if level >= 12:
        return "critical"
    elif level >= 7:
        return "high"
    elif level >= 3:
        return "medium"
    else:
        return "low"


def query_wazuh_alerts():
    """Query Wazuh indexer for alerts."""

    # ---- Settings from .env ----
    indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
    username = os.getenv("WAZUH_USER", "admin")
    password = os.getenv("WAZUH_PASSWORD")
    agent_name = os.getenv("WAZUH_AGENT_NAME", "Windows-PC")
    lookback = os.getenv("WAZUH_LOOKBACK", "now-24h").strip()

    if not password:
        raise ValueError("WAZUH_PASSWORD is not set. Check your .env file.")
    if not indexer_url.startswith("https://"):
        raise ValueError("WAZUH_INDEXER_URL must start with https://")
    if not _LOOKBACK_PATTERN.match(lookback):
        raise ValueError("WAZUH_LOOKBACK is invalid. Use e.g. now-24h, now-2d.")

    verify = _get_verify_setting()

    query = {
        "query": {
            "bool": {
                "must": [{"range": {"timestamp": {"gte": lookback, "lte": "now"}}}],
                "filter": [{"term": {"agent.name": agent_name}}],
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 100,
    }

    try:
        response = requests.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            auth=(username, password),
            json=query,
            verify=verify,
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            print(f"✅ Found {len(hits)} alerts in indexer")

            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                level = source.get("rule", {}).get("level", 0)
                alerts.append({
                    "id": hit.get("_id"),
                    "timestamp": source.get("timestamp"),
                    "severity": map_severity(level),
                    "asset_type": "production",
                    "threat_type": "suspicious_activity",
                    "source_ip": _safe_ip(source.get("data", {}).get("srcip", "N/A")),
                    "destination": source.get("agent", {}).get("name", "N/A"),
                    "is_malicious_ip": level >= 10,
                    "failed_attempts": 0,
                    "description": source.get("rule", {}).get("description", "Alert"),
                    "rule_id": source.get("rule", {}).get("id", "N/A"),
                    "rule_level": level,
                    "source": "wazuh",
                })
            return alerts

        if response.status_code == 401:
            print("❌ Authentication failed. Check WAZUH_USER / WAZUH_PASSWORD in .env")
        elif response.status_code == 403:
            print("❌ Access denied (403) for this user.")
        else:
            print(f"❌ Indexer returned: {response.status_code}")
        return []

    except requests.exceptions.SSLError:
        print("❌ SSL error. Set WAZUH_CA_CERT, or (lab only) WAZUH_VERIFY_SSL=false in .env")
        return []
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to the Wazuh Indexer. Is Docker running?")
        return []
    except requests.exceptions.Timeout:
        print("❌ Indexer request timed out.")
        return []
    except Exception as exc:
        # Print only the error type, never request details or credentials
        print(f"❌ Error querying indexer: {type(exc).__name__}")
        return []


if __name__ == "__main__":
    alerts = query_wazuh_alerts()
    print(f"Total: {len(alerts)} alerts")
    if alerts:
        print("First alert:", alerts[0])
