"""
wazuh_test.py

Tests the connection to your Wazuh stack using settings from the .env file.
It never prints passwords or tokens.

  Test 1: Wazuh Indexer (port 9200)  -> needs WAZUH_USER / WAZUH_PASSWORD
  Test 2: Wazuh Manager API (55000)  -> needs WAZUH_API_USER / WAZUH_API_PASSWORD
"""

import os

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def get_verify_setting():
    ca_cert = os.getenv("WAZUH_CA_CERT")
    if ca_cert:
        return ca_cert if os.path.isfile(ca_cert) else True
    if _env_bool("WAZUH_VERIFY_SSL", True):
        return True
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("⚠️  TLS verification is DISABLED (lab mode)\n")
    return False


def test_indexer(verify):
    print("=== Test 1: Wazuh Indexer ===")
    url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
    user = os.getenv("WAZUH_USER", "admin")
    password = os.getenv("WAZUH_PASSWORD")

    if not password:
        print("⏭️  Skipped: WAZUH_PASSWORD is not set in .env\n")
        return

    if not url.startswith("https://"):
        print("❌ WAZUH_INDEXER_URL must start with https://\n")
        return

    try:
        response = requests.get(
            f"{url}/_cluster/health", auth=(user, password), verify=verify, timeout=10
        )
        if response.status_code == 200:
            status = response.json().get("status", "unknown")
            print(f"✅ Indexer login OK (cluster status: {status})\n")
        elif response.status_code == 401:
            print("❌ Authentication failed. Check WAZUH_USER / WAZUH_PASSWORD\n")
        else:
            print(f"❌ Indexer returned HTTP {response.status_code}\n")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect. Is Docker running? (docker ps)\n")
    except requests.exceptions.SSLError:
        print("❌ SSL error. Set WAZUH_VERIFY_SSL=false (lab) or WAZUH_CA_CERT in .env\n")
    except Exception as exc:
        print(f"❌ Error: {type(exc).__name__}\n")


def test_manager_api(verify):
    print("=== Test 2: Wazuh Manager API ===")
    url = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    user = os.getenv("WAZUH_API_USER", "wazuh-wui")
    password = os.getenv("WAZUH_API_PASSWORD")

    if not password:
        print("⏭️  Skipped: WAZUH_API_PASSWORD is not set in .env\n")
        return

    if not url.startswith("https://"):
        print("❌ WAZUH_API_URL must start with https://\n")
        return

    try:
        response = requests.get(
            f"{url}/security/user/authenticate",
            auth=(user, password),
            verify=verify,
            timeout=10,
        )
        if response.status_code != 200:
            print(f"❌ API login failed (HTTP {response.status_code}). "
                  "Check WAZUH_API_USER / WAZUH_API_PASSWORD\n")
            return

        token = response.json()["data"]["token"]  # kept in memory, never printed
        print("✅ API login OK")

        # The Wazuh API has no /alerts endpoint (alerts live in the Indexer),
        # so we test by listing agents instead.
        agents = requests.get(
            f"{url}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 5},
            verify=verify,
            timeout=10,
        )
        if agents.status_code == 200:
            count = len(agents.json().get("data", {}).get("affected_items", []))
            print(f"✅ Agents API OK ({count} agents returned)\n")
        else:
            print(f"❌ Agents request failed (HTTP {agents.status_code})\n")

    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect. Is Docker running? (docker ps)\n")
    except requests.exceptions.SSLError:
        print("❌ SSL error. Set WAZUH_VERIFY_SSL=false (lab) or WAZUH_CA_CERT in .env\n")
    except Exception as exc:
        print(f"❌ Error: {type(exc).__name__}\n")


if __name__ == "__main__":
    print("Testing Wazuh connections...\n")
    verify_setting = get_verify_setting()
    test_indexer(verify_setting)
    test_manager_api(verify_setting)
    print("=" * 60)
    print("Test Complete!")
