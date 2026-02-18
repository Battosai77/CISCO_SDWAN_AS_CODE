#!/usr/bin/env python3
"""
CLIENT API VMANAGE 20.18 - SD-WAN as Code
Charge Ansible Vault → Auth → Devices → Compliance checks

Usage:
  python vmanage_devices.py --vault                        # Ansible Vault (password prompted)
  python vmanage_devices.py --config config/vmanage.yaml  # Plain YAML mode (lab)

Fonctionnalités:
- 🔐 Ansible Vault (prod) ou YAML plain (lab)
- 📊 Liste devices avec status/reachability
- ✅ Check conformité templates Terraform
- 📤 Export JSON/CSV pour Ansible/Terraform
"""

import argparse
import json
import sys
import yaml
import csv
import getpass
from pathlib import Path
from typing import Dict, List, Any
from ansible_vault import Vault
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

VAULT_FILE = Path(__file__).parent.parent / "ansible" / "group_vars" / "all" / "vault.yml"
PLAIN_CONFIG = Path(__file__).parent.parent / "config" / "vmanage.yaml"

class VManageClient:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.session = None
        self.base_url = cfg["url"].rstrip("/")

    def authenticate(self) -> bool:
        """Auth vManage: POST /j_security_check → JSESSIONID"""
        session = requests.Session()
        
        # Retry + timeouts
        retry_strategy = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.verify = self.cfg.get("verify_ssl", False)
        # Disable InsecureRequestWarning when user explicitly disables SSL verification
        if not session.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        login_url = f'{self.base_url}/j_security_check'
        payload = {
            "j_username": self.cfg["username"],
            "j_password": self.cfg["password"],
        }

        resp = session.post(login_url, data=payload, timeout=30)
        
        if resp.status_code != 200 or "JSESSIONID" not in session.cookies:
            print(f"❌ Auth failed: {resp.status_code}")
            print(f"   Response: {resp.text[:200]}...")
            return False

        print("✅ Authentification OK")
        self.session = session
        return True

    def get_devices(self) -> List[Dict[str, Any]]:
        """GET /dataservice/device/action/status → devices + reachability"""
        if not self.session:
            raise RuntimeError("Not authenticated")

        # Endpoint status complet (reachability, version...)
        url = f'{self.base_url}/dataservice/device/action/status'
        # Some vManage versions expect a POST to this action endpoint.
        # Try POST first; fall back to GET if server returns 405.
        try:
            resp = self.session.post(url, json={"action": "status"}, timeout=30)
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}")

        # If not allowed, try GET. If forbidden, try alternative endpoint.
        if resp.status_code == 405:
            resp = self.session.get(url, timeout=30)

        if resp.status_code == 403:
            # Try alternative endpoint that returns device list
            alt_url = f'{self.base_url}/dataservice/device'
            alt_resp = self.session.get(alt_url, timeout=30)
            if alt_resp.ok:
                # vManage returns devices under 'data' for this endpoint too
                return alt_resp.json().get("data", [])
            else:
                # Provide more diagnostic information
                raise RuntimeError(f"Access forbidden (403) for {url}. Alt endpoint returned {alt_resp.status_code}: {alt_resp.text[:200]}")

        # For other errors, raise with server message to help debugging
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"HTTP error {resp.status_code} on {url}: {resp.text[:300]}")

        data = resp.json()
        return data.get("data", [])

    def get_templates(self) -> List[Dict[str, Any]]:
        """GET /dataservice/template/device → device templates"""
        url = f'{self.base_url}/dataservice/template/device'
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def compliance_check(self, expected_templates: List[str]) -> Dict[str, Any]:
        """Vérifier présence templates Terraform"""
        templates = self.get_templates()
        template_names = [t.get("templateName") for t in templates]
        
        missing = [t for t in expected_templates if t not in template_names]
        present = [t for t in expected_templates if t in template_names]
        
        return {
            "total_templates": len(templates),
            "expected": len(expected_templates),
            "present": len(present),
            "missing": missing,
            "status": "OK" if not missing else "KO"
        }

def load_vault_config(vault_pass: str) -> Dict[str, Any]:
    """Charge Ansible Vault (prod)"""
    if not VAULT_FILE.exists():
        raise FileNotFoundError(f"Vault file missing: {VAULT_FILE}")
    
    with open(VAULT_FILE, "r") as f:
        vault_content = f.read()
    
    vault = Vault(vault_pass)
    try:
        decrypted = vault.load(vault_content)
        config = decrypted["vmanage_secrets"]
        print("🔐 Vault decrypted")
        return config
    except Exception as e:
        raise RuntimeError(f"Vault decrypt failed: {e}")

def load_plain_config() -> Dict[str, Any]:
    """Charge YAML plain (lab uniquement)"""
    if not PLAIN_CONFIG.exists():
        raise FileNotFoundError(f"Plain config missing: {PLAIN_CONFIG}")
    
    with open(PLAIN_CONFIG, "r") as f:
        config = yaml.safe_load(f)["vmanage"]
        print("📄 Plain config loaded")
        return config

def export_csv(devices: List[Dict], filename: str):
    """Export devices → CSV"""
    if not devices:
        return
    
    fieldnames = ["host-name", "system-ip", "site-id", "reachability", "platform-id"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            row = {k: device.get(k, "N/A") for k in fieldnames}
            writer.writerow(row)
    print(f"📤 CSV exported: {filename}")

def main():
    parser = argparse.ArgumentParser(description="vManage API Client")
    parser.add_argument("--vault", action="store_true", help="Use Ansible Vault (prod) - password will be prompted")
    parser.add_argument("--config", help="Plain YAML config (lab)")
    parser.add_argument("--export-json", help="Export JSON filename")
    parser.add_argument("--export-csv", action="store_true", help="Export CSV")
    parser.add_argument("--check-templates", nargs="+", 
                       help="Check these templates exist")
    
    args = parser.parse_args()

    # Load config
    if args.vault:
        vault_pass = getpass.getpass("🔐 Enter Ansible Vault password: ")
        cfg = load_vault_config(vault_pass)
    elif args.config:
        cfg = load_plain_config()
    else:
        print("❌ Specify --vault or --config")
        sys.exit(1)

    # Client + auth
    client = VManageClient(cfg)
    if not client.authenticate():
        sys.exit(1)

    # Devices
    devices = client.get_devices()
    print(f"\n📊 {len(devices)} devices:")
    for device in devices[:10]:  # Top 10
        status = "🟢" if device.get("reachability") == "reachable" else "🔴"
        print(f"  {status} {device.get('host-name')} "
              f"({device.get('system-ip')}) site {device.get('site-id')}")

    # Compliance
    if args.check_templates:
        check = client.compliance_check(args.check_templates)
        print(f"\n✅ Template compliance: {check['status']}")
        print(f"   Expected: {check['expected']}, Present: {check['present']}")
        if check["missing"]:
            print(f"   ❌ Missing: {', '.join(check['missing'])}")

    # Exports
    if args.export_json:
        with open(args.export_json, "w") as f:
            json.dump(devices, f, indent=2)
        print(f"📤 JSON: {args.export_json}")

    if args.export_csv:
        export_csv(devices, "devices.csv")

if __name__ == "__main__":
    main()
