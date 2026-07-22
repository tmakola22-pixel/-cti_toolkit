"""
update_attack_data.py

Pulls the official MITRE ATT&CK Enterprise STIX 2.1 bundle from MITRE's
public GitHub CTI repository and distills it into a small, fast-loading
JSON lookup table (technique ID -> name, tactics, description) saved as
attack_techniques.json next to this script.

Run this once before using cli.py's `mitre` or `convert --techniques`
commands, and again whenever you want to refresh against the latest
ATT&CK release:

    python update_attack_data.py

Author: MMAKOLA THATO
"""

import json
import urllib.request
from pathlib import Path

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT_PATH = Path(__file__).resolve().parent / "attack_techniques.json"


def fetch_attack_bundle() -> dict:
    req = urllib.request.Request(ATTACK_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def distill(bundle: dict) -> dict:
    """Extract a compact technique_id -> details lookup."""
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[technique_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "description": (obj.get("description") or "")[:400],
            "platforms": obj.get("x_mitre_platforms", []),
        }
    return techniques


def main():
    print(f"Fetching ATT&CK bundle from {ATTACK_URL} ...")
    bundle = fetch_attack_bundle()
    print(f"Fetched {len(bundle.get('objects', []))} STIX objects.")

    techniques = distill(bundle)
    print(f"Distilled {len(techniques)} techniques.")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, sort_keys=True)
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()