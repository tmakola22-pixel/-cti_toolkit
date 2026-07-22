"""
cti_toolkit.py

Cyber Threat Intelligence Toolkit - core library.

Everything the toolkit does lives in this one file:
  1. IOC validation (hashes, IPs, domains, URLs, emails) with defang support
  2. STIX 2.1 object/bundle generation (via the official `stix2` library)
  3. MITRE ATT&CK technique lookup (via a local JSON file you generate once
     with update_attack_data.py)
  4. A high-level convert() pipeline tying the above three together
  5. JSON export helpers

Author: THATO MMAKOLA
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import stix2


# ===========================================================================
# 1. IOC VALIDATION
# ===========================================================================

class IOCType(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"


_HASH_PATTERNS = {
    IOCType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}

_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

_EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

_URL_PATTERN = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


@dataclass
class IOCResult:
    """Result of validating a single IOC."""
    raw_input: str
    refanged: str
    ioc_type: IOCType
    is_valid: bool
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "raw_input": self.raw_input,
            "refanged": self.refanged,
            "type": self.ioc_type.value,
            "is_valid": self.is_valid,
            "detail": self.detail,
        }


def refang(value: str) -> str:
    """Convert a defanged IOC (hxxp://evil[.]com) back to its real form."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    v = v.replace("hxxp://", "http://").replace("hxxps://", "https://")
    v = v.replace("hXXp://", "http://").replace("hXXps://", "https://")
    v = v.replace("[@]", "@").replace("[at]", "@")
    v = v.replace("[:]", ":")
    return v


def defang(value: str) -> str:
    """Convert a real IOC into a safe-to-paste defanged form."""
    v = value
    v = v.replace("http://", "hxxp://").replace("https://", "hxxps://")
    v = v.replace(".", "[.]")
    v = v.replace("@", "[@]")
    return v


def classify(value: str) -> IOCResult:
    """Classify and validate a single IOC string (defanged or not)."""
    original = value
    candidate = refang(value.strip())

    for ioc_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(candidate):
            return IOCResult(original, candidate, ioc_type, True)

    try:
        ip_obj = ipaddress.ip_address(candidate)
        ioc_type = IOCType.IPV4 if ip_obj.version == 4 else IOCType.IPV6
        return IOCResult(original, candidate, ioc_type, True)
    except ValueError:
        pass

    if "@" in candidate and _EMAIL_PATTERN.match(candidate):
        return IOCResult(original, candidate, IOCType.EMAIL, True)

    if candidate.lower().startswith(("http://", "https://", "ftp://")):
        if _URL_PATTERN.match(candidate):
            return IOCResult(original, candidate, IOCType.URL, True)
        return IOCResult(original, candidate, IOCType.URL, False,
                          detail="Malformed URL structure")

    if _DOMAIN_PATTERN.match(candidate):
        return IOCResult(original, candidate, IOCType.DOMAIN, True)

    return IOCResult(original, candidate, IOCType.UNKNOWN, False,
                      detail="Did not match any known IOC pattern")


def classify_batch(values: list[str]) -> list[IOCResult]:
    """Classify a list of IOC strings, one per line/entry."""
    return [classify(v) for v in values if v.strip()]


# ===========================================================================
# 2. STIX 2.1 GENERATION
# ===========================================================================

_STIX_PATTERN_BUILDERS = {
    IOCType.MD5: lambda v: f"[file:hashes.MD5 = '{v}']",
    IOCType.SHA1: lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    IOCType.SHA256: lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    IOCType.IPV4: lambda v: f"[ipv4-addr:value = '{v}']",
    IOCType.IPV6: lambda v: f"[ipv6-addr:value = '{v}']",
    IOCType.DOMAIN: lambda v: f"[domain-name:value = '{v}']",
    IOCType.URL: lambda v: f"[url:value = '{v}']",
    IOCType.EMAIL: lambda v: f"[email-addr:value = '{v}']",
}

_INDICATOR_TYPE_LABELS = {
    IOCType.MD5: "malicious-activity",
    IOCType.SHA1: "malicious-activity",
    IOCType.SHA256: "malicious-activity",
    IOCType.IPV4: "malicious-activity",
    IOCType.IPV6: "malicious-activity",
    IOCType.DOMAIN: "malicious-activity",
    IOCType.URL: "malicious-activity",
    IOCType.EMAIL: "anomalous-activity",
}


def build_indicator(ioc_value: str, description: str = "") -> stix2.Indicator:
    """Build a STIX 2.1 Indicator SDO from a raw IOC string.
    Raises ValueError if the IOC does not validate.
    """
    result = classify(ioc_value)
    if not result.is_valid:
        raise ValueError(
            f"Cannot build indicator: '{ioc_value}' is not a valid IOC "
            f"({result.detail})"
        )
    pattern = _STIX_PATTERN_BUILDERS[result.ioc_type](result.refanged)
    label = _INDICATOR_TYPE_LABELS[result.ioc_type]
    return stix2.Indicator(
        pattern=pattern,
        pattern_type="stix",
        indicator_types=[label],
        description=description or f"Indicator for {result.refanged}",
    )


def build_malware(name: str, description: str = "", is_family: bool = True,
                   malware_types: Optional[list[str]] = None,
                   external_references: Optional[list[dict]] = None) -> stix2.Malware:
    kwargs = dict(
        name=name,
        description=description,
        is_family=is_family,
        malware_types=malware_types or ["remote-access-trojan"],
    )
    if external_references:
        kwargs["external_references"] = external_references
    return stix2.Malware(**kwargs)


def build_threat_actor(name: str, description: str = "",
                        roles: Optional[list[str]] = None) -> stix2.ThreatActor:
    return stix2.ThreatActor(
        name=name,
        description=description,
        threat_actor_types=roles or ["unknown"],
    )


def build_identity(name: str, identity_class: str = "organization",
                    description: str = "") -> stix2.Identity:
    return stix2.Identity(name=name, identity_class=identity_class, description=description)


def build_campaign(name: str, description: str = "") -> stix2.Campaign:
    return stix2.Campaign(name=name, description=description)


def build_tool(name: str, description: str = "",
               tool_types: Optional[list[str]] = None) -> stix2.Tool:
    return stix2.Tool(name=name, description=description,
                       tool_types=tool_types or ["remote-access"])


def build_relationship(source, target, relationship_type: str,
                        description: str = "") -> stix2.Relationship:
    """e.g. build_relationship(indicator, malware, 'indicates')"""
    return stix2.Relationship(
        source_ref=source.id,
        target_ref=target.id,
        relationship_type=relationship_type,
        description=description,
    )


def build_bundle(*objects) -> stix2.Bundle:
    """Assemble any set of STIX SDOs/SROs into a validated 2.1 Bundle."""
    return stix2.Bundle(objects=list(objects))


def bundle_to_json(bundle: stix2.Bundle, pretty: bool = True) -> str:
    return bundle.serialize(pretty=pretty)


# ===========================================================================
# 3. MITRE ATT&CK MAPPING
# ===========================================================================

_ATTACK_DATA_PATH = Path(__file__).resolve().parent / "attack_techniques.json"
_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


@dataclass
class Technique:
    technique_id: str
    name: str
    tactics: list[str] = field(default_factory=list)
    description: str = ""
    platforms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": self.tactics,
            "description": self.description,
            "platforms": self.platforms,
        }


class AttackMapper:
    """Loads the local ATT&CK dataset once and serves lookups from it.

    Requires attack_techniques.json to exist next to this file — run
    `python update_attack_data.py` first to generate it.
    """

    def __init__(self, data_path: Optional[Path] = None):
        self._path = data_path or _ATTACK_DATA_PATH
        self._data: dict = {}
        self._load()

    def _load(self):
        if not self._path.exists():
            raise FileNotFoundError(
                f"ATT&CK dataset not found at {self._path}. "
                "Run 'python update_attack_data.py' to generate it."
            )
        with open(self._path, "r", encoding="utf-8") as f:
            self._data = json.load(f)

    def __len__(self) -> int:
        return len(self._data)

    def lookup(self, technique_id: str) -> Optional[Technique]:
        """Look up a single technique by ID (e.g. 'T1027' or 't1027.002')."""
        tid = technique_id.strip().upper()
        if not _TECHNIQUE_ID_PATTERN.match(tid):
            return None
        entry = self._data.get(tid)
        if not entry:
            return None
        return Technique(technique_id=tid, **entry)

    def lookup_many(self, technique_ids: list[str]) -> list[Technique]:
        results = []
        for tid in technique_ids:
            t = self.lookup(tid)
            if t:
                results.append(t)
        return results

    def search(self, keyword: str, limit: int = 10) -> list[Technique]:
        """Free-text search across technique names and descriptions."""
        kw = keyword.lower()
        matches = []
        for tid, entry in self._data.items():
            haystack = f"{entry['name']} {entry['description']}".lower()
            if kw in haystack:
                matches.append(Technique(technique_id=tid, **entry))
            if len(matches) >= limit:
                break
        return matches


# ===========================================================================
# 4. HIGH-LEVEL CONVERT PIPELINE
# ===========================================================================

@dataclass
class ConversionReport:
    """Summary of what happened during an IOC -> STIX conversion."""
    valid: list[IOCResult] = field(default_factory=list)
    invalid: list[IOCResult] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    bundle: Optional[stix2.Bundle] = None

    @property
    def success_rate(self) -> float:
        total = len(self.valid) + len(self.invalid)
        return (len(self.valid) / total * 100) if total else 0.0


def convert(
    ioc_lines: list[str],
    malware_name: Optional[str] = None,
    malware_description: str = "",
    technique_ids: Optional[list[str]] = None,
    threat_actor_name: Optional[str] = None,
    attack_mapper: Optional[AttackMapper] = None,
) -> ConversionReport:
    """Convert a batch of raw IOC strings into a STIX 2.1 bundle.

    Invalid IOCs are reported but excluded from the bundle — a bundle
    should only ever contain analyst-verified data.
    """
    results = classify_batch(ioc_lines)
    valid = [r for r in results if r.is_valid]
    invalid = [r for r in results if not r.is_valid]

    stix_objects = []
    indicators = []
    for r in valid:
        indicator = build_indicator(r.refanged)
        indicators.append(indicator)
        stix_objects.append(indicator)

    # Resolve ATT&CK techniques first so they can be attached to the
    # Malware object at creation time (stix2 SDOs are immutable).
    techniques: list[Technique] = []
    if technique_ids:
        mapper = attack_mapper or AttackMapper()
        techniques = mapper.lookup_many(technique_ids)

    malware_obj = None
    if malware_name:
        ext_refs = [
            {
                "source_name": "mitre-attack",
                "external_id": t.technique_id,
                "url": (
                    "https://attack.mitre.org/techniques/"
                    f"{t.technique_id.replace('.', '/')}/"
                ),
            }
            for t in techniques
        ] or None
        malware_obj = build_malware(
            malware_name, malware_description, external_references=ext_refs
        )
        stix_objects.append(malware_obj)
        for ind in indicators:
            stix_objects.append(build_relationship(ind, malware_obj, "indicates"))

    if threat_actor_name:
        actor_obj = build_threat_actor(threat_actor_name)
        stix_objects.append(actor_obj)
        if malware_obj:
            stix_objects.append(build_relationship(actor_obj, malware_obj, "uses"))

    bundle = build_bundle(*stix_objects) if stix_objects else None

    return ConversionReport(valid=valid, invalid=invalid, techniques=techniques, bundle=bundle)


# ===========================================================================
# 5. EXPORT HELPERS
# ===========================================================================

def export_bundle(bundle: stix2.Bundle, output_path: str | Path) -> Path:
    """Write a STIX bundle to disk as pretty-printed JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    return path


def export_report_summary(report: ConversionReport, output_path: str | Path) -> Path:
    """Write a human-readable JSON summary of a conversion run."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ioc_summary": {
            "total": len(report.valid) + len(report.invalid),
            "valid": len(report.valid),
            "invalid": len(report.invalid),
            "success_rate_pct": round(report.success_rate, 1),
        },
        "valid_iocs": [r.to_dict() for r in report.valid],
        "invalid_iocs": [r.to_dict() for r in report.invalid],
        "attack_techniques": [t.to_dict() for t in report.techniques],
        "bundle_object_count": len(report.bundle.objects) if report.bundle else 0,
    }
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return path
