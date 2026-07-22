"""
test_cti_toolkit.py

Full pytest suite for cti_toolkit.py, covering IOC validation, STIX
generation, MITRE ATT&CK mapping, and the end-to-end convert() pipeline.

Run:
    pytest test_cti_toolkit.py -v

Note: TestMitreMapper and the ATT&CK-technique tests in TestConvert
require attack_techniques.json to exist (run update_attack_data.py first).

Author: MMAKOLA THATO
"""

import stix2
import pytest

import cti_toolkit as cti


# ===========================================================================
# IOC VALIDATOR TESTS
# ===========================================================================

class TestHashValidation:
    def test_md5_valid(self):
        r = cti.classify("d41d8cd98f00b204e9800998ecf8427e")
        assert r.is_valid and r.ioc_type == cti.IOCType.MD5

    def test_sha1_valid(self):
        r = cti.classify("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert r.is_valid and r.ioc_type == cti.IOCType.SHA1

    def test_sha256_valid(self):
        r = cti.classify(
            "0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2"
        )
        assert r.is_valid and r.ioc_type == cti.IOCType.SHA256

    def test_hash_wrong_length_invalid(self):
        r = cti.classify("d41d8cd98f00b204e9800998ecf842")  # 30 chars
        assert not r.is_valid


class TestIPValidation:
    def test_valid_ipv4(self):
        r = cti.classify("8.8.8.8")
        assert r.is_valid and r.ioc_type == cti.IOCType.IPV4

    def test_valid_ipv6(self):
        r = cti.classify("2001:4860:4860::8888")
        assert r.is_valid and r.ioc_type == cti.IOCType.IPV6

    def test_invalid_ipv4_octet(self):
        r = cti.classify("999.999.999.999")
        assert not r.is_valid

    def test_defanged_ipv4(self):
        r = cti.classify("1[.]2[.]3[.]4")
        assert r.is_valid and r.ioc_type == cti.IOCType.IPV4


class TestDomainValidation:
    def test_valid_domain(self):
        r = cti.classify("evil-c2-domain.com")
        assert r.is_valid and r.ioc_type == cti.IOCType.DOMAIN

    def test_defanged_domain(self):
        r = cti.classify("evil-c2-domain[.]com")
        assert r.is_valid and r.ioc_type == cti.IOCType.DOMAIN

    def test_domain_leading_hyphen_invalid(self):
        r = cti.classify("-badstart.com")
        assert not r.is_valid


class TestURLValidation:
    def test_valid_https_url(self):
        r = cti.classify("https://malicious-sender.com/payload.exe")
        assert r.is_valid and r.ioc_type == cti.IOCType.URL

    def test_defanged_url(self):
        r = cti.classify("hxxp://185[.]199[.]108[.]153/payload.exe")
        assert r.is_valid and r.ioc_type == cti.IOCType.URL


class TestEmailValidation:
    def test_valid_email(self):
        r = cti.classify("phish@malicious-sender.com")
        assert r.is_valid and r.ioc_type == cti.IOCType.EMAIL

    def test_invalid_email_no_tld(self):
        r = cti.classify("phish@localhost")
        assert not r.is_valid


class TestUnknownAndEdgeCases:
    def test_garbage_input(self):
        r = cti.classify("not_a_real_ioc_at_all")
        assert not r.is_valid and r.ioc_type == cti.IOCType.UNKNOWN

    def test_empty_string(self):
        r = cti.classify("")
        assert not r.is_valid


class TestDefangRefang:
    def test_refang_domain(self):
        assert cti.refang("evil[.]com") == "evil.com"

    def test_refang_url(self):
        assert cti.refang("hxxp://evil[.]com") == "http://evil.com"

    def test_defang_roundtrip_domain(self):
        original = "evil.com"
        assert cti.refang(cti.defang(original)) == original


# ===========================================================================
# STIX GENERATOR TESTS
# ===========================================================================

class TestBuildIndicator:
    def test_valid_hash_indicator(self):
        ind = cti.build_indicator(
            "0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2"
        )
        assert isinstance(ind, stix2.Indicator)
        assert "SHA-256" in ind.pattern

    def test_valid_domain_indicator(self):
        ind = cti.build_indicator("evil-c2-domain.com")
        assert "domain-name:value" in ind.pattern

    def test_invalid_ioc_raises(self):
        with pytest.raises(ValueError):
            cti.build_indicator("not_a_real_ioc")


class TestBuildObjects:
    def test_build_malware(self):
        m = cti.build_malware("XWorm", "A RAT")
        assert isinstance(m, stix2.Malware)
        assert m.name == "XWorm"
        assert m.is_family is True

    def test_build_threat_actor(self):
        actor = cti.build_threat_actor("Unknown")
        assert isinstance(actor, stix2.ThreatActor)

    def test_build_identity(self):
        ident = cti.build_identity("Zaio SOC Team")
        assert isinstance(ident, stix2.Identity)
        assert ident.identity_class == "organization"

    def test_build_campaign(self):
        camp = cti.build_campaign("Operation Test")
        assert isinstance(camp, stix2.Campaign)

    def test_build_tool(self):
        tool = cti.build_tool("Mimikatz")
        assert isinstance(tool, stix2.Tool)


class TestRelationshipsAndBundles:
    def test_build_relationship(self):
        ind = cti.build_indicator("evil-c2-domain.com")
        mal = cti.build_malware("XWorm")
        rel = cti.build_relationship(ind, mal, "indicates")
        assert isinstance(rel, stix2.Relationship)
        assert rel.source_ref == ind.id
        assert rel.target_ref == mal.id

    def test_build_bundle_valid(self):
        ind = cti.build_indicator("8.8.8.8")
        mal = cti.build_malware("XWorm")
        rel = cti.build_relationship(ind, mal, "indicates")
        bundle = cti.build_bundle(ind, mal, rel)
        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 3

    def test_bundle_to_json_roundtrip(self):
        ind = cti.build_indicator("8.8.8.8")
        bundle = cti.build_bundle(ind)
        raw = cti.bundle_to_json(bundle)
        assert '"type": "bundle"' in raw


# ===========================================================================
# MITRE ATT&CK MAPPER TESTS
# (require attack_techniques.json — run update_attack_data.py first)
# ===========================================================================

@pytest.fixture(scope="module")
def mapper():
    try:
        return cti.AttackMapper()
    except FileNotFoundError:
        pytest.skip("attack_techniques.json not found — run update_attack_data.py first")


class TestMitreMapper:
    def test_known_technique(self, mapper):
        t = mapper.lookup("T1027")
        assert t is not None
        assert t.name == "Obfuscated Files or Information"

    def test_lowercase_input_normalized(self, mapper):
        assert mapper.lookup("t1027") is not None

    def test_unknown_technique_returns_none(self, mapper):
        assert mapper.lookup("T9999") is None

    def test_malformed_id_returns_none(self, mapper):
        assert mapper.lookup("not-a-technique") is None

    def test_lookup_many_mixed(self, mapper):
        results = mapper.lookup_many(["T1027", "T9999", "T1055"])
        ids = [t.technique_id for t in results]
        assert "T1027" in ids and "T1055" in ids
        assert len(results) == 2

    def test_search_finds_process_injection(self, mapper):
        results = mapper.search("process injection", limit=5)
        assert any(t.technique_id == "T1055" for t in results)

    def test_dataset_loaded(self, mapper):
        assert len(mapper) > 100


# ===========================================================================
# END-TO-END CONVERT() TESTS
# ===========================================================================

SAMPLE_IOCS = [
    "0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2",
    "hxxp://185[.]199[.]108[.]153/payload.exe",
    "evil-c2-domain[.]com",
    "not_a_real_ioc",
]


class TestConvertBasic:
    def test_valid_invalid_split(self):
        report = cti.convert(SAMPLE_IOCS)
        assert len(report.valid) == 3
        assert len(report.invalid) == 1

    def test_bundle_has_indicators_only_when_no_malware(self):
        report = cti.convert(SAMPLE_IOCS)
        assert report.bundle is not None
        assert len(report.bundle.objects) == 3

    def test_success_rate(self):
        report = cti.convert(SAMPLE_IOCS)
        assert abs(report.success_rate - 75.0) < 0.01


class TestConvertWithMalwareAndActor:
    def test_malware_and_relationships_added(self):
        report = cti.convert(SAMPLE_IOCS, malware_name="XWorm")
        assert len(report.bundle.objects) == 7  # 3 indicators + malware + 3 relationships

    def test_actor_adds_uses_relationship(self):
        report = cti.convert(SAMPLE_IOCS, malware_name="XWorm", threat_actor_name="Unknown")
        assert len(report.bundle.objects) == 9

    def test_actor_without_malware_still_included(self):
        report = cti.convert(SAMPLE_IOCS, threat_actor_name="Unknown")
        assert len(report.bundle.objects) == 4


class TestConvertWithTechniques:
    def test_techniques_resolved(self, mapper):
        report = cti.convert(SAMPLE_IOCS, malware_name="XWorm", technique_ids=["T1027", "T1055"])
        assert len(report.techniques) == 2

    def test_unknown_technique_ignored(self, mapper):
        report = cti.convert(SAMPLE_IOCS, malware_name="XWorm", technique_ids=["T9999"])
        assert len(report.techniques) == 0

    def test_no_techniques_no_call(self):
        report = cti.convert(SAMPLE_IOCS)
        assert report.techniques == []


class TestEmptyInput:
    def test_all_invalid_produces_no_bundle(self):
        report = cti.convert(["garbage1", "garbage2"])
        assert report.bundle is None
        assert len(report.invalid) == 2