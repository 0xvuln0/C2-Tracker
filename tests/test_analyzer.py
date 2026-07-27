"""Tests for the threat analyzer — scoring logic, threat labels, and detection."""

from analyzer import (
    C2_PORT_INDICATORS,
    KNOWN_C2_FRAMEWORKS,
    ThreatResult,
    analyze_censys_services,
    analyze_connection_ports,
    analyze_shodan_banners,
    analyze_threat,
)
from malware_db import (
    KNOWN_MALWARE_IPS,
    check_ip,
    get_all_actors,
    get_all_families,
    search_actor,
    search_family,
)
from models import CensysResult, ShodanResult
from network import Connection

# ---------------------------------------------------------------------------
# ThreatResult scoring and labelling
# ---------------------------------------------------------------------------

class TestThreatResultScoring:
    def test_empty_result_is_zero(self):
        r = ThreatResult(ip="1.2.3.4")
        assert r.score == 0

    def test_score_capped_at_100(self):
        r = ThreatResult(
            ip="1.2.3.4",
            detected_frameworks=["A", "B", "C", "D"],
            indicators=["i1", "i2", "i3", "i4", "i5"],
            associated_ports=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )
        assert r.score <= 100

    def test_frameworks_contribute_30_each(self):
        r1 = ThreatResult(ip="1.2.3.4", detected_frameworks=["A"])
        r2 = ThreatResult(ip="1.2.3.4", detected_frameworks=["A", "B"])
        assert r2.score - r1.score == 30

    def test_indicators_contribute_10_each(self):
        r1 = ThreatResult(ip="1.2.3.4", indicators=["a"])
        r2 = ThreatResult(ip="1.2.3.4", indicators=["a", "b"])
        assert r2.score - r1.score == 10

    def test_ports_contribute_5_each(self):
        r1 = ThreatResult(ip="1.2.3.4", associated_ports=[1])
        r2 = ThreatResult(ip="1.2.3.4", associated_ports=[1, 2])
        assert r2.score - r1.score == 5

    def test_shodan_vulns_contribute_3_each(self):
        shodan = ShodanResult(ip="1.2.3.4", vulns=["CVE-2021-1234", "CVE-2021-5678"])
        r = ThreatResult(ip="1.2.3.4", shodan_result=shodan)
        assert r.score == 6

    def test_shodan_c2_suspect_adds_25(self):
        shodan = ShodanResult(
            ip="1.2.3.4",
            banners=[{"product": "cobalt strike", "data": "beacon"}],
        )
        r = ThreatResult(ip="1.2.3.4", shodan_result=shodan)
        assert r.score == 25

    def test_censys_c2_suspect_adds_25(self):
        censys = CensysResult(
            ip="1.2.3.4",
            services=[{"service_name": "sliver", "port": 8888}],
        )
        r = ThreatResult(ip="1.2.3.4", censys_result=censys)
        assert r.score == 25

    def test_db_matches_contribute_20_each_capped_at_40(self):
        from malware_db import MalwareIP
        m1 = MalwareIP("1.2.3.4", "Cobalt Strike", "Various", "test", 50050)
        m2 = MalwareIP("1.2.3.4", "Metasploit", "Various", "test", 4444)
        r = ThreatResult(ip="1.2.3.4", malware_db_matches=[m1, m2])
        assert r.score == 40
        # Three matches should still cap at 40
        m3 = MalwareIP("1.2.3.4", "Sliver", "Various", "test", 8888)
        r3 = ThreatResult(ip="1.2.3.4", malware_db_matches=[m1, m2, m3])
        assert r3.score == 40


class TestThreatResultLabels:
    def test_low_label(self):
        r = ThreatResult(ip="1.2.3.4")
        assert r.threat_label == "LOW"

    def test_medium_label(self):
        r = ThreatResult(ip="1.2.3.4", indicators=["a"] * 3)
        assert r.threat_label == "MEDIUM"

    def test_high_label(self):
        # 1 framework (30) + 2 indicators (20) = 50 -> HIGH
        r = ThreatResult(
            ip="1.2.3.4",
            detected_frameworks=["A"],
            indicators=["a", "b"],
        )
        assert r.threat_label == "HIGH"

    def test_critical_label(self):
        r = ThreatResult(
            ip="1.2.3.4",
            detected_frameworks=["A", "B", "C"],
            indicators=["a"] * 3,
        )
        assert r.threat_label == "CRITICAL"

    def test_threshold_boundaries(self):
        # 2 indicators = 20, below MEDIUM threshold (25)
        r_below = ThreatResult(ip="1.2.3.4", indicators=["x", "y"])
        assert r_below.score == 20
        assert r_below.threat_label == "LOW"

        # 3 indicators = 30, above MEDIUM threshold (25)
        r_med = ThreatResult(ip="1.2.3.4", indicators=["x", "y", "z"])
        assert r_med.score == 30
        assert r_med.threat_label == "MEDIUM"


# ---------------------------------------------------------------------------
# Banner / service analysis
# ---------------------------------------------------------------------------

class TestAnalyzeShodanBanners:
    def test_detects_cobalt_strike(self):
        r = ShodanResult(
            ip="1.2.3.4",
            banners=[{"product": "Cobalt Strike", "data": "malleable c2"}],
        )
        assert "Cobalt Strike" in analyze_shodan_banners(r)

    def test_detects_metasploit(self):
        r = ShodanResult(
            ip="1.2.3.4",
            banners=[{"data": "meterpreter reverse_tcp"}],
        )
        assert "Metasploit" in analyze_shodan_banners(r)

    def test_no_false_positive_on_normal_banner(self):
        r = ShodanResult(
            ip="1.2.3.4",
            banners=[{"product": "nginx", "data": "HTTP/1.1 200 OK"}],
        )
        assert analyze_shodan_banners(r) == []

    def test_empty_banners(self):
        r = ShodanResult(ip="1.2.3.4", banners=[])
        assert analyze_shodan_banners(r) == []

    def test_multiple_frameworks(self):
        r = ShodanResult(
            ip="1.2.3.4",
            banners=[
                {"product": "cobalt strike"},
                {"data": "meterpreter"},
            ],
        )
        indicators = analyze_shodan_banners(r)
        assert "Cobalt Strike" in indicators
        assert "Metasploit" in indicators


class TestAnalyzeCensysServices:
    def test_detects_framework(self):
        r = CensysResult(
            ip="1.2.3.4",
            services=[{"service_name": "SLIVER", "port": 8888}],
        )
        assert "Sliver" in analyze_censys_services(r)

    def test_no_false_positive_on_normal_service(self):
        r = CensysResult(
            ip="1.2.3.4",
            services=[{"service_name": "SSH", "port": 22}],
        )
        assert analyze_censys_services(r) == []


class TestAnalyzeConnectionPorts:
    def test_detects_cobalt_strike_port(self):
        conn = Connection(
            local_addr="10.0.0.1", local_port=12345,
            remote_addr="1.2.3.4", remote_port=50050,
            status="ESTABLISHED", pid=1, process_name="test",
        )
        indicators = analyze_connection_ports([conn])
        assert "Cobalt Strike" in indicators

    def test_detects_metasploit_port(self):
        conn = Connection(
            local_addr="10.0.0.1", local_port=12345,
            remote_addr="1.2.3.4", remote_port=4444,
            status="ESTABLISHED", pid=1, process_name="test",
        )
        indicators = analyze_connection_ports([conn])
        assert "Metasploit (common)" in indicators

    def test_no_match_on_unknown_port(self):
        conn = Connection(
            local_addr="10.0.0.1", local_port=12345,
            remote_addr="1.2.3.4", remote_port=9999,
            status="ESTABLISHED", pid=1, process_name="test",
        )
        assert analyze_connection_ports([conn]) == []


# ---------------------------------------------------------------------------
# Full threat analysis
# ---------------------------------------------------------------------------

class TestAnalyzeThreat:
    def test_no_data_returns_low(self):
        r = analyze_threat("1.2.3.4")
        assert r.threat_label == "LOW"
        assert r.score == 0

    def test_known_malicious_ip_scores_high(self):
        r = analyze_threat("45.77.65.114")
        assert r.score > 0
        assert len(r.malware_db_matches) > 0
        assert r.threat_label in ("CRITICAL", "HIGH", "MEDIUM")

    def test_shodan_cobalt_boosts_score(self):
        shodan = ShodanResult(
            ip="1.2.3.4",
            banners=[{"product": "cobalt strike", "data": "beacon"}],
            ports=[50050, 443],
        )
        r = analyze_threat("1.2.3.4", shodan_result=shodan)
        assert r.score > 0
        assert "Cobalt Strike" in r.detected_frameworks

    def test_connection_port_adds_indicator(self):
        conn = Connection(
            local_addr="10.0.0.1", local_port=12345,
            remote_addr="1.2.3.4", remote_port=50050,
            status="ESTABLISHED", pid=1, process_name="test",
        )
        r = analyze_threat("1.2.3.4", connections=[conn])
        assert r.score > 0
        assert any("50050" in ind for ind in r.indicators)

    def test_shodan_error_does_not_crash(self):
        shodan = ShodanResult(ip="1.2.3.4", error="API down")
        r = analyze_threat("1.2.3.4", shodan_result=shodan)
        assert r.threat_label == "LOW"

    def test_censys_error_does_not_crash(self):
        censys = CensysResult(ip="1.2.3.4", error="Auth failed")
        r = analyze_threat("1.2.3.4", censys_result=censys)
        assert r.threat_label == "LOW"

    def test_combined_sources_accumulate(self):
        shodan = ShodanResult(
            ip="1.2.3.4",
            banners=[{"product": "cobalt strike"}],
            vulns=["CVE-2021-1234"],
        )
        conn = Connection(
            local_addr="10.0.0.1", local_port=12345,
            remote_addr="1.2.3.4", remote_port=50050,
            status="ESTABLISHED", pid=1, process_name="test",
        )
        r = analyze_threat("1.2.3.4", shodan_result=shodan, connections=[conn])
        assert r.score > 25
        assert "Cobalt Strike" in r.detected_frameworks


# ---------------------------------------------------------------------------
# Known C2 framework / port constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_frameworks_populated(self):
        assert len(KNOWN_C2_FRAMEWORKS) >= 8
        assert "Cobalt Strike" in KNOWN_C2_FRAMEWORKS
        assert "Metasploit" in KNOWN_C2_FRAMEWORKS
        assert "Sliver" in KNOWN_C2_FRAMEWORKS

    def test_port_indicators_populated(self):
        assert 50050 in C2_PORT_INDICATORS
        assert 4444 in C2_PORT_INDICATORS
        assert 8888 in C2_PORT_INDICATORS


# ---------------------------------------------------------------------------
# Malware database
# ---------------------------------------------------------------------------

class TestMalwareDatabase:
    def test_database_populated(self):
        assert len(KNOWN_MALWARE_IPS) >= 500

    def test_check_known_ip(self):
        matches = check_ip("45.77.65.114")
        assert len(matches) > 0
        assert matches[0].malware_family == "Cobalt Strike"

    def test_check_unknown_ip(self):
        assert check_ip("1.2.3.4") == []

    def test_search_family_partial_match(self):
        results = search_family("cobalt")
        assert len(results) > 0
        assert all("cobalt" in m.malware_family.lower() for m in results)

    def test_search_family_no_match(self):
        assert search_family("nonexistent_xyz") == []

    def test_search_actor(self):
        results = search_actor("Evil Corp")
        assert len(results) > 0
        assert all(m.threat_actor == "Evil Corp" for m in results)

    def test_search_actor_no_match(self):
        assert search_actor("nonexistent_xyz") == []

    def test_get_all_families(self):
        families = get_all_families()
        assert len(families) > 10
        assert families == sorted(families)

    def test_get_all_actors(self):
        actors = get_all_actors()
        assert len(actors) > 0
        assert actors == sorted(actors)

    def test_all_entries_have_valid_ips(self):
        for entry in KNOWN_MALWARE_IPS:
            import ipaddress
            ipaddress.ip_address(entry.ip)

    def test_all_entries_have_required_fields(self):
        for entry in KNOWN_MALWARE_IPS:
            assert entry.ip
            assert entry.malware_family
            assert entry.threat_actor
            assert entry.description
