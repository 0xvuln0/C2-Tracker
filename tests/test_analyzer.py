from c2tracker.analyzer import (
    KNOWN_C2_FRAMEWORKS,
    analyze_shodan_banners,
    analyze_threat,
)
from c2tracker.censys_lookup import CensysResult
from c2tracker.malware_db import (
    KNOWN_MALWARE_IPS,
    check_ip,
    get_all_actors,
    get_all_families,
    search_actor,
    search_family,
)
from c2tracker.network import is_private_ip
from c2tracker.shodan_lookup import ShodanResult


def test_private_ip_detection():
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("172.16.0.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("1.1.1.1")


def test_shodan_c2_detection():
    result = ShodanResult(
        ip="1.2.3.4",
        banners=[{"product": "Cobalt Strike", "data": "some banner data"}],
    )
    assert result.is_c2_suspect


def test_shodan_banners_analysis():
    result = ShodanResult(
        ip="1.2.3.4",
        banners=[{"product": "cobalt strike", "data": "malleable c2 profile"}],
    )
    indicators = analyze_shodan_banners(result)
    assert "Cobalt Strike" in indicators


def test_censys_c2_detection():
    result = CensysResult(
        ip="1.2.3.4",
        services=[{"service_name": "COBALT_STRIKE", "port": 50050}],
    )
    assert result.is_c2_suspect


def test_threat_analysis_no_data():
    result = analyze_threat("1.2.3.4")
    assert result.threat_label == "LOW"
    assert result.score == 0


def test_threat_analysis_cobalt():
    shodan = ShodanResult(
        ip="1.2.3.4",
        banners=[{"product": "cobalt strike", "data": "malleable c2"}],
        ports=[50050, 443],
        org="Evil Corp",
        country="RU",
    )
    result = analyze_threat("1.2.3.4", shodan_result=shodan)
    assert result.score > 0
    assert "Cobalt Strike" in result.detected_frameworks


def test_framework_list_populated():
    assert len(KNOWN_C2_FRAMEWORKS) >= 8
    assert "Cobalt Strike" in KNOWN_C2_FRAMEWORKS
    assert "Metasploit" in KNOWN_C2_FRAMEWORKS
    assert "Sliver" in KNOWN_C2_FRAMEWORKS


def test_malware_db_populated():
    assert len(KNOWN_MALWARE_IPS) >= 100


def test_malware_db_check_known_ip():
    matches = check_ip("45.77.65.114")
    assert len(matches) > 0
    assert matches[0].malware_family == "Cobalt Strike"


def test_malware_db_check_unknown_ip():
    matches = check_ip("1.2.3.4")
    assert len(matches) == 0


def test_malware_db_search_family():
    results = search_family("cobalt")
    assert len(results) > 0
    assert all("cobalt" in m.malware_family.lower() for m in results)


def test_malware_db_search_actor():
    results = search_actor("Evil Corp")
    assert len(results) > 0


def test_malware_db_get_families():
    families = get_all_families()
    assert len(families) > 10
    assert "cobalt strike" in families


def test_malware_db_get_actors():
    actors = get_all_actors()
    assert len(actors) > 0


def test_threat_analysis_known_malicious_ip():
    result = analyze_threat("45.77.65.114")
    assert result.score > 0
    assert len(result.malware_db_matches) > 0
    assert result.threat_label in ("CRITICAL", "HIGH", "MEDIUM")
