from c2tracker.analyzer import (
    KNOWN_C2_FRAMEWORKS,
    analyze_shodan_banners,
    analyze_threat,
)
from c2tracker.censys_lookup import CensysResult
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
