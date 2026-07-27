"""Export scan results to JSON, CSV, and IOC formats."""

from __future__ import annotations

import csv
import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from file_scanner import FileScanResult


def export_json(results: FileScanResult | list[FileScanResult], output_path: str) -> str:
    """Export scan results to JSON file.

    Args:
        results: Single result or list of results.
        output_path: Path to write JSON file.

    Returns:
        Path to the written file.
    """
    if not isinstance(results, list):
        results = [results]

    data = []
    for r in results:
        entry = {
            "path": r.path,
            "file_size": r.file_size,
            "md5": r.md5,
            "sha1": r.sha1,
            "sha256": r.sha256,
            "file_type": r.file_type,
            "entropy": r.entropy,
            "risk_score": r.risk_score,
            "risk_label": r.risk_label,
            "detected_families": r.detected_families,
            "family_reasons": r.family_reasons,
            "embedded_ips": r.embedded_ips,
            "embedded_domains": r.embedded_domains,
            "suspicious_behaviors": r.suspicious_strings,
            "similar_known_malware": r.similar_known_malware,
            "indicators": r.indicators,
            "pe_info": r.pe_info,
        }
        data.append(entry)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    return output_path


def export_csv(results: FileScanResult | list[FileScanResult], output_path: str) -> str:
    """Export scan results to CSV file.

    Args:
        results: Single result or list of results.
        output_path: Path to write CSV file.

    Returns:
        Path to the written file.
    """
    if not isinstance(results, list):
        results = [results]

    fieldnames = [
        "path", "file_size", "md5", "sha256", "file_type", "entropy",
        "risk_score", "risk_label", "detected_families", "embedded_ips",
        "embedded_domains", "suspicious_behaviors",
    ]

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "path": r.path,
                "file_size": r.file_size,
                "md5": r.md5,
                "sha256": r.sha256,
                "file_type": r.file_type,
                "entropy": r.entropy,
                "risk_score": r.risk_score,
                "risk_label": r.risk_label,
                "detected_families": "|".join(r.detected_families),
                "embedded_ips": "|".join(r.embedded_ips),
                "embedded_domains": "|".join(r.embedded_domains),
                "suspicious_behaviors": "|".join(r.suspicious_strings),
            })

    return output_path


def export_iocs(results: FileScanResult | list[FileScanResult], output_path: str) -> str:
    """Export IOCs (hashes, IPs, domains) to a text file, one per line.

    Args:
        results: Single result or list of results.
        output_path: Path to write IOC file.

    Returns:
        Path to the written file.
    """
    if not isinstance(results, list):
        results = [results]

    iocs = set()
    for r in results:
        if r.sha256:
            iocs.add(f"sha256:{r.sha256}")
        if r.md5:
            iocs.add(f"md5:{r.md5}")
        for ip in r.embedded_ips:
            iocs.add(f"ip:{ip}")
        for domain in r.embedded_domains:
            iocs.add(f"domain:{domain}")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        for ioc in sorted(iocs):
            f.write(ioc + "\n")

    return output_path
