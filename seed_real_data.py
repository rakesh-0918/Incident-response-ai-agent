"""Seed IncidentOps with attributed real security incidents and a LogHub sample.

The security records are selected from ThreatCluster's CC BY 4.0 dataset. The
LogHub download is stored locally only as a sample for the log-ingest panel.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from datasets import load_dataset
from dotenv import load_dotenv
from hindsight_client import Hindsight

ROOT = Path(__file__).parent
BANK_ID = "incidentops-v1"
DATASET_ID = "threatcluster/threat-incident-clusters"
DATASET_URL = "https://huggingface.co/datasets/threatcluster/threat-incident-clusters"
LOGHUB_URL = "https://raw.githubusercontent.com/logpai/loghub/master/BGL/BGL_2k.log"
LOGHUB_PAGE = "https://github.com/logpai/loghub"
KEYWORDS = {
    "ransomware": ("ransomware", "extortion"),
    "breach": ("breach", "data leak", "exposed data", "stolen data"),
    "phishing": ("phishing", "credential theft"),
    "exploit": ("exploit", "vulnerability", "zero-day", "zero day", "cve-"),
    "malware": ("malware", "trojan", "botnet"),
}


def _field(row: dict[str, Any], key: str, default: Any = "") -> Any:
    value = row.get(key, default)
    return default if value is None else value


def _incident_category(row: dict[str, Any]) -> str | None:
    searchable = " ".join(
        str(_field(row, key, ""))
        for key in ("title", "summary", "keywords", "entities")
    ).lower()
    for category, phrases in KEYWORDS.items():
        if any(phrase in searchable for phrase in phrases):
            return category
    return None


def select_incidents(limit: int = 15) -> list[dict[str, Any]]:
    """Stream the public dataset and select up to 15 multi-source incidents."""
    stream = load_dataset(DATASET_ID, split="train", streaming=True)
    candidates: list[tuple[float, dict[str, Any]]] = []
    for row in stream:
        title = str(_field(row, "title", "")).strip()
        summary = str(_field(row, "summary", "")).strip()
        if not title or not summary or not _incident_category(row):
            continue
        try:
            source_count = int(_field(row, "source_count", 0))
        except (TypeError, ValueError):
            source_count = 0
        if source_count < 2:
            continue
        try:
            score = float(_field(row, "threat_score", 0))
        except (TypeError, ValueError):
            score = 0.0
        candidates.append((score, row))
    candidates.sort(key=lambda item: item[0], reverse=True)

    selected: list[dict[str, Any]] = []
    category_counts = {category: 0 for category in KEYWORDS}
    used_ids: set[str] = set()

    def add_candidate(row: dict[str, Any]) -> None:
        cluster_id = str(_field(row, "cluster_id", "")).strip()
        category = _incident_category(row)
        if not cluster_id or cluster_id in used_ids or not category or category_counts[category] >= 5:
            return
        selected.append(row)
        used_ids.add(cluster_id)
        category_counts[category] += 1

    # Guarantee category coverage before filling the remaining slots by score.
    for category in ("ransomware", "breach", "phishing", "exploit"):
        for _, row in candidates:
            if _incident_category(row) == category:
                add_candidate(row)
                break

    for _, row in candidates:
        add_candidate(row)
        if len(selected) == limit:
            break
    return selected


def download_loghub_sample() -> Path:
    """Download up to 200 real BGL lines, capped to fit the ingest request."""
    destination = ROOT / "data" / "loghub_bgl_sample.log"
    destination.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(LOGHUB_URL, timeout=60)
    response.raise_for_status()
    lines: list[str] = []
    char_count = 0
    for line in response.text.splitlines()[:200]:
        if char_count + len(line) + 1 > 12000:
            break
        lines.append(line)
        char_count += len(line) + 1
    if not lines:
        raise RuntimeError("The LogHub download was empty.")
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def main() -> None:
    load_dotenv()
    base_url = os.getenv("HINDSIGHT_BASE_URL")
    if not base_url:
        raise SystemExit("Set HINDSIGHT_BASE_URL in .env before seeding.")

    client = Hindsight(base_url=base_url, api_key=os.getenv("HINDSIGHT_API_KEY"))
    client.create_bank(
        bank_id=BANK_ID,
        name="IncidentOps",
        mission="Support incident response with evidence from approved lessons. Never invent past incidents or fixes.",
    )
    incidents = select_incidents()
    if not incidents:
        raise SystemExit("No qualifying records found in the Hugging Face dataset.")

    for row in incidents:
        title = str(_field(row, "title")).strip()
        summary = str(_field(row, "summary")).strip()
        cluster_id = str(_field(row, "cluster_id")).strip()
        content = f"Real incident: {title}\n{summary}"
        client.retain(
            bank_id=BANK_ID,
            content=content,
            context="verified, multi-source security incident from ThreatCluster",
            document_id=f"threatcluster-{cluster_id}",
            metadata={
                "source": DATASET_URL,
                "license": "CC BY 4.0",
                "cluster_id": cluster_id,
                "source_count": str(_field(row, "source_count", "")),
                "first_reported": str(_field(row, "first_reported", "")),
            },
        )
        print(f"Retained: {title}")

    sample = download_loghub_sample()
    print(f"\nSeeded {len(incidents)} real security incidents into bank {BANK_ID}.")
    print(f"Downloaded LogHub BGL sample to {sample}.")
    print(f"ThreatCluster source: {DATASET_URL} (CC BY 4.0; attribution required).")
    print(f"LogHub source: {LOGHUB_PAGE} (research/academic use; cite LogHub).")
    print("Live triage will use the configured bank; reset to Cold Start for a clean demo.")


if __name__ == "__main__":
    main()
