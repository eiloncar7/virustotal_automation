import argparse
import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
import csv

VT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_POLL_SECONDS = 10
DEFAULT_POLL_TIMEOUT = 300


@dataclass
class Detection:
    engine: str
    category: str
    result: str


@dataclass
class ScanResult:
    sha256: str
    detections: list[Detection]
    analysis_url: str


class VirusTotalClient:
    def __init__(self, api_key: str, session: Optional[requests.Session] = None) -> None:
        self.api_key = api_key
        self.session = session or requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def fetch_file_report(self, sha256: str) -> Optional[dict]:
        response = self.session.get(f"{VT_BASE_URL}/files/{sha256}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def upload_file(self, file_path: Path) -> dict:
        with file_path.open("rb") as handle:
            response = self.session.post(f"{VT_BASE_URL}/files", files={"file": handle})
        response.raise_for_status()
        return response.json()

    def fetch_analysis(self, analysis_id: str) -> dict:
        response = self.session.get(f"{VT_BASE_URL}/analyses/{analysis_id}")
        response.raise_for_status()
        return response.json()

    def wait_for_analysis(self, analysis_id: str, timeout_seconds: int) -> dict:
        deadline = time.time() + timeout_seconds
        while True:
            analysis = self.fetch_analysis(analysis_id)
            status = analysis["data"]["attributes"]["status"]
            if status == "completed":
                return analysis
            if time.time() >= deadline:
                raise TimeoutError("VirusTotal analysis timed out")
            time.sleep(DEFAULT_POLL_SECONDS)


DEFAULT_HEADERS = [
    "vendor",
    "engine",
    "link",
    "description",
    "result",
    "category",
    "sha256",
    "analysis_url",
]


def download_file(url: str, output_dir: Path) -> Path:
    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()
    filename = url.split("/")[-1] or "installer"
    destination = output_dir / filename
    with destination.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                handle.write(chunk)
    return destination


def sha256_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_detections(report: dict) -> list[Detection]:
    results = report["data"]["attributes"].get("last_analysis_results", {})
    detections = []
    for engine, details in results.items():
        category = details.get("category", "")
        result = details.get("result") or ""
        if category in {"malicious", "suspicious"}:
            detections.append(Detection(engine=engine, category=category, result=result))
    return detections


def ensure_scan(vt_client: VirusTotalClient, file_path: Path, timeout_seconds: int) -> ScanResult:
    sha256 = sha256_digest(file_path)
    report = vt_client.fetch_file_report(sha256)
    analysis_url = ""
    if report is None:
        upload = vt_client.upload_file(file_path)
        analysis_id = upload["data"]["id"]
        analysis = vt_client.wait_for_analysis(analysis_id, timeout_seconds)
        analysis_url = analysis["data"]["links"]["self"]
        report = vt_client.fetch_file_report(sha256)
    else:
        analysis_url = report["data"]["links"]["self"]
    detections = extract_detections(report)
    return ScanResult(sha256=sha256, detections=detections, analysis_url=analysis_url)


def normalize_header(header: str) -> str:
    return header.strip().lower().replace(" ", "_")


def build_row(headers: list[str], payload: dict[str, str]) -> list[str]:
    row = []
    normalized = {normalize_header(key): value for key, value in payload.items()}
    for header in headers:
        value = normalized.get(normalize_header(header), "")
        row.append(value)
    return row


def load_existing_rows(csv_path: Path) -> tuple[list[str], list[list[str]]]:
    if not csv_path.exists():
        return DEFAULT_HEADERS[:], [DEFAULT_HEADERS[:]]
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    if not rows:
        return DEFAULT_HEADERS[:], [DEFAULT_HEADERS[:]]
    return rows[0], rows


def append_rows(csv_path: Path, rows: list[list[str]]) -> None:
    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for row in rows:
            writer.writerow(row)


def detection_already_documented(
    existing_rows: list[list[str]],
    headers: list[str],
    link: str,
    detection: Detection,
) -> bool:
    header_map = {normalize_header(name): idx for idx, name in enumerate(headers)}
    link_idx = header_map.get("link")
    engine_idx = header_map.get("engine") or header_map.get("vendor")
    result_idx = header_map.get("result") or header_map.get("description")
    if link_idx is None or engine_idx is None:
        return False
    for row in existing_rows[1:]:
        if link_idx < len(row) and row[link_idx].strip() == link:
            engine_value = row[engine_idx].strip() if engine_idx < len(row) else ""
            if engine_value != detection.engine:
                continue
            if result_idx is None:
                return True
            result_value = row[result_idx].strip() if result_idx < len(row) else ""
            if detection.result and detection.result in result_value:
                return True
            if not detection.result:
                return True
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VirusTotal detection pipeline")
    parser.add_argument("--links", nargs="*", help="Installer download links")
    parser.add_argument("--links-file", help="Path to a file with one link per line")
    parser.add_argument(
        "--output-csv",
        default=os.getenv("OUTPUT_CSV", "detections.csv"),
        help="Path to the output CSV file",
    )
    parser.add_argument(
        "--vt-api-key",
        help="VirusTotal API key",
        default=os.getenv("VT_API_KEY"),
    )
    parser.add_argument(
        "--poll-timeout",
        type=int,
        default=int(os.getenv("VT_POLL_TIMEOUT", DEFAULT_POLL_TIMEOUT)),
        help="Timeout in seconds for VirusTotal analysis",
    )
    return parser.parse_args()


def load_links(args: argparse.Namespace) -> list[str]:
    links: list[str] = []
    if args.links:
        links.extend(args.links)
    if args.links_file:
        content = Path(args.links_file).read_text(encoding="utf-8")
        links.extend([line.strip() for line in content.splitlines() if line.strip()])
    return links


def main() -> None:
    args = parse_args()
    links = load_links(args)
    if not links:
        raise SystemExit("Provide installer links via --links or --links-file")
    if not args.vt_api_key:
        raise SystemExit("VirusTotal API key is required")

    vt_client = VirusTotalClient(api_key=args.vt_api_key)
    output_path = Path(args.output_csv)
    headers, rows = load_existing_rows(output_path)

    output_dir = Path("downloads")
    output_dir.mkdir(exist_ok=True)

    new_rows: list[list[str]] = []
    for link in links:
        installer_path = download_file(link, output_dir)
        scan = ensure_scan(vt_client, installer_path, args.poll_timeout)
        for detection in scan.detections:
            if detection_already_documented(rows, headers, link, detection):
                continue
            payload = {
                "vendor": detection.engine,
                "engine": detection.engine,
                "link": link,
                "description": detection.result,
                "result": detection.result,
                "category": detection.category,
                "sha256": scan.sha256,
                "analysis_url": scan.analysis_url,
            }
            row = build_row(headers, payload)
            new_rows.append(row)
            rows.append(row)

    if output_path.exists():
        if new_rows:
            append_rows(output_path, new_rows)
    else:
        append_rows(output_path, rows)


if __name__ == "__main__":
    main()