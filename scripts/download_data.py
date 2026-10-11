#!/usr/bin/env python
"""Download the CIC-IDS2017 dataset from public Hugging Face mirrors.

Sources
-------
  traffic_labels  (default)  bvsam/cic-ids-2017, folder `traffic_labels`:
                 the full CICFlowMeter output incl. Protocol and endpoint IPs,
                 converted to parquet (~305 MB total). Recommended: smallest
                 download that still contains every canonical feature.
  machine_learning          bvsam/cic-ids-2017, folder `machine_learning`:
                 MachineLearningCVE parquet conversion (~261 MB), no Protocol.
  csv                       c01dsnap/CIC-IDS2017: the ORIGINAL
                 MachineLearningCVE CSV files (~884 MB).

Files are downloaded with resume support and verified against the SHA-256
hashes published in the mirror's git-LFS metadata.

Examples
--------
  python scripts/download_data.py                     # recommended parquet
  python scripts/download_data.py --source csv
  python scripts/download_data.py --only Wednesday --only Monday
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import anchor_project_root

HF_API = "https://huggingface.co/api/datasets"
HF_RESOLVE = "https://huggingface.co/datasets"

SOURCES = {
    "traffic_labels": {
        "repo": "bvsam/cic-ids-2017",
        "folder": "traffic_labels",
        "dest": "data/raw/cicids2017/traffic_labels",
    },
    "machine_learning": {
        "repo": "bvsam/cic-ids-2017",
        "folder": "machine_learning",
        "dest": "data/raw/cicids2017/machine_learning",
    },
    "csv": {
        "repo": "c01dsnap/CIC-IDS2017",
        "folder": "",
        "dest": "data/raw/cicids2017/csv",
    },
}


def list_files(repo: str, folder: str) -> list[dict]:
    url = f"{HF_API}/{repo}/tree/main" + (f"/{folder}" if folder else "")
    url += "?recursive=false"
    with urllib.request.urlopen(url, timeout=30) as resp:
        entries = json.load(resp)
    files = [e for e in entries
             if e["type"] == "file"
             and (e["path"].endswith(".parquet") or e["path"].endswith(".csv"))]
    if not files:
        raise RuntimeError(f"no dataset files listed at {url}")
    return files


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(repo: str, remote_path: str, dest: Path, expected_size: int,
             expected_sha: str | None, verify: bool) -> bool:
    """Download with resume; returns True if the file is present+valid."""
    if dest.exists():
        if dest.stat().st_size == expected_size:
            if not verify or expected_sha is None:
                print(f"  [skip] {dest.name} (complete)")
                return True
            if sha256_file(dest) == expected_sha:
                print(f"  [skip] {dest.name} (checksum ok)")
                return True
        print(f"  [resume] {dest.name} "
              f"({dest.stat().st_size:,}/{expected_size:,} bytes)")

    url = f"{HF_RESOLVE}/{repo}/resolve/main/{remote_path}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    req_headers = {"User-Agent": "unithreat-downloader/0.1"}
    start_at = tmp.stat().st_size if tmp.exists() else 0
    if start_at:
        if start_at >= expected_size:
            tmp.unlink(missing_ok=True)  # corrupt part; restart
            start_at = 0
        else:
            req_headers["Range"] = f"bytes={start_at}-"

    request = urllib.request.Request(url, headers=req_headers)
    last_report = time.time()
    with urllib.request.urlopen(request, timeout=60) as resp, \
            tmp.open("ab" if start_at else "wb") as out:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
            if time.time() - last_report > 2:
                done = tmp.stat().st_size
                pct = 100 * done / max(expected_size, 1)
                print(f"\r  {dest.name}: {pct:5.1f}% "
                      f"({done:,}/{expected_size:,})", end="", flush=True)
                last_report = time.time()
    print("\r" + " " * 8 + "\r", end="")

    if tmp.stat().st_size != expected_size:
        raise RuntimeError(f"size mismatch for {dest.name}: got "
                           f"{tmp.stat().st_size:,}, expected {expected_size:,}")
    if verify and expected_sha:
        got = sha256_file(tmp)
        if got != expected_sha:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"checksum mismatch for {dest.name}: "
                               f"expected {expected_sha}, got {got}")
    shutil.move(str(tmp), str(dest))
    print(f"  [done] {dest.name} ({expected_size:,} bytes)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=list(SOURCES), default="traffic_labels",
                        help="which mirror/variant to download (default: traffic_labels)")
    parser.add_argument("--dest", default=None,
                        help="destination directory (default: data/raw/cicids2017/<source>)")
    parser.add_argument("--only", action="append", default=[],
                        metavar="SUBSTR",
                        help="download only files whose name contains SUBSTR "
                             "(repeatable), e.g. --only Wednesday")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip sha256 verification")
    parser.add_argument("--list-only", action="store_true",
                        help="list files and exit")
    args = parser.parse_args()

    anchor_project_root()   # default dest paths -> repo root

    src = SOURCES[args.source]
    dest_dir = Path(args.dest) if args.dest else Path(src["dest"])
    print(f"Fetching file list from {src['repo']} ...")
    files = list_files(src["repo"], src["folder"])

    if args.only:
        files = [f for f in files
                 if any(s.lower() in f["path"].lower() for s in args.only)]
    if not files:
        print("no files matched the --only filter", file=sys.stderr)
        return 2

    total = sum(f["size"] for f in files)
    print(f"{len(files)} file(s), {total / 1e6:.1f} MB -> {dest_dir}\n")
    if args.list_only:
        for f in files:
            print(f"  {f['size']:>12,}  {Path(f['path']).name}")
        return 0

    dest_dir.mkdir(parents=True, exist_ok=True)
    verify = not args.no_verify
    for f in files:
        name = Path(f["path"]).name
        expected_sha = (f.get("lfs") or {}).get("oid")
        download(src["repo"], f["path"], dest_dir / name,
                 f["size"], expected_sha, verify)
    print("\nAll downloads complete. Next step:")
    print(f"  python scripts/train.py --data {dest_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
