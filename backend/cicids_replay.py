"""CIC-IDS2017 live replay routes for MemorySOC.

Register once from the existing FastAPI main.py:
    from cicids_replay import register_cicids_routes
    register_cicids_routes(app)

The replay converts real CIC-IDS2017 network-flow rows into the same Alert
shape already accepted by /investigate. The frontend can therefore demonstrate
real-data ingestion without changing the Hindsight/Groq investigation agent.
"""
from pathlib import Path
from typing import Any
import os
import threading

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

try:
    import pandas as pd
except Exception as exc:  # pragma: no cover
    pd = None
    _PANDAS_ERROR = exc

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = Path(os.getenv("CICIDS_DATASET_DIR", ROOT / "frontend" / "public" / "dataset"))
DATASET_DIR.mkdir(parents=True, exist_ok=True)

FILES = {
    "bruteforce": "Bruteforce-Tuesday-no-metadata.parquet",
    "dos": "DoS-Wednesday-no-metadata.parquet",
    "ddos": "DDoS-Friday-no-metadata.parquet",
    "portscan": "Portscan-Friday-no-metadata.parquet",
    "webattacks": "WebAttacks-Thursday-no-metadata.parquet",
    "botnet": "Botnet-Friday-no-metadata.parquet",
    "infiltration": "Infiltration-Thursday-no-metadata.parquet",
    "benign": "Benign-Monday-no-metadata.parquet",
}

FAMILY_LABELS = {
    "bruteforce": "FTP/SSH-Patator",
    "dos": "DoS",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "webattacks": "Web Attack",
    "botnet": "Botnet",
    "infiltration": "Infiltration",
    "benign": "BENIGN",
}

MITRE = {
    "bruteforce": "T1110",
    "dos": "T1498",
    "ddos": "T1498",
    "portscan": "T1046",
    "webattacks": "T1190",
    "botnet": "T1071",
    "infiltration": "T1190",
    "benign": None,
}

SEVERITY = {
    "bruteforce": "HIGH",
    "dos": "CRITICAL",
    "ddos": "CRITICAL",
    "portscan": "MEDIUM",
    "webattacks": "HIGH",
    "botnet": "CRITICAL",
    "infiltration": "CRITICAL",
    "benign": "LOW",
}

class NextRequest(BaseModel):
    source: str = "cicids2017"
    attack_family: str = "bruteforce"

_state = {
    "family": None,
    "file": None,
    "frame": None,
    "index": 0,
    "total": 0,
}
_lock = threading.Lock()


def _norm(value: Any) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def _pick(columns, *names):
    normalized = {_norm(c): c for c in columns}
    for name in names:
        if _norm(name) in normalized:
            return normalized[_norm(name)]
    for c in columns:
        nc = _norm(c)
        for name in names:
            if _norm(name) in nc:
                return c
    return None


def _safe(value):
    if value is None:
        return None
    try:
        value = value.item()
    except Exception:
        pass
    if isinstance(value, float) and pd is not None and pd.isna(value):
        return None
    return value


def _choose_file(family: str):
    family = (family or "bruteforce").lower()
    if family == "all":
        # Default to an attack family for the hackathon live demo; the analyst
        # can explicitly select benign traffic when desired.
        family = "bruteforce"
    if family not in FILES:
        raise HTTPException(400, f"Unknown CIC-IDS2017 family: {family}")
    path = DATASET_DIR / FILES[family]
    if not path.exists():
        raise HTTPException(404, f"Dataset file not found: {path.name}")
    return family, path


def _read_dataset(path: Path):
    if pd is None:
        raise HTTPException(500, f"pandas is required: {_PANDAS_ERROR}")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix == ".parquet":
        try:
            return pd.read_parquet(path, engine="fastparquet")
        except Exception as exc:
            raise HTTPException(
                500,
                "Unable to read parquet. Install fastparquet in the backend environment. "
                f"Details: {exc}",
            ) from exc
    raise HTTPException(400, "Only .parquet and .csv dataset files are supported")


def _load_frame(family: str):
    selected_family, path = _choose_file(family)
    with _lock:
        if _state["frame"] is None or _state["file"] != str(path):
            frame = _read_dataset(path)
            if frame.empty:
                raise HTTPException(422, f"Dataset file is empty: {path.name}")
            _state.update({"family": selected_family, "file": str(path), "frame": frame, "index": 0, "total": len(frame)})
        return _state["family"], Path(_state["file"]).name, _state["frame"], _state["index"], _state["total"]


def _to_alert(family: str, filename: str, index: int, row: dict[str, Any]):
    cols = list(row.keys())
    src_ip = _safe(row.get(_pick(cols, "Source IP", "Src IP", "SourceIP")))
    dst_ip = _safe(row.get(_pick(cols, "Destination IP", "Dst IP", "DestinationIP")))
    src_port = _safe(row.get(_pick(cols, "Source Port", "Src Port", "SourcePort")))
    dst_port = _safe(row.get(_pick(cols, "Destination Port", "Dst Port", "DestinationPort")))
    protocol = _safe(row.get(_pick(cols, "Protocol", "Protocol Type")))
    duration = _safe(row.get(_pick(cols, "Flow Duration", "Duration")))
    label_col = _pick(cols, "Label", "Attack", "Class")
    label = str(_safe(row.get(label_col))) if label_col else FAMILY_LABELS[family]
    if not label or label.lower() in {"nan", "none"}:
        label = FAMILY_LABELS[family]

    title = f"{label} Network Activity"
    event = (
        f"Real CIC-IDS2017 network flow classified as {label}. "
        f"Source {src_ip or 'unknown'} → destination {dst_ip or 'unknown'}."
    )
    if src_port is not None or dst_port is not None or protocol is not None:
        event += f" Ports {src_port or '—'} → {dst_port or '—'}, protocol {protocol or '—'}."

    alert = {
        "alert_id": f"CIC-IDS2017-{family.upper()}-{index:07d}",
        "title": title,
        "user": "unknown",
        "host": "CICIDS-NETFLOW",
        "severity": SEVERITY[family],
        "event": event,
        "command": None,
        "destination_ip": str(dst_ip) if dst_ip is not None else None,
        "mitre_technique": MITRE[family],
    }
    flow = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "duration": duration,
        "label": label,
        "dataset_file": filename,
    }
    return alert, flow


def register_cicids_routes(app):
    router = APIRouter(prefix="/dataset", tags=["CIC-IDS2017 Live Replay"])

    @router.get("/status")
    async def dataset_status():
        files = []
        for family, filename in FILES.items():
            path = DATASET_DIR / filename
            files.append({
                "family": family,
                "file": filename,
                "exists": path.exists(),
                "bytes": path.stat().st_size if path.exists() else 0,
            })
        return {
            "status": "ready" if any(item["exists"] for item in files) else "missing",
            "source": "CIC-IDS2017",
            "dataset_dir": str(DATASET_DIR),
            "files": files,
            "rows": _state["total"],
            "processed": _state["index"],
            "current_family": _state["family"],
        }

    @router.post("/upload")
    async def dataset_upload(file: UploadFile = File(...)):
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in {".parquet", ".csv"}:
            raise HTTPException(400, "Upload a .parquet or .csv CIC-IDS2017 file")
        filename = Path(file.filename).name
        destination = DATASET_DIR / filename
        with destination.open("wb") as target:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
        # Reset cached reader so the next replay sees the new file.
        with _lock:
            _state.update({"frame": None, "file": None, "index": 0, "total": 0})
        return {"status": "uploaded", "dataset_file": filename, "bytes": destination.stat().st_size}

    @router.post("/next")
    async def dataset_next(req: NextRequest):
        if req.source.lower() != "cicids2017":
            raise HTTPException(400, "Only CIC-IDS2017 is supported by this replay endpoint")
        family, filename, frame, current_index, total = _load_frame(req.attack_family)
        with _lock:
            index = _state["index"] % total
            row = frame.iloc[index].to_dict()
            _state["index"] = index + 1
        alert, flow = _to_alert(family, filename, index + 1, row)
        return {
            "status": "ok",
            "source": "CIC-IDS2017",
            "dataset_file": filename,
            "row_number": index + 1,
            "total_rows": total,
            "family": family,
            "label": flow["label"],
            "alert": alert,
            "flow": flow,
        }

    app.include_router(router)
