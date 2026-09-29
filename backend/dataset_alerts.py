from pathlib import Path
from datetime import datetime
import uuid

import pandas as pd


# ============================================================
# CIC-IDS2017 CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = PROJECT_ROOT / "dataset" / "CIC-IDS2017"


DATASET_FILES = {
    "bruteforce": "Bruteforce-Tuesday-no-metadata.parquet",
    "ddos": "DDoS-Friday-no-metadata.parquet",
    "dos": "DoS-Wednesday-no-metadata.parquet",
    "infiltration": "Infiltration-Thursday-no-metadata.parquet",
    "portscan": "Portscan-Friday-no-metadata.parquet",
    "webattacks": "WebAttacks-Thursday-no-metadata.parquet",
    "botnet": "Botnet-Friday-no-metadata.parquet",
}


# ============================================================
# REAL DATASET LABEL → MEMORYSOC ATTACK
# ============================================================

ATTACK_MAPPING = {

    # Brute Force
    "FTP-Patator": {
        "scenario": "brute_force",
        "title": "FTP Brute Force Authentication Attempt",
        "severity": "HIGH",
        "mitre_technique": "T1110",
    },

    "SSH-Patator": {
        "scenario": "brute_force",
        "title": "SSH Brute Force Authentication Attempt",
        "severity": "HIGH",
        "mitre_technique": "T1110",
    },

    # DDoS
    "DDoS": {
        "scenario": "dos",
        "title": "Distributed Denial of Service Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1498",
    },

    # DoS
    "DoS Hulk": {
        "scenario": "dos",
        "title": "HTTP DoS Hulk Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1498",
    },

    "DoS GoldenEye": {
        "scenario": "dos",
        "title": "GoldenEye Denial of Service Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1498",
    },

    "DoS slowloris": {
        "scenario": "dos",
        "title": "Slowloris Denial of Service Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1498",
    },

    "DoS Slowhttptest": {
        "scenario": "dos",
        "title": "Slow HTTP Denial of Service Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1498",
    },

    # Heartbleed
    "Heartbleed": {
        "scenario": "web_shell",
        "title": "Heartbleed Exploitation Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1190",
    },

    # Infiltration
    "Infiltration": {
        "scenario": "malware",
        "title": "Network Infiltration Activity",
        "severity": "CRITICAL",
        "mitre_technique": "T1190",
    },

    # Port Scan
    "PortScan": {
        "scenario": "port_scan",
        "title": "Network Port Scanning Activity",
        "severity": "MEDIUM",
        "mitre_technique": "T1046",
    },

    # Web attacks
    "Web Attack   Brute Force": {
        "scenario": "brute_force",
        "title": "Web Application Brute Force Attack",
        "severity": "HIGH",
        "mitre_technique": "T1110",
    },

    "Web Attack   XSS": {
        "scenario": "web_shell",
        "title": "Cross-Site Scripting Attack",
        "severity": "HIGH",
        "mitre_technique": "T1189",
    },

    "Web Attack   Sql Injection": {
        "scenario": "sql_injection",
        "title": "SQL Injection Attack",
        "severity": "HIGH",
        "mitre_technique": "T1190",
    },

    # Botnet
    "Bot": {
        "scenario": "command_control",
        "title": "Potential Botnet Activity",
        "severity": "HIGH",
        "mitre_technique": "T1071",
    },
}


# ============================================================
# NORMALIZE LABEL
# ============================================================

def normalize_label(label):
    """
    Normalize dataset labels without changing their meaning.
    """

    if label is None:
        return ""

    return str(label).strip()


# ============================================================
# MAP DATASET LABEL
# ============================================================

def map_attack(label):
    """
    Convert a CIC-IDS2017 label into a MemorySOC attack definition.
    """

    label = normalize_label(label)

    if label.lower() == "benign":
        return {
            "scenario": "benign",
            "title": "Benign Network Traffic",
            "severity": "INFO",
            "mitre_technique": None,
        }

    return ATTACK_MAPPING.get(label)


# ============================================================
# CONVERT DATASET ROW → SOC ALERT
# ============================================================

def row_to_alert(row):
    """
    Convert one CIC-IDS2017 dataframe row into
    a MemorySOC-compatible alert.
    """

    label = normalize_label(row.get("Label"))

    attack = map_attack(label)

    if attack is None:
        return None

    # --------------------------------------------------------
    # Basic network information
    # --------------------------------------------------------

    protocol = row.get("Protocol")

    flow_duration = row.get("Flow Duration")

    packet_count = (
        row.get("Total Fwd Packets", 0)
        + row.get("Total Backward Packets", 0)
    )

    # --------------------------------------------------------
    # Generate alert
    # --------------------------------------------------------

    alert = {
        "alert_id": f"DATA-{uuid.uuid4().hex[:10].upper()}",

        "timestamp": datetime.utcnow().isoformat(),

        "source": "CIC-IDS2017",

        "dataset_label": label,

        "scenario": attack["scenario"],

        "title": attack["title"],

        "severity": attack["severity"],

        "mitre_technique": attack["mitre_technique"],

        "protocol": protocol,

        "flow_duration": flow_duration,

        "packet_count": packet_count,

        "event": (
            f"CIC-IDS2017 network traffic classified as "
            f"{label}"
        ),

        "raw_label": label,
    }

    return alert


# ============================================================
# LOAD DATASET
# ============================================================

def load_attack_dataset(dataset_name):

    if dataset_name not in DATASET_FILES:
        raise ValueError(
            f"Unknown dataset: {dataset_name}"
        )

    file_path = DATASET_DIR / DATASET_FILES[dataset_name]

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    print(f"Loading: {file_path}")

    return pd.read_parquet(
        file_path,
        engine="fastparquet"
    )


# ============================================================
# GET SAMPLE ATTACK
# ============================================================

def get_sample_attack(dataset_name):

    df = load_attack_dataset(dataset_name)

    for row in df.to_dict(orient="records"):

        label = normalize_label(row.get("Label"))

        if label.lower() != "benign":

            alert = row_to_alert(row)

            if alert:
                return alert

    return None


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n======================================")
    print(" MemorySOC Dataset Alert Generator")
    print("======================================")

    alert = get_sample_attack("bruteforce")

    if alert:

        print("\nREAL DATASET ATTACK DETECTED\n")

        for key, value in alert.items():

            print(
                f"{key:<20}: {value}"
            )

    else:

        print(
            "\nNo attack record found."
        )