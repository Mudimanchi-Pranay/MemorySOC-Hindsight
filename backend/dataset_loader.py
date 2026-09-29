from pathlib import Path
import pandas as pd


# ============================================================
# CIC-IDS2017 DATASET CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = PROJECT_ROOT / "dataset" / "CIC-IDS2017"


DATASET_FILES = {
    "benign": "Benign-Monday-no-metadata.parquet",
    "botnet": "Botnet-Friday-no-metadata.parquet",
    "bruteforce": "Bruteforce-Tuesday-no-metadata.parquet",
    "ddos": "DDoS-Friday-no-metadata.parquet",
    "dos": "DoS-Wednesday-no-metadata.parquet",
    "infiltration": "Infiltration-Thursday-no-metadata.parquet",
    "portscan": "Portscan-Friday-no-metadata.parquet",
    "webattacks": "WebAttacks-Thursday-no-metadata.parquet",
}


# ============================================================
# CHECK DATASET
# ============================================================

def check_dataset():
    """
    Verify that all CIC-IDS2017 files exist.
    """

    print("\n========================================")
    print(" CIC-IDS2017 DATASET CHECK")
    print("========================================")

    print(f"Dataset directory:")
    print(DATASET_DIR)

    if not DATASET_DIR.exists():
        print("\nERROR: Dataset directory does not exist.")
        return False

    missing_files = []

    for attack_type, filename in DATASET_FILES.items():

        file_path = DATASET_DIR / filename

        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)

            print(
                f"[OK] {attack_type:<12} "
                f"{filename} "
                f"({size_mb:.2f} MB)"
            )

        else:
            print(f"[MISSING] {filename}")
            missing_files.append(filename)

    print("----------------------------------------")

    if missing_files:
        print(f"Missing files: {len(missing_files)}")
        return False

    print("All CIC-IDS2017 files found.")
    return True


# ============================================================
# LOAD SINGLE DATASET
# ============================================================

def load_dataset(dataset_name: str):
    """
    Load one CIC-IDS2017 parquet dataset.
    """

    if dataset_name not in DATASET_FILES:
        raise ValueError(
            f"Unknown dataset: {dataset_name}. "
            f"Available: {list(DATASET_FILES.keys())}"
        )

    file_path = DATASET_DIR / DATASET_FILES[dataset_name]

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {file_path}"
        )

    print(f"\nLoading dataset: {dataset_name}")
    print(f"File: {file_path}")

    df = pd.read_parquet(file_path)

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    return df


# ============================================================
# DATASET SUMMARY
# ============================================================

def dataset_summary(dataset_name: str):
    """
    Return basic information about a dataset.
    """

    df = load_dataset(dataset_name)

    return {
        "dataset": dataset_name,
        "rows": len(df),
        "columns": len(df.columns),
        "column_names": list(df.columns),
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    success = check_dataset()

    if not success:
        raise SystemExit(1)

    print("\nTesting one dataset...")

    df = load_dataset("bruteforce")

    print("\nFirst 5 rows:")
    print(df.head())

    print("\nColumn names:")
    print(list(df.columns))

    print("\nDataset loader working successfully.")