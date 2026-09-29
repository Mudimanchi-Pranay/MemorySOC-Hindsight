import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not configured in the project .env file."
    )


def get_connection():
    return psycopg.connect(DATABASE_URL)


def test_connection():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database();")
            database_name = cur.fetchone()[0]

    return database_name


def init_database():
    with get_connection() as conn:
        with conn.cursor() as cur:

            # 1. SOC alerts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    host TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    event TEXT NOT NULL,
                    command TEXT,
                    destination_ip TEXT,
                    mitre_technique TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 2. Investigation records
            cur.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    recall_query TEXT,
                    memory_count INTEGER DEFAULT 0,
                    assessment TEXT,
                    status TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_investigation_alert
                        FOREIGN KEY (alert_id)
                        REFERENCES alerts(alert_id)
                        ON DELETE CASCADE
                );
            """)

            # 3. Historical memories used during investigations
            cur.execute("""
                CREATE TABLE IF NOT EXISTS investigation_memories (
                    id BIGSERIAL PRIMARY KEY,
                    investigation_id BIGINT NOT NULL,
                    memory_id TEXT,
                    memory_text TEXT,
                    score DOUBLE PRECISION,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_memory_investigation
                        FOREIGN KEY (investigation_id)
                        REFERENCES investigations(id)
                        ON DELETE CASCADE
                );
            """)

            # 4. Analyst feedback
            cur.execute("""
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT fk_feedback_alert
                        FOREIGN KEY (alert_id)
                        REFERENCES alerts(alert_id)
                        ON DELETE CASCADE
                );
            """)

        conn.commit()


if __name__ == "__main__":
    print("DATABASE:", test_connection())
    init_database()
    print("DATABASE TABLES: initialized successfully")