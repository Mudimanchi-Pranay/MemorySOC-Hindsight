import os
import uuid
from pathlib import Path
from typing import Any
from database import init_database

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from hindsight_client import Hindsight
from groq import Groq
from database import get_connection
from cicids_replay import register_cicids_routes


# ============================================================
# ENVIRONMENT
# ============================================================

# Load .env from project root
load_dotenv(Path(__file__).resolve().parents[1] / ".env")


HINDSIGHT_API_URL = os.getenv(
    "HINDSIGHT_API_URL",
    "http://localhost:8888",
)

HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY")

BANK_ID = os.getenv(
    "HINDSIGHT_BANK_ID",
    "memorysoc-soc",
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise RuntimeError(
        "GROQ_API_KEY is not configured. "
        "Set it in the project .env file."
    )


GROQ_MODEL = "openai/gpt-oss-20b"

# ============================================================
# MITRE ATT&CK LOCAL MAPPING
# ============================================================

MITRE_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell to execute commands, scripts, or payloads.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use repeated authentication attempts to gain access to accounts.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform denial-of-service activity to prevent access to services.",
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan systems to identify available services and attack surfaces.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may use phishing techniques to deliver malicious content or obtain access.",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversaries may rely on users executing malicious files or content.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to obtain credentials from operating system components.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate with compromised systems using application-layer protocols.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by sending it over an existing command-and-control channel.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in applications exposed to the internet.",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to obtain higher privileges.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "description": "Adversaries may create scheduled tasks or jobs to execute malicious activity.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use legitimate account credentials to access systems.",
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": "Adversaries may use DNS for command-and-control communication.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data to disrupt availability and cause impact.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use remote services to move between systems.",
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may install web shells on servers to maintain access and execute commands.",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate accounts to identify available users and privileges.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate running processes to understand system activity.",
    },
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "Adversaries may compress collected data before moving or exfiltrating it.",
    },
}
# ============================================================
# ATTACK SCENARIOS — SYNTHETIC SOC ALERT GENERATOR
# ============================================================

ATTACK_SCENARIOS = {

    "powershell": {
        "title": "Suspicious PowerShell Execution",
        "user": "john.doe",
        "host": "FIN-PC-024",
        "severity": "HIGH",
        "event": "Encoded PowerShell command executed",
        "command": "powershell.exe -EncodedCommand SQBFAFgA",
        "destination_ip": "185.10.10.10",
        "mitre_technique": "T1059.001",
    },

    "brute_force": {
        "title": "Brute Force Authentication Attempt",
        "user": "admin",
        "host": "AUTH-SRV-01",
        "severity": "HIGH",
        "event": "Multiple failed authentication attempts detected",
        "command": None,
        "destination_ip": "185.20.20.20",
        "mitre_technique": "T1110",
    },

    "dos": {
        "title": "Denial of Service Activity",
        "user": "unknown",
        "host": "WEB-SRV-01",
        "severity": "CRITICAL",
        "event": "Abnormally high volume of network requests detected",
        "command": None,
        "destination_ip": "10.10.20.15",
        "mitre_technique": "T1498",
    },

    "port_scan": {
        "title": "Network Service Scanning",
        "user": "unknown",
        "host": "NET-SENSOR-01",
        "severity": "MEDIUM",
        "event": "Multiple destination ports scanned from a single source",
        "command": None,
        "destination_ip": "10.10.30.20",
        "mitre_technique": "T1046",
    },

    "phishing": {
        "title": "Suspicious Phishing Email",
        "user": "alice.smith",
        "host": "HR-PC-031",
        "severity": "HIGH",
        "event": "Email containing suspicious external link detected",
        "command": None,
        "destination_ip": "185.30.30.30",
        "mitre_technique": "T1566",
    },

    "malware": {
        "title": "Malicious File Execution",
        "user": "employee01",
        "host": "USER-PC-045",
        "severity": "CRITICAL",
        "event": "Suspicious executable launched from temporary directory",
        "command": "unknown.exe",
        "destination_ip": "185.40.40.40",
        "mitre_technique": "T1204",
    },

    "credential_dumping": {
        "title": "Credential Dumping Activity",
        "user": "SYSTEM",
        "host": "DC-SRV-01",
        "severity": "CRITICAL",
        "event": "Suspicious access to credential-related process memory",
        "command": "credential_access.exe",
        "destination_ip": None,
        "mitre_technique": "T1003",
    },

    "command_control": {
        "title": "Suspicious Command and Control Communication",
        "user": "SYSTEM",
        "host": "ENG-PC-017",
        "severity": "HIGH",
        "event": "Host established repeated outbound communication with unusual destination",
        "command": None,
        "destination_ip": "185.50.50.50",
        "mitre_technique": "T1071",
    },

    "data_exfiltration": {
        "title": "Potential Data Exfiltration",
        "user": "employee07",
        "host": "FIN-PC-011",
        "severity": "CRITICAL",
        "event": "Large volume of sensitive data transferred to external destination",
        "command": None,
        "destination_ip": "185.60.60.60",
        "mitre_technique": "T1041",
    },

    "sql_injection": {
        "title": "SQL Injection Attempt",
        "user": "web-user",
        "host": "WEB-SRV-02",
        "severity": "HIGH",
        "event": "Suspicious SQL syntax detected in web request parameters",
        "command": None,
        "destination_ip": "10.10.40.10",
        "mitre_technique": "T1190",
    },

    "privilege_escalation": {
        "title": "Privilege Escalation Attempt",
        "user": "employee12",
        "host": "DEV-PC-009",
        "severity": "HIGH",
        "event": "Unexpected attempt to obtain elevated privileges",
        "command": "sudo suspicious_process",
        "destination_ip": None,
        "mitre_technique": "T1068",
    },

    "scheduled_task": {
        "title": "Suspicious Scheduled Task",
        "user": "SYSTEM",
        "host": "OPS-PC-021",
        "severity": "HIGH",
        "event": "New scheduled task created with suspicious executable",
        "command": "schtasks.exe /create /tn UpdateService",
        "destination_ip": None,
        "mitre_technique": "T1053",
    },

    "valid_accounts": {
        "title": "Suspicious Valid Account Usage",
        "user": "admin",
        "host": "SERVER-07",
        "severity": "HIGH",
        "event": "Valid account used from unusual source location",
        "command": None,
        "destination_ip": "185.70.70.70",
        "mitre_technique": "T1078",
    },

    "dns_tunneling": {
        "title": "Potential DNS Tunneling",
        "user": "SYSTEM",
        "host": "ENG-PC-032",
        "severity": "HIGH",
        "event": "High-frequency DNS requests with unusually long subdomains",
        "command": None,
        "destination_ip": "8.8.8.8",
        "mitre_technique": "T1071.004",
    },

    "ransomware": {
        "title": "Ransomware-Like File Activity",
        "user": "employee22",
        "host": "FIN-PC-055",
        "severity": "CRITICAL",
        "event": "Rapid modification of large numbers of user files detected",
        "command": "file_process.exe",
        "destination_ip": None,
        "mitre_technique": "T1486",
    },

    "remote_services": {
        "title": "Suspicious Remote Service Usage",
        "user": "admin",
        "host": "SERVER-12",
        "severity": "HIGH",
        "event": "Unexpected remote service connection detected",
        "command": "remote_service.exe",
        "destination_ip": "10.10.50.25",
        "mitre_technique": "T1021",
    },

    "web_shell": {
        "title": "Potential Web Shell",
        "user": "www-data",
        "host": "WEB-SRV-03",
        "severity": "CRITICAL",
        "event": "Suspicious server-side script execution detected",
        "command": "cmd.php",
        "destination_ip": "185.80.80.80",
        "mitre_technique": "T1505.003",
    },

    "account_discovery": {
        "title": "Account Discovery Activity",
        "user": "employee14",
        "host": "DEV-PC-014",
        "severity": "MEDIUM",
        "event": "Unusual enumeration of local and domain accounts",
        "command": "net user",
        "destination_ip": None,
        "mitre_technique": "T1087",
    },

    "process_discovery": {
        "title": "Suspicious Process Discovery",
        "user": "employee18",
        "host": "DEV-PC-018",
        "severity": "MEDIUM",
        "event": "Unexpected enumeration of running processes",
        "command": "tasklist.exe",
        "destination_ip": None,
        "mitre_technique": "T1057",
    },

    "archive_data": {
        "title": "Suspicious Data Archiving",
        "user": "employee09",
        "host": "FIN-PC-019",
        "severity": "HIGH",
        "event": "Sensitive files compressed into archive before external transfer",
        "command": "archive_tool.exe sensitive_data.zip",
        "destination_ip": None,
        "mitre_technique": "T1560",
    },
}
# ============================================================
# CLIENTS
# ============================================================

hindsight_client = Hindsight(
    base_url=HINDSIGHT_API_URL,
    api_key=HINDSIGHT_API_KEY
)

groq_client = Groq(
    api_key=GROQ_API_KEY
)


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="MemorySOC Hindsight POC",
    version="0.3.0",
    description="Persistent-memory SOC investigation proof of concept.",
)

init_database()

# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://memorysoc-i5h6jvj9q-pranay-3df5.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_cicids_routes(app)

# ============================================================
# DATA MODELS
# ============================================================

class Alert(BaseModel):
    alert_id: str
    title: str
    user: str
    host: str
    severity: str
    event: str
    command: str | None = None
    destination_ip: str | None = None
    mitre_technique: str | None = None


class Feedback(BaseModel):
    alert_id: str

    decision: str = Field(
        description="true_positive, false_positive, or needs_review"
    )

    action: str
    outcome: str
    notes: str | None = None


# ============================================================
# MEMORY SERIALIZATION
# ============================================================

def serialize_recall(result: Any) -> list[dict[str, Any]]:
    """
    Convert Hindsight recall results into JSON-safe dictionaries.
    """

    output = []

    for item in getattr(result, "results", []) or []:
        output.append(
            {
                "text": getattr(item, "text", None),
                "score": getattr(item, "score", None),
                "memory_id": getattr(item, "id", None),
            }
        )

    return output


# ============================================================
# INVESTIGATION AGENT
# ============================================================

class InvestigationAgent:
    """
    MemorySOC LLM investigation orchestrator.

    Pipeline:

    1. Understand alert
    2. Build investigation plan
    3. Recall historical memory
    4. Build reasoning context
    5. Generate SOC assessment
    6. Return complete investigation trace
    """

    def __init__(
        self,
        hindsight,
        groq,
    ):
        self.hindsight = hindsight
        self.groq = groq

    # --------------------------------------------------------
    # IOC / MITRE ENRICHMENT
    # --------------------------------------------------------

    def enrich_alert(
        self,
        alert: Alert,
    ) -> dict[str, Any]:

        iocs = []

        # ----------------------------------------------------
        # Destination IP
        # ----------------------------------------------------

        if alert.destination_ip:
            iocs.append(
                {
                    "type": "ip",
                    "value": alert.destination_ip,
                    "source": "alert",
                }
            )

        # ----------------------------------------------------
        # Command indicator
        # ----------------------------------------------------

        if alert.command:
            command_lower = alert.command.lower()

            if "powershell" in command_lower:
                iocs.append(
                    {
                        "type": "command",
                        "value": "PowerShell",
                        "source": "alert.command",
                    }
                )

            if "-encodedcommand" in command_lower:
                iocs.append(
                    {
                        "type": "command_indicator",
                        "value": "-EncodedCommand",
                        "source": "alert.command",
                    }
                )

        # ----------------------------------------------------
        # MITRE ATT&CK mapping
        # ----------------------------------------------------

        mitre = None

        if alert.mitre_technique:
            technique_id = alert.mitre_technique.upper()

            technique = MITRE_TECHNIQUES.get(
                technique_id
            )

            if technique:
                mitre = {
                    "technique_id": technique_id,
                    "name": technique["name"],
                    "tactic": technique["tactic"],
                    "description": technique["description"],
                    "source": "local_mitre_mapping",
                }
            else:
                mitre = {
                    "technique_id": technique_id,
                    "name": "Unknown technique",
                    "tactic": "Unknown",
                    "description": None,
                    "source": "alert",
                }

        return {
            "iocs": iocs,
            "mitre": mitre,
        }

    # --------------------------------------------------------
    # STAGE 1 — BUILD RECALL QUERY
    # --------------------------------------------------------

    def build_recall_query(self, alert: Alert) -> str:

        query_parts = [
            alert.title,
            alert.event,
            f"severity {alert.severity}",
            f"user {alert.user}",
            f"host {alert.host}",
        ]

        if alert.command:
            query_parts.append(alert.command)

        if alert.destination_ip:
            query_parts.append(
                f"destination {alert.destination_ip}"
            )

        if alert.mitre_technique:
            query_parts.append(
                alert.mitre_technique
            )

        return (
            "Find previous SOC incidents relevant to: "
            + " | ".join(query_parts)
        )

    # --------------------------------------------------------
    # STAGE 2 — INVESTIGATION PLAN
    # --------------------------------------------------------

    def build_investigation_plan(
        self,
        alert: Alert,
    ) -> list[str]:

        return [
            "Analyze the alert and identify suspicious indicators.",
            "Compare the alert with historical organizational incidents.",
            "Review previous analyst decisions and response actions.",
            "Identify evidence required to confirm or dismiss the alert.",
            "Generate practical SOC investigation and response guidance.",
        ]

    # --------------------------------------------------------
    # STAGE 3 — HINDSIGHT RECALL
    # --------------------------------------------------------

    async def recall_memory(
        self,
        query: str,
    ) -> list[dict[str, Any]]:

        recalled = await self.hindsight.arecall(
            bank_id=BANK_ID,
            query=query,
        )

        return serialize_recall(recalled)

    # --------------------------------------------------------
    # STAGE 4 — BUILD LLM PROMPT
    # --------------------------------------------------------

    def build_prompt(
        self,
        alert: Alert,
        memories: list[dict[str, Any]],
        investigation_plan: list[str],
        enrichment: dict[str, Any],
    ) -> str:

        # Limit context sent to the LLM
        useful_memories = memories[:8]

        if useful_memories:

            memory_text = "\n\n".join(
                [
                    (
                        f"Historical Memory {index + 1}:\n"
                        f"{memory.get('text', '')}"
                    )
                    for index, memory in enumerate(
                        useful_memories
                    )
                ]
            )

        else:
            memory_text = "No historical memories were retrieved."

        alert_json = alert.model_dump_json(
            indent=2
        )

        enrichment_text = str(
            enrichment
        )
        

        plan_text = "\n".join(
            [
                f"{index + 1}. {step}"
                for index, step in enumerate(
                    investigation_plan
                )
            ]
        )

        return f"""
You are MemorySOC, an experienced SOC investigation agent.

Your job is to investigate the CURRENT ALERT using
organizational historical memory.

============================================================
CURRENT ALERT
============================================================

{alert_json}


============================================================
HISTORICAL ORGANIZATIONAL MEMORY
============================================================

{memory_text}


============================================================
INVESTIGATION PLAN
============================================================

{plan_text}


============================================================
IMPORTANT RULES
============================================================

- Historical similarity is evidence for comparison, NOT proof.
- Do not automatically classify the current alert as malicious.
- Do not invent evidence.
- Clearly separate historical facts from current-alert evidence.
- Be conservative and evidence-based.
- Provide practical SOC investigation guidance.


============================================================
RETURN EXACTLY THESE SECTIONS
============================================================

1. CURRENT ALERT VERDICT

State one of:

SUSPICIOUS — REQUIRES INVESTIGATION
LIKELY BENIGN
INSUFFICIENT EVIDENCE

Explain why.


2. HISTORICAL SIMILARITY

Explain which historical incidents are relevant and why.


3. HISTORICAL ANALYST DECISIONS

Summarize previous analyst decisions,
containment actions, and outcomes.


4. KEY INVESTIGATION STEPS

Give exactly 5 concrete SOC investigation steps.


5. RECOMMENDED RESPONSE

Explain appropriate actions depending on
the investigation result.


6. MEMORY-BASED LESSON

Explain what the organization learned
from previous incidents.


7. AGENT SUMMARY

Give a concise SOC analyst summary
in 2-3 sentences.
"""

    # --------------------------------------------------------
    # STAGE 5 — GROQ ANALYSIS
    # --------------------------------------------------------

    def generate_assessment(
        self,
        prompt: str,
    ) -> str:

        completion = self.groq.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity SOC investigation "
                        "agent. Be precise, evidence-based, "
                        "conservative, and never treat historical "
                        "similarity as proof."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.2,
            max_tokens=2500,
        )

        return completion.choices[0].message.content

    # --------------------------------------------------------
    # STAGE 6 — COMPLETE INVESTIGATION
    # --------------------------------------------------------

    async def investigate(
        self,
        alert: Alert,
    ) -> dict[str, Any]:

        # IOC / MITRE ENRICHMENT
        enrichment = self.enrich_alert(
            alert
        )

        # Stage 1
        query = self.build_recall_query(
            alert
        )

        # Stage 2
        investigation_plan = (
            self.build_investigation_plan(
                alert
            )
        )

        # Stage 3
        historical_memories = (
            await self.recall_memory(
                query
            )
        )

        # Stage 4
        prompt = self.build_prompt(
            alert=alert,
            memories=historical_memories,
            investigation_plan=investigation_plan,
            enrichment=enrichment,
        )

        # Stage 5
        assessment = self.generate_assessment(
            prompt
        )

        # Stage 6
        return {
            "status": "success",

            "enrichment": enrichment,

            "agent": {
                "name": "MemorySOC Investigation Agent",
                "version": "1.0",
                "stages_completed": 6,
            },

            "alert": alert.model_dump(),

            "investigation_plan": investigation_plan,

            "recall_query": query,

            "historical_memories": historical_memories,

            "memory_count": len(
                historical_memories
            ),

            "memory_grounded_assessment": assessment,
        }


# ============================================================
# CREATE AGENT
# ============================================================

investigation_agent = InvestigationAgent(
    hindsight=hindsight_client,
    groq=groq_client,
)


# ============================================================
# SYNTHETIC SOC INCIDENTS
# ============================================================

SEED_INCIDENTS = [

    """
Incident INC-1001 — Confirmed malicious.

Alert: Encoded PowerShell execution on FIN-PC-024.
User: john.doe.
Technique: T1059.001 PowerShell.

Observed behavior:
powershell.exe used an encoded command and contacted external IP
185.10.10.10.

Analyst decision: True positive.
Response: Endpoint isolated.
Outcome: Malicious payload contained.

Lesson:
Encoded PowerShell combined with unexpected external communication
was confirmed malicious.
""",

    """
Incident INC-1002 — False positive.

Alert: PowerShell execution on IT-ADMIN-02.
User: svc-admin.
Technique: T1059.001 PowerShell.

Observed behavior:
An approved internal administration script used PowerShell.

Analyst decision: False positive.
Response: No containment.
Outcome: Approved administrative activity.

Lesson:
Internal administration context and approved script origin can explain
PowerShell activity.
""",

    """
Incident INC-1003 — Confirmed malicious.

Alert: PowerShell downloaded a payload from an external destination.
User: alice.smith.
Host: HR-PC-031.
Technique: T1059.001 PowerShell.

Observed behavior:
PowerShell contacted an external IP and downloaded an executable.

Analyst decision: True positive.
Response: Endpoint isolated and credentials reset.
Outcome: Malware contained.

Lesson:
PowerShell plus unexpected external communication was associated with
a confirmed compromise.
"""
]


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "hindsight_api_url": HINDSIGHT_API_URL,
        "bank_id": BANK_ID,
        "groq_model": GROQ_MODEL,
        "agent": "MemorySOC Investigation Agent",
    }


# ============================================================
# SEED MEMORY
# ============================================================

@app.post("/seed")
async def seed():

    try:

        for incident in SEED_INCIDENTS:

            await hindsight_client.aretain(
                bank_id=BANK_ID,
                content=incident,
                context="MemorySOC synthetic SOC incident",
            )

        return {
            "status": "seeded",
            "bank_id": BANK_ID,
            "incidents_added": len(
                SEED_INCIDENTS
            ),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Hindsight seed failed: {exc}",
        ) from exc

# ============================================================
# ATTACK SIMULATOR
# ============================================================

@app.get("/attack-scenarios")
def get_attack_scenarios():
    """Return available synthetic SOC attack scenarios."""
    return {
        "count": len(ATTACK_SCENARIOS),
        "scenarios": [
            {
                "id": scenario_id,
                "title": scenario["title"],
                "severity": scenario["severity"],
                "mitre_technique": scenario["mitre_technique"],
            }
            for scenario_id, scenario in ATTACK_SCENARIOS.items()
        ],
    }


@app.post("/simulate")
async def simulate_attack(payload: dict):
    """Generate a synthetic SOC alert for the selected attack scenario."""

    scenario_id = payload.get("scenario")

    if not scenario_id:
        raise HTTPException(
            status_code=400,
            detail="scenario is required",
        )

    if scenario_id not in ATTACK_SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown attack scenario: {scenario_id}",
        )

    scenario = ATTACK_SCENARIOS[scenario_id]

    alert_id = f"SIM-{scenario_id.upper()}-{uuid.uuid4().hex[:8].upper()}"

    alert = Alert(
        alert_id=alert_id,
        title=scenario["title"],
        severity=scenario["severity"],
        user=scenario["user"],
        host=scenario["host"],
        event=scenario["event"],
        command=scenario.get("command"),
        source_ip=None,
        destination_ip=scenario.get("destination_ip"),
        mitre_technique=scenario.get("mitre_technique"),
    )

    # Send the generated alert through the existing
    # MemorySOC investigation pipeline.

    result = await investigate(alert)

    result["simulation"] = {
        "scenario": scenario_id,
        "generated": True,
    }

    return result

# ============================================================
# MAIN INVESTIGATION ENDPOINT
# ============================================================

@app.post("/investigate")
async def investigate(
    alert: Alert,
):
    """
    Main MemorySOC investigation endpoint.

    Flow:

    Alert
      ↓
    PostgreSQL
      ↓
    Hindsight memory recall
      ↓
    Groq GPT-OSS reasoning
      ↓
    PostgreSQL investigation record
      ↓
    Return complete result
    """

    try:
        # --------------------------------------------------------
        # 1. Save current alert to PostgreSQL
        # --------------------------------------------------------

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alerts (
                        alert_id,
                        title,
                        username,
                        host,
                        severity,
                        event,
                        command,
                        destination_ip,
                        mitre_technique
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (alert_id)
                    DO UPDATE SET
                        title = EXCLUDED.title,
                        username = EXCLUDED.username,
                        host = EXCLUDED.host,
                        severity = EXCLUDED.severity,
                        event = EXCLUDED.event,
                        command = EXCLUDED.command,
                        destination_ip = EXCLUDED.destination_ip,
                        mitre_technique = EXCLUDED.mitre_technique
                    """,
                    (
                        alert.alert_id,
                        alert.title,
                        alert.user,
                        alert.host,
                        alert.severity,
                        alert.event,
                        alert.command,
                        alert.destination_ip,
                        alert.mitre_technique,
                    ),
                )

            conn.commit()

        # --------------------------------------------------------
        # 2. Run the existing MemorySOC investigation agent
        # --------------------------------------------------------

        result = await investigation_agent.investigate(alert)

        # --------------------------------------------------------
        # 3. Save investigation to PostgreSQL
        # --------------------------------------------------------

        with get_connection() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO investigations (
                        alert_id,
                        recall_query,
                        memory_count,
                        assessment,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        alert.alert_id,
                        result.get("recall_query"),
                        result.get("memory_count", 0),
                        result.get("memory_grounded_assessment"),
                        result.get("status", "success"),
                    ),
                )

                investigation_id = cur.fetchone()[0]

                # ------------------------------------------------
                # 4. Save recalled Hindsight memories
                # ------------------------------------------------

                for memory in result.get(
                    "historical_memories", []
                ):
                    cur.execute(
                        """
                        INSERT INTO investigation_memories (
                            investigation_id,
                            memory_id,
                            memory_text,
                            score
                        )
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            investigation_id,
                            memory.get("memory_id"),
                            memory.get("text"),
                            memory.get("score"),
                        ),
                    )

            conn.commit()

        # Add database ID to API response
        result["database"] = {
            "investigation_id": investigation_id,
            "saved": True,
        }

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"MemorySOC investigation failed: {exc}",
        ) from exc

# ============================================================
# AGENT ENDPOINT
# ============================================================

@app.post("/agent/investigate")
async def agent_investigate(
    alert: Alert,
):
    """
    Explicit agent endpoint.

    Kept separately so the project can later evolve
    into a more advanced LLM agent architecture.
    """

    try:

        result = await investigation_agent.investigate(
            alert
        )

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"MemorySOC agent failed: {exc}",
        ) from exc


# ============================================================
# ANALYST FEEDBACK
# ============================================================

@app.post("/feedback")
async def feedback(
    feedback: Feedback,
):
    content = f"""
MemorySOC investigation outcome for alert
{feedback.alert_id}.

Analyst decision: {feedback.decision}.
Action taken: {feedback.action}.
Outcome: {feedback.outcome}.
Additional notes: {feedback.notes or "None"}.

This is analyst feedback from a SOC investigation and may be relevant
to future investigations involving similar behavior.
"""

    try:

        # --------------------------------------------------------
        # 1. Save analyst feedback to PostgreSQL
        # --------------------------------------------------------

        with get_connection() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO analyst_feedback (
                        alert_id,
                        decision,
                        action,
                        outcome,
                        notes
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        feedback.alert_id,
                        feedback.decision,
                        feedback.action,
                        feedback.outcome,
                        feedback.notes,
                    ),
                )

            conn.commit()

        # --------------------------------------------------------
        # 2. Retain analyst feedback in Hindsight
        # --------------------------------------------------------

        await hindsight_client.aretain(
            bank_id=BANK_ID,
            content=content,
            context=(
                "MemorySOC analyst feedback "
                "and incident outcome"
            ),
        )

        # --------------------------------------------------------
        # 3. Return success
        # --------------------------------------------------------

        return {
            "status": "retained",
            "alert_id": feedback.alert_id,
            "bank_id": BANK_ID,
            "database_saved": True,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Feedback processing failed: {exc}",
        ) from exc