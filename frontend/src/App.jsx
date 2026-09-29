import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

/* ============================================================
   20 ORIGINAL HACKATHON SCENARIOS
   These remain available below the live-dataset area.
============================================================ */
const SCENARIOS = [
  ["Suspicious PowerShell Execution", "T1059.001", "HIGH"],
  ["Brute Force Authentication Attempt", "T1110", "HIGH"],
  ["Denial of Service Activity", "T1498", "CRITICAL"],
  ["Network Service Scanning", "T1046", "MEDIUM"],
  ["Suspicious Phishing Email", "T1566", "HIGH"],
  ["Malicious File Execution", "T1204", "CRITICAL"],
  ["Credential Dumping Activity", "T1003", "CRITICAL"],
  ["Suspicious Command and Control Communication", "T1071", "HIGH"],
  ["Potential Data Exfiltration", "T1041", "CRITICAL"],
  ["SQL Injection Attempt", "T1190", "HIGH"],
  ["Privilege Escalation Attempt", "T1068", "HIGH"],
  ["Suspicious Scheduled Task", "T1053", "HIGH"],
  ["Suspicious Valid Account Usage", "T1078", "HIGH"],
  ["Potential DNS Tunneling", "T1071.004", "HIGH"],
  ["Ransomware-Like File Activity", "T1486", "CRITICAL"],
  ["Suspicious Remote Service Usage", "T1021", "HIGH"],
  ["Potential Web Shell", "T1505.003", "CRITICAL"],
  ["Account Discovery Activity", "T1087", "MEDIUM"],
  ["Suspicious Process Discovery", "T1057", "MEDIUM"],
  ["Suspicious Data Archiving", "T1560", "HIGH"],
];

const PIPELINE = [
  ["01", "Alert ingest", "Normalize current telemetry"],
  ["02", "IOC enrichment", "Extract network and technique context"],
  ["03", "Memory recall", "Retrieve relevant organizational history"],
  ["04", "Context build", "Compare current evidence with memory"],
  ["05", "SOC verdict", "Generate explainable investigation guidance"],
];

const LABEL_MAP = [
  { keys: ["ftp-patator", "ssh-patator", "brute force"], title: "Brute Force Authentication Attempt", mitre: "T1110", severity: "HIGH" },
  { keys: ["portscan", "port scan", "network scan"], title: "Network Service Scanning", mitre: "T1046", severity: "MEDIUM" },
  { keys: ["ddos", "dos hulk", "goldeneye", "slowloris", "slowhttptest"], title: "Denial of Service Activity", mitre: "T1498", severity: "CRITICAL" },
  { keys: ["web attack", "sql injection", "sql"], title: "SQL Injection Attempt", mitre: "T1190", severity: "HIGH" },
  { keys: ["infiltration"], title: "Suspicious Command and Control Communication", mitre: "T1071", severity: "HIGH" },
  { keys: ["bot"], title: "Suspicious Command and Control Communication", mitre: "T1071", severity: "HIGH" },
  { keys: ["heartbleed"], title: "Potential Exploitation Activity", mitre: "T1190", severity: "CRITICAL" },
];

function cleanText(text = "") {
  return String(text)
    .replace(/\*\*/g, "")
    .replace(/^\s*[:\-]\s*/, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseAssessment(text = "") {
  const sections = {
    verdict: "",
    similarity: "",
    decisions: "",
    steps: "",
    response: "",
    lesson: "",
    summary: "",
  };

  const patterns = [
    ["verdict", /1\.\s*CURRENT ALERT VERDICT([\s\S]*?)(?=2\.\s*HISTORICAL SIMILARITY|$)/i],
    ["similarity", /2\.\s*HISTORICAL SIMILARITY([\s\S]*?)(?=3\.\s*HISTORICAL ANALYST DECISIONS|$)/i],
    ["decisions", /3\.\s*HISTORICAL ANALYST DECISIONS([\s\S]*?)(?=4\.\s*KEY INVESTIGATION STEPS|$)/i],
    ["steps", /4\.\s*KEY INVESTIGATION STEPS([\s\S]*?)(?=5\.\s*RECOMMENDED RESPONSE|$)/i],
    ["response", /5\.\s*RECOMMENDED RESPONSE([\s\S]*?)(?=6\.\s*MEMORY-BASED LESSON|$)/i],
    ["lesson", /6\.\s*MEMORY-BASED LESSON([\s\S]*?)(?=7\.\s*AGENT SUMMARY|$)/i],
    ["summary", /7\.\s*AGENT SUMMARY([\s\S]*)/i],
  ];

  patterns.forEach(([key, pattern]) => {
    const match = String(text).match(pattern);
    if (match) sections[key] = cleanText(match[1]);
  });

  if (!sections.verdict) {
    sections.verdict = "SUSPICIOUS — REQUIRES INVESTIGATION";
  }

  return sections;
}

function splitSteps(text) {
  if (!text) return [];
  return text
    .split(/\n(?=\d+\.\s)/)
    .map((step) => step.trim().replace(/^\d+\.\s*/, ""))
    .filter(Boolean);
}

/* Simple CSV parser that handles quoted CICIDS fields. */
function parseCSV(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (ch === '"') {
      if (quoted && text[i + 1] === '"') {
        cell += '"';
        i += 1;
      } else {
        quoted = !quoted;
      }
    } else if (ch === "," && !quoted) {
      row.push(cell);
      cell = "";
    } else if ((ch === "\n" || ch === "\r") && !quoted) {
      if (ch === "\r" && text[i + 1] === "\n") i += 1;
      row.push(cell);
      cell = "";
      if (row.some((v) => String(v).trim() !== "")) rows.push(row);
      row = [];
    } else {
      cell += ch;
    }
  }

  if (cell.length || row.length) {
    row.push(cell);
    if (row.some((v) => String(v).trim() !== "")) rows.push(row);
  }

  if (rows.length < 2) return [];

  const headers = rows[0].map((h) => String(h).trim().replace(/^\uFEFF/, ""));
  return rows.slice(1).map((values) => {
    const item = {};
    headers.forEach((header, index) => {
      item[header] = String(values[index] ?? "").trim();
    });
    return item;
  });
}

function getField(row, candidates) {
  const keys = Object.keys(row || {});
  for (const candidate of candidates) {
    const exact = keys.find((key) => key.toLowerCase() === candidate.toLowerCase());
    if (exact && row[exact] !== "") return row[exact];

    const partial = keys.find((key) =>
      key.toLowerCase().replace(/\s+/g, "").includes(candidate.toLowerCase().replace(/\s+/g, ""))
    );
    if (partial && row[partial] !== "") return row[partial];
  }
  return "";
}

function mapDatasetLabel(label = "") {
  const value = String(label).toLowerCase();

  const match = LABEL_MAP.find((item) =>
    item.keys.some((key) => value.includes(key))
  );

  if (match) return match;

  if (value.includes("benign") || value === "normal") {
    return {
      title: "Benign / Normal Network Activity",
      mitre: "",
      severity: "LOW",
    };
  }

  return {
    title: `Dataset Alert — ${label || "Unknown Activity"}`,
    mitre: "T1190",
    severity: "HIGH",
  };
}

function rowToAlert(row, index, fileName) {
  const label =
    getField(row, ["Label", "Attack", "Attack Type", "Class", "Category"]) ||
    "Unknown";

  const mapped = mapDatasetLabel(label);

  const srcIp = getField(row, ["Source IP", "Src IP", "SourceIP"]);
  const dstIp = getField(row, ["Destination IP", "Dst IP", "DestinationIP"]);
  const srcPort = getField(row, ["Source Port", "Src Port"]);
  const dstPort = getField(row, ["Destination Port", "Dst Port"]);
  const protocol = getField(row, ["Protocol"]);
  const timestamp = getField(row, ["Timestamp", "Flow Start"]);
  const flowBytes = getField(row, ["Flow Bytes/s", "Flow Bytes", "Total Length of Fwd Packets"]);
  const packets = getField(row, ["Total Fwd Packets", "Total Backward Packets"]);
  const duration = getField(row, ["Flow Duration"]);

  const event = [
    `Live CICIDS2017 dataset event classified as "${label}".`,
    srcIp ? `Source ${srcIp}${srcPort ? `:${srcPort}` : ""}.` : "",
    dstIp ? `Destination ${dstIp}${dstPort ? `:${dstPort}` : ""}.` : "",
    protocol ? `Protocol ${protocol}.` : "",
    flowBytes ? `Observed flow metric ${flowBytes}.` : "",
    packets ? `Packet telemetry ${packets}.` : "",
    duration ? `Flow duration ${duration}.` : "",
    timestamp ? `Observed at ${timestamp}.` : "",
  ].filter(Boolean).join(" ");

  return {
    alert_id: `LIVE-CICIDS-${Date.now()}-${index}`,
    title: mapped.title,
    user: "dataset-observed",
    host: srcIp || "CICIDS2017-SENSOR",
    severity: mapped.severity,
    event,
    command: null,
    destination_ip: dstIp || null,
    mitre_technique: mapped.mitre || null,
    dataset_label: label,
    dataset_file: fileName,
    dataset_row: index + 1,
    source_ip: srcIp || null,
    destination_port: dstPort || null,
    protocol: protocol || null,
  };
}

function scenarioToAlert(title, mitre, severity) {
  const templates = {
    "Suspicious PowerShell Execution": {
      user: "new.user",
      host: "FIN-PC-099",
      event: "Encoded PowerShell command executed and contacted an unexpected external destination",
      command: "powershell.exe -EncodedCommand <synthetic-demo-value>",
      destination_ip: "185.20.20.20",
    },
    "Brute Force Authentication Attempt": {
      user: "admin",
      host: "AUTH-SRV-01",
      event: "Multiple failed authentication attempts detected",
      command: null,
      destination_ip: "185.20.20.20",
    },
    "Network Service Scanning": {
      user: "scanner",
      host: "NET-SENSOR-01",
      event: "Repeated connection attempts observed across multiple service ports",
      command: null,
      destination_ip: "10.10.20.15",
    },
  };

  const template = templates[title] || {
    user: "simulator-user",
    host: "SIM-HOST-01",
    event: `${title} activity generated by the MemorySOC attack simulator`,
    command: null,
    destination_ip: "185.20.20.20",
  };

  return {
    alert_id: `SIM-${title.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}-${Math.random().toString(16).slice(2, 10).toUpperCase()}`,
    title,
    user: template.user,
    host: template.host,
    severity,
    event: template.event,
    command: template.command,
    destination_ip: template.destination_ip,
    mitre_technique: mitre,
  };
}

function shortId(id) {
  if (!id) return "N/A";
  return id.length > 20 ? `${id.slice(0, 20)}…` : id;
}

function App() {
  const [backendOnline, setBackendOnline] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [currentAlert, setCurrentAlert] = useState(null);
  const [sourceMode, setSourceMode] = useState("SIMULATOR");

  const [datasetFile, setDatasetFile] = useState(null);
  const [datasetRows, setDatasetRows] = useState([]);
  const [datasetStatus, setDatasetStatus] = useState("");
  const [datasetLoading, setDatasetLoading] = useState(false);
  const fileInputRef = useRef(null);

  const [expandedMemory, setExpandedMemory] = useState(null);
  const [activeMemory, setActiveMemory] = useState(0);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackState, setFeedbackState] = useState({
    decision: "true_positive",
    action: "Endpoint isolated / source blocked",
    outcome: "Activity contained",
    notes: "",
  });
  const [feedbackStatus, setFeedbackStatus] = useState("");

  const assessment = useMemo(
    () => parseAssessment(result?.memory_grounded_assessment || ""),
    [result]
  );

  const steps = useMemo(() => splitSteps(assessment.steps), [assessment.steps]);
  const memories = result?.historical_memories || [];
  const verdict = assessment.verdict.toUpperCase();
  const suspicious = verdict.includes("SUSPICIOUS");

  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then((response) => {
        if (!response.ok) throw new Error("Backend unavailable");
        return response.json();
      })
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false));
  }, []);

  const executeAlert = async (alert, mode = "SIMULATOR") => {
    setLoading(true);
    setError("");
    setResult(null);
    setCurrentAlert(alert);
    setSourceMode(mode);
    setFeedbackStatus("");
    setExpandedMemory(null);
    setActiveMemory(0);

    try {
      const response = await fetch(`${API_URL}/investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_id: alert.alert_id,
          title: alert.title,
          user: alert.user || "unknown",
          host: alert.host || "unknown",
          severity: alert.severity || "MEDIUM",
          event: alert.event || "Dataset security event",
          command: alert.command || null,
          destination_ip: alert.destination_ip || null,
          mitre_technique: alert.mitre_technique || null,
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Investigation failed");

      setResult(data);
      setBackendOnline(true);
      window.setTimeout(() => {
        document.getElementById("investigation-result")?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 80);
    } catch (err) {
      setError(err.message || "Failed to connect to the MemorySOC backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleDatasetFile = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setDatasetFile(file);
    setDatasetRows([]);
    setDatasetStatus("");
    setError("");
    setDatasetLoading(true);

    try {
      const lower = file.name.toLowerCase();
      if (!lower.endsWith(".csv") && !lower.endsWith(".txt")) {
        throw new Error("For the browser demo, use the CICIDS2017 CSV/TXT file.");
      }

      const text = await file.text();
      const rows = parseCSV(text);

      if (!rows.length) {
        throw new Error("No CSV rows were detected. Check the file format.");
      }

      const limited = rows.slice(0, 20000);
      setDatasetRows(limited);

      const labelKey = Object.keys(limited[0]).find((key) =>
        ["label", "attack", "attack type", "class", "category"].includes(key.toLowerCase())
      );

      const counts = {};
      limited.forEach((row) => {
        const label = labelKey ? row[labelKey] : "Unknown";
        counts[label] = (counts[label] || 0) + 1;
      });

      const topLabel = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      setDatasetStatus(
        `${limited.length.toLocaleString()} rows loaded${topLabel ? ` • most common label: ${topLabel[0]}` : ""}. Click LIVE EXECUTE to turn a real dataset row into a new alert.`
      );
    } catch (err) {
      setDatasetStatus("");
      setError(err.message);
    } finally {
      setDatasetLoading(false);
    }
  };

  const executeDatasetRow = (rowIndex = 0) => {
    if (!datasetRows.length || !datasetFile) {
      setError("Upload a CICIDS2017 CSV first.");
      return;
    }

    const safeIndex = Math.max(0, Math.min(rowIndex, datasetRows.length - 1));
    const alert = rowToAlert(datasetRows[safeIndex], safeIndex, datasetFile.name);
    executeAlert(alert, "LIVE DATASET");
  };

  const executeRandomDatasetRow = () => {
    if (!datasetRows.length) {
      setError("Upload a CICIDS2017 CSV first.");
      return;
    }
    const index = Math.floor(Math.random() * datasetRows.length);
    executeDatasetRow(index);
  };

  const submitFeedback = async () => {
    if (!currentAlert) return;
    setFeedbackStatus("Saving analyst feedback…");

    try {
      const response = await fetch(`${API_URL}/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_id: currentAlert.alert_id,
          ...feedbackState,
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Feedback failed");

      setFeedbackStatus("Feedback retained as organizational memory.");
      setTimeout(() => setFeedbackOpen(false), 900);
    } catch (err) {
      setFeedbackStatus(err.message || "Unable to retain feedback.");
    }
  };

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div className="scanline" />

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><span>MS</span><i /></div>
          <div>
            <h1>MemorySOC</h1>
            <p>HINDSIGHT INVESTIGATION ENGINE</p>
          </div>
        </div>

        <div className="top-actions">
          <div className={`live-pill ${backendOnline ? "online" : "offline"}`}>
            <span />
            {backendOnline ? "SYSTEM ONLINE" : "CONNECTING"}
          </div>
          <div className="bank-pill">
            <span>BANK</span>
            <strong>memorysoc-soc</strong>
          </div>
        </div>
      </header>

      <main className="dashboard">
        <section className="hero">
          <div className="hero-copy">
            <div className="eyebrow">
              <span className="pulse-dot" />
              AUTONOMOUS SOC INVESTIGATION • LIVE DATA + MEMORY
            </div>
            <h2>
              Investigate with
              <br />
              <em>organizational memory.</em>
            </h2>
            <p>
              Feed a real CICIDS2017 network event into MemorySOC, generate a fresh alert,
              recall relevant incidents, and produce the same explainable investigation used
              by the original attack-scenario simulator.
            </p>

            <div className="hero-actions">
              <button
                className="primary-action"
                disabled={loading}
                onClick={() =>
                  executeAlert(
                    scenarioToAlert(
                      "Suspicious PowerShell Execution",
                      "T1059.001",
                      "HIGH"
                    )
                  )
                }
              >
                <span className="button-orb">{loading ? "…" : "▶"}</span>
                {loading ? "INVESTIGATING…" : "RUN DEMO ALERT"}
              </button>

              <button
                className="ghost-action"
                onClick={() => fileInputRef.current?.click()}
              >
                + LOAD CICIDS2017
              </button>
            </div>
          </div>

          <div className="hero-visual" aria-hidden="true">
            <div className="orbit orbit-a" />
            <div className="orbit orbit-b" />
            <div className="core">
              <span>MS</span>
              <small>MEMORY<br />ENGINE</small>
            </div>
            <div className="node node-a">IOC</div>
            <div className="node node-b">MITRE</div>
            <div className="node node-c">LIVE</div>
            <div className="node node-d">HISTORY</div>
          </div>
        </section>

        {/* =====================================================
            TOP: LIVE DATASET INGESTION
        ====================================================== */}
        <section className="dataset-panel panel" id="dataset">
          <div className="section-header">
            <div>
              <span className="section-kicker"><span className="live-dot" /> 01 • LIVE DATASET INGESTION</span>
              <h3>Put real CICIDS2017 telemetry in front of the investigator</h3>
              <p>
                Upload a CSV, convert one real dataset row into a fresh security alert,
                then send that alert through the same MemorySOC investigation pipeline.
              </p>
            </div>
            <div className="dataset-badge">
              <strong>{datasetRows.length ? datasetRows.length.toLocaleString() : "0"}</strong>
              <span>ROWS LOADED</span>
            </div>
          </div>

          <div className="dataset-actions">
            <input
              ref={fileInputRef}
              className="hidden-file"
              type="file"
              accept=".csv,.txt"
              onChange={handleDatasetFile}
            />

            <button
              className="upload-zone"
              onClick={() => fileInputRef.current?.click()}
              disabled={datasetLoading}
            >
              <div className="upload-icon">⇧</div>
              <div>
                <strong>{datasetFile ? datasetFile.name : "Choose CICIDS2017 CSV"}</strong>
                <span>{datasetFile ? "File loaded • click to replace" : "CSV / TXT • browser parses the rows locally"}</span>
              </div>
            </button>

            <button
              className="primary-action dataset-execute"
              disabled={!datasetRows.length || datasetLoading || loading}
              onClick={() => executeDatasetRow(0)}
            >
              <span className="button-orb">▶</span>
              LIVE EXECUTE FIRST ROW
            </button>

            <button
              className="ghost-action random-execute"
              disabled={!datasetRows.length || datasetLoading || loading}
              onClick={executeRandomDatasetRow}
            >
              RANDOM ROW →
            </button>
          </div>

          {datasetLoading && (
            <div className="dataset-status loading-status">
              Reading dataset locally…
            </div>
          )}

          {datasetStatus && <div className="dataset-status">{datasetStatus}</div>}

          {datasetRows.length > 0 && (
            <div className="dataset-preview">
              <div className="preview-head">
                <span>LIVE ROW PREVIEW</span>
                <button onClick={executeRandomDatasetRow}>EXECUTE RANDOM ROW ↗</button>
              </div>
              <div className="preview-grid">
                {Object.entries(datasetRows[0]).slice(0, 8).map(([key, value]) => (
                  <div className="preview-cell" key={key}>
                    <span>{key}</span>
                    <strong>{String(value || "—").slice(0, 90)}</strong>
                  </div>
                ))}
              </div>
              <div className="dataset-flow">
                <span>CSV ROW</span><b>→</b><span>NEW ALERT</span><b>→</b><span>MEMORY RECALL</span><b>→</b><span>SOC RESULT</span>
              </div>
            </div>
          )}

          <div className="dataset-note">
            <span>HACKATHON DEMO</span>
            <p>
              The uploaded row is not shown as a static scenario. It becomes a new alert with
              a unique LIVE-CICIDS ID and is sent to <code>/investigate</code>. The original
              20 simulator scenarios remain below as the controlled fallback/demo path.
            </p>
          </div>
        </section>

        {currentAlert && (
          <section className="current-source panel">
            <div>
              <span className="section-kicker">
                {sourceMode === "LIVE DATASET" ? "● LIVE DATASET ALERT" : "● SIMULATED ALERT"}
              </span>
              <h3>{currentAlert.title}</h3>
              <p>{currentAlert.event}</p>
            </div>
            <div className="source-meta">
              <span>{currentAlert.alert_id}</span>
              <strong>{currentAlert.severity}</strong>
              {currentAlert.mitre_technique && <b>{currentAlert.mitre_technique}</b>}
            </div>
          </section>
        )}

        {loading && (
          <section className="investigating panel">
            <div className="loading-core">
              <div className="spinner-ring" />
              <div className="loading-center">MS</div>
            </div>
            <div>
              <div className="section-kicker">ACTIVE INVESTIGATION</div>
              <h3>Generating SOC verdict…</h3>
              <p>Current evidence → Hindsight recall → contextual reasoning → explainable response</p>
            </div>
            <div className="loading-bars"><i /><i /><i /><i /><i /></div>
          </section>
        )}

        {error && (
          <section className="error-panel panel">
            <span className="error-icon">!</span>
            <div>
              <div className="section-kicker">INVESTIGATION ERROR</div>
              <h3>Agent request failed</h3>
              <p>{error}</p>
            </div>
          </section>
        )}

        {result && (
          <section id="investigation-result">
            <section className="verdict-section">
              <div className={`verdict-card ${suspicious ? "danger" : ""}`}>
                <div className="verdict-glow" />
                <div className="verdict-main">
                  <div className="section-kicker">MEMORY-GROUNDED VERDICT</div>
                  <div className="verdict-icon">{suspicious ? "!" : "✓"}</div>
                  <h3>{suspicious ? "SUSPICIOUS" : "REVIEW"}</h3>
                  <p>{assessment.verdict}</p>
                </div>

                <div className="verdict-metrics">
                  <Metric label="SEVERITY" value={currentAlert?.severity} danger />
                  <Metric label="MITRE" value={currentAlert?.mitre_technique || "—"} />
                  <Metric label="MEMORIES" value={result.memory_count} accent />
                  <Metric label="STATUS" value="COMPLETED" success />
                </div>
              </div>
            </section>

            <section className="pipeline panel">
              <SectionHeader
                eyebrow="02 • INVESTIGATION TRACE"
                title="Evidence → memory → decision"
                description="The same reasoning path is used for both live dataset alerts and the original simulator."
                right={<span className="completed">● TRACE COMPLETE</span>}
              />
              <div className="pipeline-track">
                {PIPELINE.map(([number, title, description]) => (
                  <div className="pipeline-stage" key={number}>
                    <div className="stage-connector" />
                    <div className="stage-node"><span>{number}</span></div>
                    <div className="stage-copy">
                      <small>STAGE {number}</small>
                      <h4>{title}</h4>
                      <p>{description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="enrichment-grid">
              <div className="enrichment-card panel">
                <div className="card-icon cyan">◈</div>
                <div>
                  <span>IOC ENRICHMENT</span>
                  <h3>{currentAlert?.destination_ip || "No destination IP"}</h3>
                  <p>Network indicator carried into the investigation context.</p>
                </div>
                <div className="indicator-status">OBSERVED</div>
              </div>

              <div className="enrichment-card panel">
                <div className="card-icon violet">◆</div>
                <div>
                  <span>MITRE ATT&CK</span>
                  <h3>{currentAlert?.mitre_technique || "Unmapped"}</h3>
                  <p>Technique attached to the current alert.</p>
                </div>
                <div className="indicator-status">MAPPED</div>
              </div>

              <div className="enrichment-card panel">
                <div className="card-icon green">◉</div>
                <div>
                  <span>MEMORY RECALL</span>
                  <h3>{result.memory_count} historical matches</h3>
                  <p>Organizational memory retrieved before AI assessment.</p>
                </div>
                <div className="indicator-status">RECALLED</div>
              </div>
            </section>

            <section className="reasoning-grid">
              <article className="assessment-panel panel">
                <SectionHeader
                  eyebrow="MEMORY-GROUNDED ASSESSMENT"
                  title="Why the agent reached this view"
                  description="Historical similarity is evidence for comparison — not proof."
                />
                <div className="assessment-content">
                  <AssessmentBlock title="Historical similarity" text={assessment.similarity} />
                  <AssessmentBlock title="Historical analyst decisions" text={assessment.decisions} />
                  <AssessmentBlock title="Memory-based lesson" text={assessment.lesson} />
                </div>
              </article>

              <article className="agent-card panel">
                <div className="agent-orb"><div className="agent-orb-inner">AI</div></div>
                <span className="section-kicker">AGENT SUMMARY</span>
                <h3>Context before conclusion.</h3>
                <p>{assessment.summary || assessment.verdict}</p>
                <div className="reasoning-tags">
                  <span>HINDSIGHT</span><span>GROQ</span><span>MITRE</span><span>IOC</span>
                </div>
              </article>
            </section>

            <section className="steps panel">
              <SectionHeader
                eyebrow="03 • RECOMMENDED INVESTIGATION"
                title="Concrete analyst moves"
                description="Actions generated from the current evidence and remembered incidents."
              />
              <div className="steps-grid">
                {steps.slice(0, 5).map((step, index) => (
                  <div className="playbook-step" key={index}>
                    <div className="playbook-number">{String(index + 1).padStart(2, "0")}</div>
                    <div>
                      <span>INVESTIGATION MOVE</span>
                      <p>{step}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="response-callout">
                <span>RECOMMENDED RESPONSE</span>
                <p>{assessment.response}</p>
              </div>
            </section>

            <section className="memory-section">
              <SectionHeader
                eyebrow="04 • HINDSIGHT MEMORY"
                title="Historical incidents recalled for this alert"
                description="Persistent organizational memory is visible evidence — not a black box."
                right={<div className="memory-counter"><strong>{result.memory_count}</strong><span>RECALLED</span></div>}
              />

              <div className="memory-layout">
                <div className="memory-feature panel">
                  {memories.length > 0 ? (
                    <>
                      <div className="memory-feature-top">
                        <span>TOP RECALL</span>
                        <span>{shortId(memories[activeMemory]?.memory_id)}</span>
                      </div>
                      <div className="memory-signal">
                        <div className="signal-ring">↯</div>
                        <div><small>HISTORICAL MATCH</small><h3>Relevant organizational memory</h3></div>
                      </div>
                      <p>{memories[activeMemory]?.text}</p>
                      <div className="memory-feature-footer">
                        <span>MEMORY {String(activeMemory + 1).padStart(2, "0")} / {String(memories.length).padStart(2, "0")}</span>
                        <div>
                          <button onClick={() => setActiveMemory((activeMemory - 1 + memories.length) % memories.length)}>←</button>
                          <button onClick={() => setActiveMemory((activeMemory + 1) % memories.length)}>→</button>
                        </div>
                      </div>
                    </>
                  ) : <p>No historical memories returned.</p>}
                </div>

                <div className="memory-stack">
                  {memories.slice(0, 8).map((memory, index) => {
                    const expanded = expandedMemory === index;
                    return (
                      <article
                        className={`memory-row ${expanded ? "expanded" : ""}`}
                        key={memory.memory_id || index}
                        onClick={() => {
                          setActiveMemory(index);
                          setExpandedMemory(expanded ? null : index);
                        }}
                      >
                        <div className="memory-row-number">{String(index + 1).padStart(2, "0")}</div>
                        <div className="memory-row-content">
                          <span>HISTORICAL MEMORY</span>
                          <p>{memory.text}</p>
                        </div>
                        <div className="memory-row-arrow">{expanded ? "↕" : "+"}</div>
                      </article>
                    );
                  })}
                </div>
              </div>
            </section>

            <section className="feedback-banner panel">
              <div>
                <span className="section-kicker">05 • CLOSE THE LOOP</span>
                <h3>Teach the memory engine what happened next.</h3>
                <p>Record the analyst decision, response and outcome so future investigations inherit organizational learning.</p>
              </div>
              <button className="primary-action compact" onClick={() => setFeedbackOpen(true)}>
                LOG OUTCOME →
              </button>
            </section>
          </section>
        )}

        {/* =====================================================
            BOTTOM: ORIGINAL 20 SCENARIOS
        ====================================================== */}
        <section className="scenario-library" id="scenarios">
          <div className="section-header">
            <div>
              <span className="section-kicker">06 • ATTACK SIMULATOR</span>
              <h3>Original 20 attack scenarios</h3>
              <p>
                Your morning demo is preserved here. Select a scenario and execute it through
                the same live investigation pipeline.
              </p>
            </div>
            <div className="scenario-count"><strong>20</strong><span>SCENARIOS</span></div>
          </div>

          <div className="scenario-grid">
            {SCENARIOS.map(([title, mitre, severity]) => (
              <button
                className={`scenario-card ${severity.toLowerCase()}`}
                key={title}
                disabled={loading}
                onClick={() => executeAlert(scenarioToAlert(title, mitre, severity), "SIMULATOR")}
              >
                <div className="scenario-icon">◈</div>
                <div className="scenario-copy">
                  <strong>{title}</strong>
                  <span>{mitre}</span>
                </div>
                <em>{severity}</em>
              </button>
            ))}
          </div>
        </section>
      </main>

      <footer className="footer">
        <div><strong>MemorySOC</strong><span>Live dataset + persistent-memory SOC investigation platform</span></div>
        <div><span>HINDSIGHT BANK</span><b>memorysoc-soc</b></div>
      </footer>

      {feedbackOpen && (
        <div className="modal-backdrop" onClick={() => setFeedbackOpen(false)}>
          <div className="feedback-modal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <div><span className="section-kicker">ANALYST FEEDBACK</span><h3>Close the investigation loop</h3></div>
              <button onClick={() => setFeedbackOpen(false)}>×</button>
            </div>

            <label>
              DECISION
              <select value={feedbackState.decision} onChange={(e) => setFeedbackState({ ...feedbackState, decision: e.target.value })}>
                <option value="true_positive">True positive</option>
                <option value="false_positive">False positive</option>
                <option value="needs_review">Needs review</option>
              </select>
            </label>

            <label>
              ACTION TAKEN
              <input value={feedbackState.action} onChange={(e) => setFeedbackState({ ...feedbackState, action: e.target.value })} />
            </label>

            <label>
              OUTCOME
              <input value={feedbackState.outcome} onChange={(e) => setFeedbackState({ ...feedbackState, outcome: e.target.value })} />
            </label>

            <label>
              NOTES
              <textarea value={feedbackState.notes} onChange={(e) => setFeedbackState({ ...feedbackState, notes: e.target.value })} placeholder="Add analyst context for future investigations…" />
            </label>

            {feedbackStatus && <div className="feedback-status">{feedbackStatus}</div>}

            <button className="primary-action full" onClick={submitFeedback}>
              RETAIN AS ORGANIZATIONAL MEMORY →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function InfoCard({ label, value, accent, danger, mono }) {
  return (
    <div className={`info-card ${accent ? "accent" : ""} ${danger ? "danger" : ""}`}>
      <span>{label}</span>
      <strong className={mono ? "mono" : ""}>{value || "—"}</strong>
    </div>
  );
}

function Metric({ label, value, danger, accent, success }) {
  return (
    <div className={`metric ${danger ? "danger" : ""} ${accent ? "accent" : ""} ${success ? "success" : ""}`}>
      <span>{label}</span>
      <strong>{value || "—"}</strong>
    </div>
  );
}

function SectionHeader({ eyebrow, title, description, right }) {
  return (
    <div className="section-header">
      <div>
        <span className="section-kicker">{eyebrow}</span>
        <h3>{title}</h3>
        {description && <p>{description}</p>}
      </div>
      {right}
    </div>
  );
}

function AssessmentBlock({ title, text }) {
  return (
    <div className="assessment-block">
      <span>{title}</span>
      <p>{text || "No additional information returned."}</p>
    </div>
  );
}

export default App;
