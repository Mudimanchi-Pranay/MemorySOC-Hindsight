import { useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

const ALERT = {
  alert_id: "NEW-POWER-001",
  title: "Suspicious PowerShell execution",
  user: "new.user",
  host: "FIN-PC-099",
  severity: "HIGH",
  event:
    "Encoded PowerShell command executed and contacted an unexpected external destination",
  command: "powershell.exe -EncodedCommand <synthetic-demo-value>",
  destination_ip: "185.20.20.20",
  mitre_technique: "T1059.001",
};

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
    const match = text.match(pattern);
    if (match) {
      sections[key] = cleanText(match[1]);
    }
  });

  if (!sections.verdict) {
    sections.verdict = "SUSPICIOUS — REQUIRES INVESTIGATION";
  }

  return sections;
}

function cleanText(text) {
  return text
    .replace(/\*\*/g, "")
    .replace(/^\s*[:\-]\s*/, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function splitSteps(text) {
  if (!text) return [];

  return text
    .split(/\n(?=\d+\.\s)/)
    .map((step) => step.trim())
    .filter(Boolean);
}

function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [expandedMemory, setExpandedMemory] = useState(null);

  const investigateAlert = async () => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/investigate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(ALERT),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Investigation failed");
      }

      setResult(data);
    } catch (err) {
      setError(
        `${err.message}. Make sure the FastAPI backend is running on port 8000.`
      );
    } finally {
      setLoading(false);
    }
  };

  const assessment = result
    ? parseAssessment(result.memory_grounded_assessment)
    : null;

  const steps = assessment ? splitSteps(assessment.steps) : [];

  return (
    <div className="app">
      {/* TOP NAVIGATION */}
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">M</div>

          <div>
            <h1>MemorySOC</h1>
            <p>HINDSIGHT-POWERED SOC INVESTIGATION</p>
          </div>
        </div>

        <div className="top-status">
          <span className="status-dot"></span>
          <span>BACKEND ONLINE</span>
        </div>
      </header>

      <main className="dashboard">
        {/* HERO */}
        <section className="hero">
          <div>
            <span className="eyebrow">SECURITY OPERATIONS CENTER</span>

            <h2>
              Investigate alerts with
              <span> organizational memory.</span>
            </h2>

            <p>
              MemorySOC combines historical SOC incidents with AI reasoning to
              provide context-aware investigation guidance.
            </p>
          </div>

          <div className="hero-status">
            <div className="pulse-ring">
              <span></span>
            </div>

            <div>
              <strong>MEMORY ENGINE</strong>
              <small>READY</small>
            </div>
          </div>
        </section>

        {/* CURRENT ALERT */}
        <section className="panel alert-panel">
          <div className="panel-header">
            <div>
              <span className="eyebrow">LIVE ALERT</span>
              <h2>Current Alert</h2>
            </div>

            <div className="severity-badge">
              <span>●</span>
              {ALERT.severity}
            </div>
          </div>

          <div className="alert-title">
            <div className="alert-icon">⚠</div>

            <div>
              <h3>{ALERT.title}</h3>
              <p>{ALERT.event}</p>
            </div>
          </div>

          <div className="alert-grid">
            <InfoItem label="Alert ID" value={ALERT.alert_id} />
            <InfoItem label="User" value={ALERT.user} />
            <InfoItem label="Host" value={ALERT.host} />
            <InfoItem label="MITRE Technique" value={ALERT.mitre_technique} />
            <InfoItem label="Destination IP" value={ALERT.destination_ip} />
            <InfoItem label="Command" value="PowerShell -EncodedCommand" />
          </div>

          <button
            className={`investigate-btn ${loading ? "loading" : ""}`}
            onClick={investigateAlert}
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner"></span>
                Running investigation...
              </>
            ) : (
              <>▶ Investigate Alert</>
            )}
          </button>
        </section>

        {/* ERROR */}
        {error && (
          <section className="error-card">
            <div className="error-icon">!</div>

            <div>
              <h3>Investigation Error</h3>
              <p>{error}</p>
            </div>
          </section>
        )}

        {/* RESULTS */}
        {result && assessment && (
          <>
            {/* VERDICT */}
            <section className="verdict-panel">
              <div className="verdict-left">
                <span className="eyebrow">CURRENT ALERT VERDICT</span>

                <h2>⚠ SUSPICIOUS</h2>

                <p>REQUIRES INVESTIGATION</p>
              </div>

              <div className="verdict-stats">
                <Stat
                  label="SEVERITY"
                  value={ALERT.severity}
                  danger
                />

                <Stat
                  label="MITRE"
                  value={ALERT.mitre_technique}
                />

                <Stat
                  label="MEMORIES"
                  value={result.memory_count}
                />

                <Stat
                  label="STATUS"
                  value="COMPLETED"
                />
              </div>
            </section>

            {/* INVESTIGATION TIMELINE */}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <span className="eyebrow">INVESTIGATION PIPELINE</span>
                  <h2>Analysis Timeline</h2>
                </div>

                <span className="completed-badge">● COMPLETED</span>
              </div>

              <div className="timeline">
                <TimelineItem
                  number="01"
                  title="Alert analyzed"
                  description="Alert metadata and suspicious indicators identified."
                />

                <TimelineItem
                  number="02"
                  title="Historical memory retrieved"
                  description={`${result.memory_count} organizational memories recalled.`}
                />

                <TimelineItem
                  number="03"
                  title="Historical decisions compared"
                  description="Previous analyst decisions and response outcomes reviewed."
                />

                <TimelineItem
                  number="04"
                  title="AI assessment generated"
                  description="Groq reasoning engine produced a memory-grounded assessment."
                />
              </div>
            </section>

            {/* AI ASSESSMENT */}
            <section className="assessment-panel">
              <div className="assessment-heading">
                <div className="ai-icon">✦</div>

                <div>
                  <span className="eyebrow">HINDSIGHT ANALYSIS</span>
                  <h2>AI Investigation Assessment</h2>
                </div>

                <span className="memory-count">
                  {result.memory_count} memories
                </span>
              </div>

              <div className="assessment-grid">
                <AssessmentCard
                  icon="🔎"
                  title="Historical Similarity"
                  text={assessment.similarity}
                />

                <AssessmentCard
                  icon="🧠"
                  title="Historical Analyst Decisions"
                  text={assessment.decisions}
                />

                <AssessmentCard
                  icon="⚠"
                  title="Current Assessment"
                  text={assessment.verdict}
                  highlight
                />

                <AssessmentCard
                  icon="📋"
                  title="Memory-Based Lesson"
                  text={assessment.lesson}
                />
              </div>

              {/* INVESTIGATION STEPS */}
              <div className="steps-section">
                <div className="subheading">
                  <span>🔬</span>
                  <div>
                    <h3>Key Investigation Steps</h3>
                    <p>Recommended SOC analyst workflow</p>
                  </div>
                </div>

                <div className="steps-list">
                  {steps.length > 0 ? (
                    steps.map((step, index) => (
                      <div className="step-item" key={index}>
                        <div className="step-number">
                          {String(index + 1).padStart(2, "0")}
                        </div>

                        <p>{step.replace(/^\d+\.\s*/, "")}</p>
                      </div>
                    ))
                  ) : (
                    <div className="fallback-text">{assessment.steps}</div>
                  )}
                </div>
              </div>

              {/* RESPONSE */}
              <div className="response-section">
                <div className="subheading">
                  <span>🛡️</span>

                  <div>
                    <h3>Recommended Response</h3>
                    <p>Actions based on investigation findings</p>
                  </div>
                </div>

                <div className="response-box">
                  {assessment.response}
                </div>
              </div>

              {/* SUMMARY */}
              {assessment.summary && (
                <div className="agent-summary">
                  <span className="eyebrow">AGENT SUMMARY</span>

                  <p>{assessment.summary}</p>
                </div>
              )}

              <details className="query-details">
                <summary>View Hindsight Recall Query</summary>

                <div className="query-content">
                  {result.recall_query}
                </div>
              </details>
            </section>

            {/* HISTORICAL MEMORIES */}
            <section className="memories-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">RECALLED INCIDENTS</span>
                  <h2>Historical SOC Memories</h2>
                  <p>
                    Organizational knowledge retrieved by the Hindsight memory
                    engine.
                  </p>
                </div>

                <div className="memory-total">
                  {result.memory_count}
                  <small>MEMORIES</small>
                </div>
              </div>

              <div className="memory-grid">
                {result.historical_memories.map((memory, index) => {
                  const isExpanded = expandedMemory === index;

                  return (
                    <article
                      className={`memory-card ${
                        isExpanded ? "expanded" : ""
                      }`}
                      key={memory.memory_id || index}
                    >
                      <div className="memory-top">
                        <span className="memory-number">
                          MEMORY {String(index + 1).padStart(2, "0")}
                        </span>

                        <span className="memory-score">
                          {memory.score
                            ? `${Math.round(memory.score * 100)}%`
                            : "MATCH"}
                        </span>
                      </div>

                      <div className="memory-indicator">
                        <span></span>
                        Historical Match
                      </div>

                      <p>{memory.text}</p>

                      <div className="memory-footer">
                        <span>
                          ID:{" "}
                          {memory.memory_id
                            ? `${memory.memory_id.slice(0, 16)}...`
                            : "N/A"}
                        </span>

                        <button
                          onClick={() =>
                            setExpandedMemory(
                              isExpanded ? null : index
                            )
                          }
                        >
                          {isExpanded ? "Collapse" : "Expand"}
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>
          </>
        )}
      </main>

      <footer className="footer">
        <span>MemorySOC Hindsight POC</span>
        <span>Persistent-memory SOC investigation platform</span>
      </footer>
    </div>
  );
}

function InfoItem({ label, value }) {
  return (
    <div className="info-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Stat({ label, value, danger }) {
  return (
    <div className={`stat ${danger ? "danger" : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TimelineItem({ number, title, description }) {
  return (
    <div className="timeline-item">
      <div className="timeline-marker">
        ✓
      </div>

      <div className="timeline-content">
        <span>STAGE {number}</span>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

function AssessmentCard({ icon, title, text, highlight }) {
  return (
    <article className={`assessment-card ${highlight ? "highlight" : ""}`}>
      <div className="assessment-card-top">
        <span className="assessment-icon">{icon}</span>
        <h3>{title}</h3>
      </div>

      <p>{text || "No additional information returned."}</p>
    </article>
  );
}

export default App;