# CYBERNEXUS SOC
> **"Detect. Investigate. Explain. Respond."**

A production-quality, mobile-first AI-assisted Security Operations Centre (SOC) and Threat Intelligence Analyzer.

---

## 1. Executive Overview & Problem Statement

Modern Security Operations Centres (SOCs) face alert fatigue, opaque autonomous "black-box" systems, and disconnected tooling. When analysts receive an alert, they must answer six fundamental questions within minutes:
1. **What happened?** (Observed telemetry vs inferences)
2. **Why does it matter?** (Explainable 0–100 risk scoring)
3. **What evidence exists?** (Audited, unalterable forensic artifacts)
4. **What does MITRE ATT&CK say?** (Adversary TTP candidate alignment)
5. **What does the AI think?** (Decision support & explanation, **not** autonomous authority)
6. **What should the analyst do next?** (Recommended containment actions with human-in-the-loop approval)

**CYBERNEXUS SOC** answers every question with strict safety guardrails, deterministic detection heuristics, and instant PDF SOC incident dossier generation.

---

## 2. Fundamental SOC Architecture & Workflow

```
EVENT / INDICATOR (URL, Domain, IP, Hash)
       ↓
DATA NORMALIZATION & VALIDATION (Anti-SSRF Safe String Parsing)
       ↓
THREAT INTELLIGENCE (Synthetic Catalog + VirusTotal, URLScan, AbuseIPDB, SafeBrowsing, RDAP)
       ↓
DETERMINISTIC DETECTION RULES (Heuristic Feature Scoring)
       ↓
EXPLAINABLE RISK SCORING (0–100 Scale: LOW, MEDIUM, HIGH, CRITICAL)
       ↓
ALERT GENERATION (Queue Management)
       ↓
INVESTIGATION WORKSPACE (/investigations/:id)
       ↓
AI ANALYST (@google/genai Server-Side: OBSERVED vs INFERRED)
       ↓
MITRE ATT&CK ENTERPRISE MAPPING (T1566.002, T1204.002, T1110, T1078, etc.)
       ↓
RECOMMENDED RESPONSE ACTIONS (Containment & Eradication Proposals)
       ↓
ANALYST DECISION & MANDATORY RESOLUTION AUDIT NOTE
       ↓
PROFESSIONAL SOC DOSSIER GENERATION (Downloadable PDF)
```

---

## 3. Non-Negotiable Safety Requirements

1. **Synthetic Data By Default**: All demonstration indicators strictly use RFC 2606 reserved domains (`*.test`, `example.com`) and RFC 5737 documentation IP space (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
2. **Anti-SSRF Protection**: The backend **never** fetches user-submitted URLs directly. Only mathematical string attributes (entropy, subdomain count, punycode, TLD) and verified threat intelligence catalogs are analyzed.
3. **AI Is Decision Support, Not Authority**: AI never autonomously executes network blockades or overrides deterministic detection rules.
4. **Observed vs Inferred Distinction**: Telemetry directly observed is strictly separated from analytical deductions.
5. **No Hallucinated Data**: If external intelligence is unreachable or unconfigured, the system returns `"DATA NOT AVAILABLE"` rather than fabricating observations.

---

## 4. Complete MVP Features

- **SOC Dashboard**: Real-time KPI counters (Total, Critical, High, Open, Investigating, Resolved, False Positives), risk distribution graphs, and live alert feed.
- **Alert Queue**: Filter by severity, status, indicator, or title with quick-investigate actions.
- **Phishing URL Feature Analyzer**: Extracts 14+ lexical features: protocol, host_is_ip, subdomains, length, punycode, @ symbol, entropy, and sensitive authentication keywords.
- **Indicator Lookup**: Multi-provider intelligence for Domains, IP addresses, and SHA-256 file digests.
- **Rule Engine**: Modular heuristic rules supporting `phishing_url`, `malware_hash`, `failed_login_burst`, `impossible_travel`, `unusual_login`, `suspicious_dns`, and `suspicious_ip`.
- **AI Security Analyst**: Server-side `@google/genai` model (`gemini-3.8-flash`) returning structured JSON with confidence, key findings, and recommended response actions.
- **Investigation Workspace**: 14 ordered investigation sections optimized for both desktop and 360px mobile screens with collapsible drawers.
- **MITRE ATT&CK Matrix**: Deep-dive into enterprise tactics and techniques with SOC detection and mitigation guidance.
- **PDF Report Generator**: High-fidelity, client- and server-side PDF generation containing executive summaries, forensic timelines, and required safety disclaimers.
- **Role-Based Access Control (RBAC)**: Operator profiles for Analyst, Lead, and Administrator.

---

## 5. Technology Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, Lucide React
- **Full-Stack Backend**: Node.js & Express (`server.ts`) with mounted Vite middleware
- **Python Backend**: FastAPI, Pydantic, ReportLab, pytest (`backend/`)
- **AI Integration**: `@google/genai` TypeScript SDK (server-side only) with Gemini 3.8 Flash
- **Database**: Relational in-memory store with persistence & SQLite migration path
- **Reporting**: jsPDF & ReportLab

---

## 6. The 12 Synthetic Demo Alerts

| ID | Title | Event Type | Indicator | Severity | Risk Score |
|---|---|---|---|---|---|
| **CNX-001** | Credential Harvesting Link | `phishing_url` | `http://login.secure-sso.verify-portal.account-update.test/...` | CRITICAL | 88 |
| **CNX-002** | Corporate Docs Portal Access | `url_inspection` | `https://internal-portal.corp.example.test/docs/handbook` | LOW | 8 |
| **CNX-003** | DNS Tunneling Volume Anomaly | `suspicious_dns` | `tunnel-exfil-test.reserved.test` | HIGH | 78 |
| **CNX-004** | LockNexus Ransomware Loader | `malware_hash` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | CRITICAL | 96 |
| **CNX-005** | Failed Auth Spray Burst | `failed_login_burst`| `198.51.100.77` | HIGH | 75 |
| **CNX-006** | Geo-Temporal Impossible Travel | `impossible_travel` | `203.0.113.195` | HIGH | 72 |
| **CNX-007** | Off-Hours Admin Login | `unusual_login` | `192.0.2.199` | MEDIUM | 48 |
| **CNX-008** | C2 Heartbeat Beaconing | `suspicious_ip` | `198.51.100.45` | HIGH | 74 |
| **CNX-009** | Typosquat Brand Registration | `suspicious_domain`| `cybernexus-security-auth.test` | HIGH | 68 |
| **CNX-010** | Vulnerability Scanner Probe | `vulnerability_scan`| `192.0.2.5` | LOW | 18 |
| **CNX-011** | Compromised Dev Service Token | `compromised_account`| `203.0.113.88` | HIGH | 82 |
| **CNX-012** | Ransomware Shadow Copy Tamper | `malicious_binary` | `a1b2c3d4e5f67890123456789abcdef0123456789abcdef...` | CRITICAL | 98 |

---

## 7. Siren Challenge Workflow (5 Minutes)

Click the **Siren Challenge** button in the header or follow this runbook:
1. **Identify Alert**: Open `CNX-001` (Credential Harvesting Link).
2. **Review Triage**: Note Critical severity, 88/100 risk score, and plain HTTP credential lure.
3. **Open Investigation**: Transition status to `INVESTIGATING`.
4. **Deterministic Analysis**: Inspect extracted features: 4 subdomains, auth keywords `login, secure, update`.
5. **Threat Intelligence**: Review synthetic TI match confirming reputation: `MALICIOUS`.
6. **Run AI Security Analyst**: AI models decision support, separating Observed evidence from Inferences.
7. **MITRE ATT&CK Mapping**: Correlate with Technique `T1566.002` (Spearphishing Link).
8. **Action Proposal**: Review recommended containment action: `Block Domain on Web Proxy & DNS RPZ`. Approve action.
9. **Analyst Decision**: Enter mandatory resolution audit note: *"Blocked domain on proxy. Confirmed no user credentials entered."*
10. **Resolve**: Mark incident as `RESOLVED`.
11. **Generate PDF**: Click `Download PDF Dossier` to download the completed SOC Incident Report.

---

## 8. Installation & Execution

### Full-Stack Environment (Port 3000)
```bash
# Install dependencies
npm install

# Start full-stack application (Express + Vite)
npm run dev

# Build for production
npm run build
npm run start
```

### Python Test Suite
```bash
python3 backend/tests/test_detection.py
```

### Docker
```bash
docker-compose up --build
```
