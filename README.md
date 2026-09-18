# 🛡️ ThreatLens (CYBERIDS) — AI-Based Intrusion Detection System

> **Next-Generation Machine Learning Network Threat Detection with Explainable AI & Autonomous Security Operations Copilot**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask Framework](https://img.shields.io/badge/Flask-3.0-lightgrey.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.2%2B-orange.svg?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Explainable AI](https://img.shields.io/badge/XAI-SHAP%200.43%2B-green.svg?style=for-the-badge)](https://shap.readthedocs.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS%20JIT-38B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

---

## 📌 Table of Contents
- [Overview & Context](#-overview--context)
- [Key Features & Capabilities](#-key-features--capabilities)
- [System Architecture](#-system-architecture)
- [Core Feature Engineering (12 Features)](#-core-feature-engineering-12-features)
- [Tech Stack](#-tech-stack)
- [Installation & Quickstart](#-installation--quickstart)
- [Testing & Dataset Evaluation](#-testing--dataset-evaluation)
- [API Reference](#-api-reference)
- [Repository Structure](#-repository-structure)
- [Security & Governance](#-security--governance)
- [License](#-license)

---

## 🌐 Overview & Context

Modern Security Operations Centers (SOCs) face critical operational hurdles:
1. **Alert Fatigue:** Signature-based firewalls trigger thousands of daily alarms with high false-positive rates.
2. **The "Black-Box" Trust Deficit:** Deep statistical models frequently classify traffic as malicious without explaining *why*, leaving Tier 1/2 analysts hesitant to take disruptive blocking actions.
3. **Slow Mean Time to Remediate (MTTR):** Correlating packets, reviewing vendor manuals, and writing firewall rules takes 20–40 minutes per incident.

**ThreatLens (CYBERIDS)** solves this by uniting **high-accuracy multi-class machine learning**, **game-theoretic explainability (SHAP)**, and an **autonomous RAG Security Copilot** inside a futuristic, dark-themed SOC Command Center.

---

## ⚡ Key Features & Capabilities

### 🧠 1. Multi-Class Machine Learning Threat Detection
- Trained on the standard **CIC-IDS2017** network flow benchmark.
- Detects multi-vector cyber intrusions with **>99% empirical accuracy** and sub-50ms inference latency:
  - **`BENIGN`**: Normal web (HTTP/HTTPS), DNS, NTP, SSH administrative, and database flows.
  - **`DDoS`**: Volumetric ingress exploits, HTTP floods, SYN floods, and UDP amplifications.
  - **`PortScan`**: Horizontal sweeps, stealth SYN probes, and service discovery recon.
  - **`SSH-Patator`**: Brute-force credential guessing attacks directed against Port 22.
- **Serverless Heuristic Failover:** High-fidelity rule-based classifier ensuring 100% uptime in constrained or edge environments.

### 🔍 2. Explainable AI (XAI) with SHAP
- Demystifies black-box predictions using **Shapley Additive exPlanations (SHAP)**:
  - **Interactive Force Bar:** Visualizes the dynamic tug-of-war between features pushing toward Normal (green) vs. Attack (red).
  - **Waterfall Progression:** Traces step-by-step how each parameter sequentially shifts the probability from the base value to the final confidence score.
  - **Global Feature Importance:** Ranks top indicators across the network (`Destination Port`, `Flow Packets/s`, `Flow Duration`).
  - **Surrogate Fallback:** Prevents UI rendering failures on floating-point additivity tolerance checks.

### 🤖 3. Autonomous RAG Security Copilot
- Grounded incident assistant with multi-tier failover cascade:
  1. **Groq API** (`llama-3.3-70b-versatile` — ultra-fast sub-second responses)
  2. **Google Gemini API** (`gemini-2.5-flash` — deep multi-turn reasoning)
  3. **Local Ollama** (`llama3` / `mistral` local container)
  4. **Embedded AI Expert System** (deterministic offline rulebook mapped to MITRE ATT&CK)
- **RAG Knowledge Ingestion:** Upload incident response playbooks (PDF, DOCX, TXT) to an in-memory TF-IDF cosine similarity vector store.
- **Context Binding:** Automatically binds active flow parameters (`flow_id`, IP, port, packet rates) directly into the chat prompt.
- **Analyst Modes:** Toggle between *Professional* (executive), *Concise* (rapid triage bullets), and *Technical* (deep packet dissection & shell commands).

### 📊 4. Glassmorphism SOC Command Center
- **Live Network Telemetry:** Real-time ApexCharts tracking TCP, UDP, and ICMP packet flow trends.
- **Threat Density Heatmap:** Identifies high-risk traffic spikes grouped by hour of day and weekday.
- **Protocol Distribution Donut:** Real-time breakdown of monitored protocols.
- **Slide-Over Forensic Drawer:** In-depth inspection panel with one-click edge firewall isolation commands (`iptables -A INPUT -s <IP> -j DROP`).

### 📑 5. Automated Audit & Incident Reports
- One-click export of cryptographically formatted audit logs in **PDF**, **CSV**, and structured **JSON**.
- Instant **AI Incident Brief PDF** generation (`/api/reports/ai?flow_id=...`) providing executive forensic summaries for individual attacks.

### 🧪 6. Bundled 1,500-Record Multi-Parameter Test Dataset
- Comes pre-bundled with a diverse **1,500-record dataset** (`test_dataset_1000.csv`) featuring 79 parameters across 10 distinct traffic profiles for instant drag-and-drop or CLI evaluation.

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------+
|                            PRESENTATION LAYER (UI)                                |
|  - HTML5, Tailwind CSS JIT, Space Grotesk / Inter Typography, Lucide Icons        |
|  - ApexCharts.js Dynamic Telemetry (Traffic Line, Threat Heatmap, Protocol Donut)  |
|  - Responsive Glassmorphism Shell: Sidebar Navigation, Slide-Over Forensic Drawer  |
+-----------------------------------------------------------------------------------+
                                         |  HTTP / REST JSON
                                         v
+-----------------------------------------------------------------------------------+
|                        APPLICATION LAYER (FLASK 3.0 API)                          |
|  - Blueprints: upload, prediction, dashboard, reports, shap, chat, document       |
|  - Input Validation: Werkzeug secure_filename, CSV Header & Payload Validators     |
|  - Thread-Safe SQLite3 Connection Factory & Structured Logging                    |
+-----------------------------------------------------------------------------------+
        |                                |                               |
        v                                v                               v
+------------------+           +--------------------+          +--------------------+
|   ML INFERENCE   |           |  EXPLAINABLE AI    |          |  GENERATIVE AI     |
|   & PREDICTION   |           |  (SHAP ENGINE)     |          |  & RAG COPILOT     |
| - Random Forest  |           | - TreeExplainer    |          | - Groq / Gemini /  |
| - Decision Tree  |           | - Local Force Bar  |          |   Ollama / Expert  |
| - Logistic Reg   |           | - Waterfall Steps  |          | - In-Memory TF-IDF |
| - Heuristics     |           | - Global Ranking   |          |   Vector Store     |
| - StandardScaler |           | - Surrogate Safety |          | - Playbook Parsers |
+------------------+           +--------------------+          +--------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         DATA & PERSISTENCE LAYER                                  |
|  - SQLite3 Database: `predictions`, `metrics`, `model_info`, `manual_documents`   |
|  - Vector Store: `vector_store.json` | Local Storage: `/uploads`, `/reports`      |
+-----------------------------------------------------------------------------------+
```

---

## 🔬 Core Feature Engineering (12 Features)

ThreatLens curates 12 highly discriminative features from the raw 79-column flow capture for sub-millisecond classification:

| Feature Name | Format | Significance in Cyber Threat Detection |
| :--- | :--- | :--- |
| **`Destination Port`** | Integer (0–65535) | Identifies target protocol/service (Port 22 SSH vs. Port 80/443 Web). |
| **`Flow Duration`** | Float (µs) | Distinguishes micro-burst port scans (1–50µs) from persistent DDoS connections. |
| **`Total Fwd Packets`** | Integer | Evaluates forward packet counts to detect flooding and exfiltration. |
| **`Total Length of Fwd Packets`** | Float (Bytes) | Detects heavy payload injections and jumbo-frame anomalies. |
| **`Fwd Packet Length Max`** | Float (Bytes) | Identifies single-packet anomalies or zero-byte probe packets. |
| **`Fwd Packet Length Mean`** | Float (Bytes) | Averages forward payload sizes to differentiate scripts from user sessions. |
| **`Bwd Packet Length Max`** | Float (Bytes) | Evaluates server responses and reflection amplification attacks. |
| **`Bwd Packet Length Mean`** | Float (Bytes) | Analyzes bidirectional response symmetries. |
| **`Flow Bytes/s`** | Float | Line-rate volumetric saturation indicator. |
| **`Flow Packets/s`** | Float | Packet frequency (>500 pkt/s strongly correlates with DDoS or scans). |
| **`SYN Flag Count`** | Integer (0/1) | Key indicator of TCP SYN floods and half-open stealth reconnaissance. |
| **`ACK Flag Count`** | Integer (0/1) | Validates completed handshakes vs. unsolicited probe floods. |

---

## 🛠️ Tech Stack

- **Backend:** Python 3.11+, Flask 3.0
- **Data & ML:** NumPy, Pandas, Scikit-Learn, XGBoost, LightGBM
- **Explainability:** SHAP (SHapley Additive exPlanations)
- **Generative AI:** Groq SDK, Google GenAI SDK, Requests (Local Ollama)
- **Document Processing:** PyPDF, docx2txt, ReportLab 5.0
- **Frontend:** Semantic HTML5, Vanilla JavaScript (ES6+ Modules), Tailwind CSS JIT, ApexCharts, Lucide Icons
- **Database:** Embedded SQLite3 with connection-pooling helpers

---

## 🚀 Installation & Quickstart

### 1. Prerequisites
- Python 3.11 or higher installed on your system.
- Git installed.

### 2. Clone Repository
```bash
git clone https://github.com/Sungoku-san/threat-lens-web.git
cd threat-lens-web
```

### 3. Create Virtual Environment
```bash
# Windows
py -3.11 -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables (Optional)
Copy the template configuration file:
```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```
*(ThreatLens operates out-of-the-box using its Embedded AI Expert System even without external API keys).*

### 6. Launch Application
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

- **Default Administrator Username:** `admin`
- **Default Administrator Password:** `password123`

---

## 🧪 Testing & Dataset Evaluation

### Automated Dataset Test Harness
ThreatLens includes an automated verification script that evaluates the system against the bundled **1,500-record dataset** across 4 verification phases:
```bash
python test_with_dataset.py
```
**Verification Outputs:**
- **Phase 1:** Dataset schema & parameter diversity inspection (156 unique ports, durations up to 4.95s, rates up to 1.98M pkt/s).
- **Phase 2:** Model inference throughput benchmark (~85–95 flows/second, ~11ms/record).
- **Phase 3:** SHAP local feature attribution verification across DDoS, PortScan, SSH-Patator, and Benign traffic.
- **Phase 4:** Flask REST API integration test (`/api/upload`, `/api/predict/file`, `/api/dashboard`).

### Running Full Unit Test Suite
Execute the comprehensive 17-test unit suite:
```bash
python -m unittest tests/test_backend.py
```

### Re-Generating or Expanding the Test Dataset
To generate fresh multi-parameter test datasets:
```bash
python backend/dataset/generate_test_dataset.py
```

### Model Retraining Pipeline
To retrain and evaluate the multi-model baseline:
```bash
python backend/models/train_model.py
```

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health and operational state check. |
| `GET` | `/api/dashboard` | Compiles real-time aggregated SOC metrics. |
| `GET` | `/api/recent-attacks` | Returns the 10 most recent malicious threat alerts. |
| `GET` | `/api/model-info` | Returns active machine learning model metrics & training timestamp. |
| `POST` | `/api/upload` | Uploads a CSV dataset and validates its schema. |
| `POST` | `/api/predict` | Evaluates a single network flow packet dictionary. |
| `POST` | `/api/predict/batch` | Evaluates an array of flow packets in batch. |
| `POST` | `/api/predict/file` | Parses and classifies rows from an uploaded CSV dataset. |
| `GET` | `/api/predict/history` | Fetches historical log predictions with optional filtering. |
| `GET` | `/api/shap/<flow_id>` | Retrieves pre-calculated local SHAP feature contributions. |
| `GET` | `/api/shap/importance` | Returns global feature importance rankings across all parameters. |
| `GET` | `/api/threat?ip=...` | Compiles IP and port threat intelligence. |
| `POST` | `/api/chat` | Interacts with the AI Security Copilot. |
| `GET` | `/api/chat/history` | Retrieves active session conversation memory. |
| `POST` | `/api/chat/clear` | Clears active session conversation memory. |
| `POST` | `/api/documents/upload`| Uploads manual (PDF/TXT/DOCX) into the vector store. |
| `GET` | `/api/documents/list` | Returns catalog of indexed operational manuals. |
| `GET` | `/api/manual?q=...` | Semantic vector search across incident response playbooks. |
| `GET` | `/api/reports/download` | Exports signed audit reports in `pdf`, `csv`, or `json`. |
| `GET` | `/api/reports/ai` | Generates individual AI Incident Brief PDF for a specific flow. |
| `GET` / `POST` | `/api/settings` | Reads / updates Groq and Gemini API keys. |

---

## 📁 Repository Structure

```
threat-lens-web/
├── PRD.md                             # Comprehensive Product Requirements Document
├── README.md                          # Repository Documentation & Overview
├── .gitignore                         # Strict exclusion for secrets, uploads & caches
├── .env.example                       # Environment configuration template
├── app.py                             # Application entrypoint & server bootstrap
├── requirements.txt                   # Production Python package dependencies
├── vercel.json                        # Serverless deployment configuration
├── test_dataset_1000.csv              # 1,500-record testing dataset (root copy for UI)
├── test_with_dataset.py               # Automated dataset verification & benchmark harness
├── backend/
│   ├── app.py                         # Flask factory & blueprint registration
│   ├── config.py                      # Environment configuration & path resolvers
│   ├── AI/                            # Generative AI & RAG Subsystem
│   │   ├── chatbot.py                 # Multi-turn SOC conversational handler
│   │   ├── conversation_memory.py     # Session history state management
│   │   ├── document_loader.py         # PDF / DOCX / TXT text chunker
│   │   ├── embedding_service.py       # TF-IDF & Cosine similarity vectorizer
│   │   ├── knowledge_base.py          # Cybersecurity knowledge base articles
│   │   ├── llm_service.py             # Multi-tier cascade (Groq / Gemini / Ollama / Expert)
│   │   ├── manual_search.py           # Vector search across playbooks
│   │   ├── rag_engine.py              # Retrieval-Augmented Generation pipeline
│   │   ├── recommendation_engine.py   # Incident response playbook mapper
│   │   ├── report_generator.py        # AI incident PDF report compiler
│   │   ├── threat_analyzer.py         # Flow risk assessment & threat analysis
│   │   └── vector_store.py            # In-memory document chunk indexer
│   ├── database/
│   │   ├── database.db                # Pre-seeded SQLite3 database
│   │   └── vector_store.json          # Pre-indexed document vector embeddings
│   ├── dataset/
│   │   ├── CICIDS2017.csv             # Baseline reference dataset
│   │   ├── generate_sample.py         # Baseline sample generator
│   │   ├── generate_test_dataset.py   # 1,500-record multi-parameter test generator
│   │   └── test_network_flows_1500.csv# Master 1,500-record test dataset
│   ├── models/
│   │   ├── feature_engineering.py     # 12-feature extraction & payload mapping
│   │   ├── preprocess.py              # StandardScaler & LabelEncoder preprocessors
│   │   ├── predict.py                 # ML inference & heuristic failover logic
│   │   ├── shap_explainer.py          # SHAP TreeExplainer & surrogate fallbacks
│   │   ├── train_model.py             # Multi-model training pipeline
│   │   ├── train_models.py            # Comparative training suite with XGBoost/LGBM
│   │   ├── compare_models.py          # Comparative evaluation plotter
│   │   ├── evaluate_models.py         # Classification metrics calculator
│   │   ├── model.pkl                  # Serialized active production classifier
│   │   ├── scaler.pkl                 # Serialized feature StandardScaler
│   │   └── label_encoder.pkl          # Serialized LabelEncoder
│   ├── routes/                        # Flask Blueprints
│   │   ├── chat.py                    # /api/chat endpoints
│   │   ├── dashboard.py               # /api/dashboard & telemetry endpoints
│   │   ├── document.py                # /api/documents upload & indexing
│   │   ├── knowledge.py               # /api/knowledge articles query
│   │   ├── manual.py                  # /api/manual vector search
│   │   ├── prediction.py              # /api/predict single & batch endpoints
│   │   ├── reports.py                 # /api/reports PDF/CSV/JSON exports
│   │   ├── shap.py                    # /api/shap local & global importance
│   │   ├── threat.py                  # /api/threat external intelligence
│   │   └── upload.py                  # /api/upload dataset endpoint
│   ├── services/                      # Application Business Logic
│   ├── static/                        # Frontend CSS, JS & Assets
│   │   ├── css/                       # Custom Tailwind & glassmorphism stylesheets
│   │   └── js/dashboard.js            # Frontend event orchestrator & ApexCharts logic
│   ├── templates/                     # Jinja2 HTML Templates
│   │   ├── base.html                  # Base HTML layout & asset imports
│   │   ├── landing.html               # Public CyberIDS landing page
│   │   ├── login.html                 # SOC analyst login portal
│   │   └── dashboard.html             # Command Center UI & Slide-over Drawer
│   ├── uploads/                       # User upload directory (.gitkeep)
│   └── utils/                         # Validation, Logging & DB Helpers
└── tests/
    └── test_backend.py                # Comprehensive 17-test unit suite
```

---

## 🔒 Security & Governance

- **Credential Hygiene:** All secrets, private keys, API keys, and session cookies are excluded from version control via `.gitignore`.
- **Input Sanitization:** Uploaded files are strictly filtered for `.csv` format and sanitized via Werkzeug `secure_filename()`.
- **Stateless Resilience:** Thread-safe SQLite connection handles prevent cross-thread deadlocks during concurrent stream ingestion.
- **Fail-Safe Operation:** Guaranteed uptime via cascading fallback logic across machine learning, explainability, and LLM tiers.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

*ThreatLens (CYBERIDS) — Developed for Next-Gen Security Operations Centers.*
