You are a Senior Backend Architect, ML Systems Engineer, and Security Engineer with experience in SOC tooling, anomaly detection systems, and agentic AI design.

You are building the COMPLETE backend system for a final-year project named **CyberSentinel**.

This system is primarily a **classical Machine Learning–based security monitoring platform** with a **limited, sandboxed agentic AI assistant** (sitting as a sibling to current repo, called CyberSentinel-Agentic-AI).

You must strictly follow all constraints below.
Do NOT invent features.
Do NOT merge components.
Do NOT simplify architecture.
Assume this system will be reviewed by professors, security engineers, and recruiters.

--------------------------------------------------
SYSTEM OVERVIEW
--------------------------------------------------

CyberSentinel detects security anomalies from logs using classical ML and assists analysts using a sandboxed agentic AI (sitting in a seperate repo).

The system:
- Ingests logs via REST API and Kafka
- Stores logs and alerts separately
- Performs batch-based ML inference
- Generates immutable alerts
- Pushes alerts to frontend via WebSockets
- Provides secure authentication with 2FA
- Includes an optional Investigation Planning Agent
- Is fully Dockerized
- Uses MongoDB

This system is NOT:
- Fully autonomous
- Agentic for detection
- LLM-based for ML decisions
- Auto-remediating
- Multi-tenant (single admin v1)

--------------------------------------------------
TECH STACK (LOCKED)
--------------------------------------------------

Backend: Python 3.9+
Framework: FastAPI
Database: MongoDB
Messaging: Apache Kafka
ML: scikit-learn (Isolation Forest, Random Forest)
Realtime: WebSockets
Auth: JWT + Email/Password + TOTP
Agentic AI: External, sandboxed agent service
Deployment: Docker + docker-compose

--------------------------------------------------
CORE ARCHITECTURAL PRINCIPLES
--------------------------------------------------

- Modular, clean architecture
- Clear separation of concerns
- All code must be readable, commented, and scalable
- ML detection and agentic reasoning are SEPARATE
- ML handles detection ONLY
- Agent handles reasoning ONLY
- No agent can modify system state
- Alerts are derived artifacts, not logs
- Alerts are immutable once created
- Business logic lives in services
- ML logic must not be in API routes
- Feature extraction must be reusable
- Retraining is manual and versioned
- All agent behavior is human-in-the-loop
- Add a detailed logging service and based on a flag `detailed_logging` or `debug_mode`, detailed logging should be enabled for debugging purposes, otherwise limited logging should be there

--------------------------------------------------
INGESTION REQUIREMENTS
--------------------------------------------------

- Support REST-based JSON log ingestion
- Support Kafka-based ingestion
- Both ingestion paths must feed the SAME ingestion service
- ML logic must not depend on ingestion source

--------------------------------------------------
ML REQUIREMENTS
--------------------------------------------------

- Classical ML only (no LLMs for detection)
- Models:
  - Isolation Forest (anomaly detection)
  - Random Forest (known attack classification)
- Hybrid decision logic must be explicit
- Batch-triggered inference only
- Model integrity verification required
- Retraining:
  - Manual trigger
  - Versioned models
  - Rollback supported

--------------------------------------------------
AGENTIC AI REQUIREMENTS (LIMITED & SANDBOXED)
--------------------------------------------------

The system includes an **Investigation Planning Agent**. (NOTE: Agent will be in a different repo, sitting as a sibling to current repo, called CyberSentinel-Agentic-AI AND ANY CORE AGENT RELATED CODE WILL GO IN THAT REPO, THIS REPO WILL USE THAT AGENT AND BOTH WILL CONNECT)

The agent:
- Does NOT detect attacks
- Does NOT modify data
- Does NOT retrain models
- Does NOT perform remediation
- ONLY provides investigation guidance

Agent responsibilities:
- Accept alert metadata as structured input
- Reason about investigation steps
- Output a structured investigation plan

Agent constraints:
- Read-only context
- Minimal context only (no raw logs)
- No direct DB access
- No internal service access
- No network calls beyond LLM

Agent implementation:
- Must exist in a SEPARATE repository or module (sitting as a sibling to current repo, called CyberSentinel-Agentic-AI)
- Must include:
  - Orchestrator
  - Context builder
  - Planner agent
  - system_prompt.md

--------------------------------------------------
SECURITY REQUIREMENTS
--------------------------------------------------

- Strong authentication with TOTP
- Password hashing
- JWT-based sessions
- Agent sandboxing enforced by architecture
- Agent audit logging required
- Model integrity hashing required
- Prompt-injection-aware design
- Human-in-the-loop enforced everywhere

--------------------------------------------------
DIRECTORY STRUCTURE (MANDATORY)
--------------------------------------------------

cybersentinel-backend/
│
├── app/
│   ├── main.py
│   ├── core/
│   │   ├── config.py
│   │   ├── security.py
│   │   └── websocket.py
│   ├── db/
│   │   ├── mongo.py
│   │   └── repositories/
│   ├── routes/
│   │   ├── auth.py
│   │   ├── logs.py
│   │   ├── alerts.py
│   │   ├── ml.py
│   │   └── health.py
│   ├── services/
│   │   ├── ingestion_service.py
│   │   ├── alert_service.py
│   │   ├── auth_service.py
│   │   └── ml_service.py
│   ├── ml/
│   │   ├── features/
│   │   ├── inference/
│   │   ├── training/
│   │   ├── retraining/
│   │   └── models/
│   ├── schemas/
│   ├── utils/
│   └── tests/
│
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── SETUP.md
└── TODOS.md

--------------------------------------------------
DOCUMENTATION REQUIREMENTS
--------------------------------------------------

You MUST generate:
- README.md
- SETUP.md
- TODOS.md

Documentation must explain:
- Architecture
- ML pipeline
- Agent boundaries
- Security decisions

--------------------------------------------------
FINAL OUTPUT
--------------------------------------------------

Generate REAL, production-quality code.
Add comments explaining WHY.
Use placeholders only where unavoidable.
Do NOT explain your output.
Do NOT ask questions. (ONLY ASK WHERE AMBIGUITY OR ADD QUESTIONS AS CODE COMMENTS AND AT THE END JUST TELL ME TO LOOK FOR ALL THOSE WITH A SPECIFIC PATTERN)
JUST BUILD THE SYSTEM.
GIVE ME EXACT SETUP STEPS TO RUN. EACH AND EVERY STEP