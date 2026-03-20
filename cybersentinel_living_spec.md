# 🛡️ CyberSentinel — Living Specification
**Version:** v1.0  
**Status:** Authoritative / Single Source of Truth  
**Last Updated:** 2026-01-16  

---

## 1. Vision & Identity

CyberSentinel is an **AI-driven application and system security monitoring platform** designed to detect known attacks and unknown anomalies from logs using **classical Machine Learning**, while assisting human analysts through **sandboxed agentic AI reasoning**.

The system is designed to position its creator as an **AI Security Engineer**, demonstrating:
- Practical ML-based detection
- Secure backend architecture
- Real-time monitoring
- Human-in-the-loop agentic AI
- Strong security and governance principles

CyberSentinel prioritizes **explainability, safety, and architectural clarity** over blind automation.

---

## 2. System Boundaries & Non-Goals

### In Scope
- Log ingestion via REST API
- Batch-based ML inference
- Anomaly and attack detection using classical ML
- Immutable alert generation
- Real-time alert delivery to frontend
- Secure authentication with 2FA
- Optional agentic AI for investigation assistance
- Dockerized deployment

### Explicitly Out of Scope (v1)
- Autonomous remediation or response
- Agentic AI for detection or control
- LLM-based ML models
- Multi-tenant users
- Self-modifying systems
- External SOC integrations

These boundaries are intentional to ensure **safety, clarity, and implementability**.

---

## 3. High-Level Architecture

```
Log Sources
 (Apps / Systems)
      |
      | REST API
      v
+---------------------+
| Log Ingestion Layer |
+---------------------+
          |
          v
+---------------------+
| Log Storage (Mongo) |
+---------------------+
          |
   Batch Trigger
          |
          v
+---------------------+
| ML Detection Engine |
|  - Feature Extract |
|  - RF / IF Models |
|  - Hybrid Logic   |
+---------------------+
          |
          v
+---------------------+
| Alert Manager       |
| (Immutable Alerts) |
+---------------------+
          |
     WebSockets
          |
          v
+---------------------+
| Frontend Dashboard |
+---------------------+

(Read-only)
          |
          v
+------------------------------+
| Investigation Planning Agent |
+------------------------------+
```

---

## 4. Data Model & Lifecycles

### Logs
- High-volume
- Stored as raw and/or preprocessed
- Immutable
- Used as input for ML only

### Alerts
- Low-volume
- Derived from ML decisions
- Immutable once created
- Can be acknowledged, not deleted
- Primary unit for analysis and display

### ML Models
- Versioned
- Integrity-verified
- Loaded once per runtime
- Rollback supported

### Agent Outputs
- Ephemeral
- Advisory only
- Not persisted as system state

---

## 5. Machine Learning Design (Authoritative)

### Models Used
- **Random Forest:** Known attack classification
- **Isolation Forest:** Unknown anomaly detection

### Feature Philosophy
- Centralized feature extraction
- Identical logic for training and inference
- No feature duplication

### Inference Strategy
- Batch-triggered only
- No real-time per-log detection
- Supports aggregation and noise reduction

### Hybrid Decision Logic
- RF positive → escalate
- IF positive → escalate
- Both positive → high severity
- Conflict → medium severity
- Both negative → benign

### Retraining Policy
- Manual trigger only
- Dataset validation required
- Versioned artifacts
- Rollback supported
- No inference downtime

---

## 6. Agentic AI Design

### Purpose
The agentic AI exists **only to assist human analysts**, not to control or automate the system.

### Agent Role
**Investigation Planning Agent**
- Consumes alert metadata
- Produces investigation guidance
- Suggests next steps
- Provides structured reasoning

### Agent Constraints
- No write access
- No remediation authority
- No ML control
- No database access
- Minimal, structured context only

### Architectural Choice
- Agent is implemented as a **separate service/repository**
- Communicates via read-only APIs or exported alert data
- Fully optional and isolated

---

## 7. Security Model

### Authentication & Authorization
- Email + Password
- TOTP-based 2FA
- JWT sessions
- Single admin user (v1)

### Agent Sandboxing
Sandboxing is enforced through:
- Architectural isolation
- Read-only data access
- Prompt-level guardrails
- Absence of system credentials

### Auditability
- All alerts are immutable
- Agent actions are logged
- Model integrity verified via hashing

### Human-in-the-Loop
- All critical decisions remain human-controlled
- Agent output is advisory only

---

## 8. Change Policy

This document is the **authoritative reference** for CyberSentinel.

### Requires Spec Update
- ML model changes
- Agent capability changes
- Security model changes
- Architecture changes

### Does NOT Require Spec Update
- Internal refactoring
- Performance tuning
- UI changes

All future development must align with this specification.

---

## Appendix A — Backend System Prompt
*(Placeholder — to be appended)*

---

## Appendix B — Agent System Prompt
*(Placeholder — to be appended)*
