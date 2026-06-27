# 🛡️ CyberGuard

> **AI-Powered Cybersecurity Orchestration Platform**

CyberGuard is a next-generation AI-driven cybersecurity platform developed for the **HACKVERSE Hackathon**. It unifies offensive security tools, threat intelligence, attack surface management, infrastructure security, Android application security, and Large Language Models (LLMs) into one intelligent cybersecurity ecosystem.

Unlike traditional scanners, CyberGuard doesn't simply identify vulnerabilities—it correlates findings, builds attack paths, prioritizes risks, generates exploitability analysis, and provides AI-assisted remediation.

---

# 🚀 Features

## 📊 Centralized Security Dashboard

A modern Pentration Testing Engine with dashboard providing complete visibility into the organization's security posture.

### Features

- Real-time Risk Score
- Active Assets
- Scan Status
- Running Tasks
- Recent Findings
- AI Security Summary
- Executive Overview
- Security Metrics

**Tech Stack**

- React (Vite)
- Glassmorphism UI
- FastAPI
- MongoDB

---

## 🚀 Infrastructure Vulnerability Scanner

Launch enterprise-grade vulnerability assessments.

### Supported Scanners

- Nmap
- Acunetix DAST

### Background Processing

- Celery
- Redis
- Async FastAPI

### Features

- Background execution
- Scan scheduling
- Live logs
- WebSocket streaming
- Distributed workers

---

## 🌍 Attack Surface Management

Complete external attack surface discovery.

### Recon Modules

- Subdomain Discovery
- DNS Enumeration
- WHOIS
- HTTP Fingerprinting
- Port Scanning
- Service Detection
- SSL Analysis
- CDN Detection
- Technology Detection

Provides a complete hacker's-eye view of your infrastructure.

---

## 🧠 AI Security Engine

CyberGuard integrates modern Large Language Models.

### Supported Models

- Ollama
- OpenAI
- Local LLMs

### AI Features

- Vulnerability Explanation
- AI Risk Analysis
- Root Cause Analysis
- Exploitability Assessment
- AI-generated Remediation
- Executive Summary Generation

---

## 🤖 LLM Security Scanner

Built-in AI Red Team for Large Language Models.

### Detects

- Prompt Injection
- Jailbreaks
- Data Leakage
- Prompt Extraction
- Hallucinations
- Unsafe Tool Usage
- Sensitive Information Disclosure

Powered by **Cyberguard** and custom security probes.

---

## 🔎 CVE Lookup & Threat Intelligence

Real-time vulnerability intelligence.

### Integrations

- NIST NVD
- CVSS v3.1
- MITRE ATT&CK
- Exploit References

### Features

- CVE Search
- CVSS Scores
- AI Explanation
- Attack Mapping
- Vulnerability Correlation

---

## 🌐 Global Threat Intelligence

Continuously monitors

- NVD
- MITRE
- Rapid7
- Public Threat Feeds

Automatically correlates

```
Threat Feed
      ↓
Asset Inventory
      ↓
Affected Systems
      ↓
Risk Analysis
      ↓
Alert Generation
```

---

## 📋 Scan Result Normalization

Consolidates findings from multiple scanners into a unified schema.

### Features

- Vulnerability Normalization
- Severity Correlation
- MITRE ATT&CK Mapping
- AI Prioritization
- Duplicate Detection

---

## 📈 Attack Graph Visualization

Visualizes complete attack paths using graph relationships.

Powered by

- Neo4j
- D3.js

Example

```
Internet
      ↓
Web Server
      ↓
RCE
      ↓
Database
      ↓
Credential Dump
      ↓
Domain Controller
```

---

## 🕵 Credential Leak Monitoring

Monitors

- Public Breach Databases
- Dark Web Sources
- Leaked Credentials
- Exposed API Keys
- Corporate Accounts

Provides early warning before attackers exploit exposed credentials.

---

# 📱 Mobile Security Analysis

Enterprise-grade Android Security Scanner integrated into CyberGuard.

Combines

- Static Analysis
- Dynamic Analysis
- Bytecode Analysis
- Taint Analysis
- Exploit Validation
- AI Triage

---

## 🔍 Manifest Analysis

Over **222 XPath-based security rules**

Detects

- Exported Components
- Dangerous Permissions
- Backup Configuration
- Debuggable Apps
- Deep Links
- Network Security
- Intent Filters
- Third-party SDK Risks

---

## 💻 Source Code Analysis

Over **198 Source Detection Rules**

Detects

- Hardcoded Secrets
- Weak Cryptography
- SQL Injection
- Path Traversal
- WebView Issues
- Authentication Weaknesses
- Insecure Storage
- Logging Issues
- Dynamic Code Loading

---

## ⚡ Advanced Bytecode Analysis

Powered by **Androguard**

Features

- Control Flow Graph
- Call Graph
- Cross References
- String Analysis
- Dalvik Instruction Analysis

Includes over **136 Advanced Detectors**

---

## 🔄 Taint Analysis Engine

Interprocedural Data Flow Analysis

Supports

- 60+ Sources
- 10 Sink Categories
- Field-sensitive Tracking
- Method Summaries
- Sanitization Detection

---

## 🔗 Component Graph

Automatically builds Android attack surface.

```
Activities
      ↓
Services
      ↓
Receivers
      ↓
Providers
      ↓
Deep Links
      ↓
Attack Paths
```

---

## 🧩 Android CVE Detection

Automatically

- Downloads Android CVEs
- Generates Detection Rules
- Matches CPE
- Parses Patch Diffs
- Maintains Local Cache

---

## 🎯 Dynamic Analysis

Supports

- Storage Inspection
- IPC Fuzzing
- UI Exploration
- Runtime Monitoring
- WebView Testing

---

## 🎭 Frida Runtime Analysis

Includes

- SSL Pinning Bypass
- Root Detection Bypass
- Runtime Hooks
- API Monitoring
- SharedPreferences Monitoring

---

## 📲 Emulator Automation

Automatically

- Launch Emulator
- Install APK
- Deploy Frida
- Execute PoCs
- Capture Screenshots
- Record Videos

---

## 💥 Exploit Generation

Automatically generates

- ADB PoCs
- Frida PoCs
- Drozer Payloads

Supports

- Exploit Validation
- Screenshot Comparison
- Video Recording

---

## ⛓ Attack Chain Engine

Automatically builds exploit chains.

Example

```
Exported Activity
        ↓
Intent Injection
        ↓
WebView RCE
        ↓
Token Theft
        ↓
Account Takeover
```

Additional chains

- Privilege Escalation
- Backup Extraction
- Content Provider Abuse
- Deep Link Exploitation
- Task Hijacking

---

## 🤖 AI Triage

Each finding is automatically analyzed using AI.

Provides

- Exploitability
- Attack Vector
- Business Impact
- Difficulty
- Priority
- AI-generated Remediation

Powered by Ollama.

---

# 💬 AI Security Assistant (RAG)

A context-aware cybersecurity assistant.

Powered by

- ChromaDB
- Sentence Transformers
- Ollama/OpenAI

Capabilities

- Explain Vulnerabilities
- Generate Fixes
- Explain CVEs
- MITRE Guidance
- Report Analysis
- Step-by-step Remediation

---

# 📄 Reporting

Automatically generates

- Executive Reports
- Technical Reports
- AI Summaries
- MITRE Mapping
- Attack Graphs
- Screenshots
- Exploit Evidence

Supported Formats

- HTML
- PDF
- SARIF

---

# ⚙ Task Monitor

Enterprise-grade task orchestration.

Tracks

- Pending
- Running
- Completed
- Failed

Supports distributed workers and concurrent scans.

---

# 🛠 Tech Stack

## Frontend

- React (Vite)
- Vanilla CSS
- D3.js
- React Router

## Backend

- FastAPI
- MongoDB
- Redis
- Celery
- Neo4j

## Security Tools

- Nmap
- Acunetix
- Garak
- MobSF
- Androguard
- Frida
- JADX
- ADB
- FFmpeg

## AI Stack

- Ollama
- OpenAI
- ChromaDB
- Sentence Transformers

---

# 🏗 System Architecture

```
                     React Dashboard
                           │
             ──────────────┼──────────────
                           │
                     FastAPI Backend
                           │
        ┌──────────┬──────────┬──────────┐
        │          │          │          │
     MongoDB     Redis      Neo4j     ChromaDB
        │          │          │          │
        └──────────┼──────────┴──────────┘
                   │
            Celery Workers
                   │
 ┌─────────────────┼────────────────────┐
 │                 │                    │
Nmap          Acunetix          Mobile Scanner
 │                 │                    │
 └────────────── Findings Normalizer ───┘
                   │
           MITRE Mapping Engine
                   │
          Attack Graph Generator
                   │
            AI Risk Assessment
                   │
          Reports + Dashboard
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/drishtigupta06/Hackverse.git

cd hacknova_ps
```

## Backend

```bash
cd backend

pip install -r requirements.txt

uvicorn main:app --reload --port 8000
```

## Frontend

```bash
cd frontend

npm install

npm run dev
```

Configure `.env`

```
MONGODB_URI=
REDIS_URL=
NEO4J_URI=
OLLAMA_HOST=
OPENAI_API_KEY=
NVD_API_KEY=

```

---

# 🏆 Highlights

- AI-Powered Vulnerability Assessment
- Infrastructure Security Scanning
- Android Security Analysis
- LLM Security Testing
- Threat Intelligence Correlation
- Attack Graph Visualization
- AI Risk Prioritization
- AI Security Assistant
- Enterprise Reporting
- MITRE ATT&CK Mapping
- Distributed Scan Orchestration
- Mobile Application Pentesting

---

# ❤️ HACKVERSE Hackathon

CyberGuard demonstrates how Artificial Intelligence, Graph Databases, Threat Intelligence, Infrastructure Security, Android Security, and Offensive Security can be unified into one intelligent cybersecurity platform capable of identifying, correlating, prioritizing, and explaining security risks in real time.
