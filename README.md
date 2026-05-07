# Randscript

A curated toolkit of utility scripts and tools for **AI/LLM development**, **security research**, **web archiving**, and **automation**. This repository serves as a research laboratory for experimenting with local AI agents and offensive security techniques.

## 📁 Project Structure

```
randscript/
├── rag-agent/          # Local RAG system with Ollama & PGVector ⭐
├── scanner/            # Automated XSS vulnerability scanner
├── ai_llm/             # LLM operational skills & prompt workflows
│   └── skills/
│       ├── scode/          # Bug bounty workflow (28 vulnerability scanners)
│       ├── ptest/          # Penetration testing framework with gateway system
│       └── parse-finding/  # Security finding → Jira converter
├── winapi/             # Windows API research & reverse engineering
├── secops/             # Security operations (email forensics)
└── asmin/              # Archived Asmaul Husna website (2020)
```

---

## 🚀 Components

### [rag-agent/](rag-agent/) ⭐ Featured
**Retrieval Augmented Generation (RAG) system** designed for local, offline deployment.

**Key Technical Features:**
- 🧠 **Local LLM Orchestration** — Powered by `PydanticAI` and Ollama (Mistral, Llama 3.2, Qwen).
- 📄 **High-Fidelity Ingestion** — Uses **Docling** to parse PDF, Word, PowerPoint, and Excel into clean Markdown.
- 🎙️ **Audio RAG** — Integrated Whisper ASR for speech-to-text ingestion.
- ⚡ **Semantic Chunking** — Implements LLM-driven semantic splitting with a rule-based fallback to maintain context.
- 🌐 **Knowledge Base** — PostgreSQL with **PGVector** for cosine similarity semantic search.
- 🕷️ **Web Crawler** — Recursive crawler (via crawl4ai) to ingest documentation sites directly into the knowledge base.
- 💻 **Interfaces** — Modern FastAPI Web UI and a rich CLI with streaming responses.

**Quick Start:**
```bash
cd rag-agent
uv sync
cp .env.example .env
# Configure DATABASE_URL and Ollama settings
uv run python web_app.py    # Web UI at localhost:8000
uv run python cli.py        # CLI interface
```

**Tech:** Python 3.10+, Ollama, Docling, Whisper, PostgreSQL, PGVector, FastAPI, PydanticAI, crawl4ai, Docker

---

### [scanner/](scanner/)
**Automated XSS vulnerability scanner** for API security testing.

**Features:**
- Parses OpenAPI/Swagger specifications to identify injectable endpoints.
- Tests endpoints with 9 common XSS payloads.
- Simple reflection-based detection.
- Email notification support and HTML report generation.

**Quick Start:**
```bash
cd scanner
python xss_scanner.py
```

**Tech:** Python, requests, PyYAML

---

### [ai_llm/](ai_llm/)
**LLM Operational Skills** — Structured prompt workflows for security and engineering tasks.

These are not simple prompts — they are structured workflows containing processes, tool definitions, and operational guides designed for AI-assisted security work.

#### scode/ — Bug Bounty Workflow
A comprehensive 5-phase bug bounty methodology with 28 specialized vulnerability scanners:

| Phase | Skill | Purpose |
|-------|-------|---------|
| 1 | `sc1-recon` | Map codebase structure, entry points, frameworks, data flows |
| 2 | `sc2-threat-model` | Threat modelling based on recon output |
| 3 | `sc3-vuln-scan` | Orchestrator that runs all vulnerability sub-scanners |
| 4 | `sc4-validate` | Validate findings, eliminate false positives |
| 5 | `sc5-report` | Compile polished bug bounty report |

**Vulnerability Sub-Scanners (Phase 3):**
- **Web:** Injection, Access Control, Data Exposure, SSRF, Deserialization, Misconfig, Logic, Auth/Session, Crypto, File/Path, Client-Side, Dependency, API, DoS, Memory
- **Web3/Smart Contracts:** Reentrancy, Arithmetic, Access/Proxy, MEV/Flash Loans, Token/Signature, DeFi, NFT, EVM/Assembly

#### ptest/ — Penetration Testing Framework
A structured pentest framework with a **Gateway System** (quality gates) that enforces methodical progression:

```
Gateway (Quality Gate) → Phase (Pentest Stage) → Tasks (Techniques)
```

Phases: Passive Recon → Active Recon → Exploitation → Post-Exploitation → Reporting

No phase can begin until the previous gateway is passed with user sign-off.

#### parse-finding/ — Finding → Jira Converter
Converts raw security findings (Markdown, HTML, Jira XML exports with screenshots) into structured reports ready for Jira Cloud paste.

**Tech:** Markdown, Prompt Engineering

---

### [winapi/](winapi/)
**Windows API research and reverse engineering tools** for educational purposes.

**Contents:**
- **gcheats/** — Anti-cheat PoCs: Process scanning, file hashing (SHA-256), and malicious process termination.
- **idafreekei.py** — Technical implementation of an IDA Pro license generator using RSA modulus patching.

**⚠️ Legal Notice:** These tools are for **educational and research purposes only**. Understand your local laws before using reverse engineering tools.

**Tech:** Python, C++, C#, Windows API

---

### [secops/](secops/)
**Security operations tools** for email analysis and forensics.

**Files:**
- `emlckr.html` — Client-side tool for analyzing `.eml` files (SPF/DKIM/DMARC analysis, URL defanging, and phishing detection).

**Tech:** HTML, JavaScript

---

### [asmin/](asmin/)
**Archived website** — Complete preservation of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), archived on July 7, 2020.

**Note:** Copyright belongs to the original website owners. This archive is preserved for educational and historical purposes.

---

## 🛠️ Tech Stack Summary

| Domain | Technologies |
|--------|-------------|
| **Backend** | Python 3.10+, PostgreSQL, PGVector, FastAPI, AsyncIO, PydanticAI |
| **AI/ML** | Ollama, Docling, Whisper, crawl4ai, Hugging Face |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **DevOps** | Docker, Docker Compose, UV package manager |
| **Systems** | C++, C# (Windows API, game hooks) |

---

## 📦 Installation & Setup

### Prerequisites
- **Python 3.10+** (3.11+ recommended)
- **UV** package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Ollama** for local LLM (`brew install ollama` on macOS)
- **PostgreSQL with PGVector** extension

### General Setup
```bash
# Clone the repository
git clone https://github.com/n4igme/randscript.git
cd randscript

# Navigate to any component and install dependencies
cd rag-agent
uv sync
```

---

## 🎯 Quick Start Guide

### 1. RAG Agent (Recommended Starting Point)
```bash
cd rag-agent
uv sync
cp .env.example .env

# Edit .env with your settings:
# DATABASE_URL=postgresql://raguser:ragpass@localhost:5432/postgres
# OPENAI_API_KEY=ollama
# OPENAI_BASE_URL=http://localhost:11434/v1
# LLM_CHOICE=qwen2.5-coder

# Pull Ollama models
ollama pull qwen2.5-coder
ollama pull nomic-embed-text

# Option A: Docker (recommended)
docker compose up -d

# Option B: Manual
# Set up database (run sql/schema.sql in PostgreSQL)
uv run python web_app.py
```

### 2. XSS Scanner
```bash
cd scanner
python xss_scanner.py
```

### 3. LLM Security Skills
```bash
# Explore the structured workflows in ai_llm/skills/
# scode/ for bug bounty, ptest/ for pentesting
```

---

## 📚 Documentation

| Component | Documentation |
|-----------|--------------|
| rag-agent | [README.md](rag-agent/README.md), [WEB_INTERFACE.md](rag-agent/dev_logs/WEB_INTERFACE.md) |
| rag-agent web crawler | [web_crawler/README.md](rag-agent/web_crawler/README.md) |
| rag-agent tutorials | [docling_basics/](rag-agent/docling_basics/) |
| ai_llm/scode | [skills/scode/](ai_llm/skills/scode/) |
| ai_llm/ptest | [GATEWAY_SYSTEM.md](ai_llm/skills/ptest/GATEWAY_SYSTEM.md) |
| ai_llm/parse-finding | [README.md](ai_llm/skills/parse-finding/README.md) |
| scanner | Inline comments in [xss_scanner.py](scanner/xss_scanner.py) |

---

## ⚠️ Legal & Ethical Notice

This repository is intended for **educational and research purposes only**:

- **scanner/** — Use only on systems you own or have explicit permission to test
- **winapi/** — Reverse engineering tools may be subject to local laws and software licenses
- **ai_llm/scode/** — Bug bounty skills should only be used on authorized targets
- **ai_llm/ptest/** — Penetration testing requires explicit written authorization

**Always:**
- ✅ Test only systems you own or have authorization for
- ✅ Comply with all applicable laws and regulations
- ✅ Respect software licenses and terms of service
- ✅ Use security tools responsibly and ethically

---

## 📄 License

**MIT License** — See [LICENSE](LICENSE) file for details.

**Exceptions:**
- `asmin/` — Copyright of original website owners (archived for preservation)
- `winapi/idafreekei.py` — WTFPL (Do What The Fuck You Want To Public License)

---

## 🙏 Acknowledgments

- **rag-agent/** inspired by [coleam00/ottomator-agents](https://github.com/coleam00/ottomator-agents)
- Security prompts and templates based on industry best practices
- All open-source libraries and frameworks used in this project

---

**Made with ❤️ for learning, research, and experimentation**
