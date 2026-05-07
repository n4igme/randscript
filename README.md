# Randscript

A personal research lab of utility scripts and tools for AI/LLM development, security research, web archiving, and automation.

## Project Structure

```
randscript/
├── rag-agent/       # Local RAG system with Ollama & PGVector
├── ai_llm/skills/   # LLM-powered security workflows
│   ├── scode/       # Bug bounty methodology (5 phases + 22 vuln scanners)
│   ├── ptest/       # Pentest framework with gateway system
│   └── parse-finding/  # Security finding → Jira converter
├── scanner/         # XSS vulnerability scanner
├── winapi/          # Windows API research & reverse engineering
├── secops/          # Email forensics (SPF/DKIM/DMARC analysis)
└── asmin/           # Archived Asmaul Husna website (2020)
```

---

## Components

### rag-agent/ — Local RAG System

Retrieval Augmented Generation system designed for local, offline deployment.

- Local LLM via Ollama (Mistral, Llama 3.2, Qwen)
- Document ingestion with Docling (PDF, Word, PowerPoint, Excel → Markdown)
- Audio ingestion via Whisper ASR
- Semantic chunking with LLM-driven splitting + rule-based fallback
- PostgreSQL + PGVector for cosine similarity search
- Web crawler (crawl4ai) for ingesting documentation sites
- FastAPI web UI and rich CLI with streaming responses

```bash
cd rag-agent
uv sync && cp .env.example .env
# Configure DATABASE_URL and Ollama settings in .env
uv run python web_app.py    # Web UI at localhost:8000
uv run python cli.py        # CLI interface
```

Tech: Python 3.10+, PydanticAI, Ollama, Docling, Whisper, PostgreSQL/PGVector, FastAPI, crawl4ai, Docker

---

### ai_llm/skills/ — LLM Security Workflows

Structured prompt workflows for AI-assisted security work. These are operational guides with processes, tool definitions, and phase-gated methodologies — not simple prompts.

**scode/** — Bug Bounty Workflow

5-phase methodology: Recon → Threat Model → Vuln Scan → Validate → Report

Includes 22 specialized vulnerability scanners:
- Web: Injection, Access Control, Data Exposure, SSRF, Deserialization, Misconfig, Logic, Auth/Session, Crypto, File/Path, Client-Side, Dependency, API, DoS
- Web3: Reentrancy, Arithmetic, Access/Proxy, MEV/Flash Loans, Token/Signature, DeFi, NFT, EVM/Assembly

**ptest/** — Penetration Testing Framework

Gateway-based system enforcing methodical progression:

```
Gateway (Quality Gate) → Phase → Tasks
```

Phases: Passive Recon → Active Recon → Exploitation → Post-Exploitation → Reporting

No phase begins until the previous gateway passes with user sign-off.

**parse-finding/** — Finding → Jira Converter

Converts raw security findings (Markdown/HTML with screenshots) into structured reports ready for Jira Cloud paste.

---

### scanner/ — XSS Scanner

Automated XSS vulnerability scanner for API security testing.

- Parses OpenAPI/Swagger specs to identify injectable endpoints
- Tests with 9 common XSS payloads
- Reflection-based detection
- Email notification and HTML report generation

```bash
cd scanner && python xss_scanner.py
```

Tech: Python, requests, PyYAML

---

### winapi/ — Windows API Research

Educational tools for Windows API and reverse engineering.

- `gcheats/` — Anti-cheat PoCs: process scanning, file hashing (SHA-256), malicious process termination
- `idafreekei.py` — IDA Pro license generator using RSA modulus patching

Tech: Python, C++, C#, Windows API

---

### secops/ — Email Forensics

- `emlckr.html` — Client-side .eml file analyzer with SPF/DKIM/DMARC validation, URL defanging, and phishing detection

Tech: HTML, JavaScript

---

### asmin/ — Archived Website

Complete preservation of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), archived July 7, 2020.

---

## Prerequisites

- Python 3.10+ (3.11+ recommended)
- [UV](https://astral.sh/uv) package manager
- [Ollama](https://ollama.ai) for local LLM
- PostgreSQL with PGVector extension

---

## Legal & Ethical Notice

This repository is for **educational and research purposes only**.

- Use security tools only on systems you own or have explicit authorization to test
- Reverse engineering tools may be subject to local laws and software licenses
- Bug bounty and pentest skills require authorized targets
- Comply with all applicable laws and regulations

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Exceptions:
- `asmin/` — Copyright of original website owners (archived for preservation)
- `winapi/idafreekei.py` — WTFPL

---

## Acknowledgments

- rag-agent inspired by [coleam00/ottomator-agents](https://github.com/coleam00/ottomator-agents)
- Security workflows based on industry best practices
