# Randscript

A curated toolkit of utility scripts and tools for **AI/LLM development**, **security research**, **web archiving**, and **automation**. This repository serves as a research laboratory for experimenting with local AI agents and offensive security techniques.

## 📁 Project Structure

```
randscript/
├── rag-agent/          # Local RAG system with Ollama & PGVector ⭐
├── scanner/            # Automated XSS vulnerability scanner
├── ai_llm/             # LLM operational skills & prompt workflows
├── winapi/             # Windows API research & reverse engineering
├── secops/             # Security operations (email forensics)
└── asmin/              # Archived Asmaul Husna website (2020)
```

---

## 🚀 Components

### [rag-agent/](rag-agent/) ⭐ Featured
**Retrieval Augmented Generation (RAG) system** designed for local, offline deployment.

**Key Technical Features:**
- 🧠 **Local LLM Orchestration** - Powered by `PydanticAI` and Ollama (Mistral, Llama 3.2, Qwen).
- 📄 **High-Fidelity Ingestion** - Uses **Docling** to parse PDF, Word, PowerPoint, and Excel into clean Markdown.
- 🎙️ **Audio RAG** - Integrated Whisper ASR for speech-to-text ingestion.
- ⚡ **Semantic Chunking** - Implements LLM-driven semantic splitting with a rule-based fallback to maintain context.
- 🌐 **Knowledge Base** - PostgreSQL with **PGVector** for cosine similarity semantic search.
- 🕷️ **Web Crawler** - Recursive crawler to ingest documentation sites directly into the knowledge base.
- 💻 **Interfaces** - Modern FastAPI Web UI and a rich CLI with streaming responses.

**Quick Start:**
```bash
cd rag-agent
uv sync
cp .env.example .env
# Configure DATABASE_URL and Ollama settings
uv run python web_app.py    # Web UI at localhost:8000
uv run python cli.py        # CLI interface
```

**Tech:** Python, Ollama, Docling, Whisper, PostgreSQL, PGVector, FastAPI, PydanticAI, Docker

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
**LLM Operational Skills** - Structured prompt workflows for security and engineering.

**The "Skill" Concept:**
Unlike simple prompts, these are structured workflows containing a process, tool definitions, and operational guides.

**Structure:**
```
ai_llm/
└── skills/
    ├── parse-finding/   # Converts raw security findings into structured Jira reports
    ├── ptest/          # Penetration testing phases (Recon -> Exploit -> Post-Exploit)
    └── scode/          # Bug bounty workflows (Recon -> Threat Model -> Scan -> Validate)
```

**Tech:** Markdown, Prompt Engineering

---

### [winapi/](winapi/)
**Windows API research and reverse engineering tools** for educational purposes.

**Contents:**
- **gcheats/** - Anti-cheat PoCs: Process scanning, file hashing (SHA-256), and malicious process termination.
- **idafreekei.py** - Technical implementation of an IDA Pro license generator using RSA modulus patching.

**⚠️ Legal Notice:** These tools are for **educational and research purposes only**. Understand your local laws before using reverse engineering tools.

**Tech:** Python, C++, C#, Windows API

---

### [secops/](secops/)
**Security operations tools** for email analysis and forensics.

**Files:**
- `emlckr.html` - Client-side tool for analyzing `.eml` files (SPF/DKIM/DMARC analysis, URL defanging, and phishing detection).

**Tech:** HTML, JavaScript

---

### [asmin/](asmin/)
**Archived website** - Complete preservation of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), archived on July 7, 2020.

**Note:** Copyright belongs to the original website owners. This archive is preserved for educational and historical purposes.

---

## 🛠️ Tech Stack Summary

| Domain | Technologies |
|--------|-------------|
| **Backend** | Python 3.10+, PostgreSQL, PGVector, FastAPI, AsyncIO, PydanticAI |
| **AI/ML** | Ollama, Docling, Whisper, Hugging Face, MLX |
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
git clone https://github.com/yourusername/randscript.git
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
# DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
# OPENAI_API_KEY=ollama
# OPENAI_BASE_URL=http://localhost:11434/v1
# LLM_CHOICE=mistral

# Pull Ollama models
ollama pull mistral
ollama pull nomic-embed-text

# Set up database (run sql/schema.sql in PostgreSQL)
# Then start the web interface
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
```

---

## 📚 Documentation

| Component | Documentation |
|-----------|--------------|
| rag-agent | [README.md](rag-agent/README.md), [WEB_INTERFACE.md](rag-agent/dev_logs/WEB_INTERFACE.md) |
| rag-agent tutorials | [docling_basics/](rag-agent/docling_basics/) |
| scanner | Inline comments in [xss_scanner.py](scanner/xss_scanner.py) |
| ai_llm | [skills/](ai_llm/skills/) |

---

## ⚠️ Legal & Ethical Notice

This repository is intended for **educational and research purposes only**:

- **scanner/** - Use only on systems you own or have explicit permission to test
- **winapi/** - Reverse engineering tools may be subject to local laws and software licenses
- **idafreekei.py** - License generation tools may violate software terms of service

**Always:**
- ✅ Test only systems you own or have authorization for
- ✅ Comply with all applicable laws and regulations
- ✅ Respect software licenses and terms of service
- ✅ Use security tools responsibly and ethically

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- [ ] Add unit tests for scanner and winapi components
- [ ] CI/CD pipeline configuration
- [ ] Additional RAG agent integrations
- [ ] More security prompt templates
- [ ] Documentation improvements

Please feel free to submit pull requests or create issues for issues or bugs.

---

## 📄 License

**MIT License** - See [LICENSE](LICENSE) file for details.

**Exceptions:**
- `asmin/` - Copyright of original website owners (archived for preservation)
- `winapi/idafreekei.py` - WTFPL (Do What The Fuck You Want To Public License)

---

## 🙏 Acknowledgments

- **rag-agent/** inspired by [coleam00/ottomator-agents](https://github.com/coleam00/ottomator-agents)
- Security prompts and templates based on industry best practices
- All open-source libraries and frameworks used in this project

---

**Made with ❤️ for learning, research, and experimentation**
