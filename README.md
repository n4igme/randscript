# Randscript

A collection of utility scripts and tools for **AI/LLM development**, **security research**, **web archiving**, and **automation**.

## 📁 Project Structure

```
randscript/
├── rag-agent/          # RAG system with local LLM via Ollama ⭐
├── scanner/            # XSS vulnerability scanner
├── llm_model/          # LLM scripts, security prompts & templates
├── winapi/             # Windows API utils & reverse engineering tools
├── secops/             # Security operations (email analysis)
└── asmin/              # Archived Asmaul Husna website (2020)
```

---

## 🚀 Components

### [rag-agent/](rag-agent/) ⭐ Featured
**Retrieval Augmented Generation (RAG) system** with local LLM support via Ollama. Build a chatbot that answers questions from your documents with source citations.

**Features:**
- 🌐 **Web Interface** - Modern UI with chat, file uploads, and web crawler
- 💻 **CLI Interface** - Terminal-based interactive agent
- 📄 **Multi-format Support** - PDF, Word, PowerPoint, Excel, HTML, Markdown, Audio (MP3)
- 🎙️ **Audio Transcription** - Whisper ASR for speech-to-text
- 🕷️ **Web Crawler** - Crawl documentation sites into knowledge base
- 🐳 **Docker Ready** - Full containerization support
- 🧠 **Local LLM** - Run offline with Ollama (Mistral, Llama 3.2, Qwen)

**Quick Start:**
```bash
cd rag-agent
uv sync
cp .env.example .env
# Configure DATABASE_URL and Ollama settings
uv run python web_app.py    # Web UI at localhost:8000
uv run python cli.py        # CLI interface
```

**Tech:** Python, Ollama, Docling, Whisper, PostgreSQL, PGVector, FastAPI, Docker

---

### [scanner/](scanner/)
**Automated XSS vulnerability scanner** for API security testing.

**Features:**
- Parses Swagger/OpenAPI YAML files
- Tests endpoints with 9 XSS payloads
- Email notification support
- Configurable target base URL

**Quick Start:**
```bash
cd scanner
# Update swagger.yml with your target API
python xss_scanner.py
```

**Tech:** Python, requests, PyYAML

---

### [llm_model/](llm_model/)
**LLM training scripts and security-focused prompt templates** for AppSec use cases.

**Structure:**
```
llm_model/
├── scripts/
│   ├── download_model.py    # Download models from Hugging Face
│   ├── load_model.py        # Load and test models
│   ├── security_llm.py      # Security analysis with MLX (Apple Silicon)
│   └── hello_model.py       # Basic model test
├── prompt/
│   └── se001.md            # Security engineering mentor prompt
└── custom/                  # Custom model configurations
```

**Example - Security Code Analysis:**
```python
cd llm_model/scripts
uv run python security_llm.py
```

**Prompt Template (se001.md):**
> Act as a senior software engineer and security-focused mentor. Provide concise, practical, production-ready solutions with secure coding practices, PoC examples, and remediation guidance.

**Tech:** Python, MLX, Hugging Face Transformers

---

### [winapi/](winapi/)
**Windows API utilities and reverse engineering tools** for educational purposes.

**Contents:**
- **gcheats/** - Game cheat/anti-cheat code examples:
  - `ac_ammo.cpp` - Anti-cheat ammo detection
  - `ac_PID.cpp` - Process ID validation
  - `echo_anti-cheat.cpp` - Echo-based anti-cheat
  - `get_baseaddress.cs` - Base address retrieval (C#)
- **idafreekei.py** - IDA Pro license generator (⚠️ educational use only)

**⚠️ Legal Notice:** These tools are for **educational and research purposes only**. Understand your local laws before using reverse engineering tools.

**Tech:** Python, C++, C#, Windows API

---

### [secops/](secops/)
**Security operations tools** for email analysis and forensics.

**Files:**
- `emlckr.html` - Email analysis interface for examining EML files

**Tech:** HTML, JavaScript

---

### [asmin/](asmin/)
**Archived website** - Complete preservation of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), archived on July 7, 2020.

**Contents:**
- Full HTML structure with CSS and JavaScript
- Image assets
- Indonesian language interface

**Note:** Copyright belongs to the original website owners. This archive is preserved for educational and historical purposes.

---

## 🛠️ Tech Stack Summary

| Domain | Technologies |
|--------|-------------|
| **Backend** | Python 3.10+, PostgreSQL, PGVector, FastAPI, AsyncIO |
| **AI/ML** | Ollama, Docling, Whisper, Hugging Face, MLX, PydanticAI |
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
# Edit swagger.yml with your target API
python xss_scanner.py
```

### 3. LLM Security Scripts
```bash
cd llm_model/scripts
# For Apple Silicon (M1/M2/M3)
uv run python security_llm.py
```

---

## 📚 Documentation

| Component | Documentation |
|-----------|--------------|
| rag-agent | [README.md](rag-agent/README.md), [WEB_INTERFACE.md](rag-agent/dev_logs/WEB_INTERFACE.md) |
| rag-agent tutorials | [docling_basics/](rag-agent/docling_basics/) |
| scanner | Inline comments in [xss_scanner.py](scanner/xss_scanner.py) |
| llm_model | [prompt/se001.md](llm_model/prompt/se001.md) |

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

Please feel free to submit pull requests or create issues for bugs and feature requests.

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
