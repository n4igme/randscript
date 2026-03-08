# Randscript

A collection of utility scripts and tools for document AI, security testing, web archiving, and automation.

## Project Structure

```
randscript/
├── rag-agent/        # RAG system with local LLM support via Ollama
├── scanner/          # XSS vulnerability scanner
├── trading/          # Crypto trading calculator (BTC, ETH, SOL)
├── asmin/            # Archived Asmaul Husna website
├── context_aware/    # Security analysis templates
├── secops/           # Security operations tools
├── winapi/           # Windows API utilities
└── llm_model/        # LLM training/tuning scripts
```

## Components

### [rag-agent/](rag-agent/)
Retrieval Augmented Generation (RAG) system with local LLM support. Features semantic search, multi-format document processing (PDF, Office, HTML, audio), and PostgreSQL+PGVector integration.

**Features:**
- Web interface (`web_app.py`) and CLI (`cli.py`)
- Web crawler for automated content ingestion
- Docker support (`Dockerfile`, `docker-compose.yml`)
- Development logs and technical documentation

**Tech:** Python, Ollama, Docling, Whisper, PostgreSQL, PGVector, Docker

### [scanner/](scanner/)
Automated XSS vulnerability scanner that parses Swagger YAML files and tests endpoints with various payloads. Includes email notification support.

**Tech:** Python, requests, YAML

### [trading/](trading/)
Crypto trading calculator with web interface supporting BTC, ETH, and SOL calculations. Indonesian language interface.

**Tech:** HTML, CSS, JavaScript

### [asmin/](asmin/)
Complete archive of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), preserved as of July 7, 2020.

### [context_aware/](context_aware/)
Security analysis templates including:
- Static code analysis formats (`ca001-ca007`)
- Threat modeling (`TM001`)
- Security engineering prompts (`se001.md`)

### [secops/](secops/)
Security operations tools for email analysis and related tasks.

**Files:**
- `emlckr.html` - Email analysis/locker interface

### [winapi/](winapi/)
Windows API utilities and system-level tools.

**Files:**
- `gcheats/` - Game cheat/anti-cheat code examples (C++, C#)
- `idafreekei.py` - IDA Free keygen tool

**Tech:** Python, C++, C#

### [llm_model/](llm_model/)
Scripts and tuning configurations for LLM training and fine-tuning.

**Structure:**
- `scripts/` - Model download, load, and security-focused LLM scripts
- `tuning/` - AppSec model tuning configurations (`appsec_model01`, `appsec_model02`)

**Tech:** Python, Hugging Face

## Tech Stack Summary

| Component | Technologies |
|-----------|-------------|
| **Backend** | Python, PostgreSQL, PGVector |
| **AI/ML** | Ollama, Docling, Whisper, Hugging Face |
| **Frontend** | HTML, CSS, JavaScript |
| **DevOps** | Docker, docker-compose |
| **Systems** | C++, C# (Windows API) |

## Quick Start

### RAG Agent
```bash
cd rag-agent
uv run python cli.py          # CLI interface
uv run python web_app.py      # Web interface
docker-compose up             # Docker deployment
```

### XSS Scanner
```bash
cd scanner
python xss_scanner.py
```

### Trading Calculator
```bash
# Open in browser
open trading/calculator.html
```

### LLM Model Scripts
```bash
cd llm_model/scripts
python download_model.py      # Download models
python security_llm.py        # Security-focused LLM
```

## Usage

All scripts are designed for educational and research purposes. See individual component directories for specific setup and usage instructions.

## Contributing

Contributions are welcome. Please feel free to submit pull requests or create issues for improvements.

## License

MIT License - see the LICENSE file for details.

**Note:** Archived content in `asmin/` is copyright of the original website owners. This repository serves to preserve educational content.