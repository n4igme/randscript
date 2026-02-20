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

**Tech:** Python, Ollama, Docling, Whisper, PostgreSQL, PGVector

### [scanner/](scanner/)
Automated XSS vulnerability scanner that parses Swagger YAML files and tests endpoints with various payloads. Includes email notification support.

**Tech:** Python, requests, YAML

### [trading/](trading/)
Crypto trading calculator with web interface supporting BTC, ETH, and SOL calculations. Indonesian language interface.

**Tech:** HTML, CSS, JavaScript

### [asmin/](asmin/)
Complete archive of the "Asmaul Husna" (99 Names of Allah) website from [asmaulhusna.in](http://www.asmaulhusna.in/), preserved as of July 7, 2020.

### [context_aware/](context_aware/)
Security analysis templates including static code analysis formats, vulnerability assessment templates (ca001-ca007), and threat modeling (TM001).

### [secops/](secops/)
Security operations tools for email analysis and related tasks.

### [winapi/](winapi/)
Windows API utilities and system-level tools.

### [llm_model/](llm_model/)
Scripts and tuning configurations for LLM training and fine-tuning.

## Usage

All scripts are designed for educational and research purposes. See individual component directories for specific setup and usage instructions.

## Contributing

Contributions are welcome. Please feel free to submit pull requests or create issues for improvements.

## License

MIT License - see the LICENSE file for details.

**Note:** Archived content in `asmin/` is copyright of the original website owners. This repository serves to preserve educational content.