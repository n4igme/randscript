# Randscript

A personal research lab — utility scripts and tools for AI/LLM development, security research, and automation.

## Components

| Component | Description | Tech |
|-----------|-------------|------|
| [rag-agent/](rag-agent/) | Local RAG system with offline LLM, document/audio ingestion, semantic search | Python, Ollama, PGVector, Docling, Whisper, FastAPI |
| [llm/skills/](llm/skills/) | AI security skills — code review, pentest, mobile, finding reports | Structured prompts |
| [scanner/](scanner/) | XSS scanner — parses OpenAPI specs, tests 9 payloads, generates reports | Python, requests, PyYAML |
| [winapi/](winapi/) | Windows API research — anti-cheat PoCs, reverse engineering tools | Python, C++, C# |
| [secops/](secops/) | Email forensics — .eml analyzer with SPF/DKIM/DMARC validation | HTML, JavaScript |
| [asmin/](asmin/) | Archived Asmaul Husna website (2020) | Static HTML |

## Getting Started

**Prerequisites:** Python 3.10+, [UV](https://astral.sh/uv), [Ollama](https://ollama.ai), PostgreSQL + PGVector

Each component is self-contained — see its own README for setup and usage.

## License

MIT — see [LICENSE](LICENSE). Exceptions: `asmin/` (original copyright), `winapi/idafreekei.py` (WTFPL).

Security tools are for **authorized use only**. Use responsibly and comply with applicable laws.

## Acknowledgments

- rag-agent inspired by [coleam00/ottomator-agents](https://github.com/coleam00/ottomator-agents)
