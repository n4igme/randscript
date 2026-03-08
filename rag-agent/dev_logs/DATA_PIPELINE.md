# Data Collection Pipeline

Complete guide to ingesting data into the RAG knowledge base.

## Prerequisites

- **Python 3.10+** (Python 3.11+ recommended)
- PostgreSQL with PGVector extension
- System dependencies for audio/video processing:
  - **macOS**: `brew install opus opusfile`
  - **Linux**: `sudo apt-get install libopus0 libopusfile0`

## Overview

The RAG agent supports **two data collection pipelines** that converge into a unified knowledge base:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA COLLECTION PIPELINES                        │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐              ┌──────────────────────────────────┐
│   PIPELINE 1         │              │   PIPELINE 2                     │
│   Local Documents    │              │   Web Content                    │
│                      │              │                                  │
│   ┌──────────────┐   │              │   ┌──────────────────────────┐   │
│   │   Docling    │   │              │   │      Crawl4AI            │   │
│   │              │   │              │   │                          │   │
│   │ Converts:    │   │              │   │ Scrapes:                 │   │
│   │ • PDF        │   │              │   │ • Documentation sites    │   │
│   │ • Word       │   │              │   │ • Technical blogs        │   │
│   │ • PowerPoint │   │              │   │ • API references         │   │
│   │ • Excel      │   │              │   │ • Wikis                  │   │
│   │ • HTML       │   │              │   │ • Static sites           │   │
│   │ • Markdown   │   │              │   └────────────┬─────────────┘   │
│   │ • Audio MP3  │   │              │                │                 │
│   └──────┬───────┘   │              │                ▼                 │
│          │           │              │   ┌────────────────────────┐     │
│          ▼           │              │   │ documents/crawled/     │     │
│   ┌────────────────┐ │              │   │ ├── page1.md           │     │
│   │ documents/     │ │              │   │ ├── page2.md           │     │
│   │ ├── file.pdf   │ │              │   │ └── page3.md           │     │
│   │ ├── report.docx│ │              │   └────────────────────────┘     │
│   │ └── audio.mp3  │ │              │                │                 │
│   └───────┬────────┘ │              └────────────────┬─────────────────┘
│           │                                              │
└───────────┼──────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────┐
│              INGESTION PIPELINE (Common)                  │
│                                                           │
│   ┌─────────────┐    ┌──────────┐    ┌──────────────┐    │
│   │  Docling    │───▶│ Chunking │───▶│  Embedding   │    │
│   │  (convert   │    │ (semantic│    │  (Ollama/    │    │
│   │   to MD)    │    │  split)  │    │   OpenAI)    │    │
│   └─────────────┘    └──────────┘    └──────┬───────┘    │
│                                             │             │
│                                             ▼             │
│                                  ┌─────────────────────┐  │
│                                  │  PostgreSQL/PGVector│  │
│                                  │  • documents table  │  │
│                                  │  • chunks table     │  │
│                                  │  • vector index     │  │
│                                  └─────────────────────┘  │
└───────────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────┐
│              RAG AGENT (cli.py)                           │
│                                                           │
│   User Query → Embed → Search → LLM → Response + Sources │
└───────────────────────────────────────────────────────────┘
```

---

## Pipeline 1: Local Documents (Docling)

### Supported Formats

| Format | Extension | Processing |
|--------|-----------|------------|
| PDF | `.pdf` | Docling converts to markdown |
| Word | `.docx`, `.doc` | Docling converts to markdown |
| PowerPoint | `.pptx`, `.ppt` | Docling converts to markdown |
| Excel | `.xlsx`, `.xls` | Docling converts to markdown |
| HTML | `.html`, `.htm` | Docling converts to markdown |
| Markdown | `.md`, `.markdown` | Direct processing |
| Text | `.txt` | Direct processing |
| Audio | `.mp3`, `.wav`, `.m4a`, `.flac` | Whisper ASR transcription |

### Usage

```bash
# Place files in documents/ folder
cp /path/to/myfile.pdf documents/
cp /path/to/report.docx documents/
cp /path/to/podcast.mp3 documents/

# Run ingestion
uv run python -m ingestion.ingest --documents documents/

# With custom chunk size
uv run python -m ingestion.ingest --documents documents/ --chunk-size 800

# Without cleaning existing data (append mode)
uv run python -m ingestion.ingest --documents documents/ --no-clean
```

### What Happens

1. **Docling** reads the file and converts to markdown
2. **Audio files** are transcribed with Whisper Turbo ASR
3. **Chunker** splits into semantic chunks (default: 1000 tokens, 200 overlap)
4. **Embedder** generates 768-dim vectors using Ollama/OpenAI
5. **PostgreSQL** stores documents + chunks with PGVector indexing

### Output

```
PostgreSQL:
├── documents table
│   ├── id: UUID
│   ├── title: "myfile.pdf"
│   ├── source: "documents/myfile.pdf"
│   ├── content: (full markdown)
│   └── metadata: {file_size, line_count, ...}
│
└── chunks table
    ├── id: UUID
    ├── document_id: FK → documents
    ├── content: (chunk text)
    ├── embedding: vector(768)
    ├── chunk_index: 0, 1, 2...
    └── token_count: 950
```

---

## Pipeline 2: Web Content (Crawl4AI)

### Supported Sources

| Source Type | Example | Script |
|-------------|---------|--------|
| Documentation sites | ReadTheDocs, Docusaurus, MkDocs | `5-crawl_site_recursively.py` |
| Technical blogs | Medium, Dev.to, Hashnode | `3-crawl_sitemap_in_parallel.py` |
| API references | OpenAPI, Swagger UI | `1-crawl_single_page.py` |
| GitHub Wikis | `github.com/.../wiki` | `5-crawl_site_recursively.py` |
| Static sites | Gatsby, Hugo, Jekyll | `2-crawl_docs_sequential.py` |
| LLM-friendly formats | `llms.txt`, raw markdown | `4-crawl_llms_txt.py` |

### Usage

#### Option 1: Recursive Site Crawl (Recommended)

```bash
# Crawl entire site (3 levels deep)
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://ai.pydantic.dev/" \
    -r 3 \
    -o documents/crawled/pydantic-ai

# Crawl Python docs (2 levels)
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://docs.python.org/3/" \
    -r 2 \
    -o documents/crawled/python-docs

# High concurrency for large sites
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://example.com" \
    -r 3 \
    -c 20
```

#### Option 2: Sitemap Batch Crawl (Fast)

```bash
# Edit script to change sitemap URL, then run
uv run python web_crawler/3-crawl_sitemap_in_parallel.py
```

#### Option 3: Single Page

```bash
# Edit script to change URL, then run
uv run python web_crawler/1-crawl_single_page.py
```

### Output Structure

```
documents/crawled/pydantic-ai/
├── index.md              # Homepage
├── getting_started.md
├── concepts_agents.md
├── concepts_tools.md
├── api_reference.md
└── ...
```

### Ingest Crawled Content

```bash
# Ingest all crawled content
uv run python -m ingestion.ingest --documents documents/crawled/

# Ingest specific folder
uv run python -m ingestion.ingest --documents documents/crawled/pydantic-ai/
```

---

## Complete Workflow Example

### Scenario: Build RAG for Pydantic AI + Local PDFs

```bash
# Step 1: Crawl web documentation
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://ai.pydantic.dev/" \
    -r 3 \
    -o documents/crawled/pydantic-ai

# Step 2: Add local documents
cp ~/Downloads/pydantic-guide.pdf documents/
cp ~/Notes/implementation-notes.md documents/

# Step 3: Ingest everything
uv run python -m ingestion.ingest --documents documents/

# Step 4: Start RAG agent
uv run python cli.py
```

### Example Interaction

```
You: What are agents in Pydantic AI?

🤖 Assistant: Based on the knowledge base, agents in Pydantic AI are:

[Source: concepts_agents.md]
Agents are autonomous AI components that can use tools to accomplish tasks.
They consist of a model, system prompt, and optional tools...

[Source: getting_started.md]
To create an agent, import Agent from pydantic_ai and configure with
your preferred model...

[Source: pydantic-guide.pdf]
Best practices include setting clear system prompts and limiting
tool scope for focused agents.
```

---

## Configuration

### Environment Variables (`.env`)

```bash
# Database
DATABASE_URL=postgresql://raguser:ragpass@localhost:5432/postgres

# LLM (Ollama - Local)
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_CHOICE=mistral
EMBEDDING_MODEL=nomic-embed-text

# LLM (OpenAI - Cloud)
# OPENAI_API_KEY=sk-your-key-here
# LLM_CHOICE=gpt-4o-mini
# EMBEDDING_MODEL=text-embedding-3-small
```

### Ingestion Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--chunk-size` | 1000 | Tokens per chunk |
| `--chunk-overlap` | 200 | Overlap between chunks |
| `--no-semantic` | False | Disable semantic splitting |
| `--no-clean` | False | Keep existing data (append) |

### Crawler Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-r, --max-depth` | 3 | Crawl recursion depth |
| `-c, --concurrency` | 10 | Parallel browser sessions |
| `-o, --output-dir` | `documents/crawled` | Output folder |

---

## Troubleshooting

### Issue: Ingestion Clears All Data

**Expected behavior.** By default, ingestion deletes all existing documents and chunks before adding new ones.

**Solution:** Use `--no-clean` to append:
```bash
uv run python -m ingestion.ingest --documents documents/ --no-clean
```

### Issue: Crawl4AI Chromium Download Fails

**Solution:** Install manually:
```bash
# macOS
brew install chromium

# Ubuntu/Debian
sudo apt-get install chromium-browser
```

### Issue: Memory Exhaustion During Crawl

**Solution:** Reduce concurrency:
```bash
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://example.com" \
    -r 3 \
    -c 5  # Lower from 10 to 5
```

### Issue: Audio Transcription Fails

**Check:**
1. File format is supported (`.mp3`, `.wav`, `.m4a`, `.flac`)
2. File is not corrupted
3. Sufficient disk space for temporary files

---

## Best Practices

### 1. Organize Documents by Source

```
documents/
├── local/
│   ├── reports/
│   └── notes/
└── crawled/
    ├── pydantic-ai/
    ├── python-docs/
    └── internal-wiki/
```

### 2. Use Descriptive Names

```bash
# Good
documents/crawled/pydantic-ai-agents-guide.md

# Bad
documents/crawled/page123.md
```

### 3. Monitor Database Size

```sql
-- Check document count
SELECT COUNT(*) FROM documents;

-- Check chunk count
SELECT COUNT(*) FROM chunks;

-- Check total size
SELECT pg_size_pretty(pg_total_relation_size('chunks'));
```

### 4. Schedule Regular Updates

```bash
# Weekly cron job to refresh crawled content
0 2 * * 0 cd /path/to/rag-agent && \
    uv run python web_crawler/5-crawl_site_recursively.py \
        -u "https://docs.example.com/" \
        -r 3 \
        -o documents/crawled/example-docs && \
    uv run python -m ingestion.ingest --documents documents/
```

### 5. Test with Small Batches First

```bash
# Test with single page before full crawl
uv run python web_crawler/1-crawl_single_page.py

# Test ingestion with one document
cp one-file.pdf documents/
uv run python -m ingestion.ingest --documents documents/
```

---

## Performance Benchmarks

| Task | Time | Notes |
|------|------|-------|
| Crawl 50 pages (parallel) | ~2-5 min | Depends on site size |
| Ingest 100-page PDF | ~30-60 sec | With embeddings |
| Transcribe 10-min audio | ~1-2 min | Whisper Turbo |
| Generate embeddings (1000 chunks) | ~1-3 min | Ollama local |
| Vector search query | <100ms | PGVector index |

---

## Related Files

- [`ingestion/ingest.py`](./ingestion/ingest.py) - Main ingestion pipeline
- [`ingestion/chunker.py`](./ingestion/chunker.py) - Semantic chunking logic
- [`ingestion/embedder.py`](./ingestion/embedder.py) - Embedding generation
- [`web_crawler/`](./web_crawler/) - Web scraping scripts
- [`cli.py`](./cli.py) - RAG agent CLI
- [`sql/schema.sql`](./sql/schema.sql) - Database schema

---

## Resources

- [Docling Documentation](https://ds4sd.github.io/docling/)
- [Crawl4AI GitHub](https://github.com/unclecode/crawl4ai)
- [PGVector Documentation](https://github.com/pgvector/pgvector)
- [llms.txt Standard](https://llmstxt.org/)
