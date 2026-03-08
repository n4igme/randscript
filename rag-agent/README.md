# Docling RAG Agent (Ollama Edition)

An intelligent agent that provides conversational access to a knowledge base stored in PostgreSQL with PGVector. Uses RAG (Retrieval Augmented Generation) to search through embedded documents and provide contextual, accurate responses with source citations. Supports multiple document formats including audio files with Whisper transcription.

> **[Ollama Edition]** This is a modified version of the original [Docling RAG Agent](https://github.com/coleam00/ottomator-agents/tree/main/docling-rag-agent) from the [ottomator-agents](https://github.com/coleam00/ottomator-agents) repository, adapted to run with local LLMs via Ollama instead of requiring OpenAI API keys.

## 🌟 New: Web Interface Available!

A modern web interface is now available with:
- 💬 **Real-time Chat** - Streaming conversations with source citations
- 📁 **Document Management** - Drag-and-drop upload and ingestion
- 🕷️ **Web Crawler** - Crawl websites directly into your knowledge base
- 📊 **Live Statistics** - Real-time knowledge base metrics

```bash
# Start the web interface
uv run python web_app.py
```

Then open **http://localhost:8000** in your browser.

See [`WEB_INTERFACE.md`](./WEB_INTERFACE.md) for full documentation.

## 🎓 New to Docling?

**Start with the tutorials!** Check out the [`docling_basics/`](./docling_basics/) folder for progressive examples that teach Docling fundamentals:

1. **Simple PDF Conversion** - Basic document processing
2. **Multiple Format Support** - PDF, Word, PowerPoint handling
3. **Audio Transcription** - Speech-to-text with Whisper
4. **Hybrid Chunking** - Intelligent chunking for RAG systems

These tutorials provide the foundation for understanding how this full RAG agent works. [**→ Go to Docling Basics**](./docling_basics/)

## Features

### Interface Options

**Choose how you want to interact:**

| Interface | Best For | Command |
|-----------|----------|---------|
| 🌐 **Web Interface** | Visual UI, file uploads, web crawling | `uv run python web_app.py` |
| 💻 **CLI** | Terminal workflows, SSH access | `uv run python cli.py` |

### Core Features

- 💬 **Multiple Interfaces** - Web UI and CLI with streaming responses
- 🔍 **Semantic Search** - Vector-based document search with PGVector
- 📚 **Context-Aware Responses** - RAG pipeline for accurate answers
- 🎯 **Source Citations** - All responses include document references
- 🔄 **Real-time Streaming** - Token-by-token response streaming
- 💾 **PostgreSQL/PGVector** - Scalable vector knowledge base
- 🧠 **Conversation History** - Context maintained across turns
- 🎙️ **Audio Transcription** - Whisper ASR for MP3 files
- 🕷️ **Web Crawling** - Crawl documentation sites to markdown
- 🏠 **Local LLM via Ollama** - Run entirely offline without API costs

### Supported Document Formats

| Format | Extensions | Processing |
|--------|------------|------------|
| 📄 PDF | `.pdf` | Docling conversion |
| 📝 Word | `.docx`, `.doc` | Docling conversion |
| 📊 PowerPoint | `.pptx`, `.ppt` | Docling conversion |
| 📈 Excel | `.xlsx`, `.xls` | Docling conversion |
| 🌐 HTML | `.html`, `.htm` | Docling conversion |
| 📋 Markdown | `.md`, `.markdown` | Direct processing |
| 📃 Text | `.txt` | Direct processing |
| 🎵 Audio | `.mp3`, `.wav`, `.m4a` | Whisper transcription |

## Prerequisites

- **Python 3.10 or later** (Python 3.11+ recommended for full compatibility)
- PostgreSQL with PGVector extension (Supabase, Neon, self-hosted Postgres, etc.)
- **Ollama** (for local LLM) OR OpenAI API key
  - Install Ollama: https://ollama.com/download
  - Pull models: `ollama pull <model>` (e.g., `ollama pull mistral`, `ollama pull nomic-embed-text`)

### System Dependencies

**macOS:**
```bash
# Install required libraries for audio/video processing
brew install opus opusfile
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libopus0 libopusfile0
```

## Quick Start

### 1. Install Dependencies

```bash
# Install dependencies using UV
uv sync
```

### 2. Set Up Environment Variables

Copy `.env.example` to `.env` and configure your provider:

```bash
cp .env.example .env
```

#### Required variables:
- `DATABASE_URL` - PostgreSQL connection string with PGVector extension
  - Example: `postgresql://user:password@localhost:5432/dbname`
  - Supabase: `postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:5432/postgres`
  - Neon: `postgresql://[user]:[password]@[endpoint].neon.tech/[dbname]`

#### Choose your LLM provider:

**Option 1: Ollama (Local - Recommended)**
```bash
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_CHOICE=mistral              # or llama3.2, qwen2.5, etc.
EMBEDDING_MODEL=nomic-embed-text
```

Available Ollama models:
- LLM: `llama3.2`, `mistral`, `qwen2.5`, `deepseek-r1`
- Embeddings: `nomic-embed-text`, `mxbai-embed-large`, `qwen3-embedding`

**Option 2: OpenAI (Cloud)**
```bash
OPENAI_API_KEY=sk-your-key-here
LLM_CHOICE=gpt-4o-mini
EMBEDDING_MODEL=text-embedding-3-small
```

### 3. Configure Database

You must set up your PostgreSQL database with the PGVector extension and create the required schema:

1. **Enable PGVector extension** in your database (most cloud providers have this pre-installed)
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```

2. **Run the schema file** to create tables and functions:
   ```bash
   # In the SQL editor in Supabase/Neon, run:
   sql/schema.sql

   # Or using psql
   psql $DATABASE_URL < sql/schema.sql
   ```

The schema file (`sql/schema.sql`) creates:
- `documents` table for storing original documents with metadata
- `chunks` table for text chunks with 768-dimensional embeddings
- `match_chunks()` function for vector similarity search

### 4. Choose Your Interface

#### Option A: Web Interface (Recommended for First-Time Users)

```bash
# Start the web server
uv run python web_app.py
```

Then open **http://localhost:8000** in your browser.

**Web Interface Features:**
- 📁 Drag-and-drop file upload
- 🔄 Visual progress tracking for ingestion
- 🕷️ Built-in web crawler
- 📊 Real-time statistics dashboard
- 💬 Chat with streaming responses

#### Option B: CLI Interface

```bash
# Run the CLI agent
uv run python cli.py
```

**CLI Commands:**
- `help` - Show help information
- `clear` - Clear conversation history
- `stats` - Show session statistics
- `exit` or `quit` - Exit the CLI

### 5. Ingest Documents

Add your documents to the `documents/` folder, then ingest:

```bash
# Ingest all documents in the documents/ folder
# NOTE: By default, this CLEARS existing data before ingestion
uv run python -m ingestion.ingest --documents documents/

# Adjust chunk size (default: 1000)
uv run python -m ingestion.ingest --documents documents/ --chunk-size 800

# Append without cleaning (keep existing data)
uv run python -m ingestion.ingest --documents documents/ --no-clean
```

**⚠️ Important:** The ingestion process **automatically deletes all existing documents and chunks** from the database before adding new documents (unless `--no-clean` is used). This ensures a clean state and prevents duplicate data.

The ingestion pipeline will:
1. **Auto-detect file type** and use Docling for PDFs, Office docs, HTML, and audio
2. **Transcribe audio files** using Whisper Turbo ASR with timestamps
3. **Convert to Markdown** for consistent processing
4. **Split into semantic chunks** with configurable size
5. **Generate embeddings** using Ollama or OpenAI
6. **Store in PostgreSQL** with PGVector for similarity search

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER INTERFACES                            │
│  ┌─────────────────────┐           ┌─────────────────────┐      │
│  │   Web Interface     │           │     CLI Interface   │      │
│  │   (FastAPI + HTML)  │           │   (Python async)    │      │
│  └──────────┬──────────┘           └──────────┬──────────┘      │
└─────────────┼─────────────────────────────────┼────────────────┘
              │                                 │
              └─────────────┬───────────────────┘
                            │
              ┌─────────────▼───────────────────┐
              │       RAG Agent Core            │
              │  ┌───────────────────────────┐  │
              │  │ PydanticAI Agent          │  │
              │  │ + search_knowledge_base() │  │
              │  └───────────────────────────┘  │
              └─────────────┬───────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
┌────────▼────────┐  ┌──────▼───────┐  ┌──────▼───────┐
│  Embeddings     │  │    LLM       │  │  PostgreSQL  │
│  (Ollama/       │  │  (Ollama/    │  │  + PGVector  │
│   OpenAI)       │  │   OpenAI)    │  │              │
└─────────────────┘  └──────────────┘  └──────────────┘
```

### Data Flow

```
┌──────────────────┐     ┌─────────────────┐     ┌────────────────┐
│  Data Sources    │────▶│   Ingestion     │────▶│  Knowledge     │
│  • Local files   │     │   Pipeline      │     │  Base (PGVec)  │
│  • Web crawl     │     │  (Docling)      │     │                │
└──────────────────┘     └─────────────────┘     └───────┬────────┘
                                                         │
┌──────────────────┐     ┌─────────────────┐     ┌───────▼────────┐
│   User Query     │◀────│   RAG Agent     │◀────│  Semantic      │
│  (Web or CLI)    │     │  + Streaming    │     │  Search        │
└──────────────────┘     └─────────────────┘     └────────────────┘
```

## Audio Transcription Feature

Audio files are automatically transcribed using **OpenAI Whisper Turbo** model:

**How it works:**
1. When ingesting audio files (MP3 supported currently), Docling uses Whisper ASR
2. Whisper generates accurate transcriptions with timestamps
3. Transcripts are formatted as markdown with time markers
4. Audio content becomes fully searchable through the RAG system

**Benefits:**
- 🎙️ **Speech-to-text**: Convert podcasts, interviews, lectures into searchable text
- ⏱️ **Timestamps**: Track when specific content was mentioned
- 🔍 **Semantic search**: Find audio content by topic or keywords
- 🤖 **Fully automatic**: Drop audio files in `documents/` folder and run ingestion

**Model details:**
- Model: `openai/whisper-large-v3-turbo`
- Optimized for: Speed and accuracy balance
- Languages: Multilingual support (90+ languages)
- Output format: Markdown with timestamps like `[time: 0.0-4.0] Transcribed text here`

**Example transcript format:**
```markdown
[time: 0.0-4.0] Welcome to our podcast on AI and machine learning.
[time: 5.28-9.96] Today we'll discuss retrieval augmented generation systems.
```

## Key Components

### RAG Agent

The main agent (`rag_agent.py`) that:
- Manages database connections with connection pooling
- Handles interactive CLI with streaming responses
- Performs knowledge base searches via RAG
- Tracks conversation history for context

### search_knowledge_base Tool

Function tool registered with the agent that:
- Generates query embeddings using Ollama or OpenAI
- Searches using PGVector cosine similarity
- Returns top-k most relevant chunks
- Formats results with source citations

Example tool definition:
```python
async def search_knowledge_base(
    ctx: RunContext[None],
    query: str,
    limit: int = 5
) -> str:
    """Search the knowledge base using semantic similarity."""
    # Generate embedding for query
    # Search PostgreSQL with PGVector
    # Format and return results
```

### Database Schema

- `documents`: Stores original documents with metadata
  - `id`, `title`, `source`, `content`, `metadata`, `created_at`, `updated_at`

- `chunks`: Stores text chunks with vector embeddings
  - `id`, `document_id`, `content`, `embedding` (vector(1536)), `chunk_index`, `metadata`, `token_count`

- `match_chunks()`: PostgreSQL function for vector similarity search
  - Uses cosine similarity (`1 - (embedding <=> query_embedding)`)
  - Returns chunks with similarity scores above threshold

## Performance Optimization

### Database Connection Pooling
```python
db_pool = await asyncpg.create_pool(
    DATABASE_URL,
    min_size=2,
    max_size=10,
    command_timeout=60
)
```

### Embedding Cache
The embedder includes built-in caching for frequently searched queries, reducing API calls and latency.

### Streaming Responses
Token-by-token streaming provides immediate feedback to users while the LLM generates responses:
```python
async with agent.run_stream(user_input, message_history=history) as result:
    async for text in result.stream_text(delta=False):
        print(f"\rAssistant: {text}", end="", flush=True)
```

## Docker Deployment

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# Ingest documents
docker-compose --profile ingestion up ingestion

# View logs
docker-compose logs -f rag-agent
```

## API Reference

### search_knowledge_base Tool

```python
async def search_knowledge_base(
    ctx: RunContext[None],
    query: str,
    limit: int = 5
) -> str:
    """
    Search the knowledge base using semantic similarity.

    Args:
        query: The search query to find relevant information
        limit: Maximum number of results to return (default: 5)

    Returns:
        Formatted search results with source citations
    """
```

### Database Functions

```sql
-- Vector similarity search
SELECT * FROM match_chunks(
    query_embedding::vector(1536),
    match_count INT,
    similarity_threshold FLOAT DEFAULT 0.7
)
```

Returns chunks with:
- `id`: Chunk UUID
- `content`: Text content
- `embedding`: Vector embedding
- `similarity`: Cosine similarity score (0-1)
- `document_title`: Source document title
- `document_source`: Source document path

## Project Structure

```
docling-rag-agent/
├── cli.py                   # Enhanced CLI with colors and features
├── rag_agent.py             # Basic CLI agent with PydanticAI
├── web_app.py               # FastAPI web interface server ⭐ NEW
│
├── web/                     # Web interface frontend ⭐ NEW
│   └── index.html           # Single-page application (HTML/CSS/JS)
│
├── ingestion/
│   ├── ingest.py            # Document ingestion pipeline
│   ├── embedder.py          # Embedding generation with caching
│   └── chunker.py           # Document chunking logic
│
├── web_crawler/             # Web scraping utilities ⭐ NEW
│   ├── 1-crawl_single_page.py
│   ├── 2-crawl_docs_sequential.py
│   ├── 3-crawl_sitemap_in_parallel.py
│   ├── 4-crawl_llms_txt.py
│   ├── 5-crawl_site_recursively.py
│   └── _crawl_utils.py      # Shared utilities for web app
│
├── docling_basics/          # Docling tutorials
│   ├── 01_simple_pdf.py
│   ├── 02_multiple_formats.py
│   ├── 03_audio_transcription.py
│   └── 04_hybrid_chunking.py
│
├── utils/
│   ├── providers.py         # OpenAI/Ollama model/client configuration
│   ├── db_utils.py          # Database connection pooling
│   └── models.py            # Pydantic models for config
│
├── sql/
│   ├── schema.sql           # PostgreSQL schema with PGVector
│   ├── backup.sh            # Database backup script
│   └── restore.sh           # Database restore script
│
├── documents/               # Sample documents for ingestion
├── pyproject.toml           # Project dependencies
├── .env.example             # Environment variables template
│
├── README.md                # This file
├── WEB_INTERFACE.md         # Web interface documentation ⭐ NEW
└── DATA_PIPELINE.md         # Data collection guide ⭐ NEW
```

## Documentation

| Document | Description |
|----------|-------------|
| [`README.md`](./README.md) | Main project documentation |
| [`WEB_INTERFACE.md`](./dev_logs/WEB_INTERFACE.md) | Web interface usage guide |
| [`DATA_PIPELINE.md`](./dev_logs/DATA_PIPELINE.md) | Data collection pipeline guide |
| [`docling_basics/README.md`](./docling_basics/README.md) | Docling tutorials |

## Troubleshooting

### Python Version Error: `unsupported operand type(s) for |`

**Error:**
```
TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'
```

**Cause:** You're using Python 3.9, but `crawl4ai` requires Python 3.10+.

**Solution:** Upgrade to Python 3.10 or later (Python 3.11+ recommended):

```bash
# Check your Python version
python --version

# If using Python 3.9, recreate the virtual environment with Python 3.10+
uv venv --python 3.11 --clear
uv sync
```

### Port Already in Use

**Error:**
```
ERROR: [Errno 48] Address already in use
```

**Solution:**
```bash
# Kill the process using port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port
uv run python web_app.py --port 8001
```

### Missing System Libraries

**Error:**
```
fatal error: 'opus/opus.h' file not found
```

**Solution:** Install required system dependencies:

```bash
# macOS
brew install opus opusfile

# Linux (Ubuntu/Debian)
sudo apt-get install libopus0 libopusfile0
```

### Database Connection Failed

**Error:**
```
Database not initialized. Please check your DATABASE_URL configuration.
```

**Solution:**
1. Verify PostgreSQL is running: `pg_isready`
2. Check `DATABASE_URL` in your `.env` file
3. Ensure the database exists and PGVector extension is installed:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```

## Acknowledgments

This project is a modified version of the [Docling RAG Agent](https://github.com/coleam00/ottomator-agents/tree/main/docling-rag-agent) from the excellent [ottomator-agents](https://github.com/coleam00/ottomator-agents) collection by [coleam00](https://github.com/coleam00).

**Modifications made:**
- Added Ollama support via `OPENAI_BASE_URL` environment variable
- Enables fully local RAG pipeline without OpenAI API dependencies
- Configured for local embedding models (nomic-embed-text, mxbai-embed-large, etc.)