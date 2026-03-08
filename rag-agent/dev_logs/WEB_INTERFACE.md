# RAG Agent Web Interface

Modern, responsive web interface for the Docling RAG Agent with document management, web crawling, and AI chat capabilities.

## Features

- 💬 **Real-time Chat** - Streaming conversations with the RAG agent
- 📁 **Document Upload** - Drag-and-drop file upload with multiple format support
- 🔄 **Document Ingestion** - Process documents into the knowledge base with progress tracking
- 🕷️ **Web Crawler** - Crawl websites and convert to markdown for ingestion
- 📊 **Live Statistics** - Real-time knowledge base statistics
- 🎨 **Modern UI** - Dark theme with responsive design

## Quick Start

### 1. Install Dependencies

```bash
uv sync
```

### 2. System Dependencies

**macOS:**
```bash
brew install opus opusfile
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libopus0 libopusfile0
```

### 3. Configure Environment

Make sure your `.env` file is configured:

```bash
DATABASE_URL=postgresql://raguser:ragpass@localhost:5432/postgres
OPENAI_API_KEY=ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_CHOICE=mistral
EMBEDDING_MODEL=nomic-embed-text
```

### 3. Start the Web Server

```bash
uv run python web_app.py
```

The application will start at **http://localhost:8000**

**Custom port:**
```bash
uv run python web_app.py --port 8001
```

**Disable auto-reload (production):**
```bash
uv run python web_app.py --no-reload
```

## Usage

### Chat Tab

1. Type your question in the chat input
2. Press Enter or click Send
3. View streaming responses with source citations
4. Use "Clear" to reset conversation history

**Example questions:**
- "What topics are covered in the knowledge base?"
- "Tell me about [specific topic from your documents]"
- "Summarize the main concepts"

### Documents Tab

**Upload Files:**
1. Click or drag files to the upload area
2. Supported formats: PDF, Word, PowerPoint, Excel, HTML, Markdown, Audio (MP3)
3. Click "Upload Files" to save

**Ingest Documents:**
1. Set the documents path (default: `documents`)
2. Configure chunk size and overlap (optional)
3. Choose whether to clean existing data
4. Click "Start Ingestion"
5. Monitor progress in real-time

### Web Crawler Tab

1. Enter the starting URL (e.g., `https://ai.pydantic.dev/`)
2. Set max depth (1-5 levels)
3. Set concurrency (1-20 parallel requests)
4. Set output directory (default: `documents/crawled`)
5. Click "Start Crawl"
6. After crawling, ingest the content from the Documents tab

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Browser                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │    Chat     │  │  Documents  │  │   Web Crawler       │  │
│  │  Interface  │  │  Management │  │   Interface         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  /api/chat  │  │ /api/ingest │  │    /api/crawl       │  │
│  │  (streaming)│  │  (background)│ │   (background)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  RAG Agent + Tools                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  search_knowledge_base(query) -> relevant chunks    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│               PostgreSQL + PGVector                         │
│  ┌─────────────┐  ┌─────────────────────────────────────┐   │
│  │  documents  │  │  chunks (with vector embeddings)    │   │
│  └─────────────┘  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Health & Stats

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Check system health status |
| `/api/stats` | GET | Get knowledge base statistics |

### Documents

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/upload` | POST | Upload a document file |
| `/api/ingest` | POST | Start document ingestion |
| `/api/task/{task_id}` | GET | Get task status |

### Web Crawler

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/crawl` | POST | Start web crawling |
| `/api/task/{task_id}` | GET | Get crawl task status |

### Chat

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/chat` | POST | Chat with streaming response (SSE) |
| `/api/chat/clear` | POST | Clear chat history |

## Configuration

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 8000 | Port to run the server on |
| `--host` | 0.0.0.0 | Host to bind to |
| `--reload` | True | Enable auto-reload on code changes |
| `--no-reload` | False | Disable auto-reload (for production) |

### Ingestion Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `chunk_size` | 1000 | Tokens per chunk |
| `chunk_overlap` | 200 | Overlap between chunks |
| `clean_before` | true | Clean existing data before ingestion |

### Crawler Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_depth` | 3 | Recursion depth (1-5) |
| `concurrency` | 10 | Parallel requests (1-20) |
| `output_dir` | `documents/crawled` | Output directory |

## Troubleshooting

### Database Connection Failed

**Error:** "Database not initialized"

**Solution:**
1. Check `DATABASE_URL` in `.env`
2. Ensure PostgreSQL is running
3. Verify PGVector extension is installed

### Agent Not Ready

**Error:** "Agent not initialized"

**Solution:**
1. Check `OPENAI_API_KEY` in `.env`
2. For Ollama: Ensure Ollama is running (`ollama serve`)
3. Verify model is pulled (`ollama pull mistral`)

### Crawl Failed

**Error:** "Crawl failed: Chromium not found"

**Solution:**
```bash
# macOS
brew install chromium

# Ubuntu/Debian
sudo apt-get install chromium-browser
```

### Upload Failed

**Error:** "Upload failed"

**Solution:**
1. Check file size (may need server config for large files)
2. Verify `documents/` directory exists and is writable
3. Check file format is supported

## Development

### Run with Auto-Reload

```bash
uv run python web_app.py
```

The server will automatically reload on code changes.

### Access Logs

View logs in the terminal where the server is running:
```
INFO:     Started server process
INFO:     Waiting for application startup
INFO:     Application startup complete
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Debug Mode

Enable verbose logging:
```python
# In web_app.py, change:
uvicorn.run(
    "web_app:app",
    host="0.0.0.0",
    port=8000,
    reload=True,
    log_level="debug"  # Change from "info" to "debug"
)
```

## Browser Support

- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)

## Mobile Support

The interface is fully responsive and works on:
- 📱 iOS Safari
- 📱 Android Chrome
- 📱 iPadOS

## Security Notes

⚠️ **Important:** This interface is designed for local development use. For production deployment:

1. Add authentication/authorization
2. Enable HTTPS
3. Configure CORS properly
4. Set rate limits
5. Sanitize file uploads
6. Use environment secrets

## Related Files

- [`web_app.py`](./web_app.py) - FastAPI backend
- [`web/index.html`](./web/index.html) - Frontend interface
- [`web_crawler/_crawl_utils.py`](./web_crawler/_crawl_utils.py) - Crawl utilities
- [`ingestion/ingest.py`](./ingestion/ingest.py) - Document ingestion
- [`rag_agent.py`](./rag_agent.py) - RAG agent implementation

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Server-Sent Events MDN](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [Crawl4AI Documentation](https://github.com/unclecode/crawl4ai)
