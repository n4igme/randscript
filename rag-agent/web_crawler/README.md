# Web Crawler - Scrape Web Content for RAG Knowledge Base

Collection of scripts for scraping web documentation and converting it to markdown format, ready for ingestion into the RAG system.

## Overview

These scripts use **[Crawl4AI](https://github.com/unclecode/crawl4ai)** - an async web crawler optimized for extracting LLM training data from websites.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  web_crawler/   │────▶│  documents/      │────▶│  ingestion/     │
│  (scrape web)   │     │  crawled/*.md    │     │  ingest.py      │
└─────────────────┘     └──────────────────┘     └──────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  PostgreSQL     │
                                              │  PGVector       │
                                              └─────────────────┘
```

## Prerequisites

Crawl4AI is already included in the project dependencies. If installing separately:

```bash
pip install crawl4ai
```

**Note:** Crawl4AI requires Chromium browser. It will download automatically on first run, or you can install it manually:

```bash
# Install Chromium (macOS)
brew install chromium

# Install Chromium (Linux)
sudo apt-get install chromium-browser
```

## Available Scripts

| Script | Purpose | Best For |
|--------|---------|----------|
| [`1-crawl_single_page.py`](#1-single-page) | Crawl one URL | Quick tests, single pages |
| [`2-crawl_docs_sequential.py`](#2-sequential-sitemap) | Crawl sitemap URLs one-by-one | Small sites, rate-limited targets |
| [`3-crawl_sitemap_in_parallel.py`](#3-parallel-batch) | Batch crawl with parallel workers | Large documentation sites |
| [`4-crawl_llms_txt.py`](#4-llmstxt-chunking) | Scrape Markdown source + chunking | LLM-friendly content formats |
| [`5-crawl_site_recursively.py`](#5-recursive-site-mirror) | Recursive crawl with depth control | Full site mirroring |

---

## Usage Examples

### 1. Single Page

Crawl a single webpage and save as markdown:

```bash
uv run python web_crawler/1-crawl_single_page.py
```

**Output:** `documents/crawled/pydantic-ai-homepage.md`

**Customize:** Edit the URL in the script:
```python
url="https://your-target-site.com/"
```

---

### 2. Sequential Sitemap

Crawl all URLs from a sitemap.xml sequentially (reuses browser session):

```bash
uv run python web_crawler/2-crawl_docs_sequential.py
```

**What it does:**
- Fetches `https://ai.pydantic.dev/sitemap.xml`
- Extracts all URLs from `<loc>` tags
- Crawls each URL one-by-one with session reuse

**Customize:** Change the sitemap URL in `get_pydantic_ai_docs_urls()`:
```python
sitemap_url = "https://your-docs-site.com/sitemap.xml"
```

**Use when:** Target site has rate limits or you want to be gentle

---

### 3. Parallel Batch

Crawl sitemap URLs in parallel (10 concurrent workers):

```bash
uv run python web_crawler/3-crawl_sitemap_in_parallel.py
```

**Features:**
- **Memory-adaptive**: Throttles if RAM exceeds 70%
- **Parallel**: Crawls 10 pages simultaneously
- **Fast**: Complete large sites in minutes

**Adjust concurrency:**
```python
await crawl_parallel(urls, max_concurrent=20)  # Increase for more parallelism
```

**Use when:** You need speed and have sufficient RAM

---

### 4. llms.txt Chunking

Scrape raw markdown and split by headers:

```bash
uv run python web_crawler/4-crawl_llms_txt.py
```

**What it does:**
- Fetches `https://ai.pydantic.dev/llms-full.txt` (raw markdown)
- Splits content by `#` and `##` headers
- Prints chunks for inspection

**Use case:** Sites that provide LLM-friendly markdown exports

**Supported formats:**
- `llms.txt` - Standard for LLM-ready documentation
- `.md` files - Raw markdown
- `.txt` files - Plain text

---

### 5. Recursive Site Mirror

Crawl entire site recursively up to specified depth:

```bash
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://ai.pydantic.dev/" \
    -r 3 \
    -o documents/crawled/pydantic-ai
```

**Options:**
```
-u, --url           Starting URL (required)
-r, --max-depth     Maximum recursion depth (default: 3)
-o, --output-dir    Output directory (default: documents/crawled)
-c, --concurrency   Max concurrent requests (default: 10)
```

**Example outputs:**
```bash
# Crawl 2 levels deep
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://docs.python.org/3/" -r 2

# High concurrency for large sites
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://example.com" -r 3 -c 20
```

**Output structure:**
```
documents/crawled/
├── index.md              (homepage)
├── getting_started.md
├── concepts_agents.md
├── concepts_tools.md
└── ...
```

**Features:**
- ✅ Deduplicates URLs (ignores fragments)
- ✅ Follows only internal links
- ✅ Saves each page as separate `.md` file
- ✅ Parallel crawling at each depth level

---

## Complete Workflow

### Step 1: Crawl Web Content

```bash
# Crawl documentation site
uv run python web_crawler/5-crawl_site_recursively.py \
    -u "https://your-docs-site.com/" \
    -r 2 \
    -o documents/crawled/my-docs
```

### Step 2: Ingest into RAG

```bash
# Add crawled content to knowledge base
uv run python -m ingestion.ingest --documents documents/crawled/my-docs/
```

### Step 3: Chat with Content

```bash
# Start the RAG agent
uv run python cli.py
```

**Example interaction:**
```
You: What are the main concepts covered in the documentation?
🤖 Assistant: Based on the knowledge base, the main concepts include...
   [Source: concepts_agents.md]
   [Source: getting_started.md]
```

---

## Advanced Configuration

### Adjust Browser Settings

Edit browser config for specific needs:

```python
browser_config = BrowserConfig(
    headless=True,                    # Run without GUI
    verbose=False,                    # Suppress logs
    extra_args=[
        "--disable-gpu",              # Disable GPU (faster in Docker)
        "--disable-dev-shm-usage",    # Use /tmp instead of /dev/shm
        "--no-sandbox"                # Required in Docker
    ]
)
```

### Memory Management

For large crawls, monitor and limit memory:

```python
dispatcher = MemoryAdaptiveDispatcher(
    memory_threshold_percent=70.0,  # Don't exceed 70% RAM
    check_interval=1.0,             # Check every 1 second
    max_session_permit=10           # Max 10 parallel browsers
)
```

### Custom Output Paths

Change where markdown files are saved:

```python
# In 5-crawl_site_recursively.py
output_dir="documents/crawled/custom-folder"
```

---

## Tips & Best Practices

### 1. Respect Rate Limits

```python
# For rate-limited sites, use sequential crawling
await crawl_sequential(urls)  # One at a time

# Or reduce concurrency
await crawl_parallel(urls, max_concurrent=2)
```

### 2. Handle Authentication

For sites requiring login, use session cookies:

```python
crawl_config = CrawlerRunConfig(
    headers={
        "Authorization": "Bearer YOUR_TOKEN",
        "Cookie": "session=YOUR_SESSION_COOKIE"
    }
)
```

### 3. Exclude External Links

Scripts already filter to internal links only:

```python
for link in result.links.get("internal", []):
    # Only follows links to same domain
    next_level_urls.add(link["href"])
```

### 4. Resume Interrupted Crawls

Add checkpointing to resume from last successful URL:

```python
# Save progress to JSON
import json

visited_file = Path("crawl_progress.json")
if visited_file.exists():
    visited = set(json.loads(visited_file.read_text()))
else:
    visited = set()

# Save after each URL
json.dump(list(visited), open(visited_file, "w"))
```

### 5. Handle JavaScript-Heavy Sites

Crawl4AI renders JavaScript automatically. For complex SPAs:

```python
browser_config = BrowserConfig(
    headless=True,
    extra_args=["--disable-gpu"]
)

crawl_config = CrawlerRunConfig(
    wait_for="css:.content-loaded",  # Wait for specific element
    delay_before_return_html=2.0     # Wait 2s after page load
)
```

---

## Troubleshooting

### Issue: Chromium Download Fails

**Solution:** Install manually
```bash
# macOS
brew install chromium

# Ubuntu/Debian
sudo apt-get install chromium-browser

# Then set path
export CRAWL4AI_CHROMIUM_PATH=$(which chromium)
```

### Issue: Memory Exhaustion

**Solution:** Reduce concurrency
```python
await crawl_parallel(urls, max_concurrent=5)  # Lower from 10 to 5
```

### Issue: Missing Content in Markdown

Some sites use dynamic loading. Add wait time:

```python
crawl_config = CrawlerRunConfig(
    wait_for="js:() => document.querySelector('.content') !== null",
    delay_before_return_html=3.0
)
```

### Issue: Rate Limiting (429 Errors)

**Solution:** Add delays between requests
```python
import asyncio

async def crawl_with_delay(urls):
    for url in urls:
        result = await crawler.arun(url)
        await asyncio.sleep(2.0)  # 2 second delay
```

---

## Supported Websites

These scripts work well with:

- ✅ **Documentation sites** (ReadTheDocs, Docusaurus, MkDocs)
- ✅ **Technical blogs** (Medium, Dev.to, Hashnode)
- ✅ **API references** (OpenAPI, Swagger UI)
- ✅ **GitHub Wikis**
- ✅ **Static sites** (Gatsby, Hugo, Jekyll)
- ✅ **SPAs** (React, Vue, Angular - JavaScript rendered)

**Not recommended for:**
- ❌ Sites with aggressive bot detection
- ❌ Login-walled content (without auth headers)
- ❌ Infinite scroll pages (use API if available)

---

## Integration with Ingestion Pipeline

The crawled markdown files are automatically processed by the ingestion pipeline:

1. **Docling** converts markdown to structured format
2. **Chunker** splits into semantic chunks
3. **Embedder** generates vector embeddings
4. **PostgreSQL** stores with PGVector for similarity search

**Supported formats from crawling:**
- `.md` / `.markdown` - Markdown files
- `.txt` - Plain text
- `.html` / `.htm` - HTML pages
- `.pdf` - PDF documents (via Docling)

---

## Related Files

- [`ingestion/ingest.py`](../ingestion/ingest.py) - Document ingestion pipeline
- [`documents/`](../documents/) - Sample documents folder
- [`cli.py`](../cli.py) - RAG agent CLI

---

## Resources

- [Crawl4AI Documentation](https://github.com/unclecode/crawl4ai)
- [llms.txt Standard](https://llmstxt.org/) - LLM-friendly documentation format
- [Sitemap Protocol](https://www.sitemaps.org/protocol.html) - XML sitemap specification
