"""
Web Interface for RAG Agent
============================
FastAPI-based web application providing:
- Document upload and ingestion
- Web crawling interface
- Real-time chat with streaming responses
"""

import os
import sys
import asyncio
import json
import logging
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
import uuid

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import RAG agent components
from pydantic_ai import Agent, RunContext
from utils.providers import get_llm_model
from utils.db_utils import db_pool, initialize_database, close_database, test_connection

logger = logging.getLogger(__name__)

# Global state
task_status: Dict[str, Dict[str, Any]] = {}
message_history: List[Dict[str, Any]] = []
rag_agent: Optional[Agent] = None


@dataclass
class AppState:
    """Application state."""
    db_initialized: bool = False
    agent_initialized: bool = False
    ingestion_in_progress: bool = False
    crawl_in_progress: bool = False


state = AppState()


# ============================================================================
# FastAPI Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup on app start/stop."""
    global rag_agent, state

    logger.info("Starting RAG Agent Web Interface...")

    # Initialize database
    try:
        await initialize_database()
        state.db_initialized = await test_connection()
        logger.info(f"Database connection: {'✓' if state.db_initialized else '✗'}")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

    # Initialize RAG agent
    try:
        llm_model = get_llm_model()
        rag_agent = Agent(
            llm_model,
            system_prompt="""You are an intelligent knowledge assistant with access to an organization's documentation and information.
Your role is to help users find accurate information from the knowledge base.
You have a professional yet friendly demeanor.

IMPORTANT: Always search the knowledge base before answering questions about specific information.
If information isn't in the knowledge base, clearly state that and offer general guidance.
Be concise but thorough in your responses.
Ask clarifying questions if the user's query is ambiguous.
When you find relevant information, synthesize it clearly and cite the source documents.""",
            tools=[search_knowledge_base]
        )
        state.agent_initialized = True
        logger.info("RAG Agent initialized")
    except Exception as e:
        logger.error(f"Agent initialization failed: {e}")

    yield

    # Cleanup
    await close_database()
    logger.info("Application shutdown complete")


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="RAG Agent Web Interface",
    description="Document ingestion, web crawling, and AI chat interface",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# RAG Agent Tool
# ============================================================================

async def search_knowledge_base(ctx: RunContext[None], query: str, limit: int = 5) -> str:
    """Search the knowledge base using semantic similarity."""
    try:
        if not state.db_initialized:
            return "Database not initialized. Please check your DATABASE_URL configuration."

        from ingestion.embedder import create_embedder
        embedder = create_embedder()
        query_embedding = await embedder.embed_query(query)

        embedding_str = '[' + ','.join(map(str, query_embedding)) + ']'

        async with db_pool.acquire() as conn:
            results = await conn.fetch(
                "SELECT * FROM match_chunks($1::vector, $2)",
                embedding_str,
                limit
            )

        if not results:
            return "No relevant information found in the knowledge base for your query."

        response_parts = []
        for i, row in enumerate(results, 1):
            content = row['content']
            doc_title = row['document_title']
            response_parts.append(f"[Source: {doc_title}]\n{content}\n")

        return f"Found {len(response_parts)} relevant results:\n\n" + "\n---\n".join(response_parts)

    except Exception as e:
        logger.error(f"Knowledge base search failed: {e}")
        return f"I encountered an error searching the knowledge base: {str(e)}"


# ============================================================================
# Pydantic Models
# ============================================================================

class ChatMessage(BaseModel):
    """Chat message model."""
    message: str
    history: Optional[List[Dict[str, str]]] = None


class CrawlRequest(BaseModel):
    """Web crawl request model."""
    url: str
    max_depth: int = 3
    concurrency: int = 10
    output_dir: str = "documents/crawled"


class IngestRequest(BaseModel):
    """Document ingestion request model."""
    documents_path: str = "documents"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    clean_before: bool = True


class TaskStatus(BaseModel):
    """Task status model."""
    task_id: str
    status: str  # pending, running, completed, failed
    progress: int  # 0-100
    message: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ============================================================================
# API Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main HTML page."""
    html_path = Path(__file__).parent / "web" / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    raise HTTPException(status_code=404, detail="Web interface not found. Please create web/index.html")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    db_status = await test_connection() if state.db_initialized else False
    return {
        "status": "healthy" if db_status and state.agent_initialized else "degraded",
        "database": "connected" if db_status else "disconnected",
        "agent": "ready" if state.agent_initialized else "not_ready",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/stats")
async def get_stats():
    """Get knowledge base statistics."""
    try:
        async with db_pool.acquire() as conn:
            doc_count = await conn.fetchval("SELECT COUNT(*) FROM documents")
            chunk_count = await conn.fetchval("SELECT COUNT(*) FROM chunks")

            # Get recent documents
            recent_docs = await conn.fetch(
                """
                SELECT title, source, created_at
                FROM documents
                ORDER BY created_at DESC
                LIMIT 5
                """
            )

            return {
                "documents": doc_count,
                "chunks": chunk_count,
                "recent_documents": [
                    {"title": row["title"], "source": row["source"], "created_at": row["created_at"].isoformat()}
                    for row in recent_docs
                ]
            }
    except Exception as e:
        logger.error(f"Stats fetch failed: {e}")
        return {"documents": 0, "chunks": 0, "recent_documents": [], "error": str(e)}


# ============================================================================
# Document Upload & Ingestion
# ============================================================================

@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)):
    """Upload a document file."""
    try:
        # Create documents directory if not exists
        docs_dir = Path("documents")
        docs_dir.mkdir(exist_ok=True)

        # Save file
        file_path = docs_dir / file.filename
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)

        logger.info(f"Uploaded file: {file.filename} ({len(content)} bytes)")

        return {
            "success": True,
            "filename": file.filename,
            "path": str(file_path),
            "size": len(content)
        }
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ingest")
async def start_ingestion(background_tasks: BackgroundTasks, request: IngestRequest = None):
    """Start document ingestion process."""
    if state.ingestion_in_progress:
        raise HTTPException(status_code=400, detail="Ingestion already in progress")

    task_id = str(uuid.uuid4())
    task_status[task_id] = {
        "status": "pending",
        "progress": 0,
        "message": "Starting ingestion...",
        "result": None,
        "error": None
    }

    background_tasks.add_task(run_ingestion, task_id, request)

    return {"task_id": task_id, "status": "started"}


async def run_ingestion(task_id: str, request: IngestRequest = None):
    """Run ingestion task in background."""
    global state
    state.ingestion_in_progress = True

    try:
        task_status[task_id]["status"] = "running"
        task_status[task_id]["progress"] = 10
        task_status[task_id]["message"] = "Initializing ingestion pipeline..."

        from ingestion.ingest import DocumentIngestionPipeline
        from utils.models import IngestionConfig

        config = IngestionConfig(
            chunk_size=request.chunk_size if request else 1000,
            chunk_overlap=request.chunk_overlap if request else 200,
            use_semantic_chunking=True
        )

        docs_path = request.documents_path if request else "documents"
        pipeline = DocumentIngestionPipeline(
            config=config,
            documents_folder=docs_path,
            clean_before_ingest=request.clean_before if request else True
        )

        task_status[task_id]["progress"] = 30
        task_status[task_id]["message"] = f"Ingesting documents from {docs_path}..."

        results = await pipeline.ingest_documents()

        task_status[task_id]["progress"] = 90
        task_status[task_id]["message"] = "Finalizing..."

        total_chunks = sum(r.chunks_created for r in results)
        total_errors = sum(len(r.errors) for r in results)

        task_status[task_id]["status"] = "completed"
        task_status[task_id]["progress"] = 100
        task_status[task_id]["message"] = f"Ingested {len(results)} documents, {total_chunks} chunks"
        task_status[task_id]["result"] = {
            "documents": len(results),
            "chunks": total_chunks,
            "errors": total_errors
        }

        await pipeline.close()

    except Exception as e:
        logger.error(f"Ingestion failed: {e}", exc_info=True)
        task_status[task_id]["status"] = "failed"
        task_status[task_id]["error"] = str(e)
        task_status[task_id]["message"] = f"Ingestion failed: {str(e)}"
    finally:
        state.ingestion_in_progress = False


# ============================================================================
# Web Crawling
# ============================================================================

@app.post("/api/crawl")
async def start_crawl(background_tasks: BackgroundTasks, request: CrawlRequest):
    """Start web crawling process."""
    if state.crawl_in_progress:
        raise HTTPException(status_code=400, detail="Crawl already in progress")

    task_id = str(uuid.uuid4())
    task_status[task_id] = {
        "status": "pending",
        "progress": 0,
        "message": "Starting web crawl...",
        "result": None,
        "error": None
    }

    background_tasks.add_task(run_crawl, task_id, request)

    return {"task_id": task_id, "status": "started"}


async def run_crawl(task_id: str, request: CrawlRequest):
    """Run crawl task in background."""
    global state
    state.crawl_in_progress = True

    try:
        task_status[task_id]["status"] = "running"
        task_status[task_id]["progress"] = 10
        task_status[task_id]["message"] = f"Crawling {request.url}..."

        # Import crawl function
        sys.path.append(str(Path(__file__).parent))
        from web_crawler._crawl_utils import crawl_site_recursive

        output_dir = Path(request.output_dir) / f"crawl_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        await crawl_site_recursive(
            start_url=request.url,
            max_depth=request.max_depth,
            max_concurrent=request.concurrency,
            output_dir=str(output_dir)
        )

        task_status[task_id]["progress"] = 100
        task_status[task_id]["status"] = "completed"
        task_status[task_id]["message"] = f"Crawl completed: {output_dir}"
        task_status[task_id]["result"] = {"output_dir": str(output_dir)}

    except Exception as e:
        logger.error(f"Crawl failed: {e}", exc_info=True)
        task_status[task_id]["status"] = "failed"
        task_status[task_id]["error"] = str(e)
        task_status[task_id]["message"] = f"Crawl failed: {str(e)}"
    finally:
        state.crawl_in_progress = False


@app.get("/api/task/{task_id}")
async def get_task_status(task_id: str):
    """Get task status."""
    if task_id not in task_status:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, **task_status[task_id]}


# ============================================================================
# Chat with Streaming
# ============================================================================

@app.post("/api/chat")
async def chat(request: ChatMessage):
    """Chat with the RAG agent with streaming response."""
    global message_history

    if not state.agent_initialized:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    try:
        # Use provided history or global history
        history = request.history if request.history else message_history

        # Stream response
        async def generate():
            global message_history
            
            async with rag_agent.run_stream(request.message, message_history=history) as result:
                async for text in result.stream_text(delta=True):
                    yield f"data: {json.dumps({'type': 'token', 'content': text})}\n\n"

                # Update history
                message_history = result.all_messages()

                # Send completion signal
                yield f"data: {json.dumps({'type': 'complete', 'history': [str(m) for m in message_history[-2:]]})}\n\n"

        return StreamingResponse(generate(), media_type="text/event-stream")

    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat/clear")
async def clear_chat():
    """Clear chat history."""
    global message_history
    message_history = []
    return {"success": True, "message": "Chat history cleared"}


# ============================================================================
# Static Files
# ============================================================================

# Mount static files directory
web_dir = Path(__file__).parent / "web"
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RAG Agent Web Interface")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--reload", action="store_true", default=True, help="Enable auto-reload mode")
    parser.add_argument("--no-reload", action="store_false", dest="reload", help="Disable auto-reload mode")
    args = parser.parse_args()

    uvicorn.run(
        "web_app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )
