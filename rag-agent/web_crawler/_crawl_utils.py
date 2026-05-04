"""
Web Crawler Utilities for RAG Agent Web Interface
==================================================
Simplified crawl functions for web interface integration.

Note: Requires Python 3.10+ for crawl4ai compatibility.
"""

import asyncio
from pathlib import Path
from urllib.parse import urldefrag, urlparse, urljoin
from typing import List, Optional, Callable
import logging

logger = logging.getLogger(__name__)


async def crawl_site_recursive(
    start_url: str,
    max_depth: int = 3,
    max_concurrent: int = 10,
    output_dir: str = "documents/crawled",
    progress_callback: Optional[Callable] = None
) -> List[str]:
    """
    Recursively crawl a website and save as markdown files.

    Args:
        start_url: Starting URL
        max_depth: Maximum recursion depth
        max_concurrent: Maximum concurrent requests
        output_dir: Output directory for markdown files
        progress_callback: Optional callback(depth, urls_crawled, total_urls)

    Returns:
        List of saved markdown file paths
    """
    # Lazy import to avoid import errors when not using crawl functionality
    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode, MemoryAdaptiveDispatcher, UndetectedAdapter
        from crawl4ai.async_crawler_strategy import AsyncPlaywrightCrawlerStrategy
    except (TypeError, ImportError) as e:
        logger.error(f"crawl4ai import failed: {e}")
        raise RuntimeError("crawl4ai requires Python 3.10+. Please upgrade Python or install a compatible version.")

    browser_config = BrowserConfig(
        headless=True,
        verbose=False,
        extra_args=["--disable-gpu", "--disable-dev-shm-usage", "--no-sandbox"],
        enable_stealth=True,
        user_agent_mode="random"
    )

    run_config = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        stream=False,
        page_timeout=120000,  # Increase timeout to 2 minutes
    )

    dispatcher = MemoryAdaptiveDispatcher(
        memory_threshold_percent=70.0,
        check_interval=1.0,
        max_session_permit=max_concurrent
    )

    output_base = Path(output_dir)
    output_base.mkdir(parents=True, exist_ok=True)

    visited = set()

    def normalize_url(url: str) -> str:
        return urldefrag(url)[0]

    def is_binary_file(url: str) -> bool:
        binary_extensions = {'.exe', '.zip', '.pdf', '.dmg', '.bin', '.iso', '.msi'}
        return any(url.lower().endswith(ext) for ext in binary_extensions)

    current_urls = [normalize_url(start_url)]
    saved_files = []

    # Initialize strategy with UndetectedAdapter for better stealth
    strategy = AsyncPlaywrightCrawlerStrategy(
        browser_config=browser_config,
        browser_adapter=UndetectedAdapter()
    )

    async with AsyncWebCrawler(crawler_strategy=strategy) as crawler:
        for depth in range(max_depth):
            logger.info(f"Crawling depth {depth + 1}/{max_depth}")

            urls_to_crawl = [
                normalize_url(url) for url in current_urls
                if normalize_url(url) not in visited
            ]

            if not urls_to_crawl:
                break

            if progress_callback:
                progress_callback(depth + 1, len(visited), len(urls_to_crawl))

            results = await crawler.arun_many(
                urls=urls_to_crawl,
                config=run_config,
                dispatcher=dispatcher
            )

            next_level_urls = set()

            for result in results:
                norm_url = normalize_url(result.url)
                visited.add(norm_url)

                if result.success:
                    logger.info(f"[OK] {result.url}")

                    # Save markdown to file
                    parsed = urlparse(norm_url)
                    url_path = parsed.path.strip('/') or 'index'
                    filename = url_path.replace('/', '_') + '.md'
                    output_path = output_base / filename
                    output_path.write_text(result.markdown)
                    saved_files.append(str(output_path))
                    logger.info(f"  → Saved: {output_path}")

                    # Collect internal links for next depth
                    for link in result.links.get("internal", []):
                        raw_href = link["href"]
                        # Resolve relative URLs against the current page URL
                        absolute_url = urljoin(norm_url, raw_href)
                        next_url = normalize_url(absolute_url)
                        
                        if next_url not in visited and not is_binary_file(next_url):
                            next_level_urls.add(next_url)
                else:
                    logger.error(f"[ERROR] {result.url}: {result.error_message}")

            current_urls = list(next_level_urls)

    logger.info(f"Crawl completed. Saved {len(saved_files)} files.")
    return saved_files


async def crawl_single_url(
    url: str,
    output_path: Optional[str] = None
) -> str:
    """
    Crawl a single URL and return/save markdown.

    Args:
        url: URL to crawl
        output_path: Optional path to save markdown

    Returns:
        Markdown content
    """
    browser_config = BrowserConfig(
        headless=True,
        verbose=False,
        extra_args=["--disable-gpu", "--disable-dev-shm-usage", "--no-sandbox"],
        enable_stealth=True,
        user_agent_mode="random"
    )

    run_config = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        stream=False,
        page_timeout=120000,  # Increase timeout to 2 minutes
    )

    # Initialize strategy with UndetectedAdapter for better stealth
    strategy = AsyncPlaywrightCrawlerStrategy(
        browser_config=browser_config,
        browser_adapter=UndetectedAdapter()
    )

    async with AsyncWebCrawler(crawler_strategy=strategy) as crawler:
        result = await crawler.arun(url, config=run_config)

        if not result.success:
            raise Exception(f"Crawl failed: {result.error_message}")

        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(result.markdown)
            logger.info(f"Saved to {output_path}")

        return result.markdown
