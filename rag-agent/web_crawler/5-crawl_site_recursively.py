"""
5-crawl_recursive_internal_links.py
----------------------------------
Recursively crawls a site starting from a root URL, using Crawl4AI's arun_many and a memory-adaptive dispatcher.
At each depth, all internal links are discovered and crawled in parallel, up to a specified depth, with deduplication.
Usage: python 5-crawl_site_recursively.py -u "https://ai.pydantic.dev/" -r 3
"""
import argparse
import asyncio
from pathlib import Path
from urllib.parse import urldefrag, urlparse
from crawl4ai import (
    AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode,
    MemoryAdaptiveDispatcher, UndetectedAdapter
)
from crawl4ai.async_crawler_strategy import AsyncPlaywrightCrawlerStrategy

async def crawl_recursive_batch(start_urls, max_depth=3, max_concurrent=10, output_dir="documents/crawled"):
    browser_config = BrowserConfig(
        headless=True, 
        verbose=False,
        enable_stealth=True,
        user_agent_mode="random"
    )
    run_config = CrawlerRunConfig(
        cache_mode=CacheMode.BYPASS,
        stream=False,
        page_timeout=120000  # Increase timeout to 2 minutes
    )
    dispatcher = MemoryAdaptiveDispatcher(
        memory_threshold_percent=70.0,      # Don't exceed 70% memory usage
        check_interval=1.0,                 # Check memory every second
        max_session_permit=max_concurrent   # Max parallel browser sessions
    )

    # Output directory for markdown files
    output_base = Path(output_dir)
    output_base.mkdir(parents=True, exist_ok=True)

    # Track visited URLs to prevent revisiting and infinite loops (ignoring fragments)
    visited = set()
    def normalize_url(url):
        # Remove fragment (part after #)
        return urldefrag(url)[0]
    current_urls = set([normalize_url(u) for u in start_urls])

    # Initialize strategy with UndetectedAdapter for better stealth
    strategy = AsyncPlaywrightCrawlerStrategy(
        browser_config=browser_config,
        browser_adapter=UndetectedAdapter()
    )

    async with AsyncWebCrawler(crawler_strategy=strategy) as crawler:
        for depth in range(max_depth):
            print(f"\n=== Crawling Depth {depth+1} ===")
            # Only crawl URLs we haven't seen yet (ignoring fragments)
            urls_to_crawl = [normalize_url(url) for url in current_urls if normalize_url(url) not in visited]

            if not urls_to_crawl:
                break

            # Batch-crawl all URLs at this depth in parallel
            results = await crawler.arun_many(
                urls=urls_to_crawl,
                config=run_config,
                dispatcher=dispatcher
            )

            next_level_urls = set()

            for result in results:
                norm_url = normalize_url(result.url)
                visited.add(norm_url)  # Mark as visited (no fragment)
                if result.success:
                    print(f"[OK] {result.url} | Markdown: {len(result.markdown) if result.markdown else 0} chars")
                    
                    # Save markdown to file
                    parsed = urlparse(norm_url)
                    # Create filename from URL path
                    url_path = parsed.path.strip('/') or 'index'
                    # Replace slashes with underscores for filename
                    filename = url_path.replace('/', '_') + '.md'
                    output_path = output_base / filename
                    output_path.write_text(result.markdown)
                    print(f"  → Saved: {output_path}")
                    
                    # Collect all new internal links for the next depth
                    for link in result.links.get("internal", []):
                        next_url = normalize_url(link["href"])
                        if next_url not in visited:
                            next_level_urls.add(next_url)
                else:
                    print(f"[ERROR] {result.url}: {result.error_message}")
                    
            # Move to the next set of URLs for the next recursion depth
            current_urls = next_level_urls

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively crawl a website and save markdown files")
    parser.add_argument("-u", "--url", required=True, help="Starting URL for crawling")
    parser.add_argument("-r", "--max-depth", type=int, default=3, help="Maximum recursion depth (default: 3)")
    parser.add_argument("-o", "--output-dir", default="documents/crawled", help="Output directory for markdown files (default: documents/crawled)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    
    args = parser.parse_args()
    
    asyncio.run(crawl_recursive_batch(
        [args.url],
        max_depth=args.max_depth,
        max_concurrent=args.concurrency,
        output_dir=args.output_dir
    ))
