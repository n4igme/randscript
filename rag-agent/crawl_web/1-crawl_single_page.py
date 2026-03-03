import asyncio
from pathlib import Path
from crawl4ai import AsyncWebCrawler, BrowserConfig

async def main():
    async with AsyncWebCrawler() as crawler:
        result = await crawler.arun(
            url="https://ai.pydantic.dev/",
        )
        
        # Save to markdown file
        output_path = Path("documents/crawled/pydantic-ai-homepage.md")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.markdown)
        
        print(f"Saved to {output_path}")

if __name__ == "__main__":
    asyncio.run(main())