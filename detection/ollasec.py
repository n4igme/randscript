import argparse
import os
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "codellama")

PROMPT_TEMPLATE = """
You are an experienced cybersecurity engineer and static analysis expert.
Your task is to review the following code for bugs, security vulnerabilities, and maintainability issues.

- Be direct and specific—do not sugarcoat issues.
- Focus on OWASP Top 10 and common language-specific security flaws.
- If you see hardcoded secrets, weak crypto, insecure APIs, or business logic flaws, call them out.
- Suggest clear, actionable fixes and best practices.
- If the code looks good, state that clearly.
- Summarize risks and improvements in bullet points.

Here is the context:
{context}

Here is the code to analyze {language}:
{code_block}
"""

def build_prompt(code, language, context):
    code_block = f"```{language}\n{code}\n```"
    return PROMPT_TEMPLATE.format(language=language, context=context, code_block=code_block)

def analyze_code_with_ollama(prompt, model):
    response = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
        },
        timeout=120,
    )
    response.raise_for_status()
    data = response.json()
    return data['response']

def analyze_directory(directory, language, context, model):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(f".{language}"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()
                prompt = build_prompt(code, language, f"{context} | {path}")
                print(f"\n=== ANALYZING: {path} ===\n")
                try:
                    result = analyze_code_with_ollama(prompt, model)
                    print(result)
                except Exception as e:
                    print(f"Error analyzing {path}: {e}")
                print("\n" + "="*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Static code analysis with Ollama (local LLM)")
    parser.add_argument("target", help="Path to file or directory")
    parser.add_argument("--lang", required=True, help="Programming language (e.g. go, py, js)")
    parser.add_argument("--context", default="No additional context", help="Context or filename (optional)")
    parser.add_argument("--model", default=OLLAMA_MODEL, help="Ollama model to use (default: codellama)")
    args = parser.parse_args()
    # python ollasec.py source_code/ --lang kt --model deepseek-coder:latest

    if os.path.isdir(args.target):
        analyze_directory(args.target, args.lang, args.context, args.model)
    elif os.path.isfile(args.target):
        with open(args.target, "r", encoding="utf-8") as f:
            code = f.read()
        prompt = build_prompt(code, args.lang, args.context)
        print(f"\n=== ANALYZING: {args.target} ===\n")
        try:
            result = analyze_code_with_ollama(prompt, args.model)
            print(result)
        except Exception as e:
            print(f"Error analyzing {args.target}: {e}")
    else:
        print(f"Target path {args.target} is not a file or directory.")

if __name__ == "__main__":
    main()
