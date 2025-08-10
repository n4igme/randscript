import argparse
import os
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "codellama")

PROMPT_TEMPLATE = """
You are a world-class application-security engineer and vulnerability researcher with deep expertise in secure coding, threat modeling, and offensive techniques.

TASK:
Perform an exhaustive, line-by-line static analysis of the code below. Identify **every** potential security weakness, anti-pattern, or design flaw that could lead to confidentiality, integrity, or availability issues. For each finding, return the following **exact** structure:

---

### 🚨 Finding #[Number]

- ✅ **Title:** <short, clear title>
- 📄 **Description:** <what the issue is, why it’s a problem, how it could be exploited>
- 🧱 **Impact Area:** <Auth | Input Validation | Cryptography | Secrets Management | RCE | Injection | Logic Flaw | Access Control | etc.>
- 🔥 **Severity:** <Critical | High | Medium | Low>
  - Justify with exploitability, impact, prevalence, and likelihood of discovery
- 💣 **Proof of Concept (PoC):**  
  <concrete payload, curl command, test input, or malicious flow that triggers the issue>
- 🛠️ **Suggested Fix:**  
  <specific code change, secure design pattern, or configuration hardening>
- 🔎 **Reference:** <CVE / CWE / OWASP Top 10 mapping if applicable>
- 📂 **Location:** <filename.ext:line-range>

---

Requirements:
- Be precise: cite exact line numbers or ranges where possible.
- Be actionable: provide working, secure code for every suggested fix.
- Be exhaustive: do **not** stop after the first issue—continue scanning the entire snippet.
- Prioritize findings by real-world exploitability, not theoretical risk.

Code to analyze:
{code_block}
"""

# You can add more extensions as needed
LANG_TO_EXT = {
    'py': '.py',
    'js': '.js',
    'go': '.go',
    'kt': '.kt',
    'java': '.java',
    'c': '.c',
    'cpp': '.cpp',
    'rb': '.rb',
    # etc.
}

def build_prompt(code, language, context):
    code_block = f"```{language}\n{code}\n```"
    return PROMPT_TEMPLATE.format(code_block=code_block)

def analyze_code_with_ollama(prompt, model):
    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False,
        },
        timeout=120,
    )
    response.raise_for_status()
    data = response.json()
    return data['message']['content']

def analyze_directory(directory, language, context, model):
    ext = LANG_TO_EXT.get(language, f".{language}")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(ext):
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
    parser.add_argument("--lang", required=True, help="Programming language (e.g. py, js, go, kt)")
    parser.add_argument("--context", default="No additional context", help="Context or filename (optional)")
    parser.add_argument("--model", default=OLLAMA_MODEL, help="Ollama model to use (default: codellama)")
    args = parser.parse_args()
    # python ollasec.py /Path/To/Source_Code/ --lang c --model deepseek-coder:latest

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
