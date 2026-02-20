# security_llm.py
from mlx_lm import load, generate

# First run: auto-downloads model (~4.3GB)
print("Loading the Model (first run downloads model)...")
model, tokenizer = load("lmstudio-community/Qwen3-4B-Instruct-2507-MLX-4bit")

# Subsequent runs: loads instantly from cache
prompt = """Analyze this C code for vulnerabilities:
strcpy(dest, user_input);
"""

response = generate(model, tokenizer, prompt=prompt, max_tokens=200)
print(response)
