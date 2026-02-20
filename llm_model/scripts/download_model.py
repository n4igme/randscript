from huggingface_hub import hf_hub_download

# Download Q4_K_M (recommended)
hf_hub_download(
    repo_id="Qwen/Qwen2.5-Coder-7B-Instruct-GGUF",
    filename="qwen2.5-coder-7b-instruct-q4_k_m.gguf"
)
