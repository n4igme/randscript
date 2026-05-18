#!/usr/bin/env python3

import os
import sys
import json
import requests
import time

API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    print("")
    print("OPENROUTER_API_KEY not found")
    print("")
    sys.exit(1)

prompt = " ".join(sys.argv[1:])

if not prompt:
    prompt = input("AI > ")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

print("")
print("[ Fetching free AI models... ]")
print("")

try:

    models_response = requests.get(
        "https://openrouter.ai/api/v1/models",
        timeout=30
    )

    models_data = models_response.json()

except Exception as e:

    print("Failed to fetch model list")
    print(e)
    sys.exit(1)

free_models = []

for model in models_data["data"]:

    model_id = model["id"]

    if ":free" in model_id:

        free_models.append(model_id)

if not free_models:

    print("No free models found")
    sys.exit(1)

print(f"[ Found {len(free_models)} free models ]")
print("")

success = False

for model in free_models:

    print(f"[ Trying {model} ]")

    data = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert coding and Linux assistant."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    try:

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=60
        )

        result = response.json()

        if "choices" in result:

            print("")
            print(f"[ SUCCESS USING {model} ]")
            print("")
            print(result["choices"][0]["message"]["content"])
            print("")

            success = True
            break

        else:

            print("[ Failed ]")

    except Exception as e:

        print("[ Error ]")

    time.sleep(2)

if not success:

    print("")
    print("No available free AI models right now")
    print("")
