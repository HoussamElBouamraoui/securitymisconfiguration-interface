import os
import requests
from typing import Any, Dict, Optional

OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "deepseek-r1:8b")

def ollama_generate(prompt: str, *, model: Optional[str] = None, temperature: float = 0.2) -> str:
    url = f"{OLLAMA_BASE}/api/generate"
    payload: Dict[str, Any] = {
        "model": model or OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
        },
    }
    r = requests.post(url, json=payload, timeout=300)
    r.raise_for_status()
    data = r.json()
    return data.get("response", "")