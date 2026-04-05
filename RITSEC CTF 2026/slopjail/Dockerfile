FROM python:3.14-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir transformers safetensors tokenizers

RUN useradd -m -s /bin/bash jail

WORKDIR /app

COPY jail.py .
COPY model/config.json .
COPY model/generation_config.json .
COPY model/tokenizer.json .
COPY model/tokenizer_config.json .
COPY model/special_tokens_map.json .

COPY flag.txt /

RUN python -c "from transformers import AutoModelForCausalLM, PreTrainedTokenizerFast; import torch"

RUN chown -R jail:jail /app

USER jail

EXPOSE 1337

ENV HF_HUB_DISABLE_PROGRESS_BARS=1

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 -u /app/jail.py,stderr"]