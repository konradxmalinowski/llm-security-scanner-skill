# Runs the skill's CLI and MCP server in a container. The scanner comes in as a
# dependency, so this image can scan an HTTP target on its own; it still needs an
# Ollama daemon for the judge, reached over the network (see docs/INSTALL.md).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Default to the host's Ollama when run with --network host or on Docker Desktop.
    OLLAMA_HOST=http://host.docker.internal:11434

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY skills ./skills

RUN pip install --no-cache-dir ".[mcp]"

# Reports are written here; mount a volume to keep them.
VOLUME ["/reports"]

ENTRYPOINT ["llm-scanner-skill"]
CMD ["doctor"]
