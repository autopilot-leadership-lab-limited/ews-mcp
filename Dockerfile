FROM python:3.12-slim

RUN useradd --system --uid 10001 --home /data ews-mcp && mkdir -p /data && chown ews-mcp: /data
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER ews-mcp
ENV EWS_MCP_DATA_DIR=/data \
    EWS_MCP_BIND_HOST=0.0.0.0 \
    EWS_MCP_BIND_PORT=8000 \
    EWS_MCP_FORWARDED_ALLOW_IPS=*
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"
CMD ["ews-mcp", "serve"]
