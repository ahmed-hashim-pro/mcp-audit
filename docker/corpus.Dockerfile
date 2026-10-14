# The test corpus: deliberately malicious and honest MCP servers (examples/corpus).
FROM mcp-audit-sandbox
RUN pip install --no-cache-dir mcp==2.3.0
COPY examples/corpus /corpus
