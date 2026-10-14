# The reference servers from github.com/modelcontextprotocol/servers, pinned.
FROM mcp-audit-sandbox
RUN npm install -g --no-fund --no-audit \
      @modelcontextprotocol/server-everything@1.0.0 \
      @modelcontextprotocol/server-filesystem@1.0.0 \
      @modelcontextprotocol/server-memory@1.0.0 \
      @modelcontextprotocol/server-sequential-thinking@1.0.0 \
 && pip install --no-cache-dir mcp-server-fetch==2026.10.10 mcp-server-git==2026.10.10 mcp-server-time==2026.10.10 \
 && npm cache clean --force
