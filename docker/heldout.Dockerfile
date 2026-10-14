# Held-out servers: popular third-party MCP servers, pinned. The rules were not tuned on these;
# their results are reported as they came out (see docs/heldout.txt).
# (@wonderwhy-er/desktop-commander@0.3.0 was dropped: its install compiles a macOS-only module.)
FROM mcp-audit-sandbox
RUN npm install -g --no-fund --no-audit \
      @upstash/context7-mcp@4.4.1 \
      @playwright/mcp@0.0.83 \
      chrome-devtools-mcp@1.10.1 \
      @notionhq/notion-mcp-server@2.5.2 \
      mcp-server-kubernetes@4.1.9 \
 && npm cache clean --force
# Each Python server in its own venv (their pins conflict), linked onto PATH.
RUN set -eu; for spec in markitdown-mcp==0.0.1a7 awslabs.aws-documentation-mcp-server==1.2.3 arxiv-mcp-server==0.8.2; do \
      name=${spec%%==*}; python3 -m venv /opt/servers/$name; \
      /opt/servers/$name/bin/pip install --no-cache-dir -q "$spec"; \
      for b in /opt/servers/$name/bin/*; do case $(basename $b) in *mcp*|*server*) ln -sf $b /usr/local/bin/;; esac; done; \
    done
