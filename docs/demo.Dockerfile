# The VHS image plus mcp-audit, its corpus servers' SDK, and a Docker CLI, so `make demo`
# records the real CLI driving real sandboxes (through the host's Docker socket). The VHS
# image's Debian release is too old for its apt sources, so Python comes from the official
# bookworm image, copied in whole.
FROM python:3.11-slim-bookworm AS py
COPY pyproject.toml README.md /src/
COPY src /src/src
RUN pip install --no-cache-dir /src

FROM docker:28-cli AS docker

FROM ghcr.io/charmbracelet/vhs:v0.10.0
COPY --from=py /usr/local/lib /usr/local/lib
COPY --from=py /usr/local/bin /usr/local/bin
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
ENV PATH=/usr/local/bin:$PATH LD_LIBRARY_PATH=/usr/local/lib
