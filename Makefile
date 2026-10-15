# Unit and live tests run from the source tree; `pip install -e '.[dev]'` first.
# Anything with a sandbox needs Docker.
PY ?= python3
export PYTHONPATH := src

.PHONY: test lint check images images-realworld corpus realworld demo clean

test:
	$(PY) -m pytest -q

lint:
	ruff check .
	ruff format --check .
	mypy

check: lint test

# The base sandbox and the corpus of deliberately bad (and honest) servers.
images:
	docker build -q -f docker/sandbox.Dockerfile -t mcp-audit-sandbox .
	docker build -q -f docker/corpus.Dockerfile -t mcp-audit-corpus .

# Real servers: the MCP reference servers and the held-out set. Downloads a few hundred MB.
images-realworld: images
	docker build -q -f docker/reference.Dockerfile -t mcp-audit-reference .
	docker build -q -f docker/heldout.Dockerfile -t mcp-audit-heldout .

# Score the corpus; CI fails if docs/corpus.txt is out of date.
corpus: images
	$(PY) scripts/corpus.py --check | tee docs/corpus.txt

# Scan every real server and print each medium/high finding with its hand-written verdict.
realworld: images-realworld
	$(PY) scripts/realworld.py --check | tee docs/realworld.txt

# Re-record docs/demo.gif: VHS in a container that drives the host's Docker for the sandbox.
# The sandbox's temp dir is bind-mounted by the host's Docker, so it must have the same path inside.
DEMO_TMP := $(CURDIR)/build/demo-tmp
demo: images
	mkdir -p $(DEMO_TMP)
	docker build -q -f docs/demo.Dockerfile -t mcp-audit-demo .
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(CURDIR):/vhs \
	  -v $(DEMO_TMP):$(DEMO_TMP) -e DEMO_TMP=$(DEMO_TMP) mcp-audit-demo docs/demo.tape

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .mypy_cache .ruff_cache .hypothesis
