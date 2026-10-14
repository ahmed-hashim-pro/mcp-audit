# The base sandbox: Node 22, Python 3, git, strace, planted credentials and a seeded /workspace.
# Build an image for your own server FROM this one (see the README), then pass it to --sandbox.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv strace git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/root \
    UV_USE_IO_URING=0 \
    PYTHONDONTWRITEBYTECODE=1

# Planted credentials. Each holds the canary string and nothing real; any process that opens
# one was never pointed at it by mcp-audit, which only ever passes paths under /workspace.
RUN set -eu; c=MCPAUDIT-CANARY-7f3a9c; \
    mkdir -p /root/.ssh /root/.aws /root/.config/gcloud /root/.docker /root/.kube; \
    printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\n%s-ssh-key\n-----END OPENSSH PRIVATE KEY-----\n' $c > /root/.ssh/id_rsa; \
    printf 'ssh-ed25519 AAAA%s probe@sandbox\n' $c > /root/.ssh/id_rsa.pub; \
    printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s-aws\n' $c $c > /root/.aws/credentials; \
    printf '{"type": "authorized_user", "refresh_token": "%s-gcloud"}\n' $c > /root/.config/gcloud/application_default_credentials.json; \
    printf 'machine api.example.com login probe password %s-netrc\n' $c > /root/.netrc; \
    printf '//registry.npmjs.org/:_authToken=%s-npm\n' $c > /root/.npmrc; \
    printf 'https://probe:%s-git@github.com\n' $c > /root/.git-credentials; \
    printf '{"auths": {"ghcr.io": {"auth": "%s-docker"}}}\n' $c > /root/.docker/config.json; \
    printf 'apiVersion: v1\nkind: Config\nusers: [{name: probe, user: {token: %s-kube}}]\n' $c > /root/.kube/config; \
    chmod 600 /root/.ssh/id_rsa /root/.aws/credentials /root/.netrc /root/.git-credentials

# The workspace tools are pointed at: a couple of files and a small git repository.
RUN set -eu; mkdir -p /workspace/docs /workspace/repo; \
    printf 'mcp-audit sample notes\n' > /workspace/notes.txt; \
    printf '# Sample\n\nA file for tools to read.\n' > /workspace/docs/readme.md; \
    cd /workspace/repo; git init -q -b main; printf 'hello\n' > hello.txt; git add hello.txt; \
    git -c user.name=probe -c user.email=probe@example.com commit -q -m 'first commit'; \
    printf 'hello again\n' >> hello.txt

COPY docker/mcp-audit-run /usr/local/bin/mcp-audit-run
WORKDIR /workspace
