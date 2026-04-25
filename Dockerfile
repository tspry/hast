# ── Stage 1: Download security tools ─────────────────────────────────────────
# TARGETARCH is set automatically by Docker BuildKit to amd64 / arm64 / arm
ARG TARGETARCH=amd64
FROM golang:1.24-bookworm AS tool-downloader
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip tar \
 && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

WORKDIR /tools

RUN set -eux \
 && echo "==> Building for arch: ${TARGETARCH}" \
 \
 && mkdir -p /root/pd-tools \
 && HOME=/root pdtm \
      -i nuclei \
      -i subfinder \
      -i dnsx \
      -i httpx \
      -i naabu \
      -i tlsx \
      -i cdncheck \
      -i asnmap \
      -i alterx \
      -i shuffledns \
      -i urlfinder \
      -bp /root/pd-tools \
 && find /root/pd-tools -maxdepth 1 -type f -perm -111 -exec cp {} /tools/ \; \
 || echo "[warn] pdtm selective install failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/projectdiscovery/katana/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/projectdiscovery/katana/releases/download/${VER}/katana_${VER#v}_linux_${TARGETARCH}.zip" \
         -o katana.zip \
 && unzip -qjo katana.zip katana -d . && chmod +x katana && rm katana.zip \
 || echo "[warn] katana download failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/jaeles-project/gospider/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/jaeles-project/gospider/releases/download/${VER}/gospider_linux_${TARGETARCH}.zip" \
         -o gospider.zip \
 && unzip -qjo gospider.zip -d . && test -f gospider && chmod +x gospider && rm gospider.zip \
 || echo "[warn] gospider download failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/hakluke/hakrawler/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/hakluke/hakrawler/releases/download/${VER}/hakrawler_${VER#v}_linux_${TARGETARCH}.tar.gz" \
         -o hakrawler.tar.gz \
 && tar -xzf hakrawler.tar.gz --strip-components=0 --wildcards '*/hakrawler' 2>/dev/null \
    || tar -xzf hakrawler.tar.gz hakrawler \
 && chmod +x hakrawler && rm hakrawler.tar.gz \
 || echo "[warn] hakrawler download failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/lc/gau/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/lc/gau/releases/download/${VER}/gau_${VER#v}_linux_${TARGETARCH}.tar.gz" \
         -o gau.tar.gz \
 && tar -xzf gau.tar.gz gau && chmod +x gau && rm gau.tar.gz \
 || echo "[warn] gau download failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/ffuf/ffuf/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/ffuf/ffuf/releases/download/${VER}/ffuf_${VER#v}_linux_${TARGETARCH}.tar.gz" \
         -o ffuf.tar.gz \
 && tar -xzf ffuf.tar.gz ffuf && chmod +x ffuf && rm ffuf.tar.gz \
 || echo "[warn] ffuf download failed" \
 \
 && VER=$(curl -sf https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/trufflesecurity/trufflehog/releases/download/${VER}/trufflehog_${VER#v}_linux_${TARGETARCH}.tar.gz" \
         -o trufflehog.tar.gz \
 && tar -xzf trufflehog.tar.gz trufflehog && chmod +x trufflehog && rm trufflehog.tar.gz \
 || echo "[warn] trufflehog download failed" \
 \
 && GLARCH=$([ "${TARGETARCH}" = "amd64" ] && echo "x64" || echo "${TARGETARCH}") \
 && VER=$(curl -sf https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && test -n "$VER" \
 && curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/${VER}/gitleaks_${VER#v}_linux_${GLARCH}.tar.gz" \
         -o gitleaks.tar.gz \
 && tar -xzf gitleaks.tar.gz gitleaks && chmod +x gitleaks && rm gitleaks.tar.gz \
 || echo "[warn] gitleaks download failed"

# Ensure /tools/ always has at least one file so COPY doesn't fail
RUN touch /tools/.keep


# ── Stage 2: Final runtime image ──────────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="HAST Security Scanner"
LABEL org.opencontainers.image.description="Hardening & Attack Surface Tester"

# nmap, curl, whatweb (Debian Bookworm package), libcap2-bin (for setcap on nmap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl ca-certificates libcap2-bin whatweb \
 && rm -rf /var/lib/apt/lists/*

# Allow nmap to use raw sockets as non-root (needed for SYN scanning)
RUN setcap cap_net_raw+ep /usr/bin/nmap

# Create non-root user hero
RUN groupadd -r hero && useradd -r -g hero -m -d /home/hero -s /bin/sh hero

# wafw00f via pip; install requests explicitly to avoid broken dependency resolution
RUN pip install --no-cache-dir requests wafw00f

# Copy Go binaries from stage 1 — use a script so missing ones are silently skipped
COPY --from=tool-downloader /tools/ /tmp/go-tools/
RUN find /tmp/go-tools -maxdepth 1 -type f -perm -111 -exec cp {} /usr/local/bin/ \; \
 && chmod -R a+rx /usr/local/bin/ \
 && rm -rf /tmp/go-tools

# ── Application ───────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Always copy HAST custom templates (separate from community nuclei-templates)
RUN mkdir -p /nuclei-templates \
 && cp -r /app/nuclei-templates/hast /nuclei-templates/hast 2>/dev/null || true

# Patch defaults for container: bind to all interfaces, no browser launch
RUN python3 - <<'EOF'
import yaml
with open("config.yaml") as f:
    cfg = yaml.safe_load(f) or {}
cfg["server_host"] = "0.0.0.0"
cfg["open_browser"] = False
# Leave nuclei_templates_path empty — auto-detect finds ~/.local/nuclei-templates
# Users can override in the Config tab or by mounting a volume at that path
cfg["nuclei_templates_path"] = ""
with open("config.yaml", "w") as f:
    yaml.dump(cfg, f)
EOF

EXPOSE 8765

# Persist DB and config outside the image layer
VOLUME ["/data"]

ENV HAST_DB_PATH=/data/hast.db

# Set ownership so hero can write to app dirs and the data volume
RUN mkdir -p /data \
 && chown -R hero:hero /app /nuclei-templates /data

# Drop to non-root user
USER hero

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://localhost:8765/ || exit 1

CMD ["python3", "-m", "backend.main"]
