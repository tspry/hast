# ── Stage 1: Download Go-based security tools ─────────────────────────────────
FROM debian:bookworm-slim AS tool-downloader

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip tar \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# Each block downloads to /tools/<name> if it succeeds, writes nothing if it fails.
# The final image copies from /tools/ so only present binaries land on PATH.

# nuclei
RUN VER=$(curl -sf https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/projectdiscovery/nuclei/releases/download/${VER}/nuclei_${VER#v}_linux_amd64.zip" \
         -o nuclei.zip \
 && unzip -q nuclei.zip nuclei && chmod +x nuclei && rm nuclei.zip \
 || { echo "[warn] nuclei download failed — will be skipped"; true; }

# katana
RUN VER=$(curl -sf https://api.github.com/repos/projectdiscovery/katana/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/projectdiscovery/katana/releases/download/${VER}/katana_${VER#v}_linux_amd64.zip" \
         -o katana.zip \
 && unzip -q katana.zip katana && chmod +x katana && rm katana.zip \
 || { echo "[warn] katana download failed — will be skipped"; true; }

# gospider
RUN VER=$(curl -sf https://api.github.com/repos/jaeles-project/gospider/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/jaeles-project/gospider/releases/download/${VER}/gospider_linux_amd64.zip" \
         -o gospider.zip \
 && unzip -qj gospider.zip "*/gospider" -d . && chmod +x gospider && rm gospider.zip \
 || { echo "[warn] gospider download failed — will be skipped"; true; }

# hakrawler
RUN VER=$(curl -sf https://api.github.com/repos/hakluke/hakrawler/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/hakluke/hakrawler/releases/download/${VER}/hakrawler_${VER#v}_linux_amd64.tar.gz" \
         -o hakrawler.tar.gz \
 && tar -xzf hakrawler.tar.gz hakrawler && chmod +x hakrawler && rm hakrawler.tar.gz \
 || { echo "[warn] hakrawler download failed — will be skipped"; true; }

# gau
RUN VER=$(curl -sf https://api.github.com/repos/lc/gau/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/lc/gau/releases/download/${VER}/gau_${VER#v}_linux_amd64.tar.gz" \
         -o gau.tar.gz \
 && tar -xzf gau.tar.gz gau && chmod +x gau && rm gau.tar.gz \
 || { echo "[warn] gau download failed — will be skipped"; true; }

# ffuf
RUN VER=$(curl -sf https://api.github.com/repos/ffuf/ffuf/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/ffuf/ffuf/releases/download/${VER}/ffuf_${VER#v}_linux_amd64.tar.gz" \
         -o ffuf.tar.gz \
 && tar -xzf ffuf.tar.gz ffuf && chmod +x ffuf && rm ffuf.tar.gz \
 || { echo "[warn] ffuf download failed — will be skipped"; true; }

# trufflehog
RUN VER=$(curl -sf https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/trufflesecurity/trufflehog/releases/download/${VER}/trufflehog_${VER#v}_linux_amd64.tar.gz" \
         -o trufflehog.tar.gz \
 && tar -xzf trufflehog.tar.gz trufflehog && chmod +x trufflehog && rm trufflehog.tar.gz \
 || { echo "[warn] trufflehog download failed — will be skipped"; true; }

# gitleaks
RUN VER=$(curl -sf https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
          | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
 && curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/${VER}/gitleaks_${VER#v}_linux_x64.tar.gz" \
         -o gitleaks.tar.gz \
 && tar -xzf gitleaks.tar.gz gitleaks && chmod +x gitleaks && rm gitleaks.tar.gz \
 || { echo "[warn] gitleaks download failed — will be skipped"; true; }

# Ensure /tools/ always has at least one file so COPY doesn't fail
RUN touch /tools/.keep


# ── Stage 2: Final runtime image ──────────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="HAST Security Scanner"
LABEL org.opencontainers.image.description="Hardening & Attack Surface Tester"

# nmap, curl, ruby (for whatweb)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl ca-certificates \
    ruby ruby-dev build-essential \
 && gem install --no-document whatweb 2>/dev/null || echo "[warn] whatweb gem install failed" \
 && apt-get purge -y build-essential ruby-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /root/.gem/ruby/*/cache

# wafw00f via pip
RUN pip install --no-cache-dir wafw00f

# Copy Go binaries from stage 1 — use a script so missing ones are silently skipped
COPY --from=tool-downloader /tools/ /tmp/go-tools/
RUN for bin in nuclei katana gospider hakrawler gau ffuf trufflehog gitleaks; do \
      src="/tmp/go-tools/$bin"; \
      if [ -f "$src" ] && [ -x "$src" ]; then \
        cp "$src" /usr/local/bin/$bin; \
        echo "[ok] installed $bin"; \
      else \
        echo "[skip] $bin not available"; \
      fi; \
    done \
 && rm -rf /tmp/go-tools

# Pull nuclei-templates (best-effort; configurable at runtime)
RUN nuclei -update-templates -ud /nuclei-templates -silent 2>/dev/null \
 || echo "[warn] nuclei-templates not downloaded — configure path in Config tab"

# ── Application ───────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Always copy HAST custom templates (separate from community nuclei-templates)
RUN cp -r /app/nuclei-templates/hast /nuclei-templates/hast 2>/dev/null || true

# Patch defaults for container: bind to all interfaces, no browser launch
RUN python3 - <<'EOF'
import yaml
with open("config.yaml") as f:
    cfg = yaml.safe_load(f) or {}
cfg["server_host"] = "0.0.0.0"
cfg["open_browser"] = False
if not cfg.get("nuclei_templates_path"):
    cfg["nuclei_templates_path"] = "/nuclei-templates"
with open("config.yaml", "w") as f:
    yaml.dump(cfg, f)
EOF

EXPOSE 8765

# Persist DB and config outside the image layer
VOLUME ["/data"]

ENV HAST_DB_PATH=/data/hast.db

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://localhost:8765/ || exit 1

CMD ["python3", "-m", "backend.main"]
