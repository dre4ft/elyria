# Strike Pentest Sandbox — disposable attack container
# Build: docker build -t strike-sandbox .
FROM alpine:edge

# ── System deps ──
RUN apk add --no-cache \
    bash curl wget ca-certificates bind-tools unzip \
    python3 py3-pip git openssh-client \
    nmap nmap-scripts \
    jq yq

# ── Python tools ──
RUN pip3 install --break-system-packages --no-cache-dir \
    sqlmap requests aiohttp httpx pyjwt

# ── Go tools — pre-built static binaries ──
RUN mkdir -p /tmp/gotools && cd /tmp/gotools && \
    ARCH=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/') && \
    (wget -qL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.10/nuclei_3.3.10_linux_${ARCH}.zip" -O nuclei.zip && unzip -q nuclei.zip && mv nuclei /usr/local/bin/) || true && \
    (wget -qL "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_linux_${ARCH}.zip" -O subfinder.zip && unzip -q subfinder.zip && mv subfinder /usr/local/bin/) || true && \
    (wget -qL "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH}.tar.gz" -O ffuf.tar.gz && tar xzf ffuf.tar.gz && mv ffuf /usr/local/bin/) || true && \
    rm -rf /tmp/gotools

# ── Nuclei templates ──
RUN nuclei -update-templates -silent 2>/dev/null || true
# Subfinder needs a provider config (use default sources)
RUN mkdir -p /root/.config/subfinder && echo 'sources: [alienvault, anubis, bufferover, certspotter, chaos, crtsh, dnsdumpster, github, hackertarget, intelx, riddler, securitytrails, shodan, threatbook, virustotal, waybackarchive, zoomeye]' > /root/.config/subfinder/provider-config.yaml 2>/dev/null || true

# ── Entrypoint ──
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
