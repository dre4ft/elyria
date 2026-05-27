FROM alpine:edge

ENV PATH="/usr/local/bin:${PATH}" \
    PIP_BREAK_SYSTEM_PACKAGES=1

# Outils système
RUN apk add --no-cache \
    bash curl wget ca-certificates \
    bind-tools netcat-openbsd socat \
    nmap nmap-scripts \
    git openssh-client \
    python3 py3-pip \
    jq yq unzip tar \
    massdns amass wfuzz \
    chromium chromium-chromedriver

# Python tools
RUN pip3 install --no-cache-dir \
    sqlmap requests httpx aiohttp pyjwt beautifulsoup4

# Outils Go
RUN mkdir -p /tmp/gotools && cd /tmp/gotools && \
    ARCH=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/') && \

    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.2/nuclei_3.4.2_linux_${ARCH}.zip" -O nuclei.zip && unzip -q nuclei.zip && mv nuclei /usr/local/bin/ && \
    wget -q "https://github.com/projectdiscovery/subfinder/releases/download/v2.7.0/subfinder_2.7.0_linux_${ARCH}.zip" -O subfinder.zip && unzip -q subfinder.zip && mv subfinder /usr/local/bin/ && \
    wget -q "https://github.com/projectdiscovery/httpx/releases/download/v1.7.2/httpx_1.7.2_linux_${ARCH}.zip" -O httpx.zip && unzip -q httpx.zip && mv httpx /usr/local/bin/ && \
    wget -q "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_${ARCH}.zip" -O katana.zip && unzip -q katana.zip && mv katana /usr/local/bin/ && \
    wget -q "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH}.tar.gz" -O ffuf.tar.gz && tar xzf ffuf.tar.gz && mv ffuf /usr/local/bin/ && \

    rm -rf /tmp/gotools

# Templates Nuclei + config Subfinder
RUN nuclei -update-templates -silent 2>/dev/null || true

RUN mkdir -p /root/.config/subfinder && \
    echo 'sources: [alienvault, anubis, bufferover, certspotter, chaos, crtsh, dnsdumpster, github, hackertarget, intelx, riddler, securitytrails, shodan, virustotal, waybackarchive]' > /root/.config/subfinder/provider-config.yaml

# Nettoyage
RUN rm -rf /var/cache/apk/* /tmp/* /root/.cache
# ── Entrypoint ──
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
