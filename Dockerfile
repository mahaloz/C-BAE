# syntax=docker/dockerfile:1.7

# The digest pins both the Temurin JDK 21 build and its Ubuntu 24.04 (Noble)
# userspace. IDA Pro and Ghidra's native components are x86-64, so this image
# intentionally has one supported platform.
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-noble@sha256:35685c7e23352983a48882d97cd9875f5284c228db71d1e2476e5e6c1bab1080

ARG NODE_VERSION=22.23.2
ARG NODE_SHA256=d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_RELEASE_DATE=20260605
ARG GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
ARG IDA_VERSION=9.2

LABEL org.opencontainers.image.title="Zion function-name evaluation runtime" \
      org.opencontainers.image.description="Isolated Codex/Claude reverse-engineering evaluation runtime" \
      org.opencontainers.image.source="https://github.com/mahaloz/zion_big_binaires" \
      io.zion-eval.platform="linux/amd64" \
      io.zion-eval.node.version="22.23.2" \
      io.zion-eval.codex.version="0.146.0" \
      io.zion-eval.claude-code.version="2.1.220" \
      io.zion-eval.declib.version="4.4.1" \
      io.zion-eval.pyghidra.version="3.1.0" \
      io.zion-eval.angr.version="9.2.213" \
      io.zion-eval.ghidra.version="12.1.2" \
      io.zion-eval.ida.version="9.2"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/zion-venv \
    GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC \
    IDA_INSTALL_DIR=/opt/idapro-9.2 \
    NODE_HOME=/opt/node \
    ZION_EVAL_NODE_VERSION=22.23.2 \
    ZION_EVAL_CODEX_VERSION=0.146.0 \
    ZION_EVAL_CLAUDE_VERSION=2.1.220 \
    ZION_EVAL_DECLIB_VERSION=4.4.1 \
    ZION_EVAL_PYGHIDRA_VERSION=3.1.0 \
    ZION_EVAL_ANGR_VERSION=9.2.213 \
    ZION_EVAL_GHIDRA_VERSION=12.1.2 \
    ZION_EVAL_IDA_VERSION=9.2 \
    ZION_EVAL_CONTRACTS_DIR=/opt/zion-eval-contracts
ENV PATH="${VIRTUAL_ENV}/bin:${NODE_HOME}/bin:${IDA_INSTALL_DIR}:${GHIDRA_INSTALL_DIR}/support:${GHIDRA_INSTALL_DIR}:${PATH}" \
    LD_LIBRARY_PATH="${IDA_INSTALL_DIR}"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Keep the runtime useful for both ELF and PE inspection while avoiding GUI
# packages and recommended-package bloat. fontconfig is needed by Java/AWT even
# when Ghidra is launched headlessly.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install --yes --no-install-recommends \
        bash \
        binutils \
        build-essential \
        ca-certificates \
        curl \
        elfutils \
        file \
        fontconfig \
        gdb \
        git \
        jq \
        libffi-dev \
        libnss-wrapper \
        libxi6 \
        libxrender1 \
        libxtst6 \
        ltrace \
        nasm \
        patchelf \
        pkg-config \
        procps \
        python3.12 \
        python3.12-dev \
        python3.12-venv \
        ripgrep \
        strace \
        tini \
        unzip \
        xz-utils

# Node publishes per-archive checksums. Download into a BuildKit tmpfs so the
# archive is never committed to an image layer.
RUN --mount=type=tmpfs,target=/downloads \
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
        --output /downloads/node.tar.xz && \
    echo "${NODE_SHA256}  /downloads/node.tar.xz" | sha256sum --check --strict && \
    install -d --mode=0755 "${NODE_HOME}" && \
    tar --extract --xz --file=/downloads/node.tar.xz --directory="${NODE_HOME}" --strip-components=1 && \
    test "$(node --version)" = "v${NODE_VERSION}"

# The checksum is published in the signed GitHub release metadata. The archive
# expands to the directory used by GHIDRA_INSTALL_DIR above.
RUN --mount=type=tmpfs,target=/downloads \
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip" \
        --output /downloads/ghidra.zip && \
    echo "${GHIDRA_SHA256}  /downloads/ghidra.zip" | sha256sum --check --strict && \
    unzip -q /downloads/ghidra.zip -d /opt && \
    test -x "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" && \
    grep -Eq '^application\.version=12\.1\.2$' "${GHIDRA_INSTALL_DIR}/Ghidra/application.properties"

# IDA Pro is proprietary and supplied as a local BuildKit named context by
# scripts/build-image. It is intentionally not copied into the Git build
# context. Keep the complete installation so all processor modules, loaders,
# type libraries, decompilers, and the current local license remain available.
COPY --from=ida-pro / ${IDA_INSTALL_DIR}/
RUN test -x "${IDA_INSTALL_DIR}/idat" && \
    test -f "${IDA_INSTALL_DIR}/libidalib.so" && \
    test -f "${IDA_INSTALL_DIR}/idapro.hexlic"

# npm ci verifies the integrity values in package-lock.json and installs only
# the native optional dependencies compatible with linux/x64.
COPY docker/npm/package.json docker/npm/package-lock.json /opt/zion-agent-clis/
RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci --prefix /opt/zion-agent-clis --omit=dev --no-audit --no-fund && \
    ln -s /opt/zion-agent-clis/node_modules/.bin/codex /usr/local/bin/codex && \
    ln -s /opt/zion-agent-clis/node_modules/.bin/claude /usr/local/bin/claude && \
    codex --version | grep -F "${ZION_EVAL_CODEX_VERSION}" && \
    claude --version | grep -F "${ZION_EVAL_CLAUDE_VERSION}"

COPY docker/requirements.lock /opt/zion-runtime/requirements.lock
RUN python3.12 -m venv "${VIRTUAL_ENV}" && \
    python -m pip install --no-cache-dir --requirement /opt/zion-runtime/requirements.lock && \
    python -m pip install --no-cache-dir --no-deps "${IDA_INSTALL_DIR}/idalib/python" && \
    python -m pip check

# Application dependencies are already pinned above. Disabling build isolation
# prevents the build backend from fetching newer setuptools/wheel releases.
COPY prompts/ /opt/zion-eval-contracts/prompts/
COPY schemas/ /opt/zion-eval-contracts/schemas/
WORKDIR /opt/zion-eval-src
COPY pyproject.toml ./
# Use identity-neutral package metadata inside the agent image. The repository
# README names registered samples and would become an uncontrolled reverser hint.
COPY docker/PACKAGE_README.md ./README.md
COPY src/ ./src/
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation . && \
    command -v zion-eval

COPY docker/entrypoint.sh /usr/local/bin/zion-eval-entrypoint
COPY docker/smoke-test.sh /usr/local/bin/zion-runtime-smoke
RUN chmod 0755 /usr/local/bin/zion-eval-entrypoint /usr/local/bin/zion-runtime-smoke && \
    groupadd --gid 10001 zion && \
    useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash zion && \
    install -d --owner=zion --group=zion --mode=0755 /input /output /work

USER 10001:10001
ENV HOME=/home/zion \
    XDG_CACHE_HOME=/home/zion/.cache \
    XDG_CONFIG_HOME=/home/zion/.config \
    XDG_DATA_HOME=/home/zion/.local/share
WORKDIR /work

# Verify the non-root user's PATH and all credential-free imports during the
# image build. Run zion-runtime-smoke without --quick for live backend checks.
RUN zion-runtime-smoke --quick

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/zion-eval-entrypoint"]
CMD []
