# All-in-one runtime for cloudseed: Terraform + AWS CLI + gcloud + az + kubectl + helm + OpenSSH + Go + qemu-img.
# Built automatically by `cloudseed deps image` (or: docker build -t cloudseed:local .)
# Multi-arch:  docker buildx build --platform linux/amd64,linux/arm64 -t cloudseed:local .
#
# Every version is pinned below (bump the ARGs / the base digest together, then rebuild) and every download is
# verified: apt repositories by their signing keys, release archives by their published SHA256, the AWS CLI by its
# GPG signature. gcloud comes from Google's signed apt repository (latest release).
#
# Note: the `vmware` target always runs on the host (it needs Fusion/Workstation's vmrun + vmrest there); the container
# is for the cloud targets. Go is included so `cloudseed install vmware-provider` works everywhere the same way, and
# the provider sources are part of the image. Tools cloudseed installs at run time inside the container land in
# ~/.cloudseed/container-linux-<arch>/ on the host (see cloudseed/container.py), never in the host's own ~/.cloudseed/bin.

# python:3.12-slim-bookworm (to bump: docker buildx imagetools inspect python:3.12-slim-bookworm)
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

ARG TERRAFORM_VERSION=1.16.4
ARG AWSCLI_VERSION=2.37.1
ARG AZURE_CLI_VERSION=2.90.0
ARG KUBECTL_VERSION=v1.37.1
ARG HELM_VERSION=v4.3.0
ARG GO_VERSION=go1.27.1
# AWS CLI Team <aws-cli@amazon.com> (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
ARG AWSCLI_GPG_FINGERPRINT=FB5DB77FD5C118B80511ADA8A6310ACC4672475C

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    CLOUDSEED_HOME=/root/.cloudseed \
    CLOUDSEED_IN_CONTAINER=1 \
    PATH="/workspace/bin:${PATH}"

# every RUN fails on the first failing command, including the left side of a pipe
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg unzip openssh-client git lsb-release apt-transport-https qemu-utils \
    && install -d -m 0755 /etc/apt/keyrings \
    && rm -rf /var/lib/apt/lists/*

# Terraform (official HashiCorp apt repository, signed)
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /etc/apt/keyrings/hashicorp.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y --no-install-recommends "terraform=${TERRAFORM_VERSION}-1" \
    && rm -rf /var/lib/apt/lists/* \
    && terraform version

# AWS CLI v2 (release zip, verified against the AWS CLI Team's GPG signature)
RUN ARCH="$(uname -m)" && export GNUPGHOME="$(mktemp -d)" \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${AWSCLI_GPG_FINGERPRINT}" -o /tmp/awscli.asc \
    && gpg --batch --quiet --import /tmp/awscli.asc \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}-${AWSCLI_VERSION}.zip" -o /tmp/awscli.zip \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}-${AWSCLI_VERSION}.zip.sig" -o /tmp/awscli.sig \
    && gpg --batch --status-fd 1 --verify /tmp/awscli.sig /tmp/awscli.zip > /tmp/awscli.status 2>/dev/null \
    && grep -q "VALIDSIG ${AWSCLI_GPG_FINGERPRINT}" /tmp/awscli.status \
    && unzip -q /tmp/awscli.zip -d /tmp && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscli.* "$GNUPGHOME" \
    && aws --version

# Google Cloud CLI + the GKE auth plugin kubectl/helm need for GKE clusters (official apt repository, signed). The apt
# install disables gcloud's component manager, so the plugin must come from its own package here.
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin \
    && rm -rf /var/lib/apt/lists/* \
    && gke-gcloud-auth-plugin --version >/dev/null

# Azure CLI (Microsoft's apt repository, signed; not the curl | bash installer, which hides download failures)
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" \
        > /etc/apt/sources.list.d/azure-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends "azure-cli=${AZURE_CLI_VERSION}-1~$(lsb_release -cs)" \
    && rm -rf /var/lib/apt/lists/* \
    && az version >/dev/null

# kubectl + helm (release binaries, SHA256-verified): platform / dr / scan / node commands use them in the container
RUN ARCH="$(dpkg --print-architecture)" && cd /tmp \
    && curl -fsSLO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
    && echo "$(curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl.sha256")  kubectl" | sha256sum -c - \
    && install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl \
    && curl -fsSLO "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz" \
    && curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz.sha256sum" | sha256sum -c - \
    && tar -xzf "helm-${HELM_VERSION}-linux-${ARCH}.tar.gz" "linux-${ARCH}/helm" \
    && install -m 0755 "linux-${ARCH}/helm" /usr/local/bin/helm && rm -rf "linux-${ARCH}" helm-*.tar.gz \
    && kubectl version --client >/dev/null && helm version >/dev/null

# Go toolchain (builds cloudseed's VMware Terraform provider; SHA256-verified)
RUN ARCH="$(dpkg --print-architecture)" && cd /tmp \
    && curl -fsSLO "https://dl.google.com/go/${GO_VERSION}.linux-${ARCH}.tar.gz" \
    && echo "$(curl -fsSL "https://dl.google.com/go/${GO_VERSION}.linux-${ARCH}.tar.gz.sha256")  ${GO_VERSION}.linux-${ARCH}.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf "${GO_VERSION}.linux-${ARCH}.tar.gz" && rm "${GO_VERSION}.linux-${ARCH}.tar.gz"
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /workspace
COPY . /workspace

# runs /workspace/bin/cloudseed; with rootful Docker on Linux it then hands the files the run created in the mounted
# host directories back to the host user (cloudseed passes CLOUDSEED_HOST_UID/GID; see the script)
ENTRYPOINT ["/bin/sh", "/workspace/scripts/container-entrypoint.sh"]
CMD ["--help"]
