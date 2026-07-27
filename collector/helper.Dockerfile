# Malcolm's own scripts use PEP 701 f-strings and need Python >= 3.12.
# Rather than upgrading the host interpreter, run them here.
# auth_setup additionally refuses to run as root and shells out to docker,
# so this image carries a real non-root user and the docker CLI.
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl curl ca-certificates gnupg lsb-release procps \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir ruamel.yaml python-dotenv requests bcrypt passlib pyyaml
RUN useradd -u 1000 -m -s /bin/bash malcolm
WORKDIR /malcolm
