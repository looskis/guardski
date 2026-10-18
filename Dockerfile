ARG TRIVY_IMAGE=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
ARG NUCLEI_IMAGE=projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb
FROM ${TRIVY_IMAGE} AS trivy
FROM ${NUCLEI_IMAGE} AS nuclei
FROM python:3.12-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml requirements.lock ./
COPY src ./src
RUN python -m venv /opt/guardski \
    && /opt/guardski/bin/pip install --no-cache-dir --require-hashes -r requirements.lock \
    && /opt/guardski/bin/pip install --no-cache-dir --no-deps .

FROM python:3.12-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 guardski \
    && useradd --uid 10001 --gid guardski --no-create-home guardski \
    && mkdir -p /var/lib/guardski /etc/guardski /targets/application \
    && chown guardski:guardski /var/lib/guardski \
    && chmod 700 /var/lib/guardski
COPY --from=builder /opt/guardski /opt/guardski
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
ENV PATH="/opt/guardski/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /var/lib/guardski
ENTRYPOINT ["guardski", "--config", "/etc/guardski/guardski.toml"]
CMD ["run"]
