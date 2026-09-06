# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS build
LABEL org.eapolkit.project=eapol-test-kit
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates curl libssl-dev openssl patch pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY runtime/ /build/runtime/
RUN /build/runtime/build-eapol-test.sh /build/upstream /opt/eapol_test
RUN python /build/runtime/tests/check_runtime.py --binary /opt/eapol_test
FROM build AS app-build
COPY pyproject.toml requirements.lock /build/
RUN python -m venv /opt/venv \
    && python -c 'import pathlib, tomllib; p = tomllib.loads(pathlib.Path("/build/pyproject.toml").read_text()); pathlib.Path("/build/requirements.txt").write_text("\n".join(p["project"]["dependencies"]) + "\n")' \
    && /opt/venv/bin/python -m pip install --no-cache-dir -r /build/requirements.txt -c /build/requirements.lock

FROM python:3.12-slim-bookworm AS runtime
LABEL org.eapolkit.project=eapol-test-kit
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app/src \
    EAPOLKIT_DATA_DIR=/data \
    EAPOLKIT_BINARY=/usr/local/bin/eapol_test
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 eapolkit \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --home-dir /data --shell /usr/sbin/nologin eapolkit \
    && install -d -m 0700 -o 10001 -g 10001 /data /tmp/eapolkit-runs
COPY --from=build /opt/eapol_test /usr/local/bin/eapol_test
COPY --from=app-build /opt/venv /opt/venv
COPY src/ /app/src/
COPY requirements.lock /app/requirements.lock
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/local/share/doc/eapol-test-kit/
COPY runtime/source.env runtime/eapol_test.config /usr/local/share/doc/eapol_test/
COPY runtime/patches/ /usr/local/share/doc/eapol_test/patches/
COPY runtime/licenses/ /usr/local/share/doc/eapol_test/licenses/
COPY runtime/SOURCE.md /usr/local/share/doc/eapol_test/SOURCE.md
COPY runtime/entrypoint.sh /usr/local/bin/eapolkit-entrypoint
WORKDIR /app
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/eapolkit-entrypoint"]
CMD ["python", "-m", "uvicorn", "eapolkit.app:app", "--host", "0.0.0.0", "--port", "8080"]
