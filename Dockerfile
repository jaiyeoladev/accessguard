FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ACCESSGUARD_DATA_DIR=/data

RUN useradd --create-home --uid 10001 accessguard \
    && mkdir -p /data && chown accessguard:accessguard /data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY accessguard ./accessguard
RUN pip install .

USER accessguard
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

# Listening on 0.0.0.0 inside the container requires ACCESSGUARD_UI_PASSWORD to be set.
CMD ["accessguard", "serve", "--host", "0.0.0.0", "--port", "8000"]
