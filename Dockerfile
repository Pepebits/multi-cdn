# Panel y controlador Multi-CDN.
# Datos (base de datos, certificados de Gcore) en el volumen /app/data; secretos por entorno.

FROM python:3.15-alpine AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.24 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
    # Pruebas y metadatos de compilación de las dependencias: no hacen falta para ejecutar.
    && find /app/.venv -type d \( -name tests -o -name test \) -prune -exec rm -rf {} + \
    && find /app/.venv -name "*.pyi" -delete

FROM python:3.15-alpine
# pip no se usa en ejecución; el sistema de ficheros es de solo lectura.
RUN rm -rf /usr/local/lib/python3.15/site-packages/pip /usr/local/bin/pip* \
    && adduser -S -D -H -u 10001 -h /app -s /sbin/nologin multicdn \
    && mkdir -p /app/data /app/config && chown multicdn /app/data
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY app ./app
# Version for error reports (release multi-cdn@<version>).
COPY pyproject.toml ./
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MULTICDN_DB=/app/data/multicdn.db
USER multicdn
VOLUME ["/app/data"]
EXPOSE 8765
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=5)"
# Without proxy headers: the client must not choose its own address with X-Forwarded-For. The app
# takes the scheme from X-Forwarded-Proto and, with MULTICDN_TRUSTED_PROXIES=1, the client IP
# from the right-most X-Forwarded-For entry (app/proxy.py).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--no-proxy-headers"]
