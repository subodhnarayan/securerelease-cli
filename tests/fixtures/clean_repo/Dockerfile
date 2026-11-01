FROM python:3.12-slim
WORKDIR /app
COPY app.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home appuser
USER appuser
HEALTHCHECK --interval=30s CMD python -c "import app" || exit 1
CMD ["python", "app.py"]
