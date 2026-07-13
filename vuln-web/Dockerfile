FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY vuln-web/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY vuln-web/app.py /app/app.py

USER 65532:65532
EXPOSE 5000
CMD ["python", "/app/app.py"]

