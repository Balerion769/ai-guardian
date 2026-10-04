FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt requirements-dashboard.txt ./
RUN python -m pip install --no-cache-dir -r requirements-dashboard.txt \
    && useradd --system --uid 10001 --create-home aiguardian
COPY main.py ./
COPY scanner ./scanner
COPY dashboard ./dashboard
USER aiguardian

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
