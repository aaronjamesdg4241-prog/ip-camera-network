FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# FIX: Switch to gthread workers, allocate concurrent threads, and extend timeout limits
CMD ["sh", "-c", "python seed.py && gunicorn --workers=2 --threads=4 --worker-class=gthread --timeout=300 -b 0.0.0.0:$PORT app:app"]
