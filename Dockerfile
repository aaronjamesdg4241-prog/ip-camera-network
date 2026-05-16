FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Automates seeding database prior to booting production Gunicorn engine on port 8080
CMD ["sh", "-c", "python seed.py && gunicorn -b 0.0.0.0:8080 app:app"]
