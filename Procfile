gunicornFROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# FIX: Dynamically read the environment variable $PORT and run multiple threads to manage stream data blocks
CMD ["sh", "-c", "python seed.py && gunicorn -b 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --worker-class gthread app:app"]
 --worker-class gthread --threads 4 camera:app
