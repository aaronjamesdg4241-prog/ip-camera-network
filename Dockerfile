FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run the database seeder first, then start Gunicorn on port 8080
CMD ["sh", "-c", "python seed.py && gunicorn -b 0.0.0.0:8080 app:app"]
