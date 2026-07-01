FROM python:3.13-slim

LABEL maintainer="José Rafael Parra Dugarte <joserafaelparrad@gmail.com>"
LABEL description="SentinelCore — Lightweight SIEM"

# System deps for notify-send (optional) and networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnotify-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Expose dashboard port
EXPOSE 5000

# Default: run dashboard
CMD ["python3", "dashboard/app.py"]
