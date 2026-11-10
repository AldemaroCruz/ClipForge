FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt && python -m pip check
COPY app/ ./app/
# Mandatory REAL imports, synthetic WAV/MP4 decoding and bundled Silero VAD.
# No Whisper weights, user media, or external API calls in this offline check.
RUN python -m app.check_runtime && python -m app.check_media && python -m app.check_presentation && python -m app.check_branding
COPY tests/ ./tests/
COPY requirements-test.txt .
EXPOSE 8080
# One Uvicorn process: job threads and locks are local to this process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
