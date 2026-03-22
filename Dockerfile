# ---------- Runtime stage ----------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY p/video.py ./p/video.py

RUN mkdir -p /var/www/video

EXPOSE 7200 7201

CMD ["python", "p/video.py"]
