# ---------- Runtime stage ----------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's|http://security.debian.org|https://security.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY p/video.py ./p/video.py
COPY p/video-r.py ./p/video-r.py
COPY p/command-r.py ./p/command-r.py

RUN mkdir -p /var/www/video

EXPOSE 1009 1200 1201

CMD ["python", "p/video.py"]
