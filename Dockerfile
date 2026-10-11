# UniThreat container — dashboard + API + live capture.
# NOTE: live sniffing inside Docker only works with host networking on Linux
# (root or NET_RAW/NET_ADMIN caps). On Windows/macOS use replay mode or run
# the sensor directly on the host.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY scripts/ scripts/
COPY config.yaml .
COPY models/ models/

# data volume keeps the alert DB and replayed pcaps
VOLUME ["/app/data"]
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "scripts/run_server.py", "--host", "0.0.0.0"]
