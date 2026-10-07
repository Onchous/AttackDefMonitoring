FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY agent.py /app/agent.py
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "/app/agent.py"]
