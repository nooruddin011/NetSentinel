FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
COPY collector/argus_collector.py /app/argus_collector.py
RUN useradd -r -u 10002 collector && mkdir -p /state && chown collector /state
USER collector
WORKDIR /app
ENTRYPOINT ["python", "/app/argus_collector.py"]
