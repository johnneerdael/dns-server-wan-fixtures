FROM python:3.12-slim
COPY proxy/proxy.py /app/proxy.py
USER 65534:65534
ENTRYPOINT ["python3", "/app/proxy.py"]
