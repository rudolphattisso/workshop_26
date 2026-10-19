# Log-forwarder vers Wazuh : lit les journaux des conteneurs via le proxy Docker (lecture
# seule) et les écrit dans le volume agent-logs. Process unique, pas d'API HTTP.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install httpx==0.28.1
WORKDIR /app
COPY logshipper/app.py ./app.py
# Tourne en root UNIQUEMENT pour écrire dans le volume partagé agent-logs ; durci par ailleurs
# (cap_drop ALL, no-new-privileges, rootfs en lecture seule, accès Docker en lecture seule).
CMD ["python", "app.py"]
