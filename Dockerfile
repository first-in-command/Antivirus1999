FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
ENV PYTHONUNBUFFERED=1 DB_PATH=/data/scans.db
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-t", "120", "app.app:app"]
