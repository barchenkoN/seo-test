FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY bot ./bot
COPY templates ./templates
COPY app.py .
EXPOSE 8000
CMD ["python", "app.py"]
