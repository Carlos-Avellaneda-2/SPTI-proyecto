FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Usuario sin privilegios: el entorno de pruebas no corre como root
RUN useradd --create-home spti && mkdir -p /app/results /app/logs && chown -R spti /app
USER spti

EXPOSE 8000 8501
CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "8000"]
