FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5002
ENV FLASK_ENV=development
EXPOSE 5002

CMD ["python", "app.py"]
