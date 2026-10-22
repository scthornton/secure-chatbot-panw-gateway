FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway_chat.py web_app.py secure_chatbot_gateway.py ./
COPY static ./static
COPY tools ./tools

ENV WEB_HOST=0.0.0.0 \
    WEB_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "web_app.py"]
