FROM python:3.9-slim

# VULNERABILITY: Copying sensitive files into the image
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa

WORKDIR /app

# VULNERABILITY: Hardcoded secrets in ENV
ENV DB_PASSWORD=supersecret123
ENV AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# VULNERABILITY: Running as root (default)
CMD ["python", "app.py"]
