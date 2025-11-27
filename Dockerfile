FROM python:3.13.3-alpine

# Update base OS
RUN apk update && apk upgrade

# Upgrade pip
RUN pip install --upgrade pip

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Set working directory inside the container
WORKDIR /app

# Source code will be mounted at runtime via docker-compose (bind mount)
