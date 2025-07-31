FROM python:3.13.3-alpine

# Actualizamos el OS
RUN apk update && apk upgrade

# Instalamos las dependecias de Python
## Actualizamos pip
RUN pip install --upgrade pip

## Ahora si instalamos la dependencias
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
