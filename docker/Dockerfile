# Imagen de demostración para análisis estático.
FROM python:3.12-slim
RUN groupadd --system eventosu && useradd --system --gid eventosu eventosu
WORKDIR /app
USER eventosu
CMD ["python", "--version"]
