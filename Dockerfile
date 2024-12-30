FROM python:latest

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN pip install --upgrade pip \
    && pip install poetry \
    && poetry install --no-root

COPY . .

CMD ["poetry", "run", "python", "telegram-bot-proxy/main.py"]

