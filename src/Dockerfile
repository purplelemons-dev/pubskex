FROM python:3.12.2-slim-bookworm

WORKDIR /app

RUN apt update -y && apt upgrade -y

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT [ "" ]
