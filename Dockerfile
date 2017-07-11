FROM python:latest

COPY . /app
WORKDIR /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

CMD [ "gunicorn", "-k", "tornado", "server:application", "-b", "0.0.0.0:8080" ]

