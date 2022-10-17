FROM python:3.8-alpine

COPY ./requirements.txt /flask_app/requirements.txt

WORKDIR /flask_app

RUN pip install -r requirements.txt

COPY ./flask_app /flask_app

ENV FLASK_APP=app

ENV FLASK_DEBUG=1

CMD [ "flask", "run", "--host=0.0.0.0"]
