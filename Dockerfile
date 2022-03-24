FROM python:3.8-slim-buster

WORKDIR /LoginApp

ADD . /LoginApp

RUN pip install -r requirements.txt

COPY . .

CMD ["python","loginginapp.py"]