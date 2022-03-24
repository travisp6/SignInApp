FROM python:3.10-alpine

WORKDIR /LoginApp

ADD . /LoginApp

RUN pip install -r requirements.txt

COPY . .

CMD ["python","loginginapp.py"]