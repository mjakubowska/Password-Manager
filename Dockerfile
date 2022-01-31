FROM python:3.10

WORKDIR /odwsi
COPY . .

RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["__init__.py"]