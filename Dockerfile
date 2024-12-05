FROM python

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt && \
    chmod a+x ./wait-for-it.sh
