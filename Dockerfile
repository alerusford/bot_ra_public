FROM python:3.10-alpine
MAINTAINER alexandr
RUN apk add --upgrade nmap
RUN apk add --upgrade tzdata
RUN apk add --upgrade mosquitto-clients
RUN python3 -m pip install --upgrade pip
COPY . /bot_ra
WORKDIR /bot_ra
RUN python3 -m pip install -r requirements.txt
ENV TZ=Europe/Moscow
RUN cp /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
CMD ["python3", "bot.py"]

