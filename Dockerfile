FROM golang:1.21-alpine3.17 AS build

RUN apk update && apk add git bash curl nodejs npm

RUN go install github.com/nats-io/nats-server/v2@v2.10.4
RUN go install github.com/nats-io/natscli/nats@v0.1.1
RUN go install github.com/nats-io/nsc/v2@v2.8.1

WORKDIR /usr/src/app

COPY . .

RUN npm install

#RUN go build -C ./service -v -o /usr/local/bin/service

ENTRYPOINT ["bash"]

CMD ["main.sh"]
