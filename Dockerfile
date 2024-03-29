FROM golang:1.18-alpine

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY *.go *.yml ./
RUN go mod tidy
RUN go build -o /usr/local/bin/app ./...

CMD ["app"]