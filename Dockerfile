FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o subidx .

FROM alpine:3.21
RUN adduser -D subidx
COPY --from=build /src/subidx /usr/local/bin/subidx
COPY scripts/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh
USER subidx
VOLUME /var/data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/start.sh"]
