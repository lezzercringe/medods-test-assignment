FROM golang:1.24.3 AS builder
COPY go.mod go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/server ./cmd/main.go

FROM alpine:latest
WORKDIR api
COPY --from=builder /bin/server server
COPY ./config.yaml /api/config.yaml
EXPOSE 3000
CMD ["/api/server"]
