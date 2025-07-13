FROM golang:1.24.3 AS builder 
WORKDIR /src/goose
ADD https://github.com/pressly/goose.git .
RUN CGO_ENABLED=0 go build -tags='no_mysql no_sqlite3 no_ydb' -o /bin/goose ./cmd/goose

FROM scratch
COPY --from=builder /bin/goose /bin/goose
COPY ./migrations/* .
ENV GOOSE_MIGRATION_DIR="./"
CMD ["/bin/goose", "up"]
