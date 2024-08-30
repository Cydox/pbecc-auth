FROM docker.io/golang:alpine as builder

COPY ./ /app/

RUN cd /app && go build -tags netgo main.go

FROM scratch as runner

COPY --from=builder /app/main /main
COPY --from=builder /app/static /static
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

CMD ["/main"]
