FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/authd ./cmd/authd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /authd ./cmd/authd \
    && mkdir /data

FROM scratch
COPY --from=build /authd /authd
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV CADDY_AUTH_LISTEN=0.0.0.0:8090 \
    CADDY_AUTH_DB=/data/auth.db
EXPOSE 8090
ENTRYPOINT ["/authd"]
