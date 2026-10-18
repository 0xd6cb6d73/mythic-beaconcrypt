FROM golang:1.27.2-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/crypto-provider .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && touch /usr/local/bin/.env \
    && chmod 0444 /usr/local/bin/.env \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin provider
COPY --from=build /out/crypto-provider /usr/local/bin/crypto-provider
COPY NOTICE /usr/share/doc/crypto-provider/NOTICE
WORKDIR /Mythic
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/crypto-provider"]
