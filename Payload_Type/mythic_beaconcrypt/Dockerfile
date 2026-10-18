FROM golang:1.27.2-bookworm AS build
RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates curl build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY scripts ./scripts
RUN ./scripts/build-native.sh
COPY . .
RUN ./scripts/go.sh build -buildvcs=false -trimpath -o /out/mythic-beaconcrypt .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && touch /usr/local/bin/.env \
    && chmod 0444 /usr/local/bin/.env \
    && useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin provider
COPY --from=build /out/mythic-beaconcrypt /usr/local/bin/mythic-beaconcrypt
COPY NOTICE /usr/share/doc/mythic-beaconcrypt/NOTICE
WORKDIR /Mythic
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mythic-beaconcrypt"]
