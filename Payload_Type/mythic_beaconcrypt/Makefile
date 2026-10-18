.PHONY: build test vet run

build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -o .build/crypto-provider .

test:
	go test -race ./...

vet:
	go vet ./...

run: build
	.build/crypto-provider
