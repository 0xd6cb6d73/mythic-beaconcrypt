.PHONY: native build test vet fmt-check run

native:
	./scripts/build-native.sh

build: native
	./scripts/go.sh build -buildvcs=false -trimpath -o .build/mythic-beaconcrypt .

test: native
	./scripts/go.sh test -race ./...

vet: native
	./scripts/go.sh vet ./...

fmt-check:
	@status=0; unformatted=$$(rg --files -0 -g '*.go' | xargs -0 gofmt -l) || status=$$?; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi; exit $$status

run: build
	./.build/mythic-beaconcrypt
