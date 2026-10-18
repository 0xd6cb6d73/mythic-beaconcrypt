.PHONY: native build test test-integration test-transport vet fmt-check run

native:
	./scripts/build-native.sh

build: native
	./scripts/go.sh build -buildvcs=false -trimpath -o .build/mythic-beaconcrypt .

test: native
	./scripts/go.sh test -race ./...

test-integration: native
	./scripts/test-mythic.sh

test-transport: native
	@if [ -z "$$BEACONCRYPT_AMQP_TEST_URL" ]; then \
		printf '%s\n' 'Set BEACONCRYPT_AMQP_TEST_URL to an isolated RabbitMQ broker; transport tests must not be skipped.' >&2; \
		exit 1; \
	fi
	./scripts/go.sh test -race -count=1 -run '^(TestRunLifecycleOverAMQP|TestConcurrentRPCOverAMQP)$$' ./internal/service ./internal/transport

vet: native
	./scripts/go.sh vet ./...

fmt-check:
	@status=0; unformatted=$$(rg --files -0 -g '*.go' | xargs -0 gofmt -l) || status=$$?; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi; exit $$status

run: build
	./.build/mythic-beaconcrypt
