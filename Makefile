SERVICE_DIR := Payload_Type/mythic_beaconcrypt

.PHONY: setup native build test test-integration test-poseidon test-transport vet fmt-check run

setup: native
	@if [ "$$(git config --local --get core.hooksPath)" = ".githooks" ]; then \
		git config --local --unset core.hooksPath; \
	fi
	pre-commit install

native build test test-integration test-poseidon test-transport vet run:
	$(MAKE) -C $(SERVICE_DIR) $@

fmt-check:
	@status=0; unformatted=$$(rg --files -0 -g '*.go' | xargs -0 gofmt -l) || status=$$?; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi; exit $$status
