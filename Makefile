SERVICE_DIR := Payload_Type/mythic_beaconcrypt

.PHONY: build test vet run fmt-check

build test vet run:
	$(MAKE) -C $(SERVICE_DIR) $@

fmt-check:
	@status=0; unformatted=$$(rg --files -0 -g '*.go' | xargs -0 gofmt -l) || status=$$?; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; exit 1; fi; exit $$status
