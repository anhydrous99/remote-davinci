.PHONY: bootstrap check

bootstrap:
	go mod download
	npm --prefix infra/cdk ci

check:
	go test ./...
	go vet ./...
	npm --prefix infra/cdk run typecheck
	npm --prefix infra/cdk test
	npm --prefix infra/cdk run synth
