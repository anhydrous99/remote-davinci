.PHONY: bootstrap check companion companion-app companion-app-check controller-check

bootstrap:
	go mod download
	npm --prefix infra/cdk ci

check:
	go test ./...
	go vet ./...
	npm --prefix infra/cdk run typecheck
	npm --prefix infra/cdk test
	npm --prefix infra/cdk run synth

companion:
	mkdir -p .build
	go build -trimpath -o .build/remote-davinci-companion ./cmd/companion

companion-app:
	xcodebuild -quiet -project apps/companion/RemoteDavinciCompanion.xcodeproj -scheme RemoteDavinciCompanion -configuration Debug -destination 'platform=macOS,arch=arm64' -derivedDataPath .derivedData/companion build

companion-app-check:
	xcodebuild -quiet -project apps/companion/RemoteDavinciCompanion.xcodeproj -scheme RemoteDavinciCompanion -destination 'platform=macOS,arch=arm64' -derivedDataPath .derivedData/companion-tests CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test

controller-check:
	cd apps/controller/RemoteDavinciController.swiftpm && xcodebuild -quiet -scheme RemoteDavinciController -destination 'platform=macOS,variant=Mac Catalyst' -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test
