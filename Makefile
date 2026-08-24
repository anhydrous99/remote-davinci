.PHONY: bootstrap check companion companion-app companion-app-check controller-check controller-ios-tests controller-ios-build companion-release-check

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
	cd apps/controller/RemoteDavinciController.swiftpm && xcodebuild -quiet -scheme 'Remote DaVinci' -destination 'platform=macOS,variant=Mac Catalyst' -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test

controller-ios-tests:
	cd apps/controller/RemoteDavinciController.swiftpm && set -eu; \
	for family in iPhone iPad; do \
		device_id="$$(xcrun simctl list devices available | sed -n "/^[[:space:]]*$$family/{s/.*(\([0-9A-Fa-f-]\{36\}\)).*/\1/p;q;}")"; \
		test -n "$$device_id" || { echo "No available $$family simulator" >&2; exit 1; }; \
		xcodebuild -quiet -scheme 'Remote DaVinci' -destination "platform=iOS Simulator,id=$$device_id" -derivedDataPath .derivedData/ios-tests CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test; \
	done

controller-ios-build:
	cd apps/controller/RemoteDavinciController.swiftpm && xcodebuild -quiet -scheme 'Remote DaVinci' -configuration Release -destination 'generic/platform=iOS Simulator' -derivedDataPath .derivedData/ios-build CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES build

companion-release-check:
	xcodebuild -quiet -project apps/companion/RemoteDavinciCompanion.xcodeproj -scheme RemoteDavinciCompanion -configuration Release -destination 'platform=macOS,arch=arm64' -derivedDataPath .derivedData/companion-release CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES build
