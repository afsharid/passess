VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/afsharid/passess/internal/buildinfo.Version=$(VERSION)

# The macOS menu bar app, Passess.app, with the CLI bundled inside it.
BAR := macos/PassessBar
APP := bin/Passess.app
APP_VERSION := $(shell echo '$(VERSION)' | sed -E 's/^v//; s/[^0-9.].*//; s/^$$/0.0.0/')

.PHONY: build test vet lint check hooks clean macos-app macos-check

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/passess ./cmd/passess

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

check: vet test lint

hooks:
	git config core.hooksPath .githooks

# Needs only the Xcode Command Line Tools. The app is ad-hoc signed: on first
# launch macOS asks you to confirm it (right-click → Open).
macos-app: build
	swift build -c release --package-path $(BAR) --product PassessBar
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources
	cp "$$(swift build -c release --package-path $(BAR) --show-bin-path)/PassessBar" $(APP)/Contents/MacOS/PassessBar
	cp bin/passess $(APP)/Contents/Resources/passess
	cp $(BAR)/Info.plist $(APP)/Contents/Info.plist
	plutil -replace CFBundleShortVersionString -string '$(APP_VERSION)' $(APP)/Contents/Info.plist
	codesign --force --sign - --timestamp=none $(APP)/Contents/Resources/passess
	codesign --force --sign - --timestamp=none $(APP)
	@echo "built $(APP)"

# Headless checks of the app's logic against the JSON fixtures the Go tests write.
macos-check:
	swift run -c release --package-path $(BAR) PassessKitCheck $(BAR)/Fixtures

clean:
	rm -rf bin $(BAR)/.build
