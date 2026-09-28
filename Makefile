VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# VERSION goes into shell commands below; refuse anything but a plain version
# before any of them runs. Pure make: no shell sees the value here.
version_rest := $(VERSION)
$(foreach c,0 1 2 3 4 5 6 7 8 9 a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z . + - _,$(eval version_rest := $(subst $(c),,$(version_rest))))
ifneq ($(strip $(version_rest))$(words $(VERSION)),1)
$(error VERSION may hold only letters, digits and . + - _)
endif

LDFLAGS := -s -w -X github.com/afsharid/passess/internal/buildinfo.Version=$(VERSION)

# The macOS menu bar app, Passess.app, with the CLI bundled inside it.
BAR := macos/PassessBar
APP := bin/Passess.app
APP_VERSION := $(shell echo '$(VERSION)' | sed -E 's/^v//; s/[^0-9.].*//; s/^$$/0.0.0/')

.PHONY: build test vet lint check hooks clean macos-app macos-check macos-previews macos-icon

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/passess ./cmd/passess

test:
	go test -race ./...

vet:
	go vet ./...

# Both systems: files for one of them are invisible to the linter on the other.
lint:
	golangci-lint run
	GOOS=linux golangci-lint run

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
	cp $(BAR)/AppIcon.icns $(APP)/Contents/Resources/AppIcon.icns
	cp $(BAR)/Info.plist $(APP)/Contents/Info.plist
	plutil -replace CFBundleShortVersionString -string '$(APP_VERSION)' $(APP)/Contents/Info.plist
	codesign --force --sign - --timestamp=none $(APP)/Contents/Resources/passess
	codesign --force --sign - --timestamp=none $(APP)
	@echo "built $(APP)"

# Headless checks of the app's logic against the JSON fixtures the Go tests write.
macos-check:
	swift run -c release --package-path $(BAR) PassessKitCheck $(BAR)/Fixtures

# Redraws the app icon from its paths (Sources/IconMaker) into AppIcon.icns.
macos-icon:
	swift run -c release --package-path $(BAR) IconMaker $(abspath bin/AppIcon.iconset)
	iconutil -c icns bin/AppIcon.iconset -o $(BAR)/AppIcon.icns

# The panel and the approval window in sample states, light and dark, as PNG
# files: a look at a change without clicking through the menu bar.
PREVIEWS ?= bin/previews
macos-previews:
	swift run -c release --package-path $(BAR) PassessBar --render-previews $(abspath $(PREVIEWS))

clean:
	rm -rf bin $(BAR)/.build
