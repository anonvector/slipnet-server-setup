VERSION ?= 1.3.1
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -X github.com/anonvector/slipgate/internal/version.Version=$(VERSION) \
           -X github.com/anonvector/slipgate/internal/version.Commit=$(COMMIT)

# Set RELEASE_TAG to pin binary downloads to a specific GitHub release.
# Dev builds use this so transport binaries come from the dev release.
ifdef RELEASE_TAG
LDFLAGS += -X github.com/anonvector/slipgate/internal/version.ReleaseTag=$(RELEASE_TAG)
endif

.PHONY: build clean test install release build-dev

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o slipgate .

build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o slipgate-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o slipgate-linux-arm64 .

build-dev: RELEASE_TAG = dev-$(COMMIT)
build-dev: build-linux
	@echo "Dev binaries built (release tag: dev-$(COMMIT))"
	@ls -la slipgate-linux-*

clean:
	rm -f slipgate slipgate-linux-*

test:
	go test ./...

install: build
	sudo cp slipgate /usr/local/bin/
	@echo "Installed to /usr/local/bin/slipgate"

release: clean build-linux
	@echo "Built release binaries"
	@ls -la slipgate-linux-*
