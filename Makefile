.PHONY: all build test test-race bench lint clean install uninstall

VERSION ?= 0.1.0-dev
BIN_DIR ?= ./bin
GO ?= go

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/quarantined ./cmd/quarantined
	$(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/quarantinctl ./cmd/quarantinctl

test:
	$(GO) test -v ./...

test-race:
	$(GO) test -race -v ./...

bench:
	$(GO) test -run=^$$ -bench=. -benchmem ./...

lint:
	golangci-lint run

clean:
	rm -rf $(BIN_DIR)

install:
	./install.sh

uninstall:
	./uninstall.sh
