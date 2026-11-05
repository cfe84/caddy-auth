GO ?= go
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

.PHONY: all build test install clean

all: build

build:
	$(GO) build -o authd ./cmd/authd
	$(GO) build -o authctl ./cmd/authctl
	$(GO) build -o caddy-auth ./cmd/caddy-auth

test:
	$(GO) test ./...

install: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 authd authctl caddy-auth "$(DESTDIR)$(BINDIR)"

clean:
	rm -f authd authctl caddy-auth
