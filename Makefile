BIN 		:= opa-spicedb
REPOSITORY 	:= openpolicyagent/$(BIN)
VERSION 	:= 0.1-dev
GO		:= /usr/lib/go-1.22/bin/go


build: build-go
build-go:
	$(GO) build -o $(BIN) .

build-static:
	$(GO) build -ldflags="-linkmode external -extldflags=-static" -o $(BIN) .
