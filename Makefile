BINARY := netwatch
PKG    := ./cmd/netwatch

.PHONY: all build test run clean

all: build test

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

run: build
	./$(BINARY) $(ARGS)

clean:
	rm -f $(BINARY)
	go clean
