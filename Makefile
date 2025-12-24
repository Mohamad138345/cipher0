.PHONY: build test clean install run

BINARY=cipher0
BUILD_DIR=build

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/cipher0

test:
	go test ./... -v

test-cover:
	go test ./... -cover -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

install:
	go install ./cmd/cipher0

run:
	go run ./cmd/cipher0

fmt:
	go fmt ./...

lint:
	golangci-lint run

deps:
	go mod tidy
	go mod download
