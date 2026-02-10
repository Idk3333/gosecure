.PHONY: test test-coverage lint fmt vet build clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make fmt           - Format code"
	@echo "  make vet           - Run go vet"
	@echo "  make build         - Build example"
	@echo "  make clean         - Clean build artifacts"

test:
	go test -v -race ./...

test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint:
	golangci-lint run

fmt:
	go fmt ./...
	gofmt -s -w .

vet:
	go vet ./...

build:
	cd examples/basic && go build -o ../../bin/example

clean:
	rm -f coverage.out coverage.html
	rm -rf bin/

# Install development dependencies
install-deps:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest