# Contributing to gosecure

Thank you for your interest in contributing to gosecure!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/Idk3333/gosecure.git
cd gosecure
```

2. Install dependencies:
```bash
go mod download
```

3. Run tests:
```bash
go test -v ./...
```

4. Run tests with coverage:
```bash
go test -v -cover ./...
```

## Code Style

- Follow standard Go conventions
- Use `gofmt` to format your code
- Add comments for exported functions and types
- Write tests for new functionality

## Testing

All new features should include:
- Unit tests
- Example usage in the examples directory
- Documentation in the README

Run the full test suite before submitting a PR:
```bash
go test -race -v ./...
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Reporting Issues

When reporting issues, please include:
- Go version
- Operating system
- Steps to reproduce
- Expected vs actual behavior