# gosecure

A Go library providing HTTP security middleware including CSRF protection, JWT authentication, rate limiting, and security headers.

## Installation

```bash
go get github.com/Idk3333/gosecure
```

## Features

- 🔒 **CSRF Protection** - Cross-Site Request Forgery prevention
- 🎫 **JWT Authentication** - JSON Web Token validation middleware
- ⏱️ **Rate Limiting** - IP-based request throttling
- 🛡️ **Security Headers** - Automatic security header injection
- 🔄 **Panic Recovery** - Graceful panic handling

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/Idk3333/gosecure"
)

func main() {
    // Configure security settings
    cfg := gosecure.Config{
        JWTSecret:   []byte("your-secret-key"),
        CSRFAuthKey: []byte("32-byte-csrf-key-here-must-be-32"),
        IsDev:       false,
    }

    // Define handler options
    opts := gosecure.Options{
        MustAuth:  true,
        RateLimit: true,
        RPS:       10.0,
        Burst:     20,
    }

    // Wrap your handler
    mux := http.NewServeMux()
    mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Protected route"))
    })

    secured := gosecure.Apply(cfg, mux, opts)
    http.ListenAndServe(":8080", secured)
}
```

## Documentation

See [GoDoc](https://godoc.org/github.com/Idk3333/gosecure) for detailed API documentation.

## License

MIT