# middleware

**middleware** is a Go library that provides monadic HTTP middleware, enabling seamless composition of HTTP handlers with a functional approach. Built on top of [warp](https://github.com/onur1/warp), it supports monadic chaining, error handling, and structured responses, making middleware logic modular and composable.

## Features

- **Monadic Middleware Composition**: Uses monadic patterns to compose complex middleware chains.
- **Seamless Error Handling**: Defines error-handling middleware with custom status codes and messages.
- **Flexible Data Validation**: Supports payload validation with [ozzo-validation](https://github.com/go-ozzo/ozzo-validation), integrating smoothly with Go structs.

## Installation

```sh
go get github.com/onur1/middleware
```

## Usage

The following example shows how to define and chain middleware actions, using monadic composition to handle requests and responses effectively.

```go
package main

import (
    "fmt"
    "net/http"
    "github.com/onur1/warp/result"
    w "github.com/onur1/middleware"
    validation "github.com/go-ozzo/ozzo-validation"
)

// user represents the expected request body.
type user struct {
    Login string `json:"login"`
}

// Validate ensures Login meets length requirements.
func (d *user) Validate() error {
    return validation.ValidateStruct(d,
        validation.Field(&d.Login, validation.Required, validation.Length(2, 8)),
    )
}

// greeting is the response type.
type greeting struct {
    Message string `json:"message"`
}

var (
    decodeUserMiddleware   = w.DecodeBody[user]
    sendGreetingMiddleware = w.JSON[*greeting]
)

// greetingMiddlewareFromError sets a custom response on error.
func greetingMiddlewareFromError(err error) w.Middleware[*greeting] {
    return w.ApSecond(
        w.Status(202),
        w.FromResult(result.Ok(&greeting{Message: err.Error()})),
    )
}

// greetingFromUser creates a greeting message.
func greetingFromUser(u *user) *greeting {
    return &greeting{Message: fmt.Sprintf("Hello, %s!", u.Login)}
}

// app chains middleware to handle requests or respond with validation errors.
var app = w.Chain(
    w.OrElse(
        w.Map(decodeUserMiddleware, greetingFromUser),
        greetingMiddlewareFromError,
    ),
    sendGreetingMiddleware,
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", w.ToHandlerFunc(app, onError))

    server := &http.Server{Addr: "localhost:8080", Handler: mux}
    if err := server.ListenAndServe(); err != nil {
        fmt.Printf("error: %v\n", err)
    }
}

func onError(err error, c *w.Connection) {
    fmt.Printf("Uncaught error: %v\n", err)
    c.W.WriteHeader(500)
}
```

### Example Requests

With the following request, the server validates `user.Login`, enforcing a length between 2 and 8:

```sh
curl -s -d "login=x" -X POST "http://localhost:8080"
```

Response (validation error, status 202):

```json
{
  "message": "login: the length must be between 2 and 8."
}
```

If the input is valid:

```sh
curl -s -d "login=onur1" -X POST "http://localhost:8080"
```

Response (greeting, status 200):

```json
{
  "message": "Hello, onur1!"
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.
