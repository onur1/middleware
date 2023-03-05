# middleware

A Middleware represents a computation which modifies a HTTP connection or reads from it, producing either a value of type A or an error for the next middleware in the pipeline.

```go
type Middleware[A any] func(s *Connection) data.Result[A]
```

## Example

The following example shows the use of monadic actions and sequentially composing them to write a response value.

Note that, middleware uses [ozzo-validation](https://github.com/go-ozzo/ozzo-validation) library for decoding a request body (it accepts urlencoded forms and json as well). Simply, adding a `Validate` method on a struct type makes it validatable.

```go
package main

import (
	"fmt"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/onur1/data/result"
	w "github.com/onur1/middleware"
)

// user is the expected request body.
type user struct {
	Login string `json:"login"`
}

// Validate ensures that a Login value is correctly set.
func (d *user) Validate() error {
	return validation.ValidateStruct(
		d,
		validation.Field(&d.Login, validation.Required, validation.Length(2, 8)),
	)
}

// greeting is the response value.
type greeting struct {
	Message string `json:"message"`
}

var (
  // decodeUserMiddleware decodes a request payload into a user struct and
  // returns a pointer to it.
	decodeUserMiddleware   = w.DecodeBody[user]
  // sendGreetingMiddleware sends a greeting as JSON.
	sendGreetingMiddleware = w.JSON[*greeting]
)

// greetingMiddlewareFromError creates a Middleware from an error which sets
// the status code to 202 and returns an error message as a result.
func greetingMiddlewareFromError(err error) w.Middleware[*greeting] {
	return w.ApSecond(
		w.Status(202),
		w.FromResult(result.Ok(&greeting{Message: err.Error()})),
	)
}

// greetingFromUser creates a new greeting from a user value.
func greetingFromUser(u *user) *greeting {
	return &greeting{
		Message: fmt.Sprintf("Hello, %s!", u.Login),
	}
}

// app middleware attempts decoding a request body in order to create a greeting
// message for the current user, falling back to a validation error message.
var app = w.Chain(
	w.OrElse(
		w.Map(
			decodeUserMiddleware,
			greetingFromUser,
		),
		greetingMiddlewareFromError,
	),
	sendGreetingMiddleware,
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", w.ToHandlerFunc(app, onError))

	s := &http.Server{
		Addr:    "localhost:8080",
		Handler: mux,
	}

	if err := s.ListenAndServe(); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}

func onError(err error, c *w.Connection) {
	fmt.Printf("uncaught error: %v\n", err)
	c.W.WriteHeader(500)
}
```

The `Login` attribute of a `user` struct must have a certain length, so this request will be responded with status 202 and a validation error message as JSON.

```shell
curl -s -d "login=x" -X POST "http://localhost:8080" | jq
```

Output:

```json
{
  "message": "login: the length must be between 2 and 8."
}
```

Otherwise, a greeting message will be retrieved with status 200.

```shell
curl -s -d "login=onur1" -v  -X POST "http://localhost:8080" | jq
```

Output:

```json
{
  "message": "Hello, onur1!"
}
```

## Credits

* Inspired by [purescript-hyper](https://github.com/purescript-hyper/hyper) and [hyper-ts](https://github.com/DenisFrezzato/hyper-ts).
* Uses [gorilla/schema](https://github.com/gorilla/schema) and [go-ozzo/ozzo-validation](https://github.com/go-ozzo/ozzo-validation).
