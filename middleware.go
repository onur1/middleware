// Package middleware implements the Middleware type.
package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/gorilla/schema"
	"github.com/onur1/data"
	"github.com/onur1/data/result"
)

// A Connection represents the connection between an HTTP server and a user agent.
type Connection struct {
	R   *http.Request
	W   http.ResponseWriter
	sub func(func())
}

// A Middleware represents a computation which modifies a HTTP connection or reads
// from it, producing either a value of type A or an error for the next middleware
// in the pipeline.
type Middleware[A any] func(*Connection) data.Result[A]

// MIME types.
const (
	MediaTypeApplicationXML         = "application/xml"
	MediaTypeApplicationJSON        = "application/json"
	MediaTypeFormURLEncoded         = "application/x-www-form-urlencoded"
	MediaTypeImageGIF               = "image/gif"
	MediaTypeImageJPEG              = "image/jpeg"
	MediaTypeImagePNG               = "image/png"
	MediaTypeApplicationOctetStream = "application/octet-stream"
	MediaTypeTextHTML               = "text/html"
	MediaTypeTextXML                = "text/xml"
	MediaTypeTextCSV                = "text/csv"
	MediaTypeTextPlain              = "text/plain"
	MediaTypeMultipartFormData      = "multipart/form-data"
)

var (
	contentTypeJSON = ContentType[any](MediaTypeApplicationJSON)
	decoder         = schema.NewDecoder()
)

func init() {
	decoder.IgnoreUnknownKeys(true)
	decoder.SetAliasTag("json")
}

// ErrUnknownContentType is thrown by DecodeBody when a Content-Type
// is not one of "application/x-www-form-urlencoded" or "application/json".
var ErrUnknownContentType = errors.New("unknown content-type")

// Map creates a middleware by applying a function on a succeeding middleware.
func Map[A, B any](fa Middleware[A], f func(A) B) Middleware[B] {
	return func(s *Connection) data.Result[B] {
		return result.Map(fa(s), f)
	}
}

// MapError creates a middleware by applying a function on a failing middleware.
func MapError[A any](fa Middleware[A], f func(error) error) Middleware[A] {
	return func(s *Connection) data.Result[A] {
		return result.MapError(fa(s), f)
	}
}

// Ap creates a middleware by applying a function contained in the first middleware
// on the value contained in the second middleware.
func Ap[A, B any](fab Middleware[func(A) B], fa Middleware[A]) Middleware[B] {
	return func(s *Connection) data.Result[B] {
		return result.Chain(fab(s), func(ab func(A) B) data.Result[B] {
			return result.Map(fa(s), ab)
		})
	}
}

// Chain creates a middleware which combines two results in sequence, using the
// return value of one middleware to determine the next one.
func Chain[A, B any](ma Middleware[A], f func(A) Middleware[B]) Middleware[B] {
	return func(s *Connection) data.Result[B] {
		return result.Chain(ma(s), func(a A) data.Result[B] {
			return f(a)(s)
		})
	}
}

// ApFirst creates a middleware by combining two effectful computations on a
// connection, keeping only the result of the first.
func ApFirst[A, B any](fa Middleware[A], fb Middleware[B]) Middleware[A] {
	return Ap(Map(fa, fst[A, B]), fb)
}

// ApSecond creates a middleware by combining two effectful computations on a
// connection, keeping only the result of the second.
func ApSecond[A, B any](fa Middleware[A], fb Middleware[B]) Middleware[B] {
	return Ap(Map(fa, snd[A, B]), fb)
}

// ChainFirst composes two middlewares in sequence, using the return value of one
// to determine the next one, keeping only the result of the first one.
func ChainFirst[A, B any](ma Middleware[A], f func(A) Middleware[B]) Middleware[A] {
	return Chain(ma, func(a A) Middleware[A] {
		return Map(f(a), fst[A, B](a))
	})
}

// FromRequest creates a middleware for reading a request by applying a function
// on a connection request that either yields a value of type A, or fails with an error.
func FromRequest[A any](f func(c *http.Request) data.Result[A]) Middleware[A] {
	return fromConnection(func(c *Connection) data.Result[A] {
		return f(c.R)
	})
}

// GetOrElse creates a middleware which can be used to recover from a failing
// middleware with a new value.
func GetOrElse[A any](ma data.Result[A], onError func(error) A) A {
	if a, err := ma(); err != nil {
		return onError(err)
	} else {
		return a
	}
}

// OrElse creates a middleware which can be used to recover from a failing
// middleware by switching to a new middleware.
func OrElse[A any](ma Middleware[A], onError func(error) Middleware[A]) Middleware[A] {
	return func(c *Connection) data.Result[A] {
		return result.OrElse(ma(c), func(err error) data.Result[A] {
			return onError(err)(c)
		})
	}
}

// FilterOrElse creates a middleware which can be used to fail with an error unless
// a predicate holds on a succeeding result.
func FilterOrElse[A any](ma Middleware[A], predicate data.Predicate[A], onFalse func(A) error) Middleware[A] {
	return Chain(ma, func(a A) Middleware[A] {
		return func(*Connection) data.Result[A] {
			if predicate(a) {
				return result.Ok(a)
			} else {
				return result.Error[A](onFalse(a))
			}
		}
	})
}

// ModifyResponse creates a middleware for writing a response.
func ModifyResponse[A any](f func(w http.ResponseWriter)) Middleware[A] {
	return modifyConnection[A](func(c *Connection) {
		f(c.W)
	})
}

// Status creates a middleware that sets a response status code.
func Status(status int) Middleware[any] {
	return modifyConnection[any](func(c *Connection) {
		c.W.WriteHeader(status)
	})
}

// Header creates a middleware that sets a header on the response.
// Note that, changing a header after a call to Status has no effect.
func Header(name, value string) Middleware[any] {
	return modifyConnection[any](func(c *Connection) {
		c.W.Header().Set(name, value)
	})
}

// Redirect creates a middleware for redirecting a request to the given URL
// with the given 3xx code.
func Redirect(url string, code int) Middleware[any] {
	return modifyConnection[any](func(c *Connection) {
		http.Redirect(c.W, c.R, url, code)
	})
}

// Write creates a middleware for sending the given byte array response
// without specifying the Content-Type.
func Write(body []byte) Middleware[any] {
	return modifyConnection[any](func(c *Connection) {
		_, err := c.W.Write(body)
		if err != nil {
			fmt.Printf("write:  %v\n", err)
		}
	})
}

// HTML creates a middleware that sends a string as HTML response.
func HTML(html string) Middleware[any] {
	return ApSecond(
		ContentType[any](MediaTypeTextHTML),
		Write([]byte(html)),
	)
}

// PlainText creates a middleware that sends a plain text as response.
func PlainText(text string) Middleware[any] {
	return ApSecond(
		ContentType[any](MediaTypeTextPlain),
		Write([]byte(text)),
	)
}

// FromResult converts a function, which takes no parameters and returns
// a value of type A along with an error, into a Middleware.
func FromResult[A any](ra data.Result[A]) Middleware[A] {
	return func(*Connection) data.Result[A] {
		return ra
	}
}

// JSON sends a JSON object as response.
func JSON[A any](d A) Middleware[any] {
	return Chain(
		ApFirst(FromResult(marshalJSON(d)), contentTypeJSON),
		Write,
	)
}

// ContentType creates a middleware which sets the Content-Type header on
// a response.
func ContentType[A any](contentType string) Middleware[A] {
	return modifyConnection[A](func(c *Connection) {
		c.W.Header().Set("Content-Type", contentType)
	})
}

// DecodeMethod creates a Middleware by applying a function on a request method.
func DecodeMethod[A any](f func(string) data.Result[A]) Middleware[A] {
	return fromConnection(func(c *Connection) data.Result[A] {
		return f(c.R.Method)
	})
}

// DecodeBody middleware decodes (and optionally validates) a request payload
// into a value of type A.
func DecodeBody[A any](c *Connection) data.Result[*A] {
	var (
		err         error
		dst         = new(A)
		contentType = c.R.Header.Get("Content-Type")
	)

	switch contentType {
	case MediaTypeFormURLEncoded:
		if err = c.R.ParseForm(); err != nil {
			return result.Error[*A](err)
		}
		if err = decoder.Decode(dst, c.R.PostForm); err != nil {
			return result.Error[*A](err)
		}
	case MediaTypeApplicationJSON:
		if err = json.NewDecoder(c.R.Body).Decode(dst); err != nil {
			return result.Error[*A](err)
		}
	default:
		return result.Error[*A](ErrUnknownContentType)
	}

	if err = validation.Validate(dst); err != nil {
		return result.Error[*A](err)
	}

	return result.Ok(dst)
}

// DecodeHeader creates a middleware by validating a string value from a header.
func DecodeHeader(name string, rules ...validation.Rule) Middleware[string] {
	return fromConnection(func(c *Connection) data.Result[string] {
		return func() (string, error) {
			s := c.R.Header.Get(name)
			return s, validation.Validate(s, rules...)
		}
	})
}

// DecodeQuery middleware decodes (and optionally validates) a value of type A
// from the query string.
func DecodeQuery[A any](c *Connection) data.Result[*A] {
	var (
		err error
		dst = new(A)
		q   url.Values
	)
	if q, err = url.ParseQuery(c.R.URL.RawQuery); err != nil {
		return result.Error[*A](err)
	}
	if err = decoder.Decode(dst, q); err != nil {
		return result.Error[*A](err)
	}
	if err = validation.Validate(dst); err != nil {
		return result.Error[*A](err)
	}
	return result.Ok(dst)
}

// ToHandlerFunc turns a middleware into a standard http handler function.
func ToHandlerFunc[A any](
	ma Middleware[A],
	onError func(error, *Connection),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &Connection{
			R:   r,
			W:   w,
			sub: sub,
		}
		result.Fork(ma(c), func(err error) {
			onError(err, c)
		}, func(A) {
			c.sub(noop) // run effects

			c.sub = nil
			c.W = nil
			c.R = nil
		})
	}
}

func fromConnection[A any](f func(*Connection) data.Result[A]) Middleware[A] {
	return func(c *Connection) data.Result[A] {
		return f(c)
	}
}

func modifyConnection[A any](f func(*Connection)) Middleware[A] {
	return func(c *Connection) data.Result[A] {
		sub := c.sub
		c.sub = func(next func()) {
			sub(func() {
				f(c)
				next()
			})
		}
		return result.Zero[A]
	}
}

func marshalJSON(v any) data.Result[[]byte] {
	return func() ([]byte, error) {
		return json.Marshal(v)
	}
}

func fst[A, B any](a A) func(B) A {
	return func(B) A {
		return a
	}
}

func snd[A, B any](A) func(B) B {
	return func(b B) B {
		return b
	}
}

func noop() {
}

func sub(f func()) {
	f()
}
