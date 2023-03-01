package middleware_test

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/onur1/middleware"
	"github.com/stretchr/testify/assert"
)

type testCase[A any] struct {
	desc string
	m    middleware.Middleware[A]
	req  *http.Request
	fn   func(*testing.T, *http.Response, *httptest.ResponseRecorder)
}

func runEffects[A any](ma middleware.Middleware[A], w *httptest.ResponseRecorder) func(*http.Request) *http.Response {
	return func(r *http.Request) *http.Response {
		middleware.ToHandlerFunc(ma, func(err error, _ *middleware.Connection) {
			panic(err)
		})(w, r)
		res := w.Result()
		defer res.Body.Close()
		return res
	}
}

func runTestCases[A any](testCases []testCase[A], t *testing.T) {
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			w := httptest.NewRecorder()
			tC.fn(t, runEffects(tC.m, w)(tC.req), w)
		})
	}
}

type registerForm struct {
	Q string `json:"q"`
}

func (q registerForm) Validate() error {
	return validation.ValidateStruct(&q, validation.Field(&q.Q, validation.Required, is.Alphanumeric))
}

type shoe struct {
	Color string `json:"color"`
	Type  string `json:"type"`
}

func (q shoe) Validate() error {
	return validation.ValidateStruct(
		&q,
		validation.Field(&q.Color),
		validation.Field(&q.Type, validation.Length(2, 8)),
	)
}

type orderForm struct {
	Order string `json:"order"`
	Shoe  shoe   `json:"shoe"`
}

func (q orderForm) Validate() error {
	return validation.ValidateStruct(
		&q,
		validation.Field(&q.Order, validation.Required),
		validation.Field(&q.Shoe, validation.Required),
	)
}

func TestMiddleware(t *testing.T) {
	runTestCases(
		[]testCase[any]{
			{
				desc: "Status",
				m:    middleware.Status[any](349),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, 349, res.StatusCode)
				},
			},
			{
				desc: "Header",
				m:    middleware.Header[any]("X-Name", "Value"),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, "Value", res.Header.Get("X-Name"))
				},
			},
			{
				desc: "ContentType",
				m:    middleware.ContentType[any](middleware.MediaTypeApplicationJSON),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, middleware.MediaTypeApplicationJSON, res.Header.Get("Content-Type"))
				},
			},
			{
				desc: "Write",
				m:    middleware.Write[any]([]byte("foobarbaz")),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, "foobarbaz", w.Body.String())
				},
			},
			{
				desc: "JSON",
				m:    middleware.JSON[any](map[string]int{"a": 1}),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					body, _ := ioutil.ReadAll(res.Body)
					assert.Equal(t, `{"a":1}`, string(body))
					assert.Equal(t, middleware.MediaTypeApplicationJSON, res.Header.Get("Content-Type"))
				},
			},
			{
				desc: "PlainText",
				m:    middleware.PlainText[any]("quuqux"),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					body, _ := ioutil.ReadAll(res.Body)
					assert.Equal(t, "quuqux", string(body))
					assert.Equal(t, middleware.MediaTypeTextPlain, res.Header.Get("Content-Type"))
				},
			},
			{
				desc: "HTML",
				m:    middleware.HTML[any]("<h1>It works!</h1>"),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, "<h1>It works!</h1>", w.Body.String())
					assert.Equal(t, middleware.MediaTypeTextHTML, res.Header.Get("Content-Type"))
				},
			},
			{
				desc: "Redirect",
				m:    middleware.Redirect[any]("/users", 302),
				req:  httptest.NewRequest(http.MethodGet, "/", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, "/users", res.Header.Get("Location"))
					assert.Equal(t, 302, res.StatusCode)
				},
			},
			{
				desc: "DecodeQuery (ok 1)",
				m: middleware.Chain(
					middleware.DecodeQuery[registerForm](),
					middleware.JSON[*registerForm],
				),
				req: httptest.NewRequest(http.MethodGet, "/?q=tobiferret", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"q":"tobiferret"}`, w.Body.String())
				},
			},
			{
				desc: "DecodeQuery (ok 2)",
				m: middleware.Chain(
					middleware.DecodeQuery[orderForm](),
					middleware.JSON[*orderForm],
				),
				req: httptest.NewRequest(http.MethodGet, "/?order=desc&shoe.color=blue&shoe.type=converse", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"order":"desc","shoe":{"color":"blue","type":"converse"}}`, w.Body.String())
				},
			},
			{
				desc: "DecodeQuery (error)",
				m: middleware.Chain(
					middleware.OrElse(
						middleware.DecodeQuery[orderForm](),
						func(err error) middleware.Middleware[*orderForm] {
							return middleware.FromResult(func() (*orderForm, error) {
								return &orderForm{
									Order: err.Error(),
								}, nil
							})
						},
					),
					middleware.JSON[*orderForm],
				),
				req: httptest.NewRequest(http.MethodGet, "/?order=desc&shoe.color=blue&shoe.type=x", nil),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"order":"shoe: (type: the length must be between 2 and 8.).","shoe":{"color":"","type":""}}`, w.Body.String())
				},
			},
			{
				desc: "DecodeBody (form)",
				m: middleware.Chain(
					middleware.DecodeBody[registerForm](),
					middleware.JSON[*registerForm],
				),
				req: (func() (r *http.Request) {
					data := url.Values{}
					data.Set("q", "fooqux")
					r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(data.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					return
				})(),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"q":"fooqux"}`, w.Body.String())
				},
			},
			{
				desc: "DecodeBody (json)",
				m: middleware.Chain(
					middleware.DecodeBody[registerForm](),
					middleware.JSON[*registerForm],
				),
				req: (func() (r *http.Request) {
					body, err := json.Marshal(map[string]string{"q": "mytoken"})
					assert.NoError(t, err)
					r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
					r.Header.Set("Content-Type", "application/json")
					return
				})(),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"q":"mytoken"}`, w.Body.String())
				},
			},
			{
				desc: "DecodeBody (json error)",
				m: middleware.Chain(
					middleware.OrElse(
						middleware.DecodeBody[registerForm](),
						func(err error) middleware.Middleware[*registerForm] {
							return middleware.FromResult(func() (*registerForm, error) {
								return &registerForm{
									Q: err.Error(),
								}, nil
							})
						},
					),
					middleware.JSON[*registerForm],
				),
				req: (func() (r *http.Request) {
					body, err := json.Marshal(map[string]string{"z": "mytoken"})
					assert.NoError(t, err)
					r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
					r.Header.Set("Content-Type", "application/json")
					return
				})(),
				fn: func(t *testing.T, res *http.Response, w *httptest.ResponseRecorder) {
					assert.Equal(t, `{"q":"q: cannot be blank."}`, w.Body.String())
				},
			},
		},
		t,
	)
}
