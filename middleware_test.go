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
	"github.com/gorilla/mux"
	"github.com/onur1/middleware"
	"github.com/stretchr/testify/assert"
)

func newMiddleware(r *http.Request) (*middleware.Middleware, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()

	return middleware.NewMiddleware(w, r), w
}

type registerForm struct {
	Q string `schema:"q"`
}

func (q registerForm) Validate() error {
	return validation.ValidateStruct(&q, validation.Field(&q.Q, validation.Required, is.Alphanumeric))
}

type shoe struct {
	Color string `schema:"color"`
	Type  string `schema:"type"`
}

func (q shoe) Validate() error {
	return validation.ValidateStruct(
		&q,
		validation.Field(&q.Color),
		validation.Field(&q.Type, validation.Length(2, 8)),
	)
}

type orderForm struct {
	Order string `schema:"order"`
	Shoe  shoe   `schema:"shoe"`
}

func (q orderForm) Validate() error {
	return validation.ValidateStruct(
		&q,
		validation.Field(&q.Order, validation.Required),
		validation.Field(&q.Shoe, validation.Required),
	)
}

func TestStatus(t *testing.T) {
	t.Run("should write the status code", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		m.Status(349)

		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, 349, res.StatusCode)
	})
}

func TestHeader(t *testing.T) {
	t.Run("should write the headers", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		m.Header("X-Name", "Value")

		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, 200, res.StatusCode)
		assert.Equal(t, "Value", res.Header.Get("X-Name"))
	})
}

func TestSend(t *testing.T) {
	t.Run("should send the content", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		_ = m.Send([]byte("<h1>Hello world!</h1>"), http.StatusOK)

		assert.Equal(t, "<h1>Hello world!</h1>", w.Body.String())
	})
}

func TestJSON(t *testing.T) {
	t.Run("should add the proper header and send the json content", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		_ = m.SendJSON(map[string]int{"a": 1}, http.StatusOK)

		res := w.Result()
		defer res.Body.Close()

		body, _ := ioutil.ReadAll(res.Body)

		assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
		assert.Equal(t, `{"a":1}`, string(body))
	})
}

func TestSendPlainText(t *testing.T) {
	t.Run("should add the proper header and send the json content", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		_ = m.SendPlainText("Hello, world!", http.StatusOK)

		res := w.Result()
		defer res.Body.Close()

		body, _ := ioutil.ReadAll(res.Body)

		assert.Equal(t, "text/plain", res.Header.Get("Content-Type"))
		assert.Equal(t, "Hello, world!", string(body))
	})
}

func TestContentType(t *testing.T) {
	t.Run("should add the content-type header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		m.ContentType(middleware.MediaTypeApplicationXML)

		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, "application/xml", res.Header.Get("Content-Type"))
	})
}

func TestRedirect(t *testing.T) {
	t.Run("should redirect and add the correct status / header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, w := newMiddleware(r)

		m.Redirect("/users", 302)

		res := w.Result()
		defer res.Body.Close()

		assert.Equal(t, "/users", res.Header.Get("Location"))
		assert.Equal(t, 302, res.StatusCode)
	})
}

func TestDecodeParam(t *testing.T) {
	t.Run("should validate an int param (success)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "-42"},
		)

		m, _ := newMiddleware(r)

		id, err := m.DecodeIntParam("id")

		assert.NoError(t, err)
		assert.Equal(t, int64(-42), id)
	})

	t.Run("should validate an int param (failure)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "abc"},
		)

		m, _ := newMiddleware(r)

		_, err := m.DecodeIntParam("id")

		assert.EqualError(t, err, "strconv.ParseInt: parsing \"abc\": invalid syntax")
	})

	t.Run("should validate a uint param (success)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "42"},
		)

		m, _ := newMiddleware(r)

		id, err := m.DecodeUintParam("id")

		assert.NoError(t, err)
		assert.Equal(t, uint64(42), id)
	})

	t.Run("should validate a uint param (failure)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "-42"},
		)

		m, _ := newMiddleware(r)

		_, err := m.DecodeUintParam("id")

		assert.EqualError(t, err, "strconv.ParseUint: parsing \"-42\": invalid syntax")
	})

	t.Run("should validate a float param (success)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "42.2442"},
		)

		m, _ := newMiddleware(r)

		id, err := m.DecodeFloatParam("id")

		assert.NoError(t, err)
		assert.Equal(t, float64(42.2442), id)
	})

	t.Run("should validate a float param (failure)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "abc"},
		)

		m, _ := newMiddleware(r)

		_, err := m.DecodeFloatParam("id")

		assert.EqualError(t, err, "strconv.ParseFloat: parsing \"abc\": invalid syntax")
	})

	t.Run("should validate a bool param (success)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "true"},
		)

		m, _ := newMiddleware(r)

		id, err := m.DecodeBoolParam("id")

		assert.NoError(t, err)
		assert.Equal(t, true, id)
	})

	t.Run("should validate a float param (failure 1)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "abc"},
		)

		m, _ := newMiddleware(r)

		_, err := m.DecodeBoolParam("id")

		assert.EqualError(t, err, "strconv.ParseBool: parsing \"abc\": invalid syntax")
	})

	t.Run("should validate a float param (failure 2)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{},
		)

		m, _ := newMiddleware(r)

		_, err := m.DecodeBoolParam("id")

		assert.EqualError(t, err, "strconv.ParseBool: parsing \"\": invalid syntax")
	})

	t.Run("should validate a string param (success)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": "value"},
		)

		m, _ := newMiddleware(r)

		id, err := m.ValidateParam("id", validation.Required)

		assert.NoError(t, err)
		assert.Equal(t, "value", id)
	})

	t.Run("should validate a string param (failure)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{"id": ""},
		)

		m, _ := newMiddleware(r)

		_, err := m.ValidateParam("id", validation.Required, validation.Length(1, 2))

		assert.EqualError(t, err, "cannot be blank")
	})

	t.Run("should validate an optional string param", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{},
		)

		m, _ := newMiddleware(r)

		id, err := m.ValidateParam("id")

		assert.NoError(t, err)
		assert.Equal(t, "", id)
	})

	t.Run("should validate a required param (failure)", func(t *testing.T) {
		r := mux.SetURLVars(
			httptest.NewRequest(http.MethodGet, "/", nil),
			map[string]string{},
		)

		m, _ := newMiddleware(r)

		_, err := m.ValidateParam("id", validation.Required)

		assert.EqualError(t, err, "cannot be blank")
	})
}

func TestDecodeQuery(t *testing.T) {
	t.Run("should validate a query (success 1)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?q=tobiferret", nil)
		m, _ := newMiddleware(r)

		dst := &registerForm{}

		err := m.DecodeQuery(dst)

		assert.NoError(t, err)
		assert.Equal(t, "tobiferret", dst.Q)
	})

	t.Run("should validate a query (success 2)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?order=desc&shoe.color=blue&shoe.type=converse", nil)
		m, _ := newMiddleware(r)

		dst := &orderForm{}

		err := m.DecodeQuery(dst)

		assert.NoError(t, err)
		assert.Equal(t, &orderForm{
			Order: "desc",
			Shoe: shoe{
				Color: "blue",
				Type:  "converse",
			},
		}, dst)
	})

	t.Run("should validate a query (failure 1)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?q=tobi+ferret", nil)
		m, _ := newMiddleware(r)

		dst := &registerForm{}

		err := m.DecodeQuery(dst)

		assert.EqualError(t, err, "Q: must contain English letters and digits only.")
	})

	t.Run("should validate a query (failure 2)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?order=desc&shoe.color=blue&shoe.type=x", nil)
		m, _ := newMiddleware(r)

		dst := &orderForm{}

		err := m.DecodeQuery(dst)

		assert.EqualError(t, err, "Shoe: (Type: the length must be between 2 and 8.).")
	})
}

func TestDecodeHeader(t *testing.T) {
	t.Run("should validate a header (success)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, _ := newMiddleware(r)

		r.Header.Set("X-Name", "tobi ferret")

		a, err := m.ValidateHeader("X-Name")

		assert.NoError(t, err)
		assert.Equal(t, "tobi ferret", a)
	})

	t.Run("should validate a header (failure)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		m, _ := newMiddleware(r)

		_, err := m.ValidateHeader("X-Name", validation.Required)

		assert.EqualError(t, err, "cannot be blank")
	})
}

func TestDecodeBody(t *testing.T) {
	t.Run("should validate the form body (success)", func(t *testing.T) {
		data := url.Values{}

		data.Set("q", "foo")

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(data.Encode()))

		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		m, _ := newMiddleware(r)

		dst := &registerForm{}

		err := m.DecodeBody(dst)
		assert.NoError(t, err)

		assert.Equal(t, "foo", dst.Q)
	})

	t.Run("should validate the json body (success)", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{"q": "mytoken"})
		assert.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))

		r.Header.Set("Content-Type", "application/json")

		m, _ := newMiddleware(r)

		dst := &registerForm{}

		err = m.DecodeBody(dst)
		assert.NoError(t, err)

		assert.Equal(t, "mytoken", dst.Q)
	})

	t.Run("should validate the json body (failure)", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{"z": "mytoken"})
		assert.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))

		r.Header.Set("Content-Type", "application/json")

		m, _ := newMiddleware(r)

		dst := &registerForm{}

		err = m.DecodeBody(dst)
		assert.EqualError(t, err, "Q: cannot be blank.")
	})
}
